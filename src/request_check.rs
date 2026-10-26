//! The `test-request` check: screens one sample request against a configuration and
//! reports what the router would do with it.
//!
//! Nothing is forwarded, and neither the upstream nor the decision backend is
//! contacted. The request goes through the functions the server uses, in the server's
//! order: the Host lookup, the access list, the body limit, [`prefilter::screen`] and
//! [`policy::decide`]. The limit counts are the one thing left out, because they depend
//! on earlier requests: the limits that would apply are listed, and no count changes.
//!
//! The `realip` settings are not applied: the client address is the one given to the
//! command.

use std::fmt::{self, Write as _};
use std::net::IpAddr;
use std::path::Path;

use http::header::HOST;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri};

use crate::access;
use crate::block::{BlockResponse, BlockStatus};
use crate::config::{BackendConfig, Config, FailureAction, Mode, SiteConfig};
use crate::error::ConfigError;
use crate::limits::{self, LimitSet};
use crate::policy::{self, Action, Assessment, Decision};
use crate::prefilter::{self, Screening};
use crate::router::{Router, is_valid_host};
use crate::rules::{Rule, RuleInput};
use crate::server::content_length;

/// Why a check could not run.
#[derive(Debug, thiserror::Error)]
pub enum CheckError {
    /// The configuration is invalid or cannot be read. The message names the file and line.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// The request file is not a raw HTTP/1.1 request. The message names the line.
    #[error("invalid request: {0}")]
    Request(String),
}

/// What the router does with a request, as the server would decide it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Forwarded to the upstream. In shadow mode this is also the outcome, and the
    /// report says what would have been done.
    Forwarded,
    /// Blocked with this status: the site's block status, or 403 for an access denial.
    Blocked(u16),
    /// Redirected with 302.
    Redirected,
    /// Refused before the rules run, with this status: 400, 413 or the default status.
    Rejected(u16),
    /// No deterministic check decides, so the decision backend would be called. Its verdict is
    /// not known without calling it.
    BackendDecides,
}

/// The result of a check. `Display` renders the plain text report from the same data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestCheck {
    /// The name of the site the Host selected, as the access log writes it, or `None` when no site matches.
    pub site: Option<String>,
    /// What the router would do.
    pub outcome: Outcome,
    /// Why, by the access log's reason name: `rule`, `skip_rule`, `skip`, `access_denied`,
    /// `invalid_host`, `unknown_host`, `body_too_large`. `None` when the backend decides.
    pub reason: Option<&'static str>,
    /// The id of the rule that decided the request, for a block or skip rule.
    pub rule_id: Option<String>,
    lines: Vec<String>,
}

impl fmt::Display for RequestCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for line in &self.lines {
            writeln!(f, "{line}")?;
        }
        Ok(())
    }
}

/// Checks the request in `raw` against the configuration at `config_path`, for a client at `client`.
///
/// # Errors
///
/// Returns [`CheckError::Config`] when the configuration is invalid, and
/// [`CheckError::Request`] when `raw` is not a raw HTTP/1.1 request.
pub fn check_request(
    config_path: &Path,
    raw: &[u8],
    client: IpAddr,
) -> Result<RequestCheck, CheckError> {
    let config = Config::load(config_path)?;
    let request = parse_request(raw)?;
    Ok(report(&config, &request, client))
}

/// A request read from a file: the request line, the headers and the body.
#[derive(Debug)]
struct SampleRequest {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Vec<u8>,
}

/// Reads a raw HTTP/1.1 request. Lines end in LF or CRLF. The headers end at the first
/// blank line, and everything after it is the body.
fn parse_request(raw: &[u8]) -> Result<SampleRequest, CheckError> {
    let mut lines = raw.split_inclusive(|byte| *byte == b'\n').enumerate();
    let (_, first) = lines
        .next()
        .ok_or_else(|| CheckError::Request("the file is empty".to_owned()))?;
    let request_line = line_text(first, 1)?;
    let fields: Vec<&str> = request_line.split(' ').collect();
    let [method, target, version] = fields.as_slice() else {
        return Err(request_error(
            1,
            "the request line must be `METHOD target HTTP/1.1`",
        ));
    };
    if *version != "HTTP/1.1" {
        return Err(request_error(1, "the version must be HTTP/1.1"));
    }
    let method = Method::from_bytes(method.as_bytes())
        .map_err(|_| request_error(1, format!("invalid method {method:?}")))?;
    let uri = target
        .parse::<Uri>()
        .map_err(|_| request_error(1, format!("invalid request target {target:?}")))?;

    let mut headers = HeaderMap::new();
    let mut body = Vec::new();
    let mut ended = false;
    while let Some((index, line)) = lines.next() {
        let number = index + 1;
        let text = line_text(line, number)?;
        if text.is_empty() {
            ended = true;
            for (_, rest) in lines.by_ref() {
                body.extend_from_slice(rest);
            }
            break;
        }
        let (name, value) = text
            .split_once(':')
            .ok_or_else(|| request_error(number, "a header line has no colon"))?;
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| request_error(number, format!("invalid header name {name:?}")))?;
        let value = HeaderValue::from_str(value.trim_matches(|c: char| c == ' ' || c == '\t'))
            .map_err(|_| request_error(number, "invalid header value"))?;
        headers.append(name, value);
    }
    if !ended {
        return Err(CheckError::Request(
            "the headers are not ended by a blank line".to_owned(),
        ));
    }
    Ok(SampleRequest {
        method,
        uri,
        headers,
        body,
    })
}

/// The text of one line without its line ending. `number` is the line number, for errors.
fn line_text(line: &[u8], number: usize) -> Result<&str, CheckError> {
    let without_lf = line.strip_suffix(b"\n").unwrap_or(line);
    let trimmed = without_lf.strip_suffix(b"\r").unwrap_or(without_lf);
    std::str::from_utf8(trimmed).map_err(|_| request_error(number, "the line is not text"))
}

fn request_error(number: usize, reason: impl fmt::Display) -> CheckError {
    CheckError::Request(format!("line {number}: {reason}"))
}

/// The site a request is checked against, with the block response and the upstream that apply to it.
struct Target<'a> {
    config: &'a Config,
    site: &'a SiteConfig,
    /// The lowercase path views of the request, see [`prefilter::path_views`].
    lowered: Vec<String>,
    /// The block response of the selected location, or of the site.
    block: &'a BlockResponse,
    upstream: String,
}

/// The outcome, reason and rule of a decision, before the report is built.
struct Verdict {
    outcome: Outcome,
    reason: Option<&'static str>,
    rule_id: Option<String>,
}

impl Verdict {
    fn rejected(status: u16, reason: &'static str) -> Self {
        Self {
            outcome: Outcome::Rejected(status),
            reason: Some(reason),
            rule_id: None,
        }
    }

    /// The verdict of a policy decision. The rule id is set by the caller.
    fn decided(decision: &Decision, block: &BlockResponse) -> Self {
        let outcome = match &decision.action {
            Action::Allow => Outcome::Forwarded,
            Action::Block => Outcome::Blocked(status_of(block)),
            Action::Redirect(_) => Outcome::Redirected,
            Action::Reject(status) => Outcome::Rejected(status.as_u16()),
        };
        Self {
            outcome,
            reason: Some(decision.reason.name()),
            rule_id: None,
        }
    }
}

/// The status a block response sends. A 444 close is reported as 444.
fn status_of(block: &BlockResponse) -> u16 {
    match block.status {
        BlockStatus::Respond(status) => status.as_u16(),
        BlockStatus::Close => 444,
    }
}

/// Builds the check. The order of the checks follows `server::pipeline`.
#[expect(
    clippy::too_many_lines,
    reason = "the checks read top to bottom in the order of server::pipeline; splitting them would scatter that order"
)]
fn report(config: &Config, request: &SampleRequest, client: IpAddr) -> RequestCheck {
    let mut lines = Vec::new();
    let router = Router::new(&config.sites);
    let host_header = request.headers.get(HOST);
    let host_text = host_header.map_or("(none)", |value| value.to_str().unwrap_or("(not text)"));
    let path = request.uri.path();
    let target = request
        .uri
        .path_and_query()
        .map_or(path, |value| value.as_str());
    lines.push(format!(
        "request: {} {target:?} (Host: {host_text:?}, client: {client})",
        request.method
    ));

    let matched = router
        .lookup(host_header)
        .and_then(|index| config.sites.get(index));
    let site_label = matched.map(|site| site_name(site).to_owned());
    lines.push(match matched {
        Some(site) => format!(
            "site: {} (shadow {})",
            site_name(site),
            if site.mode == Mode::Shadow {
                "on"
            } else {
                "off"
            }
        ),
        None => "site: none (no site matches the Host)".to_owned(),
    });

    // The limits run first. Their counts are not simulated, see the module documentation.
    let decoded = prefilter::decoded_path(path);
    let views = prefilter::path_views(path);
    lines.push(applicable_limits_line(config, matched, &views));

    let host_valid = host_header.is_none_or(|value| value.to_str().is_ok_and(is_valid_host));
    if !host_valid {
        lines.push("result: rejected with 400 (invalid Host header)".to_owned());
        return finish(lines, site_label, Verdict::rejected(400, "invalid_host"));
    }

    let entries = matched.map_or(config.access.as_slice(), |site| site.access.as_slice());
    let allowed = access::permits(entries, client);
    lines.push(format!(
        "access list: {}",
        if allowed { "allowed" } else { "denied" }
    ));

    let Some(site) = matched else {
        if allowed {
            lines.push(format!(
                "result: rejected with {} (unknown host, no site matches the Host)",
                config.default_status.as_u16()
            ));
            let status = config.default_status.as_u16();
            return finish(lines, None, Verdict::rejected(status, "unknown_host"));
        }
        lines.push("result: blocked with 403 by the access list".to_owned());
        return finish(
            lines,
            None,
            Verdict {
                outcome: Outcome::Blocked(403),
                reason: Some("access_denied"),
                rule_id: None,
            },
        );
    };

    // The location of the decoded path sets the block response, as in the server.
    let block = limits::select_location(&site.locations, &decoded)
        .map_or(&site.block, |location| &location.block);
    let target = Target {
        config,
        site,
        lowered: views.iter().map(|view| view.to_lowercase()).collect(),
        block,
        upstream: site.upstream.to_string(),
    };

    if !allowed {
        let verdict = access_denied_lines(&target, &mut lines);
        return finish(lines, site_label, verdict);
    }

    if let Some(max) = site.timeouts.max_body_bytes {
        let declared =
            content_length(&request.headers).is_some_and(|length| u128::from(length) > max as u128);
        if declared || request.body.len() > max {
            lines.push(format!(
                "body: larger than client_max_body_size ({max} bytes)"
            ));
            lines.push("result: rejected with 413 (body_too_large)".to_owned());
            return finish(lines, site_label, Verdict::rejected(413, "body_too_large"));
        }
    }

    // The inspected prefix of the body, as the server sniffs it.
    let inspected = config.decision.inspect_body_bytes.min(request.body.len());
    let prefix = request.body.get(..inspected).unwrap_or_default();
    let input = RuleInput::with_views(
        &request.method,
        path,
        &views,
        request.uri.query(),
        &request.headers,
        prefix,
        client,
    );
    let screening = prefilter::screen(site, &input, request.body.is_empty());
    let verdict = screen_lines(&target, &input, &screening, &mut lines);
    finish(lines, site_label, verdict)
}

fn finish(lines: Vec<String>, site: Option<String>, verdict: Verdict) -> RequestCheck {
    RequestCheck {
        site,
        outcome: verdict.outcome,
        reason: verdict.reason,
        rule_id: verdict.rule_id,
        lines,
    }
}

/// The checks of a request whose client the access list denies. Its body is not read,
/// and no rule runs. The response is 403, or a shadow forward.
fn access_denied_lines(target: &Target<'_>, lines: &mut Vec<String>) -> Verdict {
    lines.push("deny_path: not checked (the access list denied the client)".to_owned());
    lines.push("rules: not checked (the access list denied the client)".to_owned());
    let decision = policy::decide(target.site, &target.lowered, &Assessment::AccessDenied);
    // An access denial is always 403, whatever block_status says.
    lines.push(format!(
        "result: {}",
        verdict_text(
            &decision,
            &BlockResponse::default(),
            &target.upstream,
            "the access list"
        )
    ));
    Verdict::decided(&decision, &BlockResponse::default())
}

/// The `deny_path` and rule checks, and the result: a decision from the rules, or the backend
/// call that would follow when no rule decides.
fn screen_lines(
    target: &Target<'_>,
    input: &RuleInput<'_>,
    screening: &Screening,
    lines: &mut Vec<String>,
) -> Verdict {
    let site = target.site;
    let denied = prefilter::denied_by(site, &target.lowered);
    lines.push(match denied {
        Some(entry) => format!("deny_path: matched {entry:?}"),
        None => "deny_path: no match".to_owned(),
    });

    let assessed = match screening {
        Screening::Rule(None) => {
            lines.push("rules: not checked (deny_path matched)".to_owned());
            let entry = denied.unwrap_or_default();
            Some((Assessment::Rule, format!("deny_path {entry}"), None))
        }
        Screening::Rule(Some(id)) => {
            let rule = site.rules.block.iter().find(|rule| rule.id == *id);
            lines.push(rule_line(rule.map(AsRef::as_ref), "block", input));
            Some((Assessment::Rule, format!("rule {id}"), Some(id.to_string())))
        }
        Screening::SkipRule(id) => {
            lines.push("rules: no block rule matched".to_owned());
            let rule = site.rules.skip.iter().find(|rule| rule.id == *id);
            lines.push(rule_line(rule.map(AsRef::as_ref), "skip", input));
            Some((
                Assessment::SkipRule,
                format!("skip rule {id}"),
                Some(id.to_string()),
            ))
        }
        Screening::Skip => {
            lines.push("rules: no block or skip rule matched".to_owned());
            lines.push("static asset skip: applies".to_owned());
            Some((Assessment::Skip, "static asset skip".to_owned(), None))
        }
        Screening::Inspect => {
            lines.push("rules: no block or skip rule matched".to_owned());
            lines.push("static asset skip: does not apply".to_owned());
            None
        }
    };

    if let Some((assessment, by, rule_id)) = assessed {
        let decision = policy::decide(site, &target.lowered, &assessment);
        lines.push(format!(
            "result: {}",
            verdict_text(&decision, target.block, &target.upstream, &by)
        ));
        Verdict {
            rule_id,
            ..Verdict::decided(&decision, target.block)
        }
    } else {
        backend_lines(target, lines);
        Verdict {
            outcome: Outcome::BackendDecides,
            reason: None,
            rule_id: None,
        }
    }
}

/// The limits line for the site, or for the location each reading of the path selects.
fn applicable_limits_line(
    config: &Config,
    matched: Option<&SiteConfig>,
    views: &[String],
) -> String {
    let locations = matched.map_or_else(Vec::new, |site| {
        limits::select_locations(&site.locations, views)
    });
    let limit_sets: Vec<&LimitSet> = if locations.is_empty() {
        vec![matched.map_or(&config.limits, |site| &site.limits)]
    } else {
        locations.iter().map(|location| &location.limits).collect()
    };
    limits_line(config, &limit_sets)
}

/// Describes the call to the backend that would follow, and what a verdict would do.
/// The verdict itself is unknown without calling the backend.
fn backend_lines(target: &Target<'_>, lines: &mut Vec<String>) {
    let site = target.site;
    lines.push(format!(
        "result: would be sent to the decision backend ({}); the verdict is not known without calling it",
        backend_name(&target.config.decision.backend)
    ));
    let blocked = action_text(&policy::site_action(site), target.block);
    let threshold = format!(
        "a verdict of attack {} or more, or ai_instruction {} or more, would be {blocked}",
        site.block_threshold, site.instruction_threshold
    );
    if site.mode == Mode::Shadow {
        lines.push(format!(
            "shadow mode: {threshold} and recorded, and the request would be forwarded to {}",
            target.upstream
        ));
    } else {
        lines.push(format!(
            "otherwise the request would be forwarded to {}; {threshold}",
            target.upstream
        ));
    }
    let failure = match site.on_decision_error {
        FailureAction::Allow => "allowed",
        FailureAction::Block => "blocked",
    };
    let fails_closed = if prefilter::fails_closed(site, &target.lowered) {
        " (a fail_closed_path matches, so it is blocked either way)"
    } else {
        ""
    };
    lines.push(format!(
        "if the backend fails, the request would be {failure} by on_decision_error{fails_closed}"
    ));
}

/// The text of one action, with the status that a block response sends.
fn action_text(action: &Action, block: &BlockResponse) -> String {
    match action {
        Action::Allow => "forwarded".to_owned(),
        Action::Block => match block.status {
            BlockStatus::Respond(status) => format!("blocked with {}", status.as_u16()),
            BlockStatus::Close => "closed without a response (444)".to_owned(),
        },
        Action::Redirect(location) => format!(
            "redirected with 302 to {:?}",
            location.to_str().unwrap_or("(not text)")
        ),
        Action::Reject(status) => format!("rejected with {}", status.as_u16()),
    }
}

/// The result line of a decision: what was done and why, and in shadow mode what would have been done.
fn verdict_text(decision: &Decision, block: &BlockResponse, upstream: &str, by: &str) -> String {
    match (&decision.action, &decision.would_have) {
        (Action::Allow, Some(would_have)) => format!(
            "forwarded to {upstream} (shadow mode: would have been {} by {by})",
            action_text(would_have, block)
        ),
        (Action::Allow, None) => {
            format!("forwarded to {upstream} without the decision backend ({by})")
        }
        (action, _) => format!("{} by {by}", action_text(action, block)),
    }
}

/// The line for the rule that matched, with the path readings it matched when it has a path condition.
fn rule_line(rule: Option<&Rule>, kind: &str, input: &RuleInput<'_>) -> String {
    let Some(rule) = rule else {
        return format!("rules: {kind} rule matched (not found in the configuration)");
    };
    let mut line = format!("rules: {} matched ({kind}): {}", rule.id, rule.description);
    let readings = rule.path_readings(input);
    if !readings.is_empty() {
        let _ = write!(line, "; path readings {readings:?}");
    }
    line
}

/// The limits that would apply, by zone name. Their counts are not simulated.
fn limits_line(config: &Config, sets: &[&LimitSet]) -> String {
    let mut req: Vec<&str> = Vec::new();
    let mut conn: Vec<&str> = Vec::new();
    for set in sets {
        for limit in &set.req {
            if let Some(zone) = config.zones.get(limit.zone)
                && !req.contains(&zone.name.as_str())
            {
                req.push(zone.name.as_str());
            }
        }
        for limit in &set.conn {
            if let Some(zone) = config.zones.get(limit.zone)
                && !conn.contains(&zone.name.as_str())
            {
                conn.push(zone.name.as_str());
            }
        }
    }
    let describe = |names: &[&str]| {
        if names.is_empty() {
            "none".to_owned()
        } else {
            names.join(", ")
        }
    };
    format!(
        "limits: not simulated (counts depend on earlier requests); limit_req zones: {}; limit_conn zones: {}",
        describe(&req),
        describe(&conn)
    )
}

fn backend_name(backend: &BackendConfig) -> String {
    match backend {
        BackendConfig::Http => "http".to_owned(),
        BackendConfig::Clef { model, .. } => format!("clef, model {}", model.as_str()),
        BackendConfig::Jev { model, .. } => format!("jev, model {model}"),
        BackendConfig::Strands { model, .. } => format!("strands, model {model}"),
    }
}

fn site_name(site: &SiteConfig) -> &str {
    site.hosts.first().map_or("", String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::lf(b"GET / HTTP/1.1\nHost: a\n\n", "GET", "/", b"".as_slice())]
    #[case::crlf(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", "GET", "/", b"".as_slice())]
    #[case::body_kept_exactly(b"POST /p HTTP/1.1\nHost: a\n\nx=1\r\n", "POST", "/p", b"x=1\r\n".as_slice())]
    fn a_raw_request_is_read(
        #[case] raw: &[u8],
        #[case] method: &str,
        #[case] path: &str,
        #[case] body: &[u8],
    ) -> Result<(), CheckError> {
        let parsed = parse_request(raw)?;
        assert_eq!(parsed.method.as_str(), method);
        assert_eq!(parsed.uri.path(), path);
        assert_eq!(parsed.body, body);
        Ok(())
    }

    #[rstest]
    #[case::empty(b"", "the file is empty")]
    #[case::no_version(b"GET /\nHost: a\n\n", "the request line must be")]
    #[case::http_2(b"GET / HTTP/2\nHost: a\n\n", "the version must be HTTP/1.1")]
    #[case::header_without_colon(
        b"GET / HTTP/1.1\nHost a\n\n",
        "line 2: a header line has no colon"
    )]
    #[case::no_blank_line(
        b"GET / HTTP/1.1\nHost: a\n",
        "the headers are not ended by a blank line"
    )]
    fn a_malformed_request_is_refused(#[case] raw: &[u8], #[case] message: &str) {
        let error = parse_request(raw).err().map(|error| error.to_string());
        assert!(
            error.as_deref().is_some_and(|text| text.contains(message)),
            "{error:?}"
        );
    }
}
