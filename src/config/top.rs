//! The top level of the configuration: the directives outside any block, and the checks that need
//! the whole file (the required directives, the sites against each other, the rules against the
//! sites).

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use http::{HeaderName, StatusCode};

use super::decision::parse_decision;
use super::logs::{
    Formats, RawFormat, collect_formats, compile_formats, parse_error_log, resolve_top_access,
};
use super::names::TOP_LEVEL_DIRECTIVES;
use super::site::{Top, access_entry, parse_site, set_site_timeout};
use super::value::{parse_header_buffers, parse_lingering_close};
use super::{
    Config, ConnectionConfig, DEFAULT_CLIENT_BODY_TIMEOUT, DEFAULT_CLIENT_HEADER_TIMEOUT,
    DEFAULT_CLIENT_MAX_BODY, DEFAULT_HEADER_BUFFER_COUNT, DEFAULT_HEADER_BUFFER_SIZE,
    DEFAULT_KEEPALIVE_REQUESTS, DEFAULT_KEEPALIVE_TIMEOUT, DEFAULT_LINGERING_TIME,
    DEFAULT_LINGERING_TIMEOUT, DEFAULT_MAX_CONNECTIONS, DEFAULT_PID_FILE,
    DEFAULT_PROXY_CONNECT_TIMEOUT, DEFAULT_PROXY_READ_TIMEOUT, DEFAULT_PROXY_SEND_TIMEOUT,
    DEFAULT_SEND_TIMEOUT, DEFAULT_STATUS, Destination, ErrorLogConfig, HeaderBuffers,
    LingeringClose, LogLevel, SiteConfig, SiteTimeouts,
};
use crate::access::AccessEntry;
use crate::block::{BLOCK_NAMES, BlockOverrides, BlockResponse};
use crate::conf::{
    Directive, block, invalid, invalid_at_top, once, one_arg, parse_bool, parse_number,
    parse_positive_time, parse_time,
};
use crate::error::ConfigError;
use crate::limits::{self, LimitOverrides, LimitSet, LimitZone};
use crate::proxy::HeaderOp;
use crate::realip::{IpNet, RealIp};
use crate::rules::{self, ParsedRule, Rule, RuleSwitches, Scope};

/// Builds the whole configuration from the directive tree. The `log_format` directives are read
/// first, so that `access_log` can refer to a format written after it.
///
/// # Errors
///
/// Returns [`ConfigError::Invalid`] naming the file and line of the directive at fault, or of the
/// first directive of the file when a required directive is missing.
pub(crate) fn build<F>(directives: &[Directive], lookup: &F) -> Result<Config, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let builtin = rules::builtin_rules()?;
    let format_directives: Vec<&Directive> = directives
        .iter()
        .filter(|directive| directive.name == "log_format")
        .collect();
    let formats = collect_formats(&format_directives)?;
    let mut draft = TopDraft::new(builtin);
    for directive in directives {
        draft.apply(directive)?;
    }
    draft.finish(directives, formats, lookup)
}

/// The top level of the file while it is read: the settings read so far, which become the fields of
/// [`Config`] of the same names (and the [`Top`] that every site inherits) once `finish` has
/// resolved them, the single-use names and the rule ids seen so far, and the directives whose
/// values `finish` reads after the whole file is known.
/// An error in one directive points at that directive, and a missing required directive points at
/// the first directive of the file.
struct TopDraft<'a> {
    /// The built-in rules, which `disable_rule` and `enable_rule` name.
    builtin: &'a [Arc<Rule>],
    /// The names of the single-use directives seen so far, which the limit and block directives
    /// share.
    seen: HashSet<String>,
    /// Every rule id in use, built-in ids included, with the place it was written. The sites add
    /// their own.
    claimed: HashMap<String, String>,
    /// Whether the built-in rules are on at the top level.
    builtin_enabled: bool,
    /// The `disable_rule` and `enable_rule` ids of the top level.
    switches: RuleSwitches,
    /// The top-level `allow` and `deny` entries.
    access: Vec<AccessEntry>,
    /// The block response directives of the top level, which `finish` resolves.
    block: BlockOverrides,
    /// The top-level `proxy_set_header` operations. `None` until the first one is written.
    headers: Option<Vec<HeaderOp>>,
    /// The rules written at the top level, each with the sites it applies to.
    rules: Vec<ParsedRule>,
    listen: Option<String>,
    pid_file: PathBuf,
    worker_threads: Option<usize>,
    max_connections: usize,
    worker_shutdown_timeout: Option<Duration>,
    request_id_header: Option<HeaderName>,
    realip: RealIp,
    default_status: u16,
    /// The `decision` directive, which `finish` parses once the whole file is read.
    decision: Option<&'a Directive>,
    /// The `site` directives, in file order.
    sites: Vec<&'a Directive>,
    error_log: ErrorLogConfig,
    /// The `access_log` directives, which `finish` resolves against the formats.
    access_logs: Vec<&'a Directive>,
    /// The `limit_req_zone` and `limit_conn_zone` directives, which `finish` builds the zones from.
    zones: Vec<&'a Directive>,
    /// The limit directives of the top level, which `finish` applies once the zones are built.
    limits: Vec<&'a Directive>,
    connection: ConnectionConfig,
    /// The top-level timers and body limit, inherited by every site.
    site_timeouts: SiteTimeouts,
}

impl<'a> TopDraft<'a> {
    /// A draft with the defaults, whose `claimed` rule ids are those of the `builtin` rules.
    fn new(builtin: &'a [Arc<Rule>]) -> Self {
        Self {
            builtin,
            seen: HashSet::new(),
            claimed: builtin
                .iter()
                .map(|rule| (rule.id.to_string(), "the built-in rules".to_owned()))
                .collect(),
            builtin_enabled: true,
            switches: RuleSwitches::default(),
            access: Vec::new(),
            block: BlockOverrides::default(),
            headers: None,
            rules: Vec::new(),
            listen: None,
            pid_file: PathBuf::from(DEFAULT_PID_FILE),
            worker_threads: None,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            worker_shutdown_timeout: None,
            request_id_header: None,
            realip: RealIp {
                trusted: Vec::new(),
                header: HeaderName::from_static("x-real-ip"),
                recursive: false,
            },
            default_status: DEFAULT_STATUS,
            decision: None,
            sites: Vec::new(),
            error_log: ErrorLogConfig {
                destination: Destination::Stderr,
                level: LogLevel::Info,
            },
            access_logs: Vec::new(),
            zones: Vec::new(),
            limits: Vec::new(),
            connection: ConnectionConfig {
                client_header_timeout: DEFAULT_CLIENT_HEADER_TIMEOUT,
                keepalive_timeout: DEFAULT_KEEPALIVE_TIMEOUT,
                keepalive_requests: DEFAULT_KEEPALIVE_REQUESTS,
                send_timeout: DEFAULT_SEND_TIMEOUT,
                large_header_buffers: HeaderBuffers {
                    count: DEFAULT_HEADER_BUFFER_COUNT,
                    size: DEFAULT_HEADER_BUFFER_SIZE,
                },
                lingering_close: LingeringClose::On,
                lingering_time: DEFAULT_LINGERING_TIME,
                lingering_timeout: DEFAULT_LINGERING_TIMEOUT,
            },
            site_timeouts: SiteTimeouts {
                client_body_timeout: DEFAULT_CLIENT_BODY_TIMEOUT,
                max_body_bytes: Some(DEFAULT_CLIENT_MAX_BODY),
                proxy_connect_timeout: DEFAULT_PROXY_CONNECT_TIMEOUT,
                proxy_read_timeout: DEFAULT_PROXY_READ_TIMEOUT,
                proxy_send_timeout: DEFAULT_PROXY_SEND_TIMEOUT,
            },
        }
    }

    /// Checks that `directive` is a top-level directive, then applies it. A repeated single-use
    /// directive fails before its argument is read. `log_format` is read before this, the zone
    /// and limit directives are kept for `finish`, and the lists, `allow`, `deny`, the rules, the
    /// sites and `access_log` add up. `max_body` and `include` are always refused, and `claimed`
    /// takes the id of each `rule`. The settings of the client connection have no arm here:
    /// `apply_connection` applies them.
    fn apply(&mut self, directive: &'a Directive) -> Result<(), ConfigError> {
        if !TOP_LEVEL_DIRECTIVES.contains(&directive.name.as_str()) {
            return Err(invalid(
                directive,
                format!("unknown directive \"{}\"", directive.name),
            ));
        }
        match directive.name.as_str() {
            "log_format" => {}
            name if limits::ZONE_NAMES.contains(&name) => self.zones.push(directive),
            name if limits::LIMIT_NAMES.contains(&name) => self.limits.push(directive),
            "listen" => {
                once(&mut self.seen, directive)?;
                self.listen = Some(one_arg(directive)?.to_owned());
            }
            "pid" => {
                once(&mut self.seen, directive)?;
                self.pid_file = PathBuf::from(one_arg(directive)?);
            }
            "worker_threads" => {
                self.worker_threads =
                    Some(self.once_count(directive, "\"worker_threads\" must be at least 1")?);
            }
            "max_connections" => {
                self.max_connections =
                    self.once_count(directive, "\"max_connections\" must be at least 1")?;
            }
            "worker_shutdown_timeout" => {
                self.worker_shutdown_timeout = Some(self.once_arg(directive, parse_positive_time)?);
            }
            "default_status" => {
                self.default_status = self.once_arg(directive, parse_default_status)?;
            }
            "request_id_header" => {
                self.request_id_header = Some(self.once_arg(directive, parse_request_id_header)?);
            }
            "real_ip_from" => self.realip.trusted.extend(trusted_nets(directive)?),
            "real_ip_header" => {
                self.realip.header = self.once_arg(directive, parse_real_ip_header)?;
            }
            "real_ip_recursive" => self.realip.recursive = self.once_arg(directive, parse_bool)?,
            "decision" => {
                once(&mut self.seen, directive)?;
                block(directive)?;
                self.decision = Some(directive);
            }
            "client_body_timeout"
            | "client_max_body_size"
            | "proxy_connect_timeout"
            | "proxy_read_timeout"
            | "proxy_send_timeout" => {
                once(&mut self.seen, directive)?;
                set_site_timeout(directive, &mut self.site_timeouts)?;
            }
            "max_body" => {
                return Err(invalid(
                    directive,
                    "\"max_body\" was replaced by \"client_max_body_size\", which is set at the top level",
                ));
            }
            "allow" | "deny" => self.access.push(access_entry(directive)?),
            name if BLOCK_NAMES.contains(&name) => self.block.apply(directive, &mut self.seen)?,
            "proxy_set_header" => self
                .headers
                .get_or_insert_with(Vec::new)
                .push(HeaderOp::parse(directive)?),
            "builtin_rules" => self.builtin_enabled = self.once_arg(directive, parse_bool)?,
            "disable_rule" => self
                .switches
                .disabled
                .extend(rules::builtin_ids(directive, self.builtin)?),
            "enable_rule" => self
                .switches
                .enabled
                .extend(rules::builtin_ids(directive, self.builtin)?),
            "rule" => {
                let parsed = rules::parse_rule(directive, Scope::Top)?;
                rules::claim_id(&mut self.claimed, &parsed)?;
                self.rules.push(parsed);
            }
            "site" => self.sites.push(directive),
            "error_log" => {
                once(&mut self.seen, directive)?;
                self.error_log = parse_error_log(directive)?;
            }
            "access_log" => self.access_logs.push(directive),
            "include" => {
                return Err(invalid(directive, "\"include\" was not expanded"));
            }
            // What is left are the settings of the client connection.
            _ => self.apply_connection(directive)?,
        }
        Ok(())
    }

    /// Applies a directive that sets a timer, a limit or the lingering close of the client
    /// connection. Each is single-use, so a repeat fails before its argument is read. `apply`
    /// sends every name it has no arm for here, so any other name is an unknown directive.
    fn apply_connection(&mut self, directive: &Directive) -> Result<(), ConfigError> {
        match directive.name.as_str() {
            "client_header_timeout" => {
                self.connection.client_header_timeout =
                    self.once_arg(directive, parse_positive_time)?;
            }
            "keepalive_timeout" => {
                self.connection.keepalive_timeout = self.once_arg(directive, parse_time)?;
            }
            "keepalive_requests" => {
                self.connection.keepalive_requests =
                    self.once_count(directive, "\"keepalive_requests\" must be at least 1")?;
            }
            "send_timeout" => {
                self.connection.send_timeout = self.once_arg(directive, parse_positive_time)?;
            }
            "large_client_header_buffers" => {
                once(&mut self.seen, directive)?;
                self.connection.large_header_buffers = parse_header_buffers(directive)?;
            }
            "lingering_close" => {
                self.connection.lingering_close =
                    self.once_arg(directive, parse_lingering_close)?;
            }
            "lingering_time" => {
                self.connection.lingering_time = self.once_arg(directive, parse_positive_time)?;
            }
            "lingering_timeout" => {
                self.connection.lingering_timeout =
                    self.once_arg(directive, parse_positive_time)?;
            }
            other => {
                return Err(invalid(directive, format!("unknown directive \"{other}\"")));
            }
        }
        Ok(())
    }

    /// Reads the one argument of a single-use directive with `parse`. A repeated directive
    /// fails before its argument is read.
    fn once_arg<T>(
        &mut self,
        directive: &Directive,
        parse: fn(&Directive, &str) -> Result<T, ConfigError>,
    ) -> Result<T, ConfigError> {
        once(&mut self.seen, directive)?;
        parse(directive, one_arg(directive)?)
    }

    /// Reads the one argument of a single-use directive as a whole number of at least 1. A
    /// repeated directive fails before its argument is read, and a zero fails with `when_zero`.
    fn once_count(&mut self, directive: &Directive, when_zero: &str) -> Result<usize, ConfigError> {
        once(&mut self.seen, directive)?;
        let count = parse_number::<usize>(directive, one_arg(directive)?)?;
        if count == 0 {
            return Err(invalid(directive, when_zero));
        }
        Ok(count)
    }

    /// Builds the configuration once every directive is applied. `directives` is the whole file,
    /// which the required directives point at, `formats` are the formats of the `log_format`
    /// directives, collected before the first directive was applied, and `lookup` gives the token
    /// variables.
    ///
    /// The checks run in this order: `listen` and `decision` are present, the decision block,
    /// the log formats, the zones, the limits, the access logs, a `site` is present, each site
    /// in file order (its block, then its hosts against the earlier sites, then
    /// `default_server`), and the sites that the top-level rules name.
    fn finish<F>(
        mut self,
        directives: &[Directive],
        formats: Vec<RawFormat<'_>>,
        lookup: &F,
    ) -> Result<Config, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let listen = self
            .listen
            .ok_or_else(|| invalid_at_top(directives, "\"listen\" is required"))?;
        let decision_directive = self
            .decision
            .ok_or_else(|| invalid_at_top(directives, "a \"decision\" block is required"))?;
        let decision = parse_decision(decision_directive, lookup)?;
        let redact = decision.redact_headers.clone();
        let formats = compile_formats(formats, &redact)?;
        let zones = limits::build_zones(&self.zones, &redact)?;
        let limits = top_limits(&self.limits, &zones, &mut self.seen)?;
        let block_response = self.block.resolve(&BlockResponse::default());
        let headers = self.headers.unwrap_or_default();
        let access_logs = resolve_top_access(&self.access_logs, &formats)?;
        if self.sites.is_empty() {
            return Err(invalid_at_top(
                directives,
                "at least one \"site\" block is required",
            ));
        }
        let top = Top {
            timeouts: self.site_timeouts,
            access: &self.access,
            builtin: self.builtin,
            builtin_enabled: self.builtin_enabled,
            switches: &self.switches,
            rules: &self.rules,
            zones: &zones,
            limits: &limits,
            block: &block_response,
            headers: &headers,
        };
        let sites = parse_sites(&self.sites, &formats, &top, &mut self.claimed)?;
        check_rule_sites(&self.rules, &sites)?;
        Ok(Config {
            listen,
            pid_file: self.pid_file,
            worker_threads: self.worker_threads,
            max_connections: self.max_connections,
            worker_shutdown_timeout: self.worker_shutdown_timeout,
            request_id_header: self.request_id_header,
            realip: self.realip,
            default_status: StatusCode::from_u16(self.default_status)
                .unwrap_or(StatusCode::MISDIRECTED_REQUEST),
            decision,
            sites,
            access_logs,
            error_log: self.error_log,
            connection: self.connection,
            access: self.access,
            zones,
            limits,
        })
    }
}

/// `default_status <code>`: a 4xx or 5xx status code.
fn parse_default_status(directive: &Directive, text: &str) -> Result<u16, ConfigError> {
    let status = parse_number::<u64>(directive, text)?;
    u16::try_from(status)
        .ok()
        .and_then(|code| StatusCode::from_u16(code).ok())
        .filter(|code| code.is_client_error() || code.is_server_error())
        .map(|code| code.as_u16())
        .ok_or_else(|| {
            invalid(
                directive,
                format!("\"default_status\" must be a 4xx or 5xx code, got {status}"),
            )
        })
}

/// `request_id_header <name>`: a header name.
fn parse_request_id_header(directive: &Directive, text: &str) -> Result<HeaderName, ConfigError> {
    HeaderName::from_str(text).map_err(|_| {
        invalid(
            directive,
            format!("\"request_id_header\" is not a header name: {text}"),
        )
    })
}

/// `real_ip_header <name>`: a header name.
fn parse_real_ip_header(directive: &Directive, text: &str) -> Result<HeaderName, ConfigError> {
    HeaderName::from_str(text).map_err(|_| {
        invalid(
            directive,
            format!("\"real_ip_header\" is not a header name: {text}"),
        )
    })
}

/// `real_ip_from <address or network>...`: the proxies whose client address header is trusted.
/// There must be at least one, and each must parse.
fn trusted_nets(directive: &Directive) -> Result<Vec<IpNet>, ConfigError> {
    if directive.args.is_empty() {
        return Err(invalid(
            directive,
            "\"real_ip_from\" needs at least one address or network",
        ));
    }
    directive
        .args
        .iter()
        .map(|text| {
            IpNet::parse(text).ok_or_else(|| {
                invalid(
                    directive,
                    format!("\"real_ip_from\" is not an address or network: {text}"),
                )
            })
        })
        .collect()
}

/// The limits of the top level: the limit `directives` applied in file order against `zones`,
/// counting repeats in `seen`, and resolved against no limits.
fn top_limits(
    directives: &[&Directive],
    zones: &[LimitZone],
    seen: &mut HashSet<String>,
) -> Result<LimitSet, ConfigError> {
    let mut overrides = LimitOverrides::default();
    for directive in directives {
        overrides.apply(directive, zones, seen)?;
    }
    Ok(overrides.resolve(&LimitSet::default()))
}

/// Parses the `site` directives in file order. A host that an earlier site lists is an error at
/// the later `site`, and so is a second `default_server`. `claimed` takes the id of each `rule`
/// of the sites.
fn parse_sites(
    directives: &[&Directive],
    formats: &Formats,
    top: &Top<'_>,
    claimed: &mut HashMap<String, String>,
) -> Result<Vec<SiteConfig>, ConfigError> {
    let mut sites = Vec::new();
    let mut hosts_seen: HashSet<String> = HashSet::new();
    let mut default_seen = false;
    for directive in directives {
        let parsed = parse_site(directive, formats, top, claimed)?;
        for pattern in &parsed.host_patterns {
            for claim in pattern.claims() {
                if !hosts_seen.insert(claim) {
                    return Err(invalid(
                        directive,
                        format!(
                            "host \"{}\" is listed by more than one site",
                            pattern.display()
                        ),
                    ));
                }
            }
        }
        if parsed.default_server {
            if default_seen {
                return Err(invalid(
                    directive,
                    "only one site may be marked default_server",
                ));
            }
            default_seen = true;
        }
        sites.push(parsed);
    }
    Ok(sites)
}

/// Checks that every site a top-level rule names is a configured host. The error points at the
/// rule.
fn check_rule_sites(top_rules: &[ParsedRule], sites: &[SiteConfig]) -> Result<(), ConfigError> {
    for parsed in top_rules {
        for name in parsed.sites.iter().flatten() {
            if !sites.iter().any(|site| site.hosts.contains(name)) {
                return Err(ConfigError::Invalid {
                    file: parsed.file.to_string(),
                    line: parsed.line,
                    message: format!("rule names no configured site: {name}"),
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::config::test_helpers::{BASE, first_site, message, parse, with_sites};

    #[rstest]
    #[case::pid("pid /run/x.pid;", "pid")]
    #[case::worker_threads("worker_threads 2;", "worker_threads")]
    #[case::max_connections("max_connections 10;", "max_connections")]
    #[case::worker_shutdown_timeout("worker_shutdown_timeout 5s;", "worker_shutdown_timeout")]
    #[case::default_status("default_status 404;", "default_status")]
    #[case::request_id_header("request_id_header x-request-id;", "request_id_header")]
    #[case::real_ip_header("real_ip_header x-forwarded-for;", "real_ip_header")]
    #[case::real_ip_recursive("real_ip_recursive on;", "real_ip_recursive")]
    #[case::keepalive_timeout("keepalive_timeout 5s;", "keepalive_timeout")]
    #[case::keepalive_requests("keepalive_requests 10;", "keepalive_requests")]
    #[case::send_timeout("send_timeout 5s;", "send_timeout")]
    #[case::large_client_header_buffers(
        "large_client_header_buffers 4 8k;",
        "large_client_header_buffers"
    )]
    #[case::lingering_close("lingering_close on;", "lingering_close")]
    #[case::lingering_time("lingering_time 5s;", "lingering_time")]
    #[case::lingering_timeout("lingering_timeout 5s;", "lingering_timeout")]
    #[case::client_body_timeout("client_body_timeout 5s;", "client_body_timeout")]
    #[case::client_max_body_size("client_max_body_size 1m;", "client_max_body_size")]
    #[case::proxy_connect_timeout("proxy_connect_timeout 5s;", "proxy_connect_timeout")]
    #[case::proxy_read_timeout("proxy_read_timeout 5s;", "proxy_read_timeout")]
    #[case::proxy_send_timeout("proxy_send_timeout 5s;", "proxy_send_timeout")]
    #[case::builtin_rules("builtin_rules on;", "builtin_rules")]
    #[case::error_log("error_log stderr;", "error_log")]
    fn a_single_use_top_level_directive_written_twice_is_rejected_at_the_second_line(
        #[case] line: &str,
        #[case] name: &str,
    ) {
        let text = message(parse(&format!("{line}\n{line}\n{BASE}")));
        assert!(
            text.contains(&format!("test.conf:2: duplicate directive \"{name}\"")),
            "{text}"
        );
    }

    #[test]
    fn a_second_decision_block_is_rejected_at_the_line_of_the_second_block() {
        let second = "decision {\n    backend http;\n    url http://stub-decider:9000/decide;\n}\n";
        let text = message(parse(&format!("{BASE}{second}")));
        assert!(
            text.contains("test.conf:9: duplicate directive \"decision\""),
            "{text}"
        );
    }

    #[test]
    fn a_repeated_time_directive_is_reported_before_its_value_is_read() {
        let text = message(parse(&format!(
            "client_header_timeout 1s;\nclient_header_timeout soon;\n{BASE}"
        )));
        assert!(
            text.contains("test.conf:2: duplicate directive \"client_header_timeout\""),
            "{text}"
        );
    }

    #[test]
    fn a_repeated_count_directive_is_reported_before_its_value_is_read() {
        let text = message(parse(&format!(
            "worker_threads 2;\nworker_threads 0;\n{BASE}"
        )));
        assert!(
            text.contains("test.conf:2: duplicate directive \"worker_threads\""),
            "{text}"
        );
    }

    #[rstest]
    #[case::worker_threads("worker_threads 0;", "\"worker_threads\" must be at least 1")]
    #[case::max_connections("max_connections 0;", "\"max_connections\" must be at least 1")]
    #[case::keepalive_requests(
        "keepalive_requests 0;",
        "\"keepalive_requests\" must be at least 1"
    )]
    fn a_count_of_zero_is_rejected_with_the_name_of_the_directive(
        #[case] line: &str,
        #[case] expected: &str,
    ) {
        let text = message(parse(&format!("{line}\n{BASE}")));
        assert!(text.contains(&format!("test.conf:1: {expected}")), "{text}");
    }

    #[rstest]
    #[case::ok("200")]
    #[case::redirect("302")]
    #[case::below_range("99")]
    #[case::above_status_codes("600")]
    #[case::beyond_u16("70000")]
    fn a_default_status_that_is_not_a_4xx_or_5xx_code_is_rejected(#[case] value: &str) {
        let text = message(parse(&format!("default_status {value};\n{BASE}")));
        assert!(
            text.contains(&format!(
                "test.conf:1: \"default_status\" must be a 4xx or 5xx code, got {value}"
            )),
            "{text}"
        );
    }

    #[rstest]
    #[case::not_found("404", StatusCode::NOT_FOUND)]
    #[case::service_unavailable("503", StatusCode::SERVICE_UNAVAILABLE)]
    fn a_default_status_of_4xx_or_5xx_is_taken_as_written(
        #[case] value: &str,
        #[case] expected: StatusCode,
    ) -> Result<(), ConfigError> {
        let config = parse(&format!("default_status {value};\n{BASE}"))?;
        assert_eq!(config.default_status, expected);
        Ok(())
    }

    #[test]
    fn a_request_id_header_that_is_not_a_header_name_is_rejected() {
        let text = message(parse(&format!("request_id_header \"bad name\";\n{BASE}")));
        assert!(
            text.contains("test.conf:1: \"request_id_header\" is not a header name: bad name"),
            "{text}"
        );
    }

    #[test]
    fn a_real_ip_header_that_is_not_a_header_name_is_rejected() {
        let text = message(parse(&format!("real_ip_header \"bad name\";\n{BASE}")));
        assert!(
            text.contains("test.conf:1: \"real_ip_header\" is not a header name: bad name"),
            "{text}"
        );
    }

    #[test]
    fn real_ip_from_without_an_address_is_rejected() {
        let text = message(parse(&format!("real_ip_from;\n{BASE}")));
        assert!(
            text.contains("test.conf:1: \"real_ip_from\" needs at least one address or network"),
            "{text}"
        );
    }

    #[test]
    fn real_ip_from_names_the_address_that_does_not_parse() {
        let text = message(parse(&format!("real_ip_from 10.0.0.0/8 bogus;\n{BASE}")));
        assert!(
            text.contains("test.conf:1: \"real_ip_from\" is not an address or network: bogus"),
            "{text}"
        );
    }

    #[test]
    fn the_replaced_max_body_directive_at_the_top_level_points_at_client_max_body_size() {
        let text = message(parse(&format!("max_body 1m;\n{BASE}")));
        assert!(
            text.contains(
                "test.conf:1: \"max_body\" was replaced by \"client_max_body_size\", which is set at the top level"
            ),
            "{text}"
        );
    }

    #[test]
    fn an_include_that_was_not_expanded_is_refused() {
        // The loader expands every `include` before the build, so no file reaches this check.
        let include = Directive {
            name: "include".to_owned(),
            args: vec!["sites.d/*.conf".to_owned()],
            children: None,
            file: Arc::from("test.conf"),
            line: 3,
        };
        let text = message(TopDraft::new(&[]).apply(&include));
        assert_eq!(text, "test.conf:3: \"include\" was not expanded");
    }

    #[test]
    fn a_file_with_listen_and_a_site_but_no_decision_block_is_rejected_at_the_top_of_the_file() {
        let text = message(parse(
            "listen 127.0.0.1:8080;\nsite example.com {\n    upstream http://upstream:80;\n}\n",
        ));
        assert!(
            text.contains("test.conf:1: a \"decision\" block is required"),
            "{text}"
        );
    }

    #[test]
    fn a_missing_listen_is_reported_before_a_missing_decision() {
        let text = message(parse(
            "site example.com {\n    upstream http://upstream:80;\n}\n",
        ));
        assert_eq!(text, "test.conf:1: \"listen\" is required");
    }

    #[test]
    fn a_missing_decision_is_reported_before_a_missing_site() {
        let text = message(parse("listen 127.0.0.1:8080;\n"));
        assert_eq!(text, "test.conf:1: a \"decision\" block is required");
    }

    #[test]
    fn an_unknown_top_level_directive_is_reported_without_a_context_suffix() {
        let text = message(parse(&format!("bogus on;\n{BASE}")));
        assert_eq!(text, "test.conf:1: unknown directive \"bogus\"");
    }

    #[test]
    fn log_format_directives_are_read_before_the_other_directives() {
        // The built-in name "main" cannot be redefined.
        let text = message(parse(&format!(
            "bogus on;\nlog_format main \"$client_ip\";\n{BASE}"
        )));
        assert_eq!(
            text,
            "test.conf:2: \"main\" is a built-in log format and cannot be redefined"
        );
    }

    #[test]
    fn a_zone_directive_is_read_after_the_required_directives_are_checked() {
        // A zone without a rate is refused once the zones are built.
        let zone = "limit_req_zone $client_ip zone=one:10m;\n";
        let with_listen = message(parse(&format!("{zone}{BASE}")));
        assert!(with_listen.contains("needs rate"), "{with_listen}");
        let without_listen = BASE.replacen("listen 127.0.0.1:8080;\n", "", 1);
        let text = message(parse(&format!("{zone}{without_listen}")));
        assert_eq!(text, "test.conf:1: \"listen\" is required");
    }

    #[test]
    fn top_level_proxy_set_header_lines_add_up_and_a_site_inherits_them() -> Result<(), ConfigError>
    {
        let config = parse(&format!(
            "proxy_set_header X-A \"a\";\nproxy_set_header X-B \"b\";\n{BASE}"
        ))?;
        assert_eq!(first_site(&config)?.proxy_headers.len(), 2);
        Ok(())
    }

    #[test]
    fn a_host_listed_by_two_sites_is_rejected_at_the_line_of_the_second_site() {
        let text = message(parse(&with_sites(
            "site example.com {\n    upstream http://u:80;\n}\nsite example.com {\n    upstream http://u:80;\n}\n",
        )));
        assert!(
            text.contains("test.conf:9: host \"example.com\" is listed by more than one site"),
            "{text}"
        );
    }

    #[test]
    fn a_top_level_rule_that_names_an_unknown_site_is_rejected_at_the_line_of_the_rule() {
        let rule = "rule scoped {\n    description \"d\";\n    action block;\n    site other.example;\n    path /x;\n}\n";
        let text = message(parse(&format!("{BASE}{rule}")));
        assert!(
            text.contains("test.conf:9: rule names no configured site: other.example"),
            "{text}"
        );
    }

    #[test]
    fn the_pid_file_defaults_to_the_run_directory() -> Result<(), ConfigError> {
        let config = parse(BASE)?;
        assert_eq!(config.pid_file, PathBuf::from("/run/vigilant-heron.pid"));
        Ok(())
    }

    #[test]
    fn the_pid_directive_sets_the_pid_file() -> Result<(), ConfigError> {
        let config = parse(&format!("pid /tmp/x.pid;\n{BASE}"))?;
        assert_eq!(config.pid_file, PathBuf::from("/tmp/x.pid"));
        Ok(())
    }
}
