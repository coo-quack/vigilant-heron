//! The `site` block, the timers and limits a site may override, and the `allow` and `deny`
//! entries of an access list.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use http::{HeaderValue, Uri};

use super::decision::parse_absolute_uri;
use super::logs::{Formats, parse_access};
use super::names::SITE_DIRECTIVES;
use super::value::{parse_body_limit, parse_failure, parse_threshold};
use super::{AccessLogConfig, FailureAction, Mode, SiteAction, SiteConfig, SiteTimeouts};
use crate::access::AccessEntry;
use crate::block::{BLOCK_NAMES, BlockOverrides, BlockResponse};
use crate::conf::{Directive, block, invalid, once, one_arg, parse_bool, parse_positive_time};
use crate::error::ConfigError;
use crate::limits::{self, LimitOverrides, LimitSet, LimitZone, LocationConfig, PendingLocation};
use crate::proxy::HeaderOp;
use crate::realip::IpNet;
use crate::router::HostPattern;
use crate::rules::{self, ParsedRule, Rule, RuleSwitches, Scope};

/// Default block threshold for a site.
const DEFAULT_BLOCK_THRESHOLD: f64 = 0.87;
/// Default AI-instruction threshold for a site.
const DEFAULT_INSTRUCTION_THRESHOLD: f64 = 0.8;

/// File extensions that skip the backend when `static_extensions` is not given.
const DEFAULT_STATIC_EXTENSIONS: [&str; 13] = [
    "css", "js", "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "woff", "woff2", "ttf", "map",
];

/// Timers that a site may override, and the top-level directives that set them.
const SITE_TIMEOUT_NAMES: [&str; 5] = [
    "client_body_timeout",
    "client_max_body_size",
    "proxy_connect_timeout",
    "proxy_read_timeout",
    "proxy_send_timeout",
];

/// Connection settings (timers, keep-alive and header limits, lingering) that apply before a site
/// is chosen, so only the top level may set them. A `site` block that sets one is rejected.
/// The removed `max_body` is listed with them.
const CONNECTION_NAMES: [&str; 9] = [
    "client_header_timeout",
    "keepalive_timeout",
    "keepalive_requests",
    "send_timeout",
    "large_client_header_buffers",
    "lingering_close",
    "lingering_time",
    "lingering_timeout",
    "max_body",
];

/// Sets one of the site-overridable timers or the body limit. Other names are left alone.
pub(crate) fn set_site_timeout(
    directive: &Directive,
    timeouts: &mut SiteTimeouts,
) -> Result<(), ConfigError> {
    match directive.name.as_str() {
        "client_body_timeout" => {
            timeouts.client_body_timeout = parse_positive_time(directive, one_arg(directive)?)?;
        }
        "client_max_body_size" => {
            timeouts.max_body_bytes = parse_body_limit(directive, one_arg(directive)?)?;
        }
        "proxy_connect_timeout" => {
            timeouts.proxy_connect_timeout = parse_positive_time(directive, one_arg(directive)?)?;
        }
        "proxy_read_timeout" => {
            timeouts.proxy_read_timeout = parse_positive_time(directive, one_arg(directive)?)?;
        }
        "proxy_send_timeout" => {
            timeouts.proxy_send_timeout = parse_positive_time(directive, one_arg(directive)?)?;
        }
        _ => {}
    }
    Ok(())
}

/// The top-level settings that a site inherits, or extends with its own rules.
pub(crate) struct Top<'a> {
    /// Timers and body limit that a site starts from.
    pub(crate) timeouts: SiteTimeouts,
    /// The top-level access list.
    pub(crate) access: &'a [AccessEntry],
    /// The built-in rules.
    pub(crate) builtin: &'a [Arc<Rule>],
    /// Whether the built-in rules are on at the top level.
    pub(crate) builtin_enabled: bool,
    /// The `disable_rule` and `enable_rule` ids of the top level.
    pub(crate) switches: &'a RuleSwitches,
    /// Top-level rules, each with the sites it applies to.
    pub(crate) rules: &'a [ParsedRule],
    /// The limit zones.
    pub(crate) zones: &'a [LimitZone],
    /// The limits of the top level.
    pub(crate) limits: &'a LimitSet,
    /// The top-level block response, inherited by every site.
    pub(crate) block: &'a BlockResponse,
    /// The top-level `proxy_set_header` operations, inherited by every site.
    pub(crate) headers: &'a [HeaderOp],
}

/// Reads one `allow` or `deny` directive.
pub(crate) fn access_entry(directive: &Directive) -> Result<AccessEntry, ConfigError> {
    let text = one_arg(directive)?;
    let net = if text == "all" {
        None
    } else {
        let net = IpNet::parse(text).ok_or_else(|| {
            invalid(
                directive,
                format!(
                    "\"{}\" must be an address, a network or all, got {text}",
                    directive.name
                ),
            )
        })?;
        Some(net)
    };
    Ok(AccessEntry {
        allow: directive.name == "allow",
        net,
    })
}

/// Parses one `site <host>... { ... }` directive. `claimed` takes the id of each `rule` in the
/// block as it is read.
///
/// # Errors
///
/// Returns [`ConfigError::Invalid`] naming the file and line of the directive at fault: a
/// directive of the block for its own name, repeat or value, and the `site` directive for its
/// host names and for a check of the block as a whole (no `upstream`, or `access_log off` next
/// to another `access_log`).
pub(crate) fn parse_site(
    directive: &Directive,
    formats: &Formats,
    top: &Top<'_>,
    claimed: &mut HashMap<String, String>,
) -> Result<SiteConfig, ConfigError> {
    let host_patterns = parse_hosts(directive)?;
    let mut draft = SiteDraft::new(directive, formats, top, host_patterns);
    for child in block(directive)? {
        draft.apply(child, claimed)?;
    }
    draft.finish()
}

/// The host patterns of a `site` directive. There must be at least one, and each must parse.
fn parse_hosts(directive: &Directive) -> Result<Vec<HostPattern>, ConfigError> {
    if directive.args.is_empty() {
        return Err(invalid(directive, "\"site\" needs at least one host name"));
    }
    directive
        .args
        .iter()
        .map(|host| {
            HostPattern::parse(host).map_err(|reason| {
                invalid(
                    directive,
                    format!("\"site\" has an invalid host name {host}: {reason}"),
                )
            })
        })
        .collect()
}

/// A `site` block while it is read: the settings read so far, which become the fields of
/// [`SiteConfig`] of the same names once `finish` has resolved them against the top-level
/// settings, and the places the errors point at. An error in one directive of the block points at
/// that directive, and a check of the block as a whole points at the `site` directive.
struct SiteDraft<'a> {
    /// The `site` directive, which the checks of the block as a whole point at.
    directive: &'a Directive,
    /// The `log_format` names that `access_log` may use.
    formats: &'a Formats,
    /// The top-level settings that the site inherits or extends.
    top: &'a Top<'a>,
    /// The parsed host names, in configuration order.
    host_patterns: Vec<HostPattern>,
    /// The names of the single-use directives seen so far, which the limit and block directives
    /// share.
    seen: HashSet<String>,
    default_server: bool,
    upstream: Option<Uri>,
    mode: Mode,
    /// `None` until `action` is written, which then may not be written again. Without one, the
    /// site blocks.
    action: Option<SiteAction>,
    block_threshold: f64,
    instruction_threshold: f64,
    deny_paths: Vec<String>,
    fail_closed_paths: Vec<String>,
    on_rate_limit: FailureAction,
    on_client_busy: FailureAction,
    on_decision_error: FailureAction,
    static_skip: StaticSkip,
    debug_headers: bool,
    access_logs: SiteAccessLogs,
    /// The top-level timers, then those the site overrides.
    timeouts: SiteTimeouts,
    /// The site's own `allow` and `deny` entries. With none, the top-level list applies.
    own_access: Vec<AccessEntry>,
    /// `None` inherits the top-level `builtin_rules`.
    builtin_enabled: Option<bool>,
    /// The `disable_rule` and `enable_rule` ids of the site.
    own_switches: RuleSwitches,
    /// The rules written inside the site.
    own_rules: Vec<ParsedRule>,
    /// The limit directives of the site, which `finish` resolves against the top-level limits.
    site_limits: LimitOverrides,
    /// The `location` blocks, which `finish` resolves against the site's settings.
    pending_locations: Vec<PendingLocation<'a>>,
    /// The block response directives of the site, which `finish` resolves against the top level.
    site_block: BlockOverrides,
    /// The site's own `proxy_set_header` operations. `None` inherits the top-level list.
    site_headers: Option<Vec<HeaderOp>>,
    websocket: bool,
}

impl<'a> SiteDraft<'a> {
    /// A draft of the `site` block `directive` with the defaults, for the hosts `host_patterns`.
    fn new(
        directive: &'a Directive,
        formats: &'a Formats,
        top: &'a Top<'a>,
        host_patterns: Vec<HostPattern>,
    ) -> Self {
        Self {
            directive,
            formats,
            top,
            host_patterns,
            seen: HashSet::new(),
            default_server: false,
            upstream: None,
            mode: Mode::Enforce,
            action: None,
            block_threshold: DEFAULT_BLOCK_THRESHOLD,
            instruction_threshold: DEFAULT_INSTRUCTION_THRESHOLD,
            deny_paths: Vec::new(),
            fail_closed_paths: Vec::new(),
            on_rate_limit: FailureAction::Allow,
            on_client_busy: FailureAction::Block,
            on_decision_error: FailureAction::Allow,
            static_skip: StaticSkip::default(),
            debug_headers: false,
            access_logs: SiteAccessLogs::default(),
            timeouts: top.timeouts,
            own_access: Vec::new(),
            builtin_enabled: None,
            own_switches: RuleSwitches::default(),
            own_rules: Vec::new(),
            site_limits: LimitOverrides::default(),
            pending_locations: Vec::new(),
            site_block: BlockOverrides::default(),
            site_headers: None,
            websocket: false,
        }
    }

    /// Checks the name of one directive of the block with [`check_site_name`], then applies the
    /// directive. A repeated single-use directive fails before its value is read, except
    /// `action`, which checks on its own, and `default_server`, which checks its arguments first.
    /// The limit and block directives count their repeats in `seen` as they see fit. The lists,
    /// `allow`, `deny`, the rules and the locations add up, and `claimed` takes the id of each
    /// `rule`.
    fn apply(
        &mut self,
        child: &'a Directive,
        claimed: &mut HashMap<String, String>,
    ) -> Result<(), ConfigError> {
        check_site_name(child)?;
        match child.name.as_str() {
            name if SITE_TIMEOUT_NAMES.contains(&name) => {
                once(&mut self.seen, child)?;
                set_site_timeout(child, &mut self.timeouts)?;
            }
            "upstream" => self.upstream = Some(self.once_arg(child, parse_upstream)?),
            "mode" => self.mode = self.once_arg(child, parse_mode)?,
            "action" => {
                if self.action.is_some() {
                    return Err(invalid(child, "duplicate directive \"action\""));
                }
                self.action = Some(parse_site_action(child)?);
            }
            "block_threshold" => self.block_threshold = self.once_arg(child, parse_threshold)?,
            "instruction_threshold" => {
                self.instruction_threshold = self.once_arg(child, parse_threshold)?;
            }
            "on_rate_limit" => self.on_rate_limit = self.once_arg(child, parse_failure)?,
            "on_client_busy" => self.on_client_busy = self.once_arg(child, parse_failure)?,
            "on_decision_error" => self.on_decision_error = self.once_arg(child, parse_failure)?,
            "deny_path" => self.deny_paths.extend_from_slice(nonempty_args(
                child,
                "\"deny_path\" needs at least one prefix",
            )?),
            "fail_closed_path" => self.fail_closed_paths.extend_from_slice(nonempty_args(
                child,
                "\"fail_closed_path\" needs at least one prefix",
            )?),
            "static_extensions" => {
                let list = self.static_skip.extensions.get_or_insert_with(Vec::new);
                list.extend(child.args.iter().map(|e| e.to_ascii_lowercase()));
            }
            "static_location" => self
                .static_skip
                .locations
                .extend(static_location_prefixes(child)?),
            "static_query_params" => self
                .static_skip
                .query_params
                .extend(query_param_names(child)?),
            "static_query_token" => {
                self.static_skip.query_token = self.once_arg(child, parse_bool)?;
            }
            "debug_headers" => self.debug_headers = self.once_arg(child, parse_bool)?,
            "access_log" => self.access_logs.add(parse_access(child, self.formats)?),
            "allow" | "deny" => self.own_access.push(access_entry(child)?),
            "builtin_rules" => self.builtin_enabled = Some(self.once_arg(child, parse_bool)?),
            "disable_rule" => self
                .own_switches
                .disabled
                .extend(rules::builtin_ids(child, self.top.builtin)?),
            "enable_rule" => self
                .own_switches
                .enabled
                .extend(rules::builtin_ids(child, self.top.builtin)?),
            "rule" => {
                let parsed = rules::parse_rule(child, Scope::Site)?;
                rules::claim_id(claimed, &parsed)?;
                self.own_rules.push(parsed);
            }
            name if limits::LIMIT_NAMES.contains(&name) => {
                self.site_limits
                    .apply(child, self.top.zones, &mut self.seen)?;
            }
            name if BLOCK_NAMES.contains(&name) => self.site_block.apply(child, &mut self.seen)?,
            "proxy_websocket" => self.websocket = self.once_arg(child, parse_bool)?,
            "proxy_set_header" => self
                .site_headers
                .get_or_insert_with(Vec::new)
                .push(HeaderOp::parse(child)?),
            "location" => self
                .pending_locations
                .push(limits::parse_location(child, self.top.zones)?),
            "default_server" => {
                if !child.args.is_empty() {
                    return Err(invalid(child, "\"default_server\" takes no arguments"));
                }
                once(&mut self.seen, child)?;
                self.default_server = true;
            }
            other => {
                return Err(invalid(
                    child,
                    format!("unknown directive \"{other}\" in site"),
                ));
            }
        }
        Ok(())
    }

    /// Reads the one argument of a single-use directive with `parse`. A repeated directive
    /// fails before its argument is read.
    fn once_arg<T>(
        &mut self,
        child: &Directive,
        parse: fn(&Directive, &str) -> Result<T, ConfigError>,
    ) -> Result<T, ConfigError> {
        once(&mut self.seen, child)?;
        parse(child, one_arg(child)?)
    }

    /// Resolves the settings against the top level, checks what the block as a whole needs
    /// (an upstream, and no `access_log off` next to another `access_log`) and builds the site.
    /// The locations are resolved first, so a repeated location is reported before the checks
    /// of the site.
    fn finish(self) -> Result<SiteConfig, ConfigError> {
        let top = self.top;
        let hosts: Vec<String> = self
            .host_patterns
            .iter()
            .map(HostPattern::display)
            .collect();
        let site_limit_set = self.site_limits.resolve(top.limits);
        let block_response = self.site_block.resolve(top.block);
        // A site with its own proxy_set_header replaces the inherited list, as in nginx.
        let proxy_headers = self.site_headers.unwrap_or_else(|| top.headers.to_vec());
        let locations = resolve_locations(
            self.pending_locations,
            &site_limit_set,
            &block_response,
            &proxy_headers,
            self.websocket,
        )?;
        let access_logs = self.access_logs.resolve(self.directive)?;
        let upstream = self
            .upstream
            .ok_or_else(|| invalid(self.directive, "\"upstream\" is required in a site"))?;

        // A site with its own access list ignores the top-level one.
        let access = if self.own_access.is_empty() {
            top.access.to_vec()
        } else {
            self.own_access
        };
        let rules = rules::site_rules(
            &hosts,
            top.builtin,
            self.builtin_enabled.unwrap_or(top.builtin_enabled),
            top.switches,
            &self.own_switches,
            top.rules,
            &self.own_rules,
        );

        Ok(SiteConfig {
            hosts,
            default_server: self.default_server,
            host_patterns: self.host_patterns,
            block: block_response,
            proxy_headers,
            websocket: self.websocket,
            upstream,
            mode: self.mode,
            action: self.action.unwrap_or(SiteAction::Block),
            block_threshold: self.block_threshold,
            instruction_threshold: self.instruction_threshold,
            deny_paths_lowered: self
                .deny_paths
                .iter()
                .map(|path| path.to_lowercase())
                .collect(),
            deny_paths: self.deny_paths,
            fail_closed_lowered: self
                .fail_closed_paths
                .iter()
                .map(|path| path.to_lowercase())
                .collect(),
            fail_closed_paths: self.fail_closed_paths,
            on_rate_limit: self.on_rate_limit,
            on_client_busy: self.on_client_busy,
            on_decision_error: self.on_decision_error,
            static_extensions: self.static_skip.extensions.unwrap_or_else(|| {
                DEFAULT_STATIC_EXTENSIONS
                    .iter()
                    .map(|e| (*e).to_owned())
                    .collect()
            }),
            static_locations: self.static_skip.locations,
            static_query_params: self.static_skip.query_params,
            static_query_token: self.static_skip.query_token,
            debug_headers: self.debug_headers,
            access_logs,
            timeouts: self.timeouts,
            access,
            rules,
            limits: site_limit_set,
            locations,
        })
    }
}

/// The static-skip settings of a site, which become the `static_*` fields of [`SiteConfig`]
/// without the prefix.
#[derive(Default)]
struct StaticSkip {
    /// `None` until `static_extensions` is written. Without it, the default list applies.
    extensions: Option<Vec<String>>,
    locations: Vec<String>,
    query_params: Vec<String>,
    query_token: bool,
}

/// The `access_log` directives of a site while they are read.
#[derive(Default)]
struct SiteAccessLogs {
    /// The logs written. `None` while there is none.
    logs: Option<Vec<AccessLogConfig>>,
    /// Whether `access_log off` was written.
    off: bool,
}

impl SiteAccessLogs {
    /// Records one `access_log` directive: a log, or `None` for `off`.
    fn add(&mut self, log: Option<AccessLogConfig>) {
        match log {
            Some(log) => self.logs.get_or_insert_with(Vec::new).push(log),
            None => self.off = true,
        }
    }

    /// The `access_log` setting of [`SiteConfig`]: `None` inherits the top-level logs, and an
    /// empty list is `access_log off`. The error points at the `site` directive.
    fn resolve(self, directive: &Directive) -> Result<Option<Vec<AccessLogConfig>>, ConfigError> {
        if !self.off {
            return Ok(self.logs);
        }
        if self.logs.is_some() {
            return Err(invalid(
                directive,
                "\"access_log off\" cannot be combined with other access_log directives",
            ));
        }
        Ok(Some(Vec::new()))
    }
}

/// Checks the name of a directive before its own checks: a site knows it, and it is not a
/// connection or zone setting, which only the top level may have.
fn check_site_name(directive: &Directive) -> Result<(), ConfigError> {
    let name = directive.name.as_str();
    if !SITE_DIRECTIVES.contains(&name) {
        return Err(invalid(
            directive,
            format!("unknown directive \"{name}\" in site"),
        ));
    }
    if CONNECTION_NAMES.contains(&name) {
        return Err(invalid(
            directive,
            format!(
                "\"{name}\" is only valid at the top level: it applies before the Host selects a site"
            ),
        ));
    }
    if limits::ZONE_NAMES.contains(&name) {
        return Err(invalid(
            directive,
            format!("\"{name}\" is only valid at the top level: zones are shared by every site"),
        ));
    }
    Ok(())
}

/// `upstream <uri>`: an absolute `http://` URI.
fn parse_upstream(directive: &Directive, text: &str) -> Result<Uri, ConfigError> {
    parse_absolute_uri(text, &["http"]).ok_or_else(|| {
        invalid(
            directive,
            format!("\"upstream\" must be an absolute http:// URI, got {text}"),
        )
    })
}

/// `mode enforce` or `mode shadow`.
fn parse_mode(directive: &Directive, text: &str) -> Result<Mode, ConfigError> {
    match text {
        "enforce" => Ok(Mode::Enforce),
        "shadow" => Ok(Mode::Shadow),
        other => Err(invalid(
            directive,
            format!("\"mode\" must be enforce or shadow, got {other}"),
        )),
    }
}

/// `action block` or `action redirect <url>`.
fn parse_site_action(directive: &Directive) -> Result<SiteAction, ConfigError> {
    match directive.args.as_slice() {
        [word] if word == "block" => Ok(SiteAction::Block),
        [word, target] if word == "redirect" => {
            let location = HeaderValue::from_str(target).map_err(|_| {
                invalid(
                    directive,
                    format!("\"action redirect\" target is not a valid header value: {target}"),
                )
            })?;
            Ok(SiteAction::Redirect(location))
        }
        _ => Err(invalid(
            directive,
            "\"action\" must be \"block\" or \"redirect <url>\"",
        )),
    }
}

/// The arguments of `directive`. With none, the error is `when_empty`.
fn nonempty_args<'d>(
    directive: &'d Directive,
    when_empty: &str,
) -> Result<&'d [String], ConfigError> {
    if directive.args.is_empty() {
        return Err(invalid(directive, when_empty));
    }
    Ok(&directive.args)
}

/// The prefixes of `static_location`, lowercased. Each must start with `/`.
fn static_location_prefixes(directive: &Directive) -> Result<Vec<String>, ConfigError> {
    let prefixes = nonempty_args(
        directive,
        "\"static_location\" needs at least one path prefix",
    )?;
    for prefix in prefixes {
        if !prefix.starts_with('/') {
            return Err(invalid(
                directive,
                format!("\"static_location\" prefix must start with /: {prefix}"),
            ));
        }
    }
    Ok(prefixes.iter().map(|p| p.to_ascii_lowercase()).collect())
}

/// The names of `static_query_params`, each of 1 to 64 letters, digits, `_` or `-`.
fn query_param_names(directive: &Directive) -> Result<Vec<String>, ConfigError> {
    let names = nonempty_args(
        directive,
        "\"static_query_params\" needs at least one parameter name",
    )?;
    for name in names {
        let valid = (1..=64).contains(&name.len())
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'));
        if !valid {
            return Err(invalid(
                directive,
                format!(
                    "\"static_query_params\" name must be 1 to 64 letters, digits, _ or -: {name}"
                ),
            ));
        }
    }
    Ok(names.to_vec())
}

/// Resolves the `location` blocks of a site against the site's limits, block response, headers
/// and `proxy_websocket` setting, keeping their order. A location that repeats the path of an
/// earlier one is an error at the repeat.
fn resolve_locations(
    pending_locations: Vec<PendingLocation<'_>>,
    site_limit_set: &LimitSet,
    block_response: &BlockResponse,
    proxy_headers: &[HeaderOp],
    websocket: bool,
) -> Result<Vec<LocationConfig>, ConfigError> {
    let mut locations: Vec<LocationConfig> = Vec::new();
    for pending in pending_locations {
        if let Some(unique) = pending.matcher.unique_path()
            && locations
                .iter()
                .any(|earlier| earlier.matcher.unique_path() == Some(unique))
        {
            return Err(invalid(
                pending.directive,
                format!("duplicate \"location\" \"{}\"", unique.1),
            ));
        }
        locations.push(LocationConfig {
            matcher: pending.matcher,
            limits: pending.overrides.resolve(site_limit_set),
            block: pending.block.resolve(block_response),
            proxy_headers: pending.headers.unwrap_or_else(|| proxy_headers.to_vec()),
            websocket: pending.websocket.unwrap_or(websocket),
        });
    }
    Ok(locations)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::config::Config;
    use crate::config::test_helpers::connection_limit::parse_plain;
    use crate::config::test_helpers::{first_site, message, parse, with_site, with_sites};

    #[test]
    fn a_site_needs_an_upstream_and_reports_its_line() {
        let text = "listen 127.0.0.1:8080;\ndecision {\n    backend http;\n    url http://stub:9000/decide;\n}\nsite example.com {\n    mode enforce;\n}\n";
        assert!(message(parse(text)).contains("test.conf:6: \"upstream\" is required"));
    }

    #[rstest]
    #[case::negative("block_threshold -0.1;")]
    #[case::above_one("block_threshold 1.5;")]
    #[case::not_a_number("instruction_threshold high;")]
    fn thresholds_must_be_numbers_in_the_unit_interval(#[case] line: &str) {
        assert!(parse(&with_site(&format!("    {line}\n"))).is_err());
    }

    #[test]
    fn redirect_takes_a_target_and_block_takes_none() -> Result<(), ConfigError> {
        let redirect = parse(&with_site(
            "    action redirect https://example.com/blocked;\n",
        ))?;
        assert!(matches!(
            &first_site(&redirect)?.action,
            SiteAction::Redirect(_)
        ));
        assert!(
            message(parse(&with_site("    action redirect;\n")))
                .contains("must be \"block\" or \"redirect <url>\"")
        );
        assert!(
            message(parse(&with_site("    action block extra;\n"))).contains("must be \"block\"")
        );
        Ok(())
    }

    #[test]
    fn failure_settings_accept_allow_and_block_only() -> Result<(), ConfigError> {
        let config = parse(&with_site(
            "    on_rate_limit block;\n    on_decision_error block;\n",
        ))?;
        let site = first_site(&config)?;
        assert_eq!(site.on_rate_limit, FailureAction::Block);
        assert_eq!(site.on_decision_error, FailureAction::Block);
        assert!(
            message(parse(&with_site("    on_rate_limit deny;\n")))
                .contains("\"on_rate_limit\" must be \"allow\" or \"block\"")
        );
        Ok(())
    }

    #[test]
    fn on_client_busy_defaults_to_block_and_accepts_allow_and_block() -> Result<(), ConfigError> {
        let allowed = parse(&with_site("    on_client_busy allow;\n"))?;
        assert_eq!(first_site(&allowed)?.on_client_busy, FailureAction::Allow);
        let blocked = parse(&with_site("    on_client_busy block;\n"))?;
        assert_eq!(first_site(&blocked)?.on_client_busy, FailureAction::Block);
        Ok(())
    }

    #[test]
    fn on_client_busy_rejects_other_values_and_duplicates() {
        assert!(
            message(parse(&with_site("    on_client_busy deny;\n")))
                .contains("\"on_client_busy\" must be \"allow\" or \"block\"")
        );
        assert!(
            message(parse(&with_site(
                "    on_client_busy allow;\n    on_client_busy block;\n"
            )))
            .contains("duplicate directive \"on_client_busy\"")
        );
    }

    #[test]
    fn on_rate_limit_does_not_change_on_client_busy() -> Result<(), ConfigError> {
        let config = parse(&with_site("    on_rate_limit block;\n"))?;
        assert_eq!(first_site(&config)?.on_client_busy, FailureAction::Block);
        Ok(())
    }

    #[test]
    fn repeated_list_directives_accumulate() -> Result<(), ConfigError> {
        let config = parse(&with_site(
            "    deny_path /.env /.git;\n    deny_path /xmlrpc.php;\n    fail_closed_path /wp-login.php;\n    static_extensions css JS;\n",
        ))?;
        let site = first_site(&config)?;
        assert_eq!(site.deny_paths, ["/.env", "/.git", "/xmlrpc.php"]);
        assert_eq!(site.fail_closed_paths, ["/wp-login.php"]);
        assert_eq!(site.static_extensions, ["css", "js"]);
        Ok(())
    }

    #[test]
    fn an_empty_static_extensions_list_turns_the_static_skip_off() -> Result<(), ConfigError> {
        let config = parse(&with_site("    static_extensions;\n"))?;
        assert_eq!(first_site(&config)?.static_extensions, Vec::<String>::new());
        Ok(())
    }

    #[test]
    fn debug_headers_takes_on_or_off() -> Result<(), ConfigError> {
        let config = parse(&with_site("    debug_headers on;\n"))?;
        assert!(first_site(&config)?.debug_headers);
        assert!(
            message(parse(&with_site("    debug_headers yes;\n")))
                .contains("must be \"on\" or \"off\"")
        );
        Ok(())
    }

    #[test]
    fn static_location_prefixes_are_read_lowercased_and_must_start_with_a_slash()
    -> Result<(), ConfigError> {
        let config = parse(&with_site(
            "    static_location /Static/ /wp-content/Uploads/;\n",
        ))?;
        assert_eq!(
            first_site(&config)?.static_locations,
            ["/static/", "/wp-content/uploads/"]
        );
        assert!(
            message(parse(&with_site("    static_location static/;\n")))
                .contains("\"static_location\" prefix must start with /: static/")
        );
        assert!(
            message(parse(&with_site("    static_location;\n")))
                .contains("\"static_location\" needs at least one path prefix")
        );
        Ok(())
    }

    #[test]
    fn static_query_params_keep_their_case_and_must_be_plain_names() -> Result<(), ConfigError> {
        let config = parse(&with_site(
            "    static_query_params ver;\n    static_query_params V_1;\n",
        ))?;
        assert_eq!(first_site(&config)?.static_query_params, ["ver", "V_1"]);
        let unset = parse(&with_site(""))?;
        assert_eq!(
            first_site(&unset)?.static_query_params,
            Vec::<String>::new()
        );
        assert!(
            message(parse(&with_site("    static_query_params;\n")))
                .contains("\"static_query_params\" needs at least one parameter name")
        );
        for bad in ["ver=1", "a.b", "%76er", &"v".repeat(65)] {
            assert!(
                message(parse(&with_site(&format!(
                    "    static_query_params {bad};\n"
                ))))
                .contains(&format!(
                    "\"static_query_params\" name must be 1 to 64 letters, digits, _ or -: {bad}"
                )),
                "{bad}"
            );
        }
        Ok(())
    }

    #[test]
    fn static_query_token_is_off_when_the_directive_is_absent() -> Result<(), ConfigError> {
        let config = parse(&with_site(""))?;
        assert!(!first_site(&config)?.static_query_token);
        Ok(())
    }

    #[test]
    fn static_query_token_set_to_on_is_enabled() -> Result<(), ConfigError> {
        let config = parse(&with_site("    static_query_token on;\n"))?;
        assert!(first_site(&config)?.static_query_token);
        Ok(())
    }

    #[test]
    fn static_query_token_refuses_a_value_other_than_on_or_off() {
        assert!(
            message(parse(&with_site("    static_query_token yes;\n")))
                .contains("\"static_query_token\" must be \"on\" or \"off\"")
        );
    }

    #[test]
    fn static_query_token_refuses_a_duplicate_directive() {
        assert!(
            message(parse(&with_site(
                "    static_query_token on;\n    static_query_token off;\n"
            )))
            .contains("duplicate directive \"static_query_token\"")
        );
    }

    #[test]
    fn an_invalid_host_name_is_reported_with_its_line() {
        let result = Config::parse_str(
            &with_sites(
                "site ok.test {\n    upstream http://u:80;\n}\nsite a*.test {\n    upstream http://u:80;\n}\n",
            ),
            "hosts.conf",
        );
        let text = message(result.map(|_| ()));
        assert!(text.contains("hosts.conf:"), "{text}");
        assert!(text.contains("invalid host name a*.test"), "{text}");
    }

    #[test]
    fn a_regex_that_does_not_compile_is_reported() {
        let result = Config::parse_str(
            &with_sites("site ~(unclosed {\n    upstream http://u:80;\n}\n"),
            "hosts.conf",
        );
        assert!(message(result.map(|_| ())).contains("does not compile"));
    }

    #[test]
    fn default_server_marks_one_site() -> Result<(), ConfigError> {
        let config = Config::parse_str(
            &with_sites(
                "site a.test {\n    upstream http://u:80;\n}\nsite b.test {\n    upstream http://u:80;\n    default_server;\n}\n",
            ),
            "default.conf",
        )?;
        let flags: Vec<bool> = config.sites.iter().map(|s| s.default_server).collect();
        assert_eq!(flags, [false, true]);
        Ok(())
    }

    #[test]
    fn default_server_takes_no_arguments() {
        let result = Config::parse_str(
            &with_sites("site a.test {\n    upstream http://u:80;\n    default_server yes;\n}\n"),
            "default.conf",
        );
        assert!(message(result.map(|_| ())).contains("takes no arguments"));
    }

    #[test]
    fn proxy_websocket_takes_on_or_off_and_is_off_by_default() -> Result<(), ConfigError> {
        let off = Config::parse_str(
            &with_sites("site a.test {\n    upstream http://u:80;\n}\n"),
            "ws.conf",
        )?;
        assert!(!off.sites.first().is_some_and(|site| site.websocket));
        let on = Config::parse_str(
            &with_sites("site a.test {\n    upstream http://u:80;\n    proxy_websocket on;\n}\n"),
            "ws.conf",
        )?;
        assert!(on.sites.first().is_some_and(|site| site.websocket));
        Ok(())
    }

    #[test]
    fn proxy_websocket_rejects_other_values_and_top_level_use() {
        let value = Config::parse_str(
            &with_sites("site a.test {\n    upstream http://u:80;\n    proxy_websocket yes;\n}\n"),
            "ws.conf",
        );
        assert!(value.is_err());
        let top = Config::parse_str(
            &format!(
                "proxy_websocket on;\n{}",
                with_sites("site a.test {\n    upstream http://u:80;\n}\n")
            ),
            "ws.conf",
        );
        assert!(message(top.map(|_| ())).contains("unknown directive \"proxy_websocket\""));
    }

    #[test]
    fn an_upstream_must_use_the_http_scheme_and_name_a_host() {
        for upstream in ["ftp://upstream:80", "http:/path-only", "http:upstream"] {
            let text = message(parse_plain(&format!(
                "listen 127.0.0.1:8080;\ndecision {{\n    backend http;\n    url http://stub-decider:9000/decide;\n}}\nsite example.com {{\n    upstream {upstream};\n}}\n"
            )));
            assert!(
                text.contains("must be an absolute http:// URI"),
                "{upstream}: {text}"
            );
        }
    }

    #[rstest]
    #[case::upstream("upstream http://other:80;", "upstream", 8)]
    #[case::mode("mode enforce;", "mode", 9)]
    #[case::action("action block;", "action", 9)]
    #[case::block_threshold("block_threshold 0.9;", "block_threshold", 9)]
    #[case::instruction_threshold("instruction_threshold 0.9;", "instruction_threshold", 9)]
    #[case::on_rate_limit("on_rate_limit allow;", "on_rate_limit", 9)]
    #[case::on_decision_error("on_decision_error allow;", "on_decision_error", 9)]
    #[case::debug_headers("debug_headers on;", "debug_headers", 9)]
    #[case::builtin_rules("builtin_rules on;", "builtin_rules", 9)]
    #[case::proxy_websocket("proxy_websocket on;", "proxy_websocket", 9)]
    #[case::default_server("default_server;", "default_server", 9)]
    #[case::client_body_timeout("client_body_timeout 5s;", "client_body_timeout", 9)]
    #[case::client_max_body_size("client_max_body_size 1m;", "client_max_body_size", 9)]
    #[case::proxy_connect_timeout("proxy_connect_timeout 5s;", "proxy_connect_timeout", 9)]
    #[case::proxy_read_timeout("proxy_read_timeout 5s;", "proxy_read_timeout", 9)]
    #[case::proxy_send_timeout("proxy_send_timeout 5s;", "proxy_send_timeout", 9)]
    fn a_single_use_directive_written_twice_is_rejected_at_the_second_one(
        #[case] directive: &str,
        #[case] name: &str,
        #[case] line: usize,
    ) {
        // The `upstream` case relies on the one that `with_site` writes on line 7.
        let text = message(parse(&with_site(&format!(
            "    {directive}\n    {directive}\n"
        ))));
        assert!(
            text.contains(&format!("test.conf:{line}: duplicate directive \"{name}\"")),
            "{text}"
        );
    }

    #[test]
    fn a_repeated_directive_is_reported_before_its_value_is_read() {
        let text = message(parse(&with_site("    mode enforce;\n    mode bogus;\n")));
        assert!(text.contains("duplicate directive \"mode\""), "{text}");
    }

    #[test]
    fn mode_shadow_selects_shadow_mode() -> Result<(), ConfigError> {
        let config = parse(&with_site("    mode shadow;\n"))?;
        assert_eq!(first_site(&config)?.mode, Mode::Shadow);
        Ok(())
    }

    #[test]
    fn a_mode_other_than_enforce_or_shadow_is_rejected() {
        let text = message(parse(&with_site("    mode monitor;\n")));
        assert!(
            text.contains("test.conf:8: \"mode\" must be enforce or shadow, got monitor"),
            "{text}"
        );
    }

    #[test]
    fn a_redirect_target_that_is_not_a_header_value_is_rejected() {
        // A quoted argument may hold an escape such as `\n`, which a header value cannot.
        let text = message(parse(&with_site(
            "    action redirect \"https://example.com/\\nSet-Cookie: a=b\";\n",
        )));
        assert!(
            text.contains("test.conf:8: \"action redirect\" target is not a valid header value"),
            "{text}"
        );
    }

    #[rstest]
    #[case::unknown_name("bogus on;", "bogus")]
    #[case::a_top_level_directive("listen 127.0.0.1:1;", "listen")]
    fn a_directive_that_a_site_does_not_have_is_rejected(#[case] line: &str, #[case] name: &str) {
        let text = message(parse(&with_site(&format!("    {line}\n"))));
        assert!(
            text.contains(&format!(
                "test.conf:8: unknown directive \"{name}\" in site"
            )),
            "{text}"
        );
    }

    #[test]
    fn a_zone_directive_in_a_site_is_rejected_because_zones_are_shared() {
        let text = message(parse(&with_site(
            "    limit_req_zone $client_ip zone=one:10m rate=1r/s;\n",
        )));
        assert!(
            text.contains(
                "test.conf:8: \"limit_req_zone\" is only valid at the top level: zones are shared by every site"
            ),
            "{text}"
        );
    }

    #[rstest]
    #[case::deny_path("deny_path")]
    #[case::fail_closed_path("fail_closed_path")]
    fn a_path_list_directive_without_prefixes_is_rejected(#[case] name: &str) {
        let text = message(parse(&with_site(&format!("    {name};\n"))));
        assert!(
            text.contains(&format!(
                "test.conf:8: \"{name}\" needs at least one prefix"
            )),
            "{text}"
        );
    }

    #[test]
    fn fail_closed_path_written_on_several_lines_adds_up() -> Result<(), ConfigError> {
        let config = parse(&with_site(
            "    fail_closed_path /a;\n    fail_closed_path /b /c;\n",
        ))?;
        assert_eq!(first_site(&config)?.fail_closed_paths, ["/a", "/b", "/c"]);
        Ok(())
    }

    #[test]
    fn static_extensions_written_on_several_lines_add_up_lowercased() -> Result<(), ConfigError> {
        let config = parse(&with_site(
            "    static_extensions css;\n    static_extensions JS;\n",
        ))?;
        assert_eq!(first_site(&config)?.static_extensions, ["css", "js"]);
        Ok(())
    }

    #[test]
    fn static_location_written_on_several_lines_adds_up_lowercased() -> Result<(), ConfigError> {
        let config = parse(&with_site(
            "    static_location /a/;\n    static_location /B/;\n",
        ))?;
        assert_eq!(first_site(&config)?.static_locations, ["/a/", "/b/"]);
        Ok(())
    }

    #[test]
    fn static_query_params_written_on_several_lines_add_up_with_their_case()
    -> Result<(), ConfigError> {
        let config = parse(&with_site(
            "    static_query_params v;\n    static_query_params Ver;\n",
        ))?;
        assert_eq!(first_site(&config)?.static_query_params, ["v", "Ver"]);
        Ok(())
    }

    #[test]
    fn deny_path_keeps_the_written_form_and_a_lowercase_form() -> Result<(), ConfigError> {
        let config = parse(&with_site("    deny_path /WP-Admin;\n"))?;
        let site = first_site(&config)?;
        assert_eq!(site.deny_paths, ["/WP-Admin"]);
        assert_eq!(site.deny_paths_lowered, ["/wp-admin"]);
        Ok(())
    }

    #[test]
    fn fail_closed_path_keeps_the_written_form_and_a_lowercase_form() -> Result<(), ConfigError> {
        let config = parse(&with_site("    fail_closed_path /WP-Login.php;\n"))?;
        let site = first_site(&config)?;
        assert_eq!(site.fail_closed_paths, ["/WP-Login.php"]);
        assert_eq!(site.fail_closed_lowered, ["/wp-login.php"]);
        Ok(())
    }

    #[test]
    fn a_repeated_location_is_reported_before_a_missing_upstream() {
        let text = message(parse(&with_sites(
            "site a.test {\n    location /a { }\n    location /a { }\n}\n",
        )));
        assert!(text.contains("duplicate \"location\""), "{text}");
    }

    #[test]
    fn an_access_log_conflict_is_reported_before_a_missing_upstream() {
        let text = message(parse(&with_sites(
            "site a.test {\n    access_log off;\n    access_log stdout;\n}\n",
        )));
        assert!(
            text.contains("\"access_log off\" cannot be combined with other access_log directives"),
            "{text}"
        );
    }

    #[test]
    fn a_repeated_location_is_reported_before_an_access_log_conflict() {
        let text = message(parse(&with_site(
            "    location /a { }\n    location /a { }\n    access_log off;\n    access_log stdout;\n",
        )));
        assert!(text.contains("duplicate \"location\""), "{text}");
    }

    #[rstest]
    #[case::off_first("    access_log off;\n    access_log stdout;\n")]
    #[case::off_last("    access_log stdout;\n    access_log off;\n")]
    fn the_access_log_off_conflict_points_at_the_site_line(#[case] lines: &str) {
        let text = message(parse(&with_site(lines)));
        assert!(
            text.contains(
                "test.conf:6: \"access_log off\" cannot be combined with other access_log directives"
            ),
            "{text}"
        );
    }

    #[test]
    fn a_site_without_a_host_name_is_rejected_at_the_site_line() {
        let text = message(parse(&with_sites("site {\n    upstream http://u:80;\n}\n")));
        assert!(
            text.contains("test.conf:6: \"site\" needs at least one host name"),
            "{text}"
        );
    }
}

#[cfg(test)]
mod timer_tests {
    use std::time::Duration;

    use super::*;
    use crate::config::test_helpers::connection_limit::{message, parse};

    #[test]
    fn connection_directives_inside_a_site_are_rejected() {
        for name in [
            "client_header_timeout 5s;",
            "keepalive_timeout 5s;",
            "keepalive_requests 5;",
            "send_timeout 5s;",
            "large_client_header_buffers 4 8k;",
            "lingering_close on;",
            "lingering_time 30s;",
            "lingering_timeout 5s;",
        ] {
            let text = message(parse("", &format!("    {name}\n")));
            assert!(
                text.contains("only valid at the top level"),
                "{name}: {text}"
            );
        }
    }

    #[test]
    fn site_timers_override_the_top_level_values_for_that_site() -> Result<(), ConfigError> {
        let config = parse(
            "client_body_timeout 30s;\nclient_max_body_size 2m;\nproxy_read_timeout 9s;\n",
            "    client_body_timeout 5s;\n    client_max_body_size 0;\n    proxy_connect_timeout 1s;\n    proxy_send_timeout 2s;\n",
        )?;
        let timeouts = config.sites[0].timeouts;
        assert_eq!(timeouts.client_body_timeout, Duration::from_secs(5));
        assert_eq!(timeouts.max_body_bytes, None);
        assert_eq!(timeouts.proxy_connect_timeout, Duration::from_secs(1));
        assert_eq!(timeouts.proxy_read_timeout, Duration::from_secs(9));
        assert_eq!(timeouts.proxy_send_timeout, Duration::from_secs(2));
        Ok(())
    }

    #[test]
    fn a_site_without_overrides_inherits_the_top_level_values() -> Result<(), ConfigError> {
        let config = parse("client_body_timeout 30s;\nclient_max_body_size 2m;\n", "")?;
        let timeouts = config.sites[0].timeouts;
        assert_eq!(timeouts.client_body_timeout, Duration::from_secs(30));
        assert_eq!(timeouts.max_body_bytes, Some(2 * 1024 * 1024));
        Ok(())
    }

    #[test]
    fn proxy_timers_must_be_positive_in_a_site() {
        let text = message(parse("", "    proxy_read_timeout 0;\n"));
        assert!(
            text.contains("\"proxy_read_timeout\" must be greater than 0"),
            "{text}"
        );
    }
}
