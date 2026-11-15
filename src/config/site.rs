//! The `site` block, the timers and limits a site may override, and the `allow` and `deny`
//! entries of an access list.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use http::HeaderValue;

use super::decision::parse_absolute_uri;
use super::logs::{Formats, parse_access};
use super::names::SITE_DIRECTIVES;
use super::value::{
    block, invalid, once, one_arg, parse_body_limit, parse_bool, parse_failure,
    parse_positive_time, parse_threshold,
};
use super::{AccessLogConfig, FailureAction, Mode, SiteAction, SiteConfig, SiteTimeouts};
use crate::access::AccessEntry;
use crate::block::{BLOCK_NAMES, BlockOverrides, BlockResponse};
use crate::conf::Directive;
use crate::error::ConfigError;
use crate::limits::{self, LimitOverrides, LimitSet, LimitZone, LocationConfig};
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

#[expect(
    clippy::too_many_lines,
    reason = "one arm per directive keeps each name and its check together"
)]
pub(crate) fn parse_site(
    directive: &Directive,
    formats: &Formats,
    top: &Top<'_>,
    claimed: &mut HashMap<String, String>,
) -> Result<SiteConfig, ConfigError> {
    if directive.args.is_empty() {
        return Err(invalid(directive, "\"site\" needs at least one host name"));
    }
    let mut host_patterns = Vec::new();
    for host in &directive.args {
        let pattern = HostPattern::parse(host).map_err(|reason| {
            invalid(
                directive,
                format!("\"site\" has an invalid host name {host}: {reason}"),
            )
        })?;
        host_patterns.push(pattern);
    }
    let hosts: Vec<String> = host_patterns.iter().map(HostPattern::display).collect();

    let mut seen = HashSet::new();
    let mut default_server = false;
    let mut upstream = None;
    let mut mode = Mode::Enforce;
    let mut action = SiteAction::Block;
    let mut action_seen = false;
    let mut block_threshold = DEFAULT_BLOCK_THRESHOLD;
    let mut instruction_threshold = DEFAULT_INSTRUCTION_THRESHOLD;
    let mut deny_paths = Vec::new();
    let mut fail_closed_paths = Vec::new();
    let mut on_rate_limit = FailureAction::Allow;
    let mut on_client_busy = FailureAction::Block;
    let mut on_decision_error = FailureAction::Allow;
    let mut static_extensions: Option<Vec<String>> = None;
    let mut static_locations: Vec<String> = Vec::new();
    let mut static_query_params: Vec<String> = Vec::new();
    let mut static_query_token = false;
    let mut debug_headers = false;
    let mut access_logs: Option<Vec<AccessLogConfig>> = None;
    let mut access_off = false;
    let mut timeouts = top.timeouts;
    let mut own_access: Vec<AccessEntry> = Vec::new();
    let mut builtin_enabled: Option<bool> = None;
    let mut own_switches = RuleSwitches::default();
    let mut own_rules: Vec<ParsedRule> = Vec::new();
    let mut site_limits = LimitOverrides::default();
    let mut pending_locations = Vec::new();
    let mut site_block = BlockOverrides::default();
    let mut site_headers: Option<Vec<HeaderOp>> = None;
    let mut websocket = false;

    for child in block(directive)? {
        if !SITE_DIRECTIVES.contains(&child.name.as_str()) {
            return Err(invalid(
                child,
                format!("unknown directive \"{}\" in site", child.name),
            ));
        }
        match child.name.as_str() {
            name if SITE_TIMEOUT_NAMES.contains(&name) => {
                once(&mut seen, child)?;
                set_site_timeout(child, &mut timeouts)?;
            }
            name if CONNECTION_NAMES.contains(&name) => {
                return Err(invalid(
                    child,
                    format!(
                        "\"{name}\" is only valid at the top level: it applies before the Host selects a site"
                    ),
                ));
            }
            "upstream" => {
                once(&mut seen, child)?;
                let text = one_arg(child)?;
                upstream = Some(parse_absolute_uri(text, &["http"]).ok_or_else(|| {
                    invalid(
                        child,
                        format!("\"upstream\" must be an absolute http:// URI, got {text}"),
                    )
                })?);
            }
            "mode" => {
                once(&mut seen, child)?;
                mode = match one_arg(child)? {
                    "enforce" => Mode::Enforce,
                    "shadow" => Mode::Shadow,
                    other => {
                        return Err(invalid(
                            child,
                            format!("\"mode\" must be enforce or shadow, got {other}"),
                        ));
                    }
                };
            }
            "action" => {
                if action_seen {
                    return Err(invalid(child, "duplicate directive \"action\""));
                }
                action_seen = true;
                action = match child.args.as_slice() {
                    [word] if word == "block" => SiteAction::Block,
                    [word, target] if word == "redirect" => {
                        let location = HeaderValue::from_str(target)
                            .map_err(|_| invalid(child, format!("\"action redirect\" target is not a valid header value: {target}")))?;
                        SiteAction::Redirect(location)
                    }
                    _ => {
                        return Err(invalid(
                            child,
                            "\"action\" must be \"block\" or \"redirect <url>\"",
                        ));
                    }
                };
            }
            "block_threshold" => {
                once(&mut seen, child)?;
                block_threshold = parse_threshold(child, one_arg(child)?)?;
            }
            "instruction_threshold" => {
                once(&mut seen, child)?;
                instruction_threshold = parse_threshold(child, one_arg(child)?)?;
            }
            "on_rate_limit" => {
                once(&mut seen, child)?;
                on_rate_limit = parse_failure(child, one_arg(child)?)?;
            }
            "on_client_busy" => {
                once(&mut seen, child)?;
                on_client_busy = parse_failure(child, one_arg(child)?)?;
            }
            "on_decision_error" => {
                once(&mut seen, child)?;
                on_decision_error = parse_failure(child, one_arg(child)?)?;
            }
            "deny_path" => {
                if child.args.is_empty() {
                    return Err(invalid(child, "\"deny_path\" needs at least one prefix"));
                }
                deny_paths.extend(child.args.iter().cloned());
            }
            "fail_closed_path" => {
                if child.args.is_empty() {
                    return Err(invalid(
                        child,
                        "\"fail_closed_path\" needs at least one prefix",
                    ));
                }
                fail_closed_paths.extend(child.args.iter().cloned());
            }
            "static_extensions" => {
                let list = static_extensions.get_or_insert_with(Vec::new);
                list.extend(child.args.iter().map(|e| e.to_ascii_lowercase()));
            }
            "static_location" => {
                if child.args.is_empty() {
                    return Err(invalid(
                        child,
                        "\"static_location\" needs at least one path prefix",
                    ));
                }
                for prefix in &child.args {
                    if !prefix.starts_with('/') {
                        return Err(invalid(
                            child,
                            format!("\"static_location\" prefix must start with /: {prefix}"),
                        ));
                    }
                }
                static_locations.extend(child.args.iter().map(|p| p.to_ascii_lowercase()));
            }
            "static_query_params" => {
                if child.args.is_empty() {
                    return Err(invalid(
                        child,
                        "\"static_query_params\" needs at least one parameter name",
                    ));
                }
                for name in &child.args {
                    let valid = (1..=64).contains(&name.len())
                        && name
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'));
                    if !valid {
                        return Err(invalid(
                            child,
                            format!(
                                "\"static_query_params\" name must be 1 to 64 letters, digits, _ or -: {name}"
                            ),
                        ));
                    }
                }
                static_query_params.extend(child.args.iter().cloned());
            }
            "static_query_token" => {
                once(&mut seen, child)?;
                static_query_token = parse_bool(child, one_arg(child)?)?;
            }
            "debug_headers" => {
                once(&mut seen, child)?;
                debug_headers = parse_bool(child, one_arg(child)?)?;
            }
            "access_log" => match parse_access(child, formats)? {
                Some(log) => access_logs.get_or_insert_with(Vec::new).push(log),
                None => access_off = true,
            },
            "allow" | "deny" => own_access.push(access_entry(child)?),
            "builtin_rules" => {
                once(&mut seen, child)?;
                builtin_enabled = Some(parse_bool(child, one_arg(child)?)?);
            }
            "disable_rule" => own_switches
                .disabled
                .extend(rules::builtin_ids(child, top.builtin)?),
            "enable_rule" => own_switches
                .enabled
                .extend(rules::builtin_ids(child, top.builtin)?),
            "rule" => {
                let parsed = rules::parse_rule(child, Scope::Site)?;
                rules::claim_id(claimed, &parsed)?;
                own_rules.push(parsed);
            }
            name if limits::ZONE_NAMES.contains(&name) => {
                return Err(invalid(
                    child,
                    format!(
                        "\"{name}\" is only valid at the top level: zones are shared by every site"
                    ),
                ));
            }
            name if limits::LIMIT_NAMES.contains(&name) => {
                site_limits.apply(child, top.zones, &mut seen)?;
            }
            name if BLOCK_NAMES.contains(&name) => site_block.apply(child, &mut seen)?,
            "proxy_websocket" => {
                once(&mut seen, child)?;
                websocket = parse_bool(child, one_arg(child)?)?;
            }
            "proxy_set_header" => site_headers
                .get_or_insert_with(Vec::new)
                .push(HeaderOp::parse(child)?),
            "location" => pending_locations.push(limits::parse_location(child, top.zones)?),
            "default_server" => {
                if !child.args.is_empty() {
                    return Err(invalid(child, "\"default_server\" takes no arguments"));
                }
                once(&mut seen, child)?;
                default_server = true;
            }
            other => {
                return Err(invalid(
                    child,
                    format!("unknown directive \"{other}\" in site"),
                ));
            }
        }
    }
    let site_limit_set = site_limits.resolve(top.limits);
    let block_response = site_block.resolve(top.block);
    // A site with its own proxy_set_header replaces the inherited list, as in nginx.
    let proxy_headers = site_headers.unwrap_or_else(|| top.headers.to_vec());
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
            limits: pending.overrides.resolve(&site_limit_set),
            block: pending.block.resolve(&block_response),
            proxy_headers: pending.headers.unwrap_or_else(|| proxy_headers.clone()),
            websocket: pending.websocket.unwrap_or(websocket),
        });
    }

    if access_off {
        if access_logs.is_some() {
            return Err(invalid(
                directive,
                "\"access_log off\" cannot be combined with other access_log directives",
            ));
        }
        access_logs = Some(Vec::new());
    }
    let upstream =
        upstream.ok_or_else(|| invalid(directive, "\"upstream\" is required in a site"))?;

    // A site with its own access list ignores the top-level one.
    let access = if own_access.is_empty() {
        top.access.to_vec()
    } else {
        own_access
    };
    let rules = rules::site_rules(
        &hosts,
        top.builtin,
        builtin_enabled.unwrap_or(top.builtin_enabled),
        top.switches,
        &own_switches,
        top.rules,
        &own_rules,
    );

    Ok(SiteConfig {
        hosts,
        default_server,
        host_patterns,
        block: block_response,
        proxy_headers,
        websocket,
        upstream,
        mode,
        action,
        block_threshold,
        instruction_threshold,
        deny_paths_lowered: deny_paths.iter().map(|path| path.to_lowercase()).collect(),
        deny_paths,
        fail_closed_lowered: fail_closed_paths
            .iter()
            .map(|path| path.to_lowercase())
            .collect(),
        fail_closed_paths,
        on_rate_limit,
        on_client_busy,
        on_decision_error,
        static_extensions: static_extensions.unwrap_or_else(|| {
            DEFAULT_STATIC_EXTENSIONS
                .iter()
                .map(|e| (*e).to_owned())
                .collect()
        }),
        static_locations,
        static_query_params,
        static_query_token,
        debug_headers,
        access_logs,
        timeouts,
        access,
        rules,
        limits: site_limit_set,
        locations,
    })
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
