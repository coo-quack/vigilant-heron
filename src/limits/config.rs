//! The limit directives: zones, `limit_req` and `limit_conn`, and the types they build.

use std::collections::HashSet;

use http::{HeaderName, StatusCode};

use crate::accesslog::FORBIDDEN_HEADERS;
use crate::conf::Directive;
use crate::config::{invalid, once, one_arg, parse_size};
use crate::error::ConfigError;

/// Bytes of memory per `limit_req` state, as in nginx.
const REQ_STATE_BYTES: usize = 128;

/// Bytes of memory per `limit_conn` state, as in nginx.
const CONN_STATE_BYTES: usize = 64;

/// The directives that set limits, at any level where they are allowed.
pub(crate) const LIMIT_NAMES: [&str; 8] = [
    "limit_req",
    "limit_conn",
    "limit_req_status",
    "limit_conn_status",
    "limit_req_dry_run",
    "limit_conn_dry_run",
    "limit_req_log_level",
    "limit_conn_log_level",
];

/// The directives that define zones. They are valid only at the top level.
pub(crate) const ZONE_NAMES: [&str; 2] = ["limit_req_zone", "limit_conn_zone"];

/// One variable of a limit key, which is known before the body is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeyVar {
    /// The client address after real-IP selection, the analogue of nginx's `$binary_remote_addr`.
    ClientIp,
    /// The address of the connection's peer.
    RemoteAddr,
    /// The first host of the matched site, or empty when no site matched.
    Site,
    /// The `Host` header, normalized.
    Host,
    /// The request method.
    Method,
    /// The decoded path without the query, dot segments removed, case kept.
    Path,
    /// A request header, which is never a credential header.
    Header(HeaderName),
}

/// One piece of a limit key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeyPart {
    /// Text copied as written.
    Literal(String),
    /// A value taken from the request.
    Var(KeyVar),
}

/// What a zone counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ZoneKind {
    /// A leaky bucket that drains one request every `interval_ns` nanoseconds.
    Req {
        /// Time for the bucket to drain one request.
        interval_ns: u64,
    },
    /// Requests in progress.
    Conn,
}

/// A zone defined by `limit_req_zone` or `limit_conn_zone`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LimitZone {
    /// The name used by `zone=` or in `limit_conn`.
    pub(crate) name: String,
    /// The key that selects a state.
    pub(crate) key: Vec<KeyPart>,
    /// How many states the zone holds.
    pub(crate) capacity: usize,
    /// What the zone counts.
    pub(crate) kind: ZoneKind,
}

/// A `limit_req` directive, resolved to its zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReqLimit {
    /// Index of the zone in the configuration's zone list.
    pub(crate) zone: usize,
    /// Excess requests that may wait or pass, in requests.
    pub(crate) burst: u32,
    /// Excess requests served without a wait. Zero without `nodelay` or `delay=`.
    pub(crate) undelayed: u32,
}

/// A `limit_conn` directive, resolved to its zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConnLimit {
    /// Index of the zone in the configuration's zone list.
    pub(crate) zone: usize,
    /// Requests in progress allowed for one key.
    pub(crate) max: u32,
}

/// The severity of a limit event in the error log, as `limit_req_log_level` sets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LimitLog {
    /// `info`.
    Info,
    /// `notice`. The error log has no notice level, so it is written at info.
    Notice,
    /// `warn`.
    Warn,
    /// `error`, the default.
    Error,
}

impl LimitLog {
    fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "info" => Self::Info,
            "notice" => Self::Notice,
            "warn" => Self::Warn,
            "error" => Self::Error,
            _ => return None,
        })
    }
}

/// The limits in force at one level: the top level, a site, or a location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LimitSet {
    /// The `limit_req` directives, applied in order.
    pub(crate) req: Vec<ReqLimit>,
    /// The `limit_conn` directives, applied in order.
    pub(crate) conn: Vec<ConnLimit>,
    /// Status of a rejected `limit_req` request.
    pub(crate) req_status: StatusCode,
    /// Status of a rejected `limit_conn` request.
    pub(crate) conn_status: StatusCode,
    /// Whether `limit_req` only accounts, without rejecting or delaying.
    pub(crate) req_dry_run: bool,
    /// Whether `limit_conn` only accounts, without rejecting.
    pub(crate) conn_dry_run: bool,
    /// Error log severity of `limit_req` events.
    pub(crate) req_log: LimitLog,
    /// Error log severity of `limit_conn` events.
    pub(crate) conn_log: LimitLog,
}

impl Default for LimitSet {
    fn default() -> Self {
        Self {
            req: Vec::new(),
            conn: Vec::new(),
            req_status: StatusCode::SERVICE_UNAVAILABLE,
            conn_status: StatusCode::SERVICE_UNAVAILABLE,
            req_dry_run: false,
            conn_dry_run: false,
            req_log: LimitLog::Error,
            conn_log: LimitLog::Error,
        }
    }
}

/// The limit directives written at one level, before inheritance is applied.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LimitOverrides {
    req: Option<Vec<ReqLimit>>,
    conn: Option<Vec<ConnLimit>>,
    req_status: Option<StatusCode>,
    conn_status: Option<StatusCode>,
    req_dry_run: Option<bool>,
    conn_dry_run: Option<bool>,
    req_log: Option<LimitLog>,
    conn_log: Option<LimitLog>,
}

impl LimitOverrides {
    /// Applies one limit directive written at this level.
    ///
    /// A `limit_req` or `limit_conn` names a zone in `zones`, which must exist and
    /// be of the matching kind. Single-value directives may appear once per level.
    ///
    /// # Errors
    ///
    /// Returns the directive's line when its arguments are invalid, its zone is
    /// unknown or of the wrong kind, or it repeats a single-value directive.
    pub(crate) fn apply(
        &mut self,
        directive: &Directive,
        zones: &[LimitZone],
        seen: &mut HashSet<String>,
    ) -> Result<(), ConfigError> {
        match directive.name.as_str() {
            "limit_req" => {
                let limit = parse_limit_req(directive, zones)?;
                self.req.get_or_insert_with(Vec::new).push(limit);
            }
            "limit_conn" => {
                let limit = parse_limit_conn(directive, zones)?;
                self.conn.get_or_insert_with(Vec::new).push(limit);
            }
            "limit_req_status" => {
                once(seen, directive)?;
                self.req_status = Some(parse_status(directive)?);
            }
            "limit_conn_status" => {
                once(seen, directive)?;
                self.conn_status = Some(parse_status(directive)?);
            }
            "limit_req_dry_run" => {
                once(seen, directive)?;
                self.req_dry_run = Some(parse_on_off(directive)?);
            }
            "limit_conn_dry_run" => {
                once(seen, directive)?;
                self.conn_dry_run = Some(parse_on_off(directive)?);
            }
            "limit_req_log_level" => {
                once(seen, directive)?;
                self.req_log = Some(parse_log_level(directive)?);
            }
            "limit_conn_log_level" => {
                once(seen, directive)?;
                self.conn_log = Some(parse_log_level(directive)?);
            }
            other => {
                return Err(invalid(
                    directive,
                    format!("\"{other}\" is not a limit directive"),
                ));
            }
        }
        Ok(())
    }

    /// Returns the limits of this level, given the limits it inherits.
    ///
    /// Like nginx, a level that has any `limit_req` replaces the inherited list,
    /// and the same holds for `limit_conn`. Each other setting is inherited unless
    /// this level sets it.
    pub(crate) fn resolve(&self, parent: &LimitSet) -> LimitSet {
        LimitSet {
            req: self.req.clone().unwrap_or_else(|| parent.req.clone()),
            conn: self.conn.clone().unwrap_or_else(|| parent.conn.clone()),
            req_status: self.req_status.unwrap_or(parent.req_status),
            conn_status: self.conn_status.unwrap_or(parent.conn_status),
            req_dry_run: self.req_dry_run.unwrap_or(parent.req_dry_run),
            conn_dry_run: self.conn_dry_run.unwrap_or(parent.conn_dry_run),
            req_log: self.req_log.unwrap_or(parent.req_log),
            conn_log: self.conn_log.unwrap_or(parent.conn_log),
        }
    }
}

fn parse_status(directive: &Directive) -> Result<StatusCode, ConfigError> {
    let text = one_arg(directive)?;
    let code = text.parse::<u16>().ok().and_then(|code| {
        StatusCode::from_u16(code)
            .ok()
            .filter(|status| status.is_client_error() || status.is_server_error())
    });
    code.ok_or_else(|| {
        invalid(
            directive,
            format!(
                "\"{}\" must be a 4xx or 5xx code, got {text}",
                directive.name
            ),
        )
    })
}

fn parse_on_off(directive: &Directive) -> Result<bool, ConfigError> {
    match one_arg(directive)? {
        "on" => Ok(true),
        "off" => Ok(false),
        other => Err(invalid(
            directive,
            format!("\"{}\" must be on or off, got {other}", directive.name),
        )),
    }
}

fn parse_log_level(directive: &Directive) -> Result<LimitLog, ConfigError> {
    let text = one_arg(directive)?;
    LimitLog::parse(text).ok_or_else(|| {
        invalid(
            directive,
            format!(
                "\"{}\" must be info, notice, warn or error, got {text}",
                directive.name
            ),
        )
    })
}

/// Finds the zone a directive names, checking that it exists and has the given kind.
fn zone_index(
    directive: &Directive,
    zones: &[LimitZone],
    name: &str,
    want_req: bool,
) -> Result<usize, ConfigError> {
    let index = zones
        .iter()
        .position(|zone| zone.name == name)
        .ok_or_else(|| invalid(directive, format!("unknown zone \"{name}\"")))?;
    let zone = zones
        .get(index)
        .ok_or_else(|| invalid(directive, format!("unknown zone \"{name}\"")))?;
    let is_req = matches!(zone.kind, ZoneKind::Req { .. });
    if is_req != want_req {
        let wanted = if want_req {
            "limit_req_zone"
        } else {
            "limit_conn_zone"
        };
        return Err(invalid(
            directive,
            format!("zone \"{name}\" was not defined by {wanted}"),
        ));
    }
    Ok(index)
}

/// Parses `limit_req zone=<name> [burst=<n>] [nodelay | delay=<n>]`.
fn parse_limit_req(directive: &Directive, zones: &[LimitZone]) -> Result<ReqLimit, ConfigError> {
    let mut zone_name = None;
    let mut burst: Option<u32> = None;
    let mut nodelay = false;
    let mut delay: Option<u32> = None;
    for arg in &directive.args {
        if let Some(name) = arg.strip_prefix("zone=") {
            if zone_name.replace(name).is_some() {
                return Err(invalid(directive, "\"limit_req\" repeats zone="));
            }
        } else if let Some(text) = arg.strip_prefix("burst=") {
            let value = text.parse::<u32>().map_err(|_| {
                invalid(
                    directive,
                    format!("\"burst\" must be a whole number, got {text}"),
                )
            })?;
            if burst.replace(value).is_some() {
                return Err(invalid(directive, "\"limit_req\" repeats burst="));
            }
        } else if let Some(text) = arg.strip_prefix("delay=") {
            let value = text.parse::<u32>().map_err(|_| {
                invalid(
                    directive,
                    format!("\"delay\" must be a whole number, got {text}"),
                )
            })?;
            if delay.replace(value).is_some() {
                return Err(invalid(directive, "\"limit_req\" repeats delay="));
            }
        } else if arg == "nodelay" {
            nodelay = true;
        } else {
            return Err(invalid(
                directive,
                format!("\"limit_req\" has an unknown parameter: {arg}"),
            ));
        }
    }
    let name = zone_name.ok_or_else(|| invalid(directive, "\"limit_req\" needs zone=<name>"))?;
    let zone = zone_index(directive, zones, name, true)?;
    let burst = burst.unwrap_or(0);
    if nodelay && delay.is_some() {
        return Err(invalid(
            directive,
            "\"nodelay\" and \"delay\" cannot be combined",
        ));
    }
    let undelayed = match (nodelay, delay) {
        (true, _) => burst,
        (false, Some(count)) => {
            if burst == 0 {
                return Err(invalid(directive, "\"delay\" needs a burst"));
            }
            if count > burst {
                return Err(invalid(directive, "\"delay\" cannot exceed \"burst\""));
            }
            count
        }
        (false, None) => 0,
    };
    Ok(ReqLimit {
        zone,
        burst,
        undelayed,
    })
}

/// Parses `limit_conn <zone> <number>`.
fn parse_limit_conn(directive: &Directive, zones: &[LimitZone]) -> Result<ConnLimit, ConfigError> {
    let [name, number] = directive.args.as_slice() else {
        return Err(invalid(
            directive,
            "\"limit_conn\" takes a zone name and a number",
        ));
    };
    let zone = zone_index(directive, zones, name, false)?;
    let max = number
        .parse::<u32>()
        .ok()
        .filter(|max| *max > 0)
        .ok_or_else(|| {
            invalid(
                directive,
                format!("\"limit_conn\" needs a number of at least 1, got {number}"),
            )
        })?;
    Ok(ConnLimit { zone, max })
}

/// Parses one `limit_req_zone` or `limit_conn_zone` directive.
///
/// The key's `$http_` variables are checked against the credential headers and
/// the decision backend's redacted headers, as log formats are.
pub(crate) fn parse_zone(
    directive: &Directive,
    redact: &[String],
) -> Result<LimitZone, ConfigError> {
    let is_req = directive.name == "limit_req_zone";
    let (key_text, params) = directive
        .args
        .split_first()
        .ok_or_else(|| invalid(directive, format!("\"{}\" needs a key", directive.name)))?;
    let key = parse_key(directive, key_text, redact)?;
    let mut zone_arg = None;
    let mut rate = None;
    for param in params {
        if let Some(text) = param.strip_prefix("zone=") {
            if zone_arg.replace(text).is_some() {
                return Err(invalid(directive, "\"zone=\" is given twice"));
            }
        } else if let Some(text) = param.strip_prefix("rate=") {
            if !is_req {
                return Err(invalid(
                    directive,
                    "\"rate=\" is valid only in limit_req_zone",
                ));
            }
            if rate.replace(text).is_some() {
                return Err(invalid(directive, "\"rate=\" is given twice"));
            }
        } else {
            return Err(invalid(
                directive,
                format!("\"{}\" has an unknown parameter: {param}", directive.name),
            ));
        }
    }
    let spec = zone_arg.ok_or_else(|| {
        invalid(
            directive,
            format!("\"{}\" needs zone=<name>:<size>", directive.name),
        )
    })?;
    let (name, size_text) = spec.split_once(':').ok_or_else(|| {
        invalid(
            directive,
            format!("\"zone=\" needs <name>:<size>, got {spec}"),
        )
    })?;
    if name.is_empty()
        || name
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
    {
        return Err(invalid(
            directive,
            format!("zone name is not valid: {name}"),
        ));
    }
    let bytes = parse_size(directive, size_text)?;
    let (state_bytes, kind) = if is_req {
        let text = rate.ok_or_else(|| {
            invalid(
                directive,
                "\"limit_req_zone\" needs rate=<N>r/s or rate=<N>r/m",
            )
        })?;
        (
            REQ_STATE_BYTES,
            ZoneKind::Req {
                interval_ns: parse_rate(directive, text)?,
            },
        )
    } else {
        (CONN_STATE_BYTES, ZoneKind::Conn)
    };
    let capacity = bytes / state_bytes;
    if capacity == 0 {
        return Err(invalid(
            directive,
            format!("zone size {size_text} holds no state; it needs at least {state_bytes} bytes"),
        ));
    }
    Ok(LimitZone {
        name: name.to_owned(),
        key,
        capacity,
        kind,
    })
}

/// Parses `<N>r/s` or `<N>r/m` and returns the time for one request to drain, in nanoseconds.
fn parse_rate(directive: &Directive, text: &str) -> Result<u64, ConfigError> {
    let invalid_rate = || {
        invalid(
            directive,
            format!("\"rate\" must be <N>r/s or <N>r/m, got {text}"),
        )
    };
    let (count_text, per_nanos) = if let Some(count) = text.strip_suffix("r/s") {
        (count, 1_000_000_000_u64)
    } else if let Some(count) = text.strip_suffix("r/m") {
        (count, 60_000_000_000_u64)
    } else {
        return Err(invalid_rate());
    };
    let count = count_text
        .parse::<u64>()
        .ok()
        .filter(|count| *count > 0)
        .ok_or_else(invalid_rate)?;
    let interval = per_nanos / count;
    if interval == 0 {
        return Err(invalid(directive, format!("\"rate\" is too high: {text}")));
    }
    Ok(interval)
}

/// Parses a limit key: literal text and `$variable` references.
fn parse_key(
    directive: &Directive,
    text: &str,
    redact: &[String],
) -> Result<Vec<KeyPart>, ConfigError> {
    let mut parts = Vec::new();
    let mut literal = String::new();
    let mut rest = text;
    while let Some(position) = rest.find('$') {
        let (before, after) = rest.split_at(position);
        literal.push_str(before);
        let name_len = after
            .get(1..)
            .unwrap_or_default()
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .count();
        let name = after.get(1..=name_len).unwrap_or_default();
        if name.is_empty() {
            return Err(invalid(
                directive,
                format!("a lone \"$\" in limit key {text}"),
            ));
        }
        if !literal.is_empty() {
            parts.push(KeyPart::Literal(std::mem::take(&mut literal)));
        }
        parts.push(KeyPart::Var(key_var(directive, name, redact)?));
        rest = after.get(1 + name_len..).unwrap_or_default();
    }
    literal.push_str(rest);
    if !literal.is_empty() {
        parts.push(KeyPart::Literal(literal));
    }
    if parts.is_empty() {
        return Err(invalid(directive, "a limit key cannot be empty"));
    }
    Ok(parts)
}

fn key_var(directive: &Directive, name: &str, redact: &[String]) -> Result<KeyVar, ConfigError> {
    Ok(match name {
        "client_ip" => KeyVar::ClientIp,
        "remote_addr" => KeyVar::RemoteAddr,
        "site" => KeyVar::Site,
        "host" => KeyVar::Host,
        "method" => KeyVar::Method,
        "path" => KeyVar::Path,
        _ => {
            let Some(header) = name.strip_prefix("http_").filter(|h| !h.is_empty()) else {
                return Err(invalid(
                    directive,
                    format!("unknown variable in limit key: ${name}"),
                ));
            };
            let header_name = header.replace('_', "-").to_ascii_lowercase();
            let forbidden = FORBIDDEN_HEADERS.contains(&header_name.as_str())
                || redact.iter().any(|r| r.eq_ignore_ascii_case(&header_name));
            if forbidden {
                return Err(invalid(
                    directive,
                    format!(
                        "${name} is not allowed: credential headers are never used in a limit key"
                    ),
                ));
            }
            let parsed = HeaderName::from_bytes(header_name.as_bytes())
                .map_err(|_| invalid(directive, format!("${name} is not a valid header name")))?;
            KeyVar::Header(parsed)
        }
    })
}

/// Builds the zones of the configuration from their directives, checking that names are unique.
pub(crate) fn build_zones(
    directives: &[&Directive],
    redact: &[String],
) -> Result<Vec<LimitZone>, ConfigError> {
    let mut zones: Vec<LimitZone> = Vec::new();
    let mut names = HashSet::new();
    for directive in directives {
        let zone = parse_zone(directive, redact)?;
        if !names.insert(zone.name.clone()) {
            return Err(invalid(
                directive,
                format!("zone \"{}\" is defined more than once", zone.name),
            ));
        }
        zones.push(zone);
    }
    Ok(zones)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::limits::test_helpers::{ONE, TWO, message, parse};

    #[rstest]
    #[case("10r/s", 100_000_000)]
    #[case("30r/m", 2_000_000_000)]
    #[case("1r/s", 1_000_000_000)]
    #[case("1000000r/s", 1_000)]
    fn rate_takes_requests_per_second_or_minute(#[case] rate: &str, #[case] interval_ns: u64) {
        let config = parse(
            &format!("limit_req_zone $client_ip zone=one:10m rate={rate};"),
            "",
        );
        let zone = config.map(|config| config.zones.first().map(|zone| zone.kind));
        assert!(matches!(zone, Ok(Some(ZoneKind::Req { interval_ns: got })) if got == interval_ns));
    }

    #[rstest]
    #[case("limit_req_zone $client_ip zone=one:10m;", "needs rate")]
    #[case("limit_req_zone $client_ip zone=one:10m rate=0r/s;", "rate")]
    #[case("limit_req_zone $client_ip zone=one:10m rate=5r/h;", "rate")]
    #[case("limit_req_zone $client_ip zone=one:10m rate=r/s;", "rate")]
    #[case(
        "limit_req_zone $client_ip zone=one:10m rate=2000000000r/s;",
        "too high"
    )]
    #[case("limit_req_zone $client_ip zone=one:0k rate=1r/s;", "holds no state")]
    #[case("limit_req_zone $client_ip zone=one rate=1r/s;", "<name>:<size>")]
    #[case("limit_req_zone $client_ip zone=one:10m rate=1r/s rate=2r/s;", "twice")]
    #[case("limit_req_zone $client_ip rate=1r/s;", "needs zone=")]
    #[case(
        "limit_req_zone $client_ip zone=one:10m rate=1r/s bogus;",
        "unknown parameter"
    )]
    #[case(
        "limit_req_zone $binary_remote_addr zone=one:10m rate=1r/s;",
        "unknown variable"
    )]
    #[case("limit_req_zone $http_cookie zone=one:10m rate=1r/s;", "credential")]
    #[case("limit_req_zone $http_x_api_key zone=one:10m rate=1r/s;", "credential")]
    #[case("limit_req_zone $ zone=one:10m rate=1r/s;", "lone")]
    #[case("limit_req_zone $http_ zone=one:10m rate=1r/s;", "unknown variable")]
    #[case("limit_conn_zone $client_ip zone=one:10m rate=1r/s;", "rate=")]
    #[case("limit_conn_zone $client_ip zone=one:0k;", "holds no state")]
    #[case("limit_req_zone $client_ip zone=bad/name:10m rate=1r/s;", "zone name")]
    fn invalid_zones_name_the_problem(#[case] line: &str, #[case] expected: &str) {
        let text = message(parse(line, ""));
        assert!(text.contains(expected), "{text}");
        assert!(text.contains("test.conf:"), "{text}");
    }

    #[test]
    fn a_zone_name_defined_twice_is_rejected_at_the_second_line() {
        let text = message(parse(
            &format!("{ONE}\n{TWO}\nlimit_conn_zone $client_ip zone=one:1m;"),
            "",
        ));
        assert!(
            text.contains("zone \"one\" is defined more than once"),
            "{text}"
        );
        assert!(text.contains("test.conf:4:"), "{text}");
    }

    #[rstest]
    #[case("limit_req zone=missing;", "unknown zone")]
    #[case("limit_req zone=two;", "was not defined by limit_req_zone")]
    #[case("limit_req burst=2;", "needs zone=")]
    #[case("limit_req zone=one burst=2 burst=3;", "repeats burst")]
    #[case("limit_req zone=one zone=one;", "repeats zone")]
    #[case("limit_req zone=one burst=x;", "whole number")]
    #[case("limit_req zone=one delay=1;", "needs a burst")]
    #[case("limit_req zone=one burst=2 delay=3;", "cannot exceed")]
    #[case("limit_req zone=one burst=2 nodelay delay=1;", "cannot be combined")]
    #[case("limit_req zone=one bogus;", "unknown parameter")]
    #[case("limit_req_status 200;", "4xx or 5xx")]
    #[case("limit_req_status 429; limit_req_status 503;", "duplicate directive")]
    #[case("limit_req_dry_run maybe;", "on or off")]
    #[case("limit_req_log_level debug;", "info, notice, warn or error")]
    #[case("limit_conn two;", "takes a zone name and a number")]
    #[case("limit_conn two 0;", "at least 1")]
    #[case("limit_conn one 2;", "was not defined by limit_conn_zone")]
    fn invalid_limit_directives_name_the_problem(#[case] line: &str, #[case] expected: &str) {
        let top = format!("{ONE}\n{TWO}\n{line}");
        let text = message(parse(&top, ""));
        assert!(text.contains(expected), "{text}");
    }

    #[test]
    fn limit_directives_inside_a_site_are_checked_too() {
        let text = message(parse(&format!("{ONE}\n{TWO}"), "limit_req zone=missing;"));
        assert!(text.contains("unknown zone \"missing\""), "{text}");
    }

    #[test]
    fn zone_directives_are_rejected_inside_a_site() {
        let text = message(parse(TWO, ONE));
        assert!(text.contains("only valid at the top level"), "{text}");
        assert!(text.contains("test.conf:"), "{text}");
    }

    #[test]
    fn a_site_without_limits_inherits_the_top_level_limits() -> Result<(), ConfigError> {
        let config = parse(
            &format!(
                "{ONE}\n{TWO}\nlimit_req zone=one burst=1;\nlimit_conn two 3;\nlimit_req_status 429;"
            ),
            "",
        )?;
        let site = config.sites.first().ok_or(ConfigError::Invalid {
            file: "test.conf".to_owned(),
            line: 1,
            message: "no site".to_owned(),
        })?;
        assert_eq!(site.limits.req, config.limits.req);
        assert_eq!(site.limits.conn, config.limits.conn);
        assert_eq!(site.limits.req_status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(config.limits.req.len(), 1);
        Ok(())
    }

    #[test]
    fn a_level_with_limit_req_replaces_the_inherited_list_and_keeps_the_rest()
    -> Result<(), ConfigError> {
        let config = parse(
            &format!(
                "{ONE}\n{TWO}\nlimit_req zone=one burst=1;\nlimit_conn two 3;\nlimit_req_status 429;"
            ),
            "limit_req zone=one burst=5 nodelay; limit_req_status 418; location /login { limit_conn two 1; }",
        )?;
        let site = config.sites.first().ok_or(ConfigError::Invalid {
            file: "test.conf".to_owned(),
            line: 1,
            message: "no site".to_owned(),
        })?;
        assert_eq!(site.limits.req.len(), 1);
        assert_eq!(site.limits.req.first().map(|l| l.burst), Some(5));
        assert_eq!(site.limits.req_status, StatusCode::IM_A_TEAPOT);
        assert_eq!(site.limits.conn.first().map(|l| l.max), Some(3));
        let location = site.locations.first().ok_or(ConfigError::Invalid {
            file: "test.conf".to_owned(),
            line: 1,
            message: "no location".to_owned(),
        })?;
        assert_eq!(location.limits.conn.first().map(|l| l.max), Some(1));
        assert_eq!(location.limits.req, site.limits.req);
        assert_eq!(location.limits.req_status, StatusCode::IM_A_TEAPOT);
        Ok(())
    }

    #[test]
    fn nodelay_and_delay_set_the_number_of_undelayed_excess_requests() -> Result<(), ConfigError> {
        let config = parse(&format!("{ONE}\nlimit_req zone=one burst=4 nodelay;"), "")?;
        assert_eq!(
            config.limits.req.first().map(|l| (l.burst, l.undelayed)),
            Some((4, 4))
        );
        let config = parse(&format!("{ONE}\nlimit_req zone=one burst=4 delay=1;"), "")?;
        assert_eq!(
            config.limits.req.first().map(|l| (l.burst, l.undelayed)),
            Some((4, 1))
        );
        let config = parse(&format!("{ONE}\nlimit_req zone=one burst=4;"), "")?;
        assert_eq!(
            config.limits.req.first().map(|l| (l.burst, l.undelayed)),
            Some((4, 0))
        );
        Ok(())
    }

    #[rstest]
    #[case("$client_ip", 1)]
    #[case("$client_ip:$site", 3)]
    #[case("login-$client_ip", 2)]
    fn keys_parse_literals_and_variables(#[case] text: &str, #[case] parts: usize) {
        let config = parse(
            &format!("limit_req_zone \"{text}\" zone=one:10m rate=1r/s;"),
            "",
        );
        let zone = config
            .ok()
            .and_then(|config| config.zones.into_iter().next());
        assert_eq!(zone.map(|zone| zone.key.len()), Some(parts));
    }

    #[test]
    fn a_delay_equal_to_the_burst_is_accepted_and_leaves_no_request_delayed()
    -> Result<(), ConfigError> {
        let config = parse(&format!("{ONE}\nlimit_req zone=one burst=2 delay=2;"), "")?;
        assert_eq!(
            config.limits.req.first().map(|l| (l.burst, l.undelayed)),
            Some((2, 2))
        );
        Ok(())
    }

    #[test]
    fn zone_names_may_contain_dashes_and_underscores() {
        let text = message(parse(
            "limit_req_zone $client_ip zone=my_zone-2:10m rate=1r/s;",
            "",
        ));
        assert_eq!(text, "accepted");
    }

    #[test]
    fn an_empty_zone_name_is_rejected() {
        let text = message(parse("limit_req_zone $client_ip zone=:10m rate=1r/s;", ""));
        assert!(text.contains("zone name is not valid"), "{text}");
    }
}
