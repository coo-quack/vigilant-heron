//! Request-rate and connection limits, with the semantics of nginx's
//! `ngx_http_limit_req_module` and `ngx_http_limit_conn_module`.
//!
//! A `limit_req_zone` names a leaky bucket per key. Each request adds one unit
//! to its key's bucket, and the bucket drains at the configured rate. A request
//! that finds the bucket above `burst` is rejected. Otherwise it passes at once,
//! or it waits until its turn when it is beyond the requests `nodelay` or
//! `delay=` allow without a wait.
//!
//! A `limit_conn_zone` counts the requests in progress per key. A request is
//! counted from the moment its header is read until its response body is done or
//! dropped.
//!
//! Zones live in the router process. A zone holds as many states as its size
//! allows, 128 bytes per `limit_req` state and 64 per `limit_conn` state, as in
//! nginx. The least recently used idle state is evicted when the zone is full.
//! When no state can be created even after eviction, the request is handled as a
//! rejection: with the configured status, or as a dry-run rejection in dry run.
//!
//! Time comes from [`tokio::time`], so tests can pause and advance it.

use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::hash::BuildHasher;
use std::sync::Arc;
use std::time::Duration;

use http::{HeaderMap, HeaderName, StatusCode};
use tokio::time::Instant;

use crate::accesslog::FORBIDDEN_HEADERS;
use crate::block::{BLOCK_NAMES, BlockOverrides, BlockResponse};
use crate::conf::Directive;
use crate::config::{block, invalid, once, one_arg, parse_bool, parse_size};
use crate::error::ConfigError;
use crate::proxy::HeaderOp;
use crate::transport::lock;

/// Bytes of memory per `limit_req` state, as in nginx.
const REQ_STATE_BYTES: usize = 128;

/// Bytes of memory per `limit_conn` state, as in nginx.
const CONN_STATE_BYTES: usize = 64;

/// Units of one request in a bucket. A request drains in `interval` nanoseconds.
const UNITS_PER_REQUEST: u64 = 1000;

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

/// How a location's path is matched, as nginx's `location` modifiers.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Matcher {
    /// `location = /path`: the whole path is equal.
    Exact(String),
    /// `location /path`: the path starts with this text.
    Prefix(String),
    /// `location ^~ /path`: a prefix that stops the search for regexes.
    PrefixPriority(String),
    /// `location ~ regex` and `location ~* regex`.
    Regex(Pattern),
}

/// A compiled regex location.
#[derive(Debug, Clone)]
pub(crate) struct Pattern {
    source: String,
    caseless: bool,
    regex: regex::Regex,
}

impl PartialEq for Pattern {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source && self.caseless == other.caseless
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.source)
    }
}

/// A location block whose limits are not yet resolved against its site.
#[derive(Debug)]
pub(crate) struct PendingLocation<'a> {
    /// The `location` directive, for error messages.
    pub(crate) directive: &'a Directive,
    /// How the location matches.
    pub(crate) matcher: Matcher,
    /// The limit directives written in the block.
    pub(crate) overrides: LimitOverrides,
    /// The block response directives written in the block.
    pub(crate) block: BlockOverrides,
    /// The `proxy_set_header` operations of the block, which replace the site's when present.
    pub(crate) headers: Option<Vec<HeaderOp>>,
    /// The `proxy_websocket` setting of the block, when it has one.
    pub(crate) websocket: Option<bool>,
}

/// Parses `location [=|~|~*|^~] <path> { ... }`, with only limit directives inside.
///
/// Plain paths are lowercased, as `deny_path` is, and must start with `/`. Regex
/// locations match the decoded path; `~*` ignores case and `~` does not.
///
/// # Errors
///
/// Returns the directive's line for a bad modifier, path or regex, for a limit
/// directive that is invalid, and for any other directive inside the block.
pub(crate) fn parse_location<'a>(
    directive: &'a Directive,
    zones: &[LimitZone],
) -> Result<PendingLocation<'a>, ConfigError> {
    let (modifier, path) = match directive.args.as_slice() {
        [path] => (None, path.as_str()),
        [modifier, path] => (Some(modifier.as_str()), path.as_str()),
        _ => {
            return Err(invalid(
                directive,
                "\"location\" takes an optional modifier and one path",
            ));
        }
    };
    let matcher = match modifier {
        None => Matcher::Prefix(plain_path(directive, path)?),
        Some("=") => Matcher::Exact(plain_path(directive, path)?),
        Some("^~") => Matcher::PrefixPriority(plain_path(directive, path)?),
        Some(sign @ ("~" | "~*")) => {
            let caseless = sign == "~*";
            let source = path.to_owned();
            let compiled = if caseless {
                format!("(?i){path}")
            } else {
                path.to_owned()
            };
            let regex = regex::Regex::new(&compiled).map_err(|error| {
                invalid(
                    directive,
                    format!("\"location\" regex is not valid: {error}"),
                )
            })?;
            Matcher::Regex(Pattern {
                source,
                caseless,
                regex,
            })
        }
        Some(other) => {
            return Err(invalid(
                directive,
                format!("\"location\" modifier must be =, ~, ~* or ^~, got {other}"),
            ));
        }
    };
    let mut overrides = LimitOverrides::default();
    let mut block_overrides = BlockOverrides::default();
    let mut headers: Option<Vec<HeaderOp>> = None;
    let mut websocket: Option<bool> = None;
    let mut seen = HashSet::new();
    for child in block(directive)? {
        let name = child.name.as_str();
        if BLOCK_NAMES.contains(&name) {
            block_overrides.apply(child, &mut seen)?;
        } else if name == "proxy_websocket" {
            once(&mut seen, child)?;
            websocket = Some(parse_bool(child, one_arg(child)?)?);
        } else if name == "proxy_set_header" {
            headers
                .get_or_insert_with(Vec::new)
                .push(HeaderOp::parse(child)?);
        } else if LIMIT_NAMES.contains(&name) {
            overrides.apply(child, zones, &mut seen)?;
        } else {
            return Err(invalid(
                child,
                format!("unknown directive \"{}\" in location", child.name),
            ));
        }
    }
    Ok(PendingLocation {
        directive,
        matcher,
        overrides,
        block: block_overrides,
        headers,
        websocket,
    })
}

fn plain_path(directive: &Directive, path: &str) -> Result<String, ConfigError> {
    if !path.starts_with('/') {
        return Err(invalid(
            directive,
            format!("\"location\" path must start with /, got {path}"),
        ));
    }
    Ok(path.to_lowercase())
}

/// One location of a site, with its limits resolved.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct LocationConfig {
    /// How the location matches.
    pub(crate) matcher: Matcher,
    /// The limits that apply to requests this location selects.
    pub(crate) limits: LimitSet,
    /// The block response for requests this location selects.
    pub(crate) block: BlockResponse,
    /// The `proxy_set_header` operations for requests this location selects.
    pub(crate) proxy_headers: Vec<HeaderOp>,
    /// Whether this location tunnels Upgrade requests.
    pub(crate) websocket: bool,
}

/// The distinct locations that the path views select, in the order they are found.
///
/// A view is one reading of the path, see [`crate::prefilter::path_views`]. Limits
/// are applied to every location found, so the reading the upstream uses cannot pick
/// a location with looser limits.
pub(crate) fn select_locations<'a>(
    locations: &'a [LocationConfig],
    views: &[String],
) -> Vec<&'a LocationConfig> {
    let mut selected: Vec<&LocationConfig> = Vec::new();
    for view in views {
        if let Some(location) = select_location(locations, view)
            && !selected.iter().any(|known| std::ptr::eq(*known, location))
        {
            selected.push(location);
        }
    }
    selected
}

/// Chooses the location for a request path, with nginx's precedence.
///
/// `decoded` is the decoded path with case kept. An exact match wins at once.
/// Otherwise the longest prefix is found. A `^~` prefix wins over the regexes.
/// Then the regexes are tried in configuration order, and the first that matches
/// wins. Without a regex match the longest prefix is used.
pub(crate) fn select_location<'a>(
    locations: &'a [LocationConfig],
    decoded: &str,
) -> Option<&'a LocationConfig> {
    let lower = decoded.to_lowercase();
    let mut longest: Option<(&LocationConfig, usize)> = None;
    for location in locations {
        match &location.matcher {
            Matcher::Exact(path) if *path == lower => return Some(location),
            Matcher::Prefix(path) | Matcher::PrefixPriority(path)
                if lower.starts_with(path.as_str()) =>
            {
                let better = longest.is_none_or(|(_, length)| path.len() > length);
                if better {
                    longest = Some((location, path.len()));
                }
            }
            _ => {}
        }
    }
    if let Some((location, _)) = longest
        && matches!(location.matcher, Matcher::PrefixPriority(_))
    {
        return Some(location);
    }
    for location in locations {
        if let Matcher::Regex(pattern) = &location.matcher
            && pattern.regex.is_match(decoded)
        {
            return Some(location);
        }
    }
    longest.map(|(location, _)| location)
}

/// The state of one zone key, shared by the requests that use it.
#[derive(Debug)]
struct Entry {
    /// Recency stamp, the key in the zone's LRU order.
    stamp: u64,
    /// Bucket content in units of 1/1000 request, as of `last`.
    excess: u64,
    /// When `excess` was last accounted.
    last: Instant,
    /// Delayed requests waiting (`limit_req`) or requests in progress (`limit_conn`).
    active: u32,
}

/// A fixed-size digest of a rendered limit key, which names the key's state.
type KeyDigest = u128;

/// The states of a zone, with least-recently-used order.
///
/// The states are keyed by a digest of the rendered key, not by the key text.
/// The key comes from the request, so its length is up to the client; a digest
/// has a fixed size, which keeps the memory of a zone bounded by its declared
/// size whatever the keys are. The digest uses two hashers with random keys
/// chosen when the zone is created, so a client cannot find two keys that share
/// a state.
#[derive(Debug)]
struct Table {
    capacity: usize,
    hashers: (RandomState, RandomState),
    entries: HashMap<KeyDigest, Entry>,
    order: BTreeMap<u64, KeyDigest>,
    clock: u64,
}

/// No state could be created: every state of the zone is in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Exhausted;

impl Table {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            hashers: (RandomState::new(), RandomState::new()),
            entries: HashMap::new(),
            order: BTreeMap::new(),
            clock: 0,
        }
    }

    /// The digest of a rendered key. Two 64-bit hashes with independent random
    /// keys make one 128-bit value, which a client cannot match with another key
    /// in practice.
    fn digest(&self, key: &str) -> KeyDigest {
        let high = u128::from(self.hashers.0.hash_one(key));
        let low = u128::from(self.hashers.1.hash_one(key));
        (high << 64) | low
    }

    /// Returns the state of `key`, creating it, and marks it most recently used.
    fn entry(&mut self, key: KeyDigest, now: Instant) -> Result<&mut Entry, Exhausted> {
        match self.entries.get(&key).map(|entry| entry.stamp) {
            Some(stamp) => {
                self.order.remove(&stamp);
            }
            None => {
                if self.entries.len() >= self.capacity {
                    self.evict()?;
                }
            }
        }
        self.clock = self.clock.saturating_add(1);
        let stamp = self.clock;
        self.order.insert(stamp, key);
        let entry = self.entries.entry(key).or_insert(Entry {
            stamp,
            excess: 0,
            last: now,
            active: 0,
        });
        entry.stamp = stamp;
        Ok(entry)
    }

    /// Removes the least recently used state that is not in use.
    fn evict(&mut self) -> Result<(), Exhausted> {
        let victim = self
            .order
            .iter()
            .find(|(_, key)| {
                self.entries
                    .get(*key)
                    .is_some_and(|entry| entry.active == 0)
            })
            .map(|(stamp, key)| (*stamp, *key));
        let (stamp, key) = victim.ok_or(Exhausted)?;
        self.order.remove(&stamp);
        self.entries.remove(&key);
        Ok(())
    }

    fn remove(&mut self, key: KeyDigest) {
        if let Some(entry) = self.entries.remove(&key) {
            self.order.remove(&entry.stamp);
        }
    }
}

/// A zone defined in the configuration, with its runtime states.
#[derive(Debug)]
pub(crate) struct ZoneStore {
    def: LimitZone,
    /// Drain time of one request, for `limit_req` zones.
    interval_ns: Option<u64>,
    /// The counted state. A reloaded configuration shares it with the zone it replaces.
    table: Arc<std::sync::Mutex<Table>>,
}

impl ZoneStore {
    /// Creates the empty state of `def`.
    pub(crate) fn new(def: LimitZone) -> Self {
        let table = Arc::new(std::sync::Mutex::new(Table::new(def.capacity)));
        Self::with_table(def, table)
    }

    /// Creates the zone `def` on the state of `previous`, which a reload keeps when the
    /// name and size are the same. The definition itself is the new one.
    pub(crate) fn sharing(def: LimitZone, previous: &Self) -> Self {
        Self::with_table(def, Arc::clone(&previous.table))
    }

    fn with_table(def: LimitZone, table: Arc<std::sync::Mutex<Table>>) -> Self {
        let interval_ns = match def.kind {
            ZoneKind::Req { interval_ns } => Some(interval_ns),
            ZoneKind::Conn => None,
        };
        Self {
            def,
            interval_ns,
            table,
        }
    }

    /// The number of states the zone holds, which is its size.
    pub(crate) fn capacity(&self) -> usize {
        self.def.capacity
    }

    /// Accounts one request against a `limit_req` zone.
    ///
    /// The bucket drains by the time since its last accounting. A request is
    /// rejected when the bucket holds more than `burst` requests. Otherwise it
    /// goes into the bucket, and waits when the bucket already holds more than
    /// the `undelayed` requests. In dry run nothing is rejected or waited for,
    /// and the request is accounted as if it passed.
    ///
    /// # Errors
    ///
    /// Returns [`Exhausted`] when the zone has no free state.
    pub(crate) fn admit(
        self: &Arc<Self>,
        key: &str,
        limit: &ReqLimit,
        dry_run: bool,
        now: Instant,
    ) -> Result<Admission, Exhausted> {
        let Some(interval_ns) = self.interval_ns else {
            // Configuration binds `limit_req` only to request-rate zones.
            return Ok(Admission::passed());
        };
        let mut table = lock(&self.table);
        let digest = table.digest(key);
        let entry = table.entry(digest, now)?;
        let elapsed = now.saturating_duration_since(entry.last).as_nanos();
        let drained =
            elapsed.saturating_mul(u128::from(UNITS_PER_REQUEST)) / u128::from(interval_ns);
        let drained = u64::try_from(drained).unwrap_or(u64::MAX);
        let excess = entry.excess.saturating_sub(drained);
        let burst_units = u64::from(limit.burst) * UNITS_PER_REQUEST;
        if excess > burst_units {
            if dry_run {
                entry.excess = excess.saturating_add(UNITS_PER_REQUEST);
                entry.last = now;
                return Ok(Admission {
                    status: ReqStatus::RejectedDryRun,
                    wait: Duration::ZERO,
                    pending: None,
                });
            }
            return Ok(Admission {
                status: ReqStatus::Rejected,
                wait: Duration::ZERO,
                pending: None,
            });
        }
        let undelayed_units = u64::from(limit.undelayed) * UNITS_PER_REQUEST;
        let over = u128::from(excess.saturating_sub(undelayed_units));
        let wait_nanos =
            over.saturating_mul(u128::from(interval_ns)) / u128::from(UNITS_PER_REQUEST);
        let wait = Duration::from_nanos(u64::try_from(wait_nanos).unwrap_or(u64::MAX));
        entry.excess = excess.saturating_add(UNITS_PER_REQUEST);
        entry.last = now;
        if wait.is_zero() {
            return Ok(Admission::passed());
        }
        if dry_run {
            return Ok(Admission {
                status: ReqStatus::DelayedDryRun,
                wait: Duration::ZERO,
                pending: None,
            });
        }
        entry.active = entry.active.saturating_add(1);
        Ok(Admission {
            status: ReqStatus::Delayed,
            wait,
            pending: Some(Pending {
                zone: Arc::clone(self),
                digest,
            }),
        })
    }

    /// Counts one request in progress for a `limit_conn` zone.
    ///
    /// A request beyond `max` is rejected and not counted, unless the zone is in
    /// dry run, where it is counted and reported as rejected in dry run.
    ///
    /// # Errors
    ///
    /// Returns [`Exhausted`] when the zone has no free state.
    pub(crate) fn acquire(
        self: &Arc<Self>,
        key: &str,
        max: u32,
        dry_run: bool,
        now: Instant,
    ) -> Result<ConnAdmission, Exhausted> {
        let mut table = lock(&self.table);
        let digest = table.digest(key);
        let entry = table.entry(digest, now)?;
        let over = entry.active >= max;
        if over && !dry_run {
            if entry.active == 0 {
                table.remove(digest);
            }
            return Ok(ConnAdmission {
                status: ConnStatus::Rejected,
                permit: None,
            });
        }
        entry.active = entry.active.saturating_add(1);
        Ok(ConnAdmission {
            status: if over {
                ConnStatus::RejectedDryRun
            } else {
                ConnStatus::Passed
            },
            permit: Some(ConnPermit {
                zone: Arc::clone(self),
                digest,
            }),
        })
    }

    /// Releases one count of `key`. A `limit_conn` state with no requests left is removed.
    fn release(&self, digest: KeyDigest) {
        let remove_idle = matches!(self.def.kind, ZoneKind::Conn);
        let mut table = lock(&self.table);
        let idle = match table.entries.get_mut(&digest) {
            Some(entry) => {
                entry.active = entry.active.saturating_sub(1);
                entry.active == 0
            }
            None => false,
        };
        if idle && remove_idle {
            table.remove(digest);
        }
    }

    /// Name of the zone, for log lines.
    pub(crate) fn name(&self) -> &str {
        &self.def.name
    }
}

/// Outcome of a `limit_req` check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ReqStatus {
    /// Passed at once.
    Passed,
    /// Passed after a wait.
    Delayed,
    /// Rejected.
    Rejected,
    /// Would have waited, in dry run.
    DelayedDryRun,
    /// Would have been rejected, in dry run.
    RejectedDryRun,
}

impl ReqStatus {
    /// The value of `$limit_req_status`.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Passed => "PASSED",
            Self::Delayed => "DELAYED",
            Self::Rejected => "REJECTED",
            Self::DelayedDryRun => "DELAYED_DRY_RUN",
            Self::RejectedDryRun => "REJECTED_DRY_RUN",
        }
    }
}

/// Outcome of a `limit_conn` check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ConnStatus {
    /// Counted and passed.
    Passed,
    /// Rejected, not counted.
    Rejected,
    /// Would have been rejected, in dry run; counted.
    RejectedDryRun,
}

impl ConnStatus {
    /// The value of `$limit_conn_status`.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Passed => "PASSED",
            Self::Rejected => "REJECTED",
            Self::RejectedDryRun => "REJECTED_DRY_RUN",
        }
    }
}

/// The result of one `limit_req` check.
#[derive(Debug)]
pub(crate) struct Admission {
    /// What happened to the request.
    pub(crate) status: ReqStatus,
    /// How long the request waits before it goes on.
    pub(crate) wait: Duration,
    /// Keeps the state from being evicted while the request waits.
    pending: Option<Pending>,
}

impl Admission {
    fn passed() -> Self {
        Self {
            status: ReqStatus::Passed,
            wait: Duration::ZERO,
            pending: None,
        }
    }
}

/// A delayed request, which holds its state until it is released.
#[derive(Debug)]
pub(crate) struct Pending {
    zone: Arc<ZoneStore>,
    digest: KeyDigest,
}

impl Drop for Pending {
    fn drop(&mut self) {
        self.zone.release(self.digest);
    }
}

/// The result of one `limit_conn` check.
#[derive(Debug)]
pub(crate) struct ConnAdmission {
    /// What happened to the request.
    pub(crate) status: ConnStatus,
    permit: Option<ConnPermit>,
}

/// One request counted in a `limit_conn` zone. Dropping it releases the count.
#[derive(Debug)]
pub(crate) struct ConnPermit {
    zone: Arc<ZoneStore>,
    digest: KeyDigest,
}

impl Drop for ConnPermit {
    fn drop(&mut self) {
        self.zone.release(self.digest);
    }
}

/// The request values a limit key can use.
#[derive(Debug, Clone, Copy)]
pub(crate) struct KeyVars<'a> {
    /// The client address after real-IP selection.
    pub(crate) client_ip: &'a str,
    /// The address of the connection's peer.
    pub(crate) remote_addr: &'a str,
    /// The first host of the matched site, or empty.
    pub(crate) site: &'a str,
    /// The normalized `Host` header.
    pub(crate) host: &'a str,
    /// The request method.
    pub(crate) method: &'a str,
    /// The decoded path, case kept.
    pub(crate) path: &'a str,
    /// The request headers.
    pub(crate) headers: &'a HeaderMap,
}

/// Renders a limit key, or returns `None` when it is empty, which nginx does not count.
pub(crate) fn render_key(parts: &[KeyPart], vars: &KeyVars<'_>) -> Option<String> {
    let mut key = String::new();
    for part in parts {
        match part {
            KeyPart::Literal(text) => key.push_str(text),
            KeyPart::Var(KeyVar::ClientIp) => key.push_str(vars.client_ip),
            KeyPart::Var(KeyVar::RemoteAddr) => key.push_str(vars.remote_addr),
            KeyPart::Var(KeyVar::Site) => key.push_str(vars.site),
            KeyPart::Var(KeyVar::Host) => key.push_str(vars.host),
            KeyPart::Var(KeyVar::Method) => key.push_str(vars.method),
            KeyPart::Var(KeyVar::Path) => key.push_str(vars.path),
            KeyPart::Var(KeyVar::Header(name)) => {
                if let Some(value) = vars.headers.get(name) {
                    key.push_str(&String::from_utf8_lossy(value.as_bytes()));
                }
            }
        }
    }
    (!key.is_empty()).then_some(key)
}

/// A request the limits refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Refusal {
    /// `limit_req` or `limit_conn`, the reason in the access log.
    pub(crate) reason: &'static str,
    /// The status to answer with.
    pub(crate) status: StatusCode,
}

/// What the limits decided for one request.
#[derive(Debug, Default)]
pub(crate) struct Screened {
    /// The worst `limit_req` outcome, when a zone applied.
    pub(crate) req_status: Option<ReqStatus>,
    /// The worst `limit_conn` outcome, when a zone applied.
    pub(crate) conn_status: Option<ConnStatus>,
    /// A rejection that is enforced. The request must not go on.
    pub(crate) refusal: Option<Refusal>,
    /// The status a rejection would have had in dry run or shadow mode.
    pub(crate) would_have: Option<StatusCode>,
}

/// Runs the `limit_req` and `limit_conn` checks of one request.
///
/// `shadow` makes every check a dry run. The `limit_req` checks run first, and
/// the delay of the request is waited for once all of them have passed. The
/// `limit_conn` permits are pushed onto `permits`, which the caller keeps until
/// the response body is done. A refused request keeps no permit.
///
/// `sets` holds the limits of every location the request selects. Each set is
/// checked in turn, so a request cannot escape one location's limits by selecting
/// another, and the longest delay of the sets is waited for once.
pub(crate) async fn screen(
    zones: &[Arc<ZoneStore>],
    sets: &[&LimitSet],
    shadow: bool,
    vars: &KeyVars<'_>,
    permits: &mut Vec<ConnPermit>,
) -> Screened {
    let mut screened = Screened::default();
    let mut wait = Duration::ZERO;
    let mut held: Vec<Pending> = Vec::new();
    for limits in sets {
        let (set_wait, set_held) = screen_req(zones, limits, shadow, vars, &mut screened);
        wait = wait.max(set_wait);
        held.extend(set_held);
        if screened.refusal.is_some() {
            break;
        }
    }
    if screened.refusal.is_none() {
        for limits in sets {
            screen_conn(zones, limits, shadow, vars, permits, &mut screened);
            if screened.refusal.is_some() {
                break;
            }
        }
    }
    if screened.refusal.is_none() && !wait.is_zero() {
        tokio::time::sleep(wait).await;
    }
    // The delayed states stay in use until the wait is over.
    drop(held);
    screened
}

/// The `limit_req` checks. Returns how long the request waits, and the delayed
/// states, which the caller holds until the wait is over.
fn screen_req(
    zones: &[Arc<ZoneStore>],
    limits: &LimitSet,
    shadow: bool,
    vars: &KeyVars<'_>,
    screened: &mut Screened,
) -> (Duration, Vec<Pending>) {
    let now = Instant::now();
    let dry_run = limits.req_dry_run || shadow;
    let mut wait = Duration::ZERO;
    let mut held: Vec<Pending> = Vec::new();
    for limit in &limits.req {
        let Some(zone) = zones.get(limit.zone) else {
            continue;
        };
        let Some(key) = render_key(&zone.def.key, vars) else {
            continue;
        };
        let Ok(admission) = zone.admit(&key, limit, dry_run, now) else {
            // nginx treats an allocation failure like a rejection, with the same status.
            log_exhausted(limits.req_log, zone.name(), vars.client_ip);
            let status = if dry_run {
                ReqStatus::RejectedDryRun
            } else {
                ReqStatus::Rejected
            };
            screened.req_status = Some(worst(screened.req_status, status));
            if dry_run {
                screened.would_have.get_or_insert(limits.req_status);
                continue;
            }
            screened.refusal = Some(Refusal {
                reason: "limit_req",
                status: limits.req_status,
            });
            break;
        };
        let status = admission.status;
        screened.req_status = Some(worst(screened.req_status, status));
        if status != ReqStatus::Passed {
            log_event(limits.req_log, zone.name(), vars.client_ip, status.name());
        }
        match status {
            ReqStatus::Passed | ReqStatus::Delayed | ReqStatus::DelayedDryRun => {}
            ReqStatus::RejectedDryRun => {
                screened.would_have.get_or_insert(limits.req_status);
            }
            ReqStatus::Rejected => {
                screened.refusal = Some(Refusal {
                    reason: "limit_req",
                    status: limits.req_status,
                });
                break;
            }
        }
        wait = wait.max(admission.wait);
        held.extend(admission.pending);
    }
    (wait, held)
}

/// The `limit_conn` checks. Each counted request is pushed onto `permits`.
fn screen_conn(
    zones: &[Arc<ZoneStore>],
    limits: &LimitSet,
    shadow: bool,
    vars: &KeyVars<'_>,
    permits: &mut Vec<ConnPermit>,
    screened: &mut Screened,
) {
    let now = Instant::now();
    let dry_run = limits.conn_dry_run || shadow;
    for limit in &limits.conn {
        let Some(zone) = zones.get(limit.zone) else {
            continue;
        };
        let Some(key) = render_key(&zone.def.key, vars) else {
            continue;
        };
        let Ok(admission) = zone.acquire(&key, limit.max, dry_run, now) else {
            // nginx releases what the request holds and treats it like a rejection.
            log_exhausted(limits.conn_log, zone.name(), vars.client_ip);
            let status = if dry_run {
                ConnStatus::RejectedDryRun
            } else {
                ConnStatus::Rejected
            };
            screened.conn_status = Some(match screened.conn_status {
                Some(previous) => previous.max(status),
                None => status,
            });
            if dry_run {
                screened.would_have.get_or_insert(limits.conn_status);
                continue;
            }
            screened.refusal = Some(Refusal {
                reason: "limit_conn",
                status: limits.conn_status,
            });
            break;
        };
        let status = admission.status;
        screened.conn_status = Some(match screened.conn_status {
            Some(previous) => previous.max(status),
            None => status,
        });
        if status != ConnStatus::Passed {
            log_event(limits.conn_log, zone.name(), vars.client_ip, status.name());
        }
        if let Some(permit) = admission.permit {
            permits.push(permit);
        }
        match status {
            ConnStatus::Passed => {}
            ConnStatus::RejectedDryRun => {
                screened.would_have.get_or_insert(limits.conn_status);
            }
            ConnStatus::Rejected => {
                screened.refusal = Some(Refusal {
                    reason: "limit_conn",
                    status: limits.conn_status,
                });
                break;
            }
        }
    }
}

fn worst(previous: Option<ReqStatus>, status: ReqStatus) -> ReqStatus {
    previous.map_or(status, |previous| previous.max(status))
}

/// Writes a zone-exhaustion event, distinct from an ordinary excess, to the error log.
fn log_exhausted(level: LimitLog, zone: &str, client: &str) {
    match level {
        LimitLog::Error => {
            tracing::error!(zone, client, limit_error = "zone_exhausted", "limit event");
        }
        LimitLog::Warn => {
            tracing::warn!(zone, client, limit_error = "zone_exhausted", "limit event");
        }
        LimitLog::Info | LimitLog::Notice => {
            tracing::info!(zone, client, limit_error = "zone_exhausted", "limit event");
        }
    }
}

/// Writes one limit event to the error log at the configured severity.
fn log_event(level: LimitLog, zone: &str, client: &str, event: &str) {
    match level {
        LimitLog::Error => tracing::error!(zone, client, event, "limit event"),
        LimitLog::Warn => tracing::warn!(zone, client, event, "limit event"),
        LimitLog::Info | LimitLog::Notice => tracing::info!(zone, client, event, "limit event"),
    }
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
    use std::sync::Arc;
    use std::time::Duration;

    use http::{HeaderMap, HeaderValue};
    use proptest::prelude::*;
    use rstest::rstest;
    use tokio::time::Instant;

    use super::*;
    use crate::config::Config;
    use crate::error::ConfigError;

    const DECISION: &str = "decision {\n    backend http;\n    url http://127.0.0.1:9/decide;\n    timeout 150ms;\n    inspect_body 512;\n}\n";

    /// Parses a configuration with `top` at the top level and `site` inside one site.
    fn parse(top: &str, site: &str) -> Result<Config, ConfigError> {
        let text = format!(
            "listen 127.0.0.1:0;\n{top}\n{DECISION}default_status 421;\nsite example.com {{\n    upstream http://127.0.0.1:9;\n    {site}\n}}\n"
        );
        Config::parse_str(&text, "test.conf")
    }

    fn message(result: Result<Config, ConfigError>) -> String {
        match result {
            Ok(_) => String::from("accepted"),
            Err(error) => error.to_string(),
        }
    }

    const ONE: &str = "limit_req_zone $client_ip zone=one:10m rate=1r/s;";
    const TWO: &str = "limit_conn_zone $client_ip zone=two:10m;";

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
    fn the_example_in_the_readme_loads() -> Result<(), ConfigError> {
        let text = format!(
            "listen 127.0.0.1:0;\nlimit_req_zone $client_ip zone=perip:10m rate=10r/s;\nlimit_conn_zone $client_ip zone=conns:10m;\n{DECISION}site example.com {{\n    upstream http://upstream:80;\n\n    location = /wp-login.php {{\n        limit_req zone=perip burst=2 nodelay;\n        limit_req_status 429;\n    }}\n    location /downloads/ {{\n        limit_conn conns 4;\n    }}\n}}\n"
        );
        let config = Config::parse_str(&text, "test.conf")?;
        let site = config.sites.first().ok_or(ConfigError::Invalid {
            file: "test.conf".to_owned(),
            line: 1,
            message: "no site".to_owned(),
        })?;
        assert_eq!(site.locations.len(), 2);
        Ok(())
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

    #[rstest]
    #[case(
        "location /a { deny_path /x; }",
        "unknown directive \"deny_path\" in location"
    )]
    #[case(
        "location /a { limit_req zone=one; limit_req_zone $client_ip zone=x:1m rate=1r/s; }",
        "in location"
    )]
    #[case("location = foo { limit_req_status 429; }", "must start with /")]
    #[case("location ?? /x { limit_req_status 429; }", "modifier must be")]
    #[case("location ~ (unclosed { limit_req_status 429; }", "regex is not valid")]
    #[case("location /a /b { limit_req_status 429; }", "modifier must be")]
    #[case(
        "location /a /b /c { limit_req_status 429; }",
        "takes an optional modifier and one path"
    )]
    #[case(
        "location /a { limit_req_status 429; limit_req_status 418; }",
        "duplicate directive"
    )]
    #[case(
        "location /a { limit_req zone=two; }",
        "was not defined by limit_req_zone"
    )]
    fn invalid_locations_name_the_problem(#[case] block: &str, #[case] expected: &str) {
        let text = message(parse(&format!("{ONE}\n{TWO}"), block));
        assert!(text.contains(expected), "{text}");
        assert!(text.contains("test.conf:"), "{text}");
    }

    #[test]
    fn a_repeated_location_with_the_same_modifier_and_path_is_rejected() {
        let text = message(parse(
            &format!("{ONE}\n{TWO}"),
            "location /a { } location /A { }",
        ));
        assert!(text.contains("duplicate \"location\""), "{text}");
    }

    #[test]
    fn a_repeated_regex_location_is_accepted_as_in_nginx() {
        let text = message(parse(
            &format!("{ONE}\n{TWO}"),
            "location ~ /a { } location ~ /a { }",
        ));
        assert_eq!(text, "accepted");
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
    fn a_key_renders_its_variables_and_an_empty_key_is_not_counted() {
        let mut headers = HeaderMap::new();
        headers.insert("x-tenant", HeaderValue::from_static("acme"));
        let vars = KeyVars {
            client_ip: "203.0.113.7",
            remote_addr: "10.0.0.2",
            site: "example.com",
            host: "example.com",
            method: "POST",
            path: "/wp-login.php",
            headers: &headers,
        };
        let key = |text: &str| -> Option<String> {
            let parts = parse_key_for_test(text);
            render_key(&parts, &vars)
        };
        assert_eq!(key("$client_ip").as_deref(), Some("203.0.113.7"));
        assert_eq!(
            key("$site|$method|$path").as_deref(),
            Some("example.com|POST|/wp-login.php")
        );
        assert_eq!(key("$http_x_tenant").as_deref(), Some("acme"));
        assert_eq!(key("$http_x_missing"), None);
        // Literal text keeps the key non-empty, so the key is counted as "-".
        assert_eq!(key("$http_x_missing-").as_deref(), Some("-"));
    }

    fn parse_key_for_test(text: &str) -> Vec<KeyPart> {
        let config = parse(
            &format!("limit_req_zone \"{text}\" zone=k:1m rate=1r/s;"),
            "",
        );
        config
            .ok()
            .and_then(|config| config.zones.into_iter().next())
            .map(|zone| zone.key)
            .unwrap_or_default()
    }

    #[rstest]
    #[case("/exact", "exact")]
    #[case("/wp-login.php", "regex-php")]
    #[case("/index.PHP", "regex-caseless")]
    #[case("/static/app.js", "priority")]
    #[case("/wp-admin/", "regex-wp")]
    #[case("/about", "root")]
    #[case("/Wp-Login", "prefix-wp")]
    #[case("/EXACT", "exact")]
    fn location_selection_follows_nginx_precedence(
        #[case] path: &str,
        #[case] expected: &str,
    ) -> Result<(), ConfigError> {
        let block = "location = /exact { limit_req_status 415; }\n\
            location / { limit_req_status 410; }\n\
            location /wp- { limit_req_status 411; }\n\
            location ^~ /static/ { limit_req_status 412; }\n\
            location ~ \\.php$ { limit_req_status 413; }\n\
            location ~* \\.PHP$ { limit_req_status 414; }\n\
            location ~ /wp- { limit_req_status 416; }";
        let config = parse(ONE, block)?;
        let site = config.sites.first().ok_or(ConfigError::Invalid {
            file: "test.conf".to_owned(),
            line: 1,
            message: "no site".to_owned(),
        })?;
        let code = match expected {
            "exact" => 415,
            "regex-php" => 413,
            "regex-caseless" => 414,
            "priority" => 412,
            "regex-wp" => 416,
            "root" => 410,
            _ => 411,
        };
        let chosen = select_location(&site.locations, path);
        assert_eq!(
            chosen.map(|l| l.limits.req_status.as_u16()),
            Some(code),
            "{path}"
        );
        Ok(())
    }

    #[test]
    fn a_request_with_no_matching_location_uses_the_site_limits() -> Result<(), ConfigError> {
        let config = parse(ONE, "location /login { limit_req_status 429; }")?;
        let site = config.sites.first().ok_or(ConfigError::Invalid {
            file: "test.conf".to_owned(),
            line: 1,
            message: "no site".to_owned(),
        })?;
        assert!(select_location(&site.locations, "/other").is_none());
        Ok(())
    }

    /// A regex pattern built the way `parse_location` builds one.
    fn regex_pattern(source: &str, caseless: bool) -> Result<Pattern, regex::Error> {
        let compiled = if caseless {
            format!("(?i){source}")
        } else {
            source.to_owned()
        };
        Ok(Pattern {
            source: source.to_owned(),
            caseless,
            regex: regex::Regex::new(&compiled)?,
        })
    }

    #[test]
    fn regex_patterns_compare_by_source_and_operator() -> Result<(), regex::Error> {
        let plain = regex_pattern("a+", false)?;
        assert_eq!(plain, regex_pattern("a+", false)?);
        assert_ne!(plain, regex_pattern("a+", true)?);
        assert_ne!(plain, regex_pattern("b+", false)?);
        Ok(())
    }

    #[test]
    fn a_regex_pattern_displays_its_source_as_written() -> Result<(), regex::Error> {
        let pattern = regex_pattern(r"\.php$", true)?;
        assert_eq!(pattern.to_string(), r"\.php$");
        Ok(())
    }

    #[test]
    fn a_key_digest_uses_both_halves_of_its_128_bits() {
        let table = Table::new(1);
        let high_half_used = (0..16).any(|n| table.digest(&format!("key-{n}")) >> 64 != 0);
        assert!(high_half_used);
    }

    fn store(capacity: usize, interval_ns: u64) -> Arc<ZoneStore> {
        Arc::new(ZoneStore::new(LimitZone {
            name: "z".to_owned(),
            key: vec![KeyPart::Var(KeyVar::ClientIp)],
            capacity,
            kind: ZoneKind::Req { interval_ns },
        }))
    }

    fn conn_store(capacity: usize) -> Arc<ZoneStore> {
        Arc::new(ZoneStore::new(LimitZone {
            name: "c".to_owned(),
            key: vec![KeyPart::Var(KeyVar::ClientIp)],
            capacity,
            kind: ZoneKind::Conn,
        }))
    }

    fn req(burst: u32, undelayed: u32) -> ReqLimit {
        ReqLimit {
            zone: 0,
            burst,
            undelayed,
        }
    }

    /// Admits one request per arrival offset (ms from `base`) and returns each outcome with its wait in ms.
    fn run(
        zone: &Arc<ZoneStore>,
        limit: &ReqLimit,
        dry: bool,
        arrivals: &[u64],
    ) -> Vec<(ReqStatus, u128)> {
        let base = Instant::now();
        let mut held = Vec::new();
        let mut outcomes = Vec::new();
        for ms in arrivals {
            let now = base + Duration::from_millis(*ms);
            let admission = zone.admit("k", limit, dry, now).ok();
            outcomes.push(match admission {
                Some(admission) => {
                    let outcome = (admission.status, admission.wait.as_millis());
                    held.push(admission);
                    outcome
                }
                None => (ReqStatus::Rejected, 0),
            });
        }
        outcomes
    }

    #[rstest]
    // One request per second, no burst: the second immediate request is rejected.
    #[case(1000, 0, 0, &[0, 0, 1000, 1000], &[(ReqStatus::Passed, 0), (ReqStatus::Rejected, 0), (ReqStatus::Passed, 0), (ReqStatus::Rejected, 0)])]
    // Burst 2 with nodelay: three at once pass, the fourth is rejected.
    #[case(1000, 2, 2, &[0, 0, 0, 0], &[(ReqStatus::Passed, 0), (ReqStatus::Passed, 0), (ReqStatus::Passed, 0), (ReqStatus::Rejected, 0)])]
    // Burst 2 without nodelay: the excess requests wait one more second each.
    #[case(1000, 2, 0, &[0, 0, 0, 0], &[(ReqStatus::Passed, 0), (ReqStatus::Delayed, 1000), (ReqStatus::Delayed, 2000), (ReqStatus::Rejected, 0)])]
    // Burst 2 with delay=1: one excess request passes at once, the next waits.
    #[case(1000, 2, 1, &[0, 0, 0, 0], &[(ReqStatus::Passed, 0), (ReqStatus::Passed, 0), (ReqStatus::Delayed, 1000), (ReqStatus::Rejected, 0)])]
    // The bucket drains: after one second a request fits again.
    #[case(1000, 2, 2, &[0, 0, 0, 0, 1000], &[(ReqStatus::Passed, 0), (ReqStatus::Passed, 0), (ReqStatus::Passed, 0), (ReqStatus::Rejected, 0), (ReqStatus::Passed, 0)])]
    // 60 requests per minute is one per second.
    #[case(1000, 0, 0, &[0, 500, 1000], &[(ReqStatus::Passed, 0), (ReqStatus::Rejected, 0), (ReqStatus::Passed, 0)])]
    fn leaky_bucket_follows_nginx(
        #[case] rate: u64,
        #[case] burst: u32,
        #[case] undelayed: u32,
        #[case] arrivals: &[u64],
        #[case] expected: &[(ReqStatus, u128)],
    ) {
        // `rate` is the drain time of one request in milliseconds: 1000 is one request per second.
        let zone = store(100, rate * 1_000_000);
        let outcomes = run(&zone, &req(burst, undelayed), false, arrivals);
        assert_eq!(outcomes, expected);
    }

    #[test]
    fn a_dry_run_accounts_without_rejecting_or_waiting() {
        let zone = store(100, 1_000_000_000);
        let outcomes = run(&zone, &req(0, 0), true, &[0, 0, 0]);
        assert_eq!(
            outcomes,
            vec![
                (ReqStatus::Passed, 0),
                (ReqStatus::RejectedDryRun, 0),
                (ReqStatus::RejectedDryRun, 0),
            ]
        );
        let zone = store(100, 1_000_000_000);
        let outcomes = run(&zone, &req(2, 0), true, &[0, 0, 0, 0]);
        assert_eq!(outcomes.get(1).map(|o| o.0), Some(ReqStatus::DelayedDryRun));
        assert_eq!(outcomes.get(1).map(|o| o.1), Some(0));
    }

    #[test]
    fn a_full_zone_evicts_the_least_recently_used_idle_state() -> Result<(), Exhausted> {
        let zone = store(2, 1_000_000_000);
        let base = Instant::now();
        let limit = req(0, 0);
        let mut keep = Vec::new();
        for key in ["a", "b"] {
            keep.push(
                zone.admit(key, &limit, false, base)
                    .map_err(|_| Exhausted)?,
            );
        }
        // "a" is the least recently used, so the third key takes its state.
        let third = zone
            .admit("c", &limit, false, base)
            .map_err(|_| Exhausted)?;
        assert_eq!(third.status, ReqStatus::Passed);
        // "b" still has its state, so its bucket is full.
        let b_again = zone.admit("b", &limit, false, base);
        assert!(matches!(b_again, Ok(ref a) if a.status == ReqStatus::Rejected));
        // "a" lost its state, so it starts with an empty bucket and passes again.
        let again = zone
            .admit("a", &limit, false, base)
            .map_err(|_| Exhausted)?;
        assert_eq!(again.status, ReqStatus::Passed);
        Ok(())
    }

    #[test]
    fn a_zone_with_only_delayed_states_is_exhausted() {
        let zone = store(1, 1_000_000_000);
        let base = Instant::now();
        let limit = req(1, 0);
        let first = zone.admit("a", &limit, false, base);
        let second = zone.admit("a", &limit, false, base);
        assert!(matches!(first, Ok(ref a) if a.status == ReqStatus::Passed));
        assert!(matches!(second, Ok(ref a) if a.status == ReqStatus::Delayed));
        // The only state is held by a delayed request, so a new key has nowhere to go.
        assert!(zone.admit("b", &limit, false, base).is_err());
        drop(second);
        assert!(zone.admit("b", &limit, false, base).is_ok());
    }

    #[test]
    fn a_connection_limit_counts_requests_until_their_permit_is_dropped() {
        let zone = conn_store(10);
        let now = Instant::now();
        let first = zone.acquire("k", 1, false, now).ok();
        let second = zone.acquire("k", 1, false, now).ok();
        assert_eq!(first.as_ref().map(|a| a.status), Some(ConnStatus::Passed));
        assert_eq!(
            second.as_ref().map(|a| a.status),
            Some(ConnStatus::Rejected)
        );
        assert!(second.is_some_and(|a| a.permit.is_none()));
        let kept = zone.acquire("k", 1, false, now).ok();
        assert_eq!(kept.as_ref().map(|a| a.status), Some(ConnStatus::Rejected));
        drop(first);
        let third = zone.acquire("k", 1, false, now).ok();
        assert_eq!(third.map(|a| a.status), Some(ConnStatus::Passed));
    }

    /// Everything the process-wide error log test subscriber has written.
    static CAPTURED: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());

    /// Serializes the tests that read `CAPTURED`, so each reads only its own lines.
    static CAPTURE_TURN: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[derive(Clone, Copy)]
    struct CaptureWriter;

    impl std::io::Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            CAPTURED
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Runs `f` with the error log's formatting on and returns the lines it wrote
    /// that contain `marker`. Each test uses a marker unique to itself, since other
    /// tests may log at the same time.
    fn log_lines_for(marker: &str, f: impl FnOnce()) -> Vec<String> {
        static INSTALL: std::sync::Once = std::sync::Once::new();
        INSTALL.call_once(|| {
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_ansi(false)
                .without_time()
                .with_writer(|| CaptureWriter)
                .finish();
            let _ = tracing::subscriber::set_global_default(subscriber);
        });
        let _turn = CAPTURE_TURN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = CAPTURED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len();
        f();
        let bytes = CAPTURED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        String::from_utf8_lossy(bytes.get(before..).unwrap_or_default())
            .lines()
            .filter(|line| line.contains(marker))
            .map(str::to_owned)
            .collect()
    }

    fn named_store(name: &str, capacity: usize, interval_ns: u64) -> Arc<ZoneStore> {
        Arc::new(ZoneStore::new(LimitZone {
            name: name.to_owned(),
            key: vec![KeyPart::Var(KeyVar::ClientIp)],
            capacity,
            kind: ZoneKind::Req { interval_ns },
        }))
    }

    fn named_conn_store(name: &str, capacity: usize) -> Arc<ZoneStore> {
        Arc::new(ZoneStore::new(LimitZone {
            name: name.to_owned(),
            key: vec![KeyPart::Var(KeyVar::ClientIp)],
            capacity,
            kind: ZoneKind::Conn,
        }))
    }

    /// Runs `screen` for one request on a fresh current-thread runtime.
    fn screen_now(
        zones: &[Arc<ZoneStore>],
        set: &LimitSet,
        vars: &KeyVars<'_>,
        permits: &mut Vec<ConnPermit>,
    ) -> Option<Screened> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .ok()?;
        Some(runtime.block_on(screen(zones, &[set], false, vars, permits)))
    }

    #[rstest]
    #[case(LimitLog::Info, "INFO")]
    #[case(LimitLog::Notice, "INFO")]
    #[case(LimitLog::Warn, "WARN")]
    #[case(LimitLog::Error, "ERROR")]
    fn a_limit_event_is_written_at_the_configured_severity(
        #[case] level: LimitLog,
        #[case] severity: &str,
    ) {
        let zone = format!("sev-{level:?}");
        let lines = log_lines_for(&zone, || {
            log_event(level, &zone, "203.0.113.7", "REJECTED");
        });
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines.first().is_some_and(|line| line.contains(severity)),
            "{lines:?}"
        );
        assert!(
            lines
                .first()
                .is_some_and(|line| line.contains("event=\"REJECTED\"")),
            "{lines:?}"
        );
    }

    #[rstest]
    #[case(LimitLog::Info, "INFO")]
    #[case(LimitLog::Notice, "INFO")]
    #[case(LimitLog::Warn, "WARN")]
    #[case(LimitLog::Error, "ERROR")]
    fn a_zone_exhaustion_is_written_at_the_configured_severity(
        #[case] level: LimitLog,
        #[case] severity: &str,
    ) {
        let zone = format!("exh-{level:?}");
        let lines = log_lines_for(&zone, || {
            log_exhausted(level, &zone, "203.0.113.7");
        });
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines.first().is_some_and(|line| line.contains(severity)),
            "{lines:?}"
        );
        assert!(
            lines
                .first()
                .is_some_and(|line| line.contains("limit_error=\"zone_exhausted\"")),
            "{lines:?}"
        );
    }

    #[rstest]
    #[case("info", "INFO")]
    #[case("notice", "INFO")]
    #[case("warn", "WARN")]
    #[case("error", "ERROR")]
    fn a_limit_log_level_word_sets_the_severity_of_limit_events(
        #[case] word: &str,
        #[case] severity: &str,
    ) -> Result<(), ConfigError> {
        let config = parse(&format!("{ONE}\n{TWO}\nlimit_req_log_level {word};"), "")?;
        let level = config.limits.req_log;
        let zone = format!("word-{word}");
        let lines = log_lines_for(&zone, || {
            log_event(level, &zone, "203.0.113.7", "REJECTED");
        });
        assert!(
            lines.first().is_some_and(|line| line.contains(severity)),
            "{lines:?}"
        );
        Ok(())
    }

    #[test]
    fn a_request_that_passes_the_limits_writes_nothing_to_the_error_log() {
        let zones = vec![named_store("pass-quiet", 100, 1_000_000_000)];
        let set = LimitSet {
            req: vec![req(5, 5)],
            ..LimitSet::default()
        };
        let headers = HeaderMap::new();
        let vars = vars_for("203.0.113.7", &headers);
        let mut permits = Vec::new();
        let mut refusal = None;
        let lines = log_lines_for("pass-quiet", || {
            refusal = screen_now(&zones, &set, &vars, &mut permits).and_then(|s| s.refusal);
        });
        assert_eq!(refusal, None);
        assert!(lines.is_empty(), "{lines:?}");
    }

    #[test]
    fn a_rejected_request_writes_one_limit_event_naming_its_zone() {
        let zones = vec![named_store("reject-once", 100, 1_000_000_000)];
        let set = LimitSet {
            req: vec![req(0, 0)],
            ..LimitSet::default()
        };
        let headers = HeaderMap::new();
        let vars = vars_for("203.0.113.7", &headers);
        let mut permits = Vec::new();
        let mut second_refusal = None;
        let lines = log_lines_for("reject-once", || {
            let _ = screen_now(&zones, &set, &vars, &mut permits);
            second_refusal = screen_now(&zones, &set, &vars, &mut permits).and_then(|s| s.refusal);
        });
        assert_eq!(second_refusal.map(|r| r.reason), Some("limit_req"));
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines.first().is_some_and(|line| line.contains("ERROR")),
            "{lines:?}"
        );
        assert!(
            lines
                .first()
                .is_some_and(|line| line.contains("event=\"REJECTED\"")),
            "{lines:?}"
        );
    }

    #[test]
    fn a_connection_limit_writes_an_event_only_when_it_rejects() {
        let zones = vec![named_conn_store("conn-once", 100)];
        let set = LimitSet {
            conn: vec![ConnLimit { zone: 0, max: 1 }],
            ..LimitSet::default()
        };
        let headers = HeaderMap::new();
        let vars = vars_for("203.0.113.7", &headers);
        let mut permits = Vec::new();
        let lines = log_lines_for("conn-once", || {
            screen_now(&zones, &set, &vars, &mut permits);
            screen_now(&zones, &set, &vars, &mut permits);
        });
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines
                .first()
                .is_some_and(|line| line.contains("event=\"REJECTED\"")),
            "{lines:?}"
        );
    }

    #[test]
    fn an_exhausted_zone_writes_a_zone_exhausted_event_naming_its_zone() {
        // One state, held by a delayed request, so the second client finds no state to evict.
        let zone = named_store("exhaust-zone", 1, 1_000_000_000);
        let now = Instant::now();
        let first = zone.admit("a", &req(1, 0), false, now).ok();
        let held = zone.admit("a", &req(1, 0), false, now).ok();
        assert!(first.is_some());
        assert!(
            held.as_ref()
                .is_some_and(|admission| admission.status == ReqStatus::Delayed)
        );
        let zones = vec![zone];
        let set = LimitSet {
            req: vec![req(1, 0)],
            ..LimitSet::default()
        };
        let headers = HeaderMap::new();
        let vars = vars_for("198.51.100.9", &headers);
        let mut permits = Vec::new();
        let mut refusal = None;
        let lines = log_lines_for("exhaust-zone", || {
            refusal = screen_now(&zones, &set, &vars, &mut permits).and_then(|s| s.refusal);
        });
        assert!(refusal.is_some());
        assert!(
            lines
                .first()
                .is_some_and(|line| line.contains("limit_error=\"zone_exhausted\"")),
            "{lines:?}"
        );
    }

    #[test]
    fn a_connection_count_is_kept_while_another_request_of_its_key_is_in_progress() {
        let zone = conn_store(10);
        let now = Instant::now();
        let first = zone.acquire("k", 2, false, now).ok();
        let second = zone.acquire("k", 2, false, now).ok();
        assert_eq!(second.as_ref().map(|a| a.status), Some(ConnStatus::Passed));
        drop(first);
        // One request is still in progress, so one more fits and then the limit holds.
        let third = zone.acquire("k", 2, false, now).ok();
        assert_eq!(third.as_ref().map(|a| a.status), Some(ConnStatus::Passed));
        let fourth = zone.acquire("k", 2, false, now).ok();
        assert_eq!(fourth.map(|a| a.status), Some(ConnStatus::Rejected));
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

    #[rstest]
    #[case("$client_ip", "203.0.113.7")]
    #[case("$remote_addr", "10.0.0.2")]
    #[case("$site", "example.com")]
    #[case("$host", "www.example.com")]
    #[case("$method", "POST")]
    #[case("$path", "/login")]
    fn each_limit_key_variable_renders_its_own_request_value(
        #[case] text: &str,
        #[case] value: &str,
    ) {
        let headers = HeaderMap::new();
        let vars = KeyVars {
            client_ip: "203.0.113.7",
            remote_addr: "10.0.0.2",
            site: "example.com",
            host: "www.example.com",
            method: "POST",
            path: "/login",
            headers: &headers,
        };
        let parts = parse_key_for_test(text);
        assert_eq!(render_key(&parts, &vars).as_deref(), Some(value));
    }

    #[test]
    fn zone_memory_does_not_grow_with_key_length() {
        // Two states of a zone of two, with keys of 8,000 bytes each.
        let zone = store(2, 1_000_000_000);
        let now = Instant::now();
        let limit = req(5, 5);
        let long_a = "a".repeat(8_000);
        let long_b = "b".repeat(8_000);
        let long_c = "c".repeat(8_000);
        for key in [&long_a, &long_b] {
            let status = zone.admit(key, &limit, false, now).ok().map(|a| a.status);
            assert_eq!(status, Some(ReqStatus::Passed));
        }
        {
            let table = lock(&zone.table);
            // Each state is ordered by a fixed-size digest, not by the key text.
            let digests: Vec<KeyDigest> = table.order.values().copied().collect();
            assert_eq!(digests.len(), 2);
            assert!(digests.contains(&table.digest(&long_a)));
            assert!(digests.contains(&table.digest(&long_b)));
        }
        // A third long key evicts the least recently used state; the zone stays at two.
        let status = zone
            .admit(&long_c, &limit, false, now)
            .ok()
            .map(|a| a.status);
        assert_eq!(status, Some(ReqStatus::Passed));
        let table = lock(&zone.table);
        assert_eq!(table.entries.len(), 2);
        assert!(!table.entries.contains_key(&table.digest(&long_a)));
        assert!(table.entries.contains_key(&table.digest(&long_c)));
    }

    #[test]
    fn distinct_keys_keep_distinct_states_with_digests() {
        let zone = store(10, 1_000_000_000);
        let now = Instant::now();
        // Burst and undelayed are zero: a second request in the same instant is rejected.
        let limit = req(0, 0);
        let long = "x".repeat(8_000);
        let near = format!("{}y", "x".repeat(7_999));
        let keys = [
            "k1",
            "k2",
            "k1",
            long.as_str(),
            near.as_str(),
            long.as_str(),
        ];
        let mut statuses = Vec::new();
        for key in keys {
            statuses.push(zone.admit(key, &limit, false, now).ok().map(|a| a.status));
        }
        assert_eq!(
            statuses,
            vec![
                Some(ReqStatus::Passed),
                Some(ReqStatus::Passed),
                Some(ReqStatus::Rejected),
                Some(ReqStatus::Passed),
                Some(ReqStatus::Passed),
                Some(ReqStatus::Rejected),
            ]
        );
    }

    #[test]
    fn an_idle_connection_state_is_removed_and_a_dry_run_still_counts() {
        let zone = conn_store(10);
        let now = Instant::now();
        let first = zone.acquire("k", 1, false, now).ok();
        let over = zone.acquire("k", 1, true, now).ok();
        assert_eq!(
            over.as_ref().map(|a| a.status),
            Some(ConnStatus::RejectedDryRun)
        );
        drop(over);
        drop(first);
        let table_len = lock(&zone.table).entries.len();
        assert_eq!(table_len, 0);
    }

    #[test]
    fn a_connection_zone_full_of_requests_in_progress_is_exhausted() {
        let zone = conn_store(1);
        let now = Instant::now();
        let held = zone.acquire("a", 5, false, now).ok();
        assert!(held.is_some());
        assert!(zone.acquire("b", 5, false, now).is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn a_refused_request_keeps_no_connection_count() {
        let zones = vec![store(10, 1_000_000_000), conn_store(10)];
        let limits = LimitSet {
            req: vec![req(0, 0)],
            conn: vec![ConnLimit { zone: 1, max: 5 }],
            ..LimitSet::default()
        };
        let headers = HeaderMap::new();
        let vars = KeyVars {
            client_ip: "203.0.113.7",
            remote_addr: "10.0.0.2",
            site: "example.com",
            host: "example.com",
            method: "GET",
            path: "/",
            headers: &headers,
        };
        let mut permits = Vec::new();
        let first = screen(&zones, &[&limits], false, &vars, &mut permits).await;
        assert!(first.refusal.is_none());
        let second = screen(&zones, &[&limits], false, &vars, &mut permits).await;
        assert_eq!(second.refusal.map(|r| r.reason), Some("limit_req"));
        assert_eq!(second.req_status, Some(ReqStatus::Rejected));
        assert_eq!(permits.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_delayed_request_waits_and_a_shadow_request_is_not_delayed() {
        let zones = vec![store(10, 1_000_000_000)];
        let limits = LimitSet {
            req: vec![req(2, 0)],
            ..LimitSet::default()
        };
        let headers = HeaderMap::new();
        let vars = KeyVars {
            client_ip: "203.0.113.7",
            remote_addr: "10.0.0.2",
            site: "example.com",
            host: "example.com",
            method: "GET",
            path: "/",
            headers: &headers,
        };
        let mut permits = Vec::new();
        let _first = screen(&zones, &[&limits], false, &vars, &mut permits).await;
        let started = Instant::now();
        let second = screen(&zones, &[&limits], false, &vars, &mut permits).await;
        assert_eq!(second.req_status, Some(ReqStatus::Delayed));
        assert_eq!(started.elapsed(), Duration::from_secs(1));
        let shadow = screen(&zones, &[&limits], true, &vars, &mut permits).await;
        assert_eq!(shadow.req_status, Some(ReqStatus::DelayedDryRun));
        assert!(shadow.refusal.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn a_key_that_is_empty_is_not_counted_at_all() {
        let zones = vec![store(10, 1_000_000_000)];
        let limits = LimitSet {
            req: vec![ReqLimit {
                zone: 0,
                burst: 0,
                undelayed: 0,
            }],
            ..LimitSet::default()
        };
        let headers = HeaderMap::new();
        let zone = Arc::new(ZoneStore::new(LimitZone {
            name: "h".to_owned(),
            key: vec![KeyPart::Var(KeyVar::Header(HeaderName::from_static(
                "x-missing",
            )))],
            capacity: 10,
            kind: ZoneKind::Req {
                interval_ns: 1_000_000_000,
            },
        }));
        let vars = KeyVars {
            client_ip: "203.0.113.7",
            remote_addr: "10.0.0.2",
            site: "",
            host: "",
            method: "GET",
            path: "/",
            headers: &headers,
        };
        let mut permits = Vec::new();
        let zones_with_header = vec![zone];
        for _ in 0..3 {
            let screened = screen(&zones_with_header, &[&limits], false, &vars, &mut permits).await;
            assert!(screened.req_status.is_none());
            assert!(screened.refusal.is_none());
        }
        let _ = zones;
    }

    #[test]
    fn a_limited_request_gets_its_status_and_the_refusal_names_its_limit() {
        let refusal = Refusal {
            reason: "limit_req",
            status: StatusCode::TOO_MANY_REQUESTS,
        };
        assert_eq!(refusal.status.as_u16(), 429);
        assert_eq!(ReqStatus::RejectedDryRun.name(), "REJECTED_DRY_RUN");
        assert_eq!(ConnStatus::RejectedDryRun.name(), "REJECTED_DRY_RUN");
    }

    fn vars_for<'a>(client: &'a str, headers: &'a HeaderMap) -> KeyVars<'a> {
        KeyVars {
            client_ip: client,
            remote_addr: "10.0.0.2",
            site: "example.com",
            host: "example.com",
            method: "GET",
            path: "/",
            headers,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_exhausted_req_zone_answers_with_the_configured_status() {
        let zones = vec![store(1, 1_000_000_000)];
        let limit = req(1, 0);
        let limits = LimitSet {
            req: vec![limit.clone()],
            req_status: StatusCode::TOO_MANY_REQUESTS,
            ..LimitSet::default()
        };
        // One delayed request holds the only state of the zone.
        let now = Instant::now();
        let _first = zones
            .first()
            .map(|zone| zone.admit("held", &limit, false, now));
        let _holder = zones
            .first()
            .map(|zone| zone.admit("held", &limit, false, now));
        let headers = HeaderMap::new();
        let mut permits = Vec::new();
        let screened = screen(
            &zones,
            &[&limits],
            false,
            &vars_for("other", &headers),
            &mut permits,
        )
        .await;
        assert_eq!(screened.req_status, Some(ReqStatus::Rejected));
        assert_eq!(
            screened.refusal,
            Some(Refusal {
                reason: "limit_req",
                status: StatusCode::TOO_MANY_REQUESTS,
            })
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_exhausted_req_zone_in_dry_run_lets_the_request_through() {
        let zones = vec![store(1, 1_000_000_000)];
        let limit = req(1, 0);
        let limits = LimitSet {
            req: vec![limit.clone()],
            req_status: StatusCode::TOO_MANY_REQUESTS,
            req_dry_run: true,
            ..LimitSet::default()
        };
        let now = Instant::now();
        let _first = zones
            .first()
            .map(|zone| zone.admit("held", &limit, false, now));
        let _holder = zones
            .first()
            .map(|zone| zone.admit("held", &limit, false, now));
        let headers = HeaderMap::new();
        let mut permits = Vec::new();
        let screened = screen(
            &zones,
            &[&limits],
            false,
            &vars_for("other", &headers),
            &mut permits,
        )
        .await;
        assert_eq!(screened.req_status, Some(ReqStatus::RejectedDryRun));
        assert!(screened.refusal.is_none());
        assert_eq!(screened.would_have, Some(StatusCode::TOO_MANY_REQUESTS));
    }

    #[tokio::test(start_paused = true)]
    async fn an_exhausted_conn_zone_answers_with_the_configured_status_and_keeps_no_count() {
        let zones = vec![conn_store(1)];
        let limits = LimitSet {
            conn: vec![ConnLimit { zone: 0, max: 5 }],
            conn_status: StatusCode::TOO_MANY_REQUESTS,
            ..LimitSet::default()
        };
        let now = Instant::now();
        let _holder = zones
            .first()
            .map(|zone| zone.acquire("held", 5, false, now));
        let headers = HeaderMap::new();
        let mut permits = Vec::new();
        let screened = screen(
            &zones,
            &[&limits],
            false,
            &vars_for("other", &headers),
            &mut permits,
        )
        .await;
        assert_eq!(screened.conn_status, Some(ConnStatus::Rejected));
        assert_eq!(
            screened.refusal,
            Some(Refusal {
                reason: "limit_conn",
                status: StatusCode::TOO_MANY_REQUESTS,
            })
        );
        assert!(permits.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn an_exhausted_conn_zone_in_dry_run_lets_the_request_through() {
        let zones = vec![conn_store(1)];
        let limits = LimitSet {
            conn: vec![ConnLimit { zone: 0, max: 5 }],
            conn_status: StatusCode::TOO_MANY_REQUESTS,
            conn_dry_run: true,
            ..LimitSet::default()
        };
        let now = Instant::now();
        let _holder = zones
            .first()
            .map(|zone| zone.acquire("held", 5, false, now));
        let headers = HeaderMap::new();
        let mut permits = Vec::new();
        let screened = screen(
            &zones,
            &[&limits],
            false,
            &vars_for("other", &headers),
            &mut permits,
        )
        .await;
        assert_eq!(screened.conn_status, Some(ConnStatus::RejectedDryRun));
        assert!(screened.refusal.is_none());
        assert_eq!(screened.would_have, Some(StatusCode::TOO_MANY_REQUESTS));
    }

    proptest! {
        /// Over any window of release times, a bucket with rate R and burst B admits
        /// at most R times the window plus B + 1 requests. The extra one is the
        /// request that finds an empty bucket, as nginx admits it.
        #[test]
        fn the_bucket_never_admits_more_than_rate_times_time_plus_burst(
            interval_ms in 1_u64..=2000,
            burst in 0_u32..=5,
            undelayed_seed in 0_u32..=5,
            gaps in proptest::collection::vec(0_u64..=1500, 1..60),
        ) {
            let undelayed = undelayed_seed.min(burst);
            let interval_ns = interval_ms * 1_000_000;
            let zone = store(10_000, interval_ns);
            let limit = req(burst, undelayed);
            let base = Instant::now();
            let mut at = 0_u64;
            let mut releases: Vec<u128> = Vec::new();
            let mut held = Vec::new();
            for gap in gaps {
                at += gap;
                let now = base + Duration::from_millis(at);
                let Ok(admission) = zone.admit("k", &limit, false, now) else {
                    continue;
                };
                if admission.status == ReqStatus::Rejected {
                    continue;
                }
                releases.push(now.duration_since(base).as_nanos() + admission.wait.as_nanos());
                held.push(admission);
            }
            releases.sort_unstable();
            let interval = u128::from(interval_ns);
            for (i, start) in releases.iter().enumerate() {
                for (j, end) in releases.iter().enumerate().skip(i) {
                    let count = u128::try_from(j - i + 1).unwrap_or(u128::MAX);
                    let span = end - start;
                    // count <= span / interval + burst + 1, multiplied through by interval.
                    let allowed = span + (u128::from(burst) + 1) * interval;
                    prop_assert!(count * interval <= allowed, "count {count} span {span}");
                }
            }
        }
    }
}
