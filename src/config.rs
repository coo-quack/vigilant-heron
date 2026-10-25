//! Building the configuration from the directive tree.
//!
//! The tree is read in two passes. The first collects `log_format` so that the
//! second can resolve `access_log` formats and check `$http_*` variables against
//! the header names the decision block redacts. Every error names the file and
//! line of the directive that caused it.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use http::{HeaderName, HeaderValue, StatusCode, Uri};

use crate::access::AccessEntry;
use crate::accesslog::{Escape, LogFormat};
use crate::block::{BLOCK_NAMES, BlockOverrides, BlockResponse};
use crate::conf::{self, Directive};
use crate::error::ConfigError;
use crate::limits::{self, LimitOverrides, LimitSet, LimitZone, LocationConfig};
use crate::logsink::Destination;
use crate::proxy::HeaderOp;
use crate::realip::{IpNet, RealIp};
use crate::router::HostPattern;
use crate::rules::{self, ParsedRule, Rule, Scope, SiteRules};
use crate::system_one::{ApiToken, ClefModel};

/// Default HTTP status for hosts that match no site.
const DEFAULT_STATUS: u16 = 421;
/// Default connection cap.
const DEFAULT_MAX_CONNECTIONS: usize = 1024;
/// Default number of concurrent decision-backend calls.
const DEFAULT_MAX_CONCURRENCY: usize = 64;
/// Default decision timeout.
const DEFAULT_TIMEOUT: Duration = Duration::from_millis(300);
/// Default block threshold for a site.
const DEFAULT_BLOCK_THRESHOLD: f64 = 0.87;
/// Default AI-instruction threshold for a site.
const DEFAULT_INSTRUCTION_THRESHOLD: f64 = 0.8;
/// Default inspected body size.
const DEFAULT_INSPECT_BODY: usize = 8 * 1024;
/// Default `client_header_timeout`.
const DEFAULT_CLIENT_HEADER_TIMEOUT: Duration = Duration::from_secs(60);
/// Default `client_body_timeout`.
const DEFAULT_CLIENT_BODY_TIMEOUT: Duration = Duration::from_secs(60);
/// Default `send_timeout`.
const DEFAULT_SEND_TIMEOUT: Duration = Duration::from_secs(60);
/// Default `keepalive_timeout`.
const DEFAULT_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(75);
/// Default `keepalive_requests`.
const DEFAULT_KEEPALIVE_REQUESTS: usize = 1000;
/// Default `lingering_time`.
const DEFAULT_LINGERING_TIME: Duration = Duration::from_secs(30);
/// Default `lingering_timeout`.
const DEFAULT_LINGERING_TIMEOUT: Duration = Duration::from_secs(5);
/// Default `large_client_header_buffers` count.
const DEFAULT_HEADER_BUFFER_COUNT: usize = 4;
/// Default `large_client_header_buffers` size.
const DEFAULT_HEADER_BUFFER_SIZE: usize = 8 * 1024;
/// Default `client_max_body_size`.
const DEFAULT_CLIENT_MAX_BODY: usize = 1024 * 1024;
/// Default `proxy_connect_timeout`.
const DEFAULT_PROXY_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
/// Default `proxy_read_timeout`.
const DEFAULT_PROXY_READ_TIMEOUT: Duration = Duration::from_secs(60);
/// Default `proxy_send_timeout`.
const DEFAULT_PROXY_SEND_TIMEOUT: Duration = Duration::from_secs(60);
/// The Jev endpoint used when `url` is omitted.
const JEV_URL: &str = "https://api.typesafe.ai/v1/systemone";
/// The Jev model used when `model` is omitted.
const JEV_MODEL: &str = "jev-latest";
/// The variable read for the Jev token when `api_token_env` is omitted.
const JEV_TOKEN_ENV: &str = "TYPESAFE_API_KEY";
/// Longest request id that is logged; longer values are cut.
pub(crate) const MAX_REQUEST_ID_BYTES: usize = 128;
/// File extensions that skip the backend when `static_extensions` is not given.
const DEFAULT_STATIC_EXTENSIONS: [&str; 13] = [
    "css", "js", "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "woff", "woff2", "ttf", "map",
];

/// Every directive name the top level accepts. The parser rejects any other name,
/// and `docs/configuration.md` must document each one (checked by `tests/docs.rs`).
pub const TOP_LEVEL_DIRECTIVES: &[&str] = &[
    "listen",
    "worker_threads",
    "worker_shutdown_timeout",
    "max_connections",
    "default_status",
    "request_id_header",
    "real_ip_from",
    "real_ip_header",
    "real_ip_recursive",
    "decision",
    "client_header_timeout",
    "keepalive_timeout",
    "keepalive_requests",
    "send_timeout",
    "large_client_header_buffers",
    "lingering_close",
    "lingering_time",
    "lingering_timeout",
    "client_body_timeout",
    "client_max_body_size",
    "proxy_connect_timeout",
    "proxy_read_timeout",
    "proxy_send_timeout",
    "max_body",
    "allow",
    "deny",
    "proxy_set_header",
    "block_status",
    "block_page",
    "builtin_rules",
    "disable_rule",
    "rule",
    "site",
    "error_log",
    "access_log",
    "log_format",
    "include",
    "limit_req_zone",
    "limit_conn_zone",
    "limit_req",
    "limit_conn",
    "limit_req_status",
    "limit_conn_status",
    "limit_req_dry_run",
    "limit_conn_dry_run",
    "limit_req_log_level",
    "limit_conn_log_level",
];

/// Every directive name a `site` block accepts, besides the ones it shares with the top level.
pub const SITE_DIRECTIVES: &[&str] = &[
    "upstream",
    "mode",
    "action",
    "block_threshold",
    "instruction_threshold",
    "on_rate_limit",
    "on_decision_error",
    "deny_path",
    "fail_closed_path",
    "static_extensions",
    "debug_headers",
    "access_log",
    "allow",
    "deny",
    "builtin_rules",
    "disable_rule",
    "rule",
    "proxy_websocket",
    "proxy_set_header",
    "location",
    "default_server",
    "block_status",
    "block_page",
    "client_body_timeout",
    "client_max_body_size",
    "proxy_connect_timeout",
    "proxy_read_timeout",
    "proxy_send_timeout",
    "limit_req",
    "limit_conn",
    "limit_req_status",
    "limit_conn_status",
    "limit_req_dry_run",
    "limit_conn_dry_run",
    "limit_req_log_level",
    "limit_conn_log_level",
    "limit_req_zone",
    "limit_conn_zone",
    "client_header_timeout",
    "keepalive_timeout",
    "keepalive_requests",
    "send_timeout",
    "large_client_header_buffers",
    "lingering_close",
    "lingering_time",
    "lingering_timeout",
];

/// Every directive name a `decision` block accepts.
pub const DECISION_DIRECTIVES: &[&str] = &[
    "backend",
    "url",
    "model",
    "api_token_env",
    "timeout",
    "queue_timeout",
    "max_concurrency",
    "inspect_body",
    "max_body",
    "redact_header",
];

/// Validated configuration for the whole proxy.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    /// Socket address the binary binds, such as `0.0.0.0:8080`.
    pub listen: String,
    /// Runtime worker threads. `None` means one per CPU core (tokio's default).
    pub worker_threads: Option<usize>,
    /// Most connections served at the same time.
    pub max_connections: usize,
    /// How long a shutdown waits for open connections and WebSocket tunnels before
    /// closing them. `None` waits for them indefinitely, as nginx does by default.
    pub worker_shutdown_timeout: Option<Duration>,
    /// Header whose value is logged as `$request_id`. It is not sent to the decision backend.
    pub request_id_header: Option<HeaderName>,
    /// How the client address is chosen.
    pub realip: RealIp,
    /// Timers and header limits of client connections.
    pub connection: ConnectionConfig,
    /// Status returned for hosts that match no site.
    pub default_status: StatusCode,
    /// Settings for the decision backend.
    pub decision: DecisionConfig,
    /// Sites, in the order they were declared.
    pub sites: Vec<SiteConfig>,
    /// Access logs of every site that does not name its own.
    pub access_logs: Vec<AccessLogConfig>,
    /// Where operational messages go.
    pub error_log: ErrorLogConfig,
    /// The top-level access list, used for every site that has none of its own.
    pub access: Vec<AccessEntry>,
    /// The `limit_req_zone` and `limit_conn_zone` zones, in definition order.
    pub(crate) zones: Vec<LimitZone>,
    /// The limits of the top level, inherited by every site.
    pub(crate) limits: LimitSet,
}

/// Settings for the decision backend and the body it receives.
#[derive(Debug, Clone, PartialEq)]
pub struct DecisionConfig {
    /// Absolute `http://` or `https://` URI the decision request is posted to.
    pub url: Uri,
    /// Protocol spoken to the decision backend.
    pub backend: BackendConfig,
    /// Time allowed for the whole decision exchange, after any queueing.
    pub timeout: Duration,
    /// Longest wait for a free slot. Zero means no queueing.
    pub queue_timeout: Duration,
    /// Most decision-backend calls in flight at the same time.
    pub max_concurrency: usize,
    /// Bytes of the request body that are sent to the backend.
    pub inspect_body_bytes: usize,
    /// Extra header names to drop before sending, lowercased.
    pub redact_headers: Vec<String>,
}

/// Timers and header limits of client connections, set at the top level only.
///
/// They apply before the request's `Host` selects a site, so no site can
/// override them. The directive names follow nginx.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionConfig {
    /// Time allowed to receive a whole request header, counted from the first
    /// byte of a request. Also bounds the first request of a connection.
    pub client_header_timeout: Duration,
    /// Idle time allowed between requests on a keep-alive connection. Zero
    /// disables keep-alive: every connection serves one request.
    pub keepalive_timeout: Duration,
    /// Requests served on one connection. The last one answers `Connection: close`.
    pub keepalive_requests: usize,
    /// Longest wait between two successive writes to the client.
    pub send_timeout: Duration,
    /// Size limits of the request line and header fields.
    pub large_header_buffers: HeaderBuffers,
    /// When a connection lingers after its response, reading and discarding the
    /// client's data, before it closes.
    pub lingering_close: LingeringClose,
    /// Longest total time one lingering close may take.
    pub lingering_time: Duration,
    /// Longest silence, with no client data, that one lingering close waits for.
    pub lingering_timeout: Duration,
}

/// When a connection lingers before it closes (`lingering_close`).
///
/// Lingering half-closes the connection after the response is written, then
/// reads and discards the client's data until the client closes, until no data
/// arrives for `lingering_timeout`, or until `lingering_time` has passed. A
/// client that is still sending when the router closes would otherwise see a
/// reset instead of the response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LingeringClose {
    /// Linger only when the request had data the router did not read: an unread
    /// body, or a request header cut short by a limit.
    On,
    /// Linger after every response to a request, whether or not the request was read.
    Always,
    /// Close at once.
    Off,
}

/// Limits for the request line and header section, as `large_client_header_buffers`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderBuffers {
    /// Number of buffers. The whole header section may use `count * size` bytes.
    pub count: usize,
    /// Size of one buffer. The request line and each header field may use `size` bytes.
    pub size: usize,
}

/// Timers and body limit of one site. Each value is the top-level value unless the site sets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SiteTimeouts {
    /// Longest wait between two successive reads of the request body from the client.
    pub client_body_timeout: Duration,
    /// Largest request body in bytes. `None` (`client_max_body_size 0`) is unlimited.
    pub max_body_bytes: Option<usize>,
    /// Time allowed to connect to the upstream.
    pub proxy_connect_timeout: Duration,
    /// Time allowed from sending a request to receiving the response head, and
    /// between two successive reads of the response body.
    pub proxy_read_timeout: Duration,
    /// Longest wait between two successive writes to the upstream.
    pub proxy_send_timeout: Duration,
}

/// The protocol used to reach the decision backend.
#[derive(Debug, Clone, PartialEq)]
pub enum BackendConfig {
    /// The JSON protocol described in the README.
    Http,
    /// Cloudflare Clef on Workers AI, or a server that speaks its protocol.
    Clef {
        /// Model that answers the questions.
        model: ClefModel,
        /// Bearer token, read from the environment variable named in the config.
        token: ApiToken,
    },
    /// `TypeSafe` Jev, or a server that speaks the same System One protocol.
    Jev {
        /// Model identifier sent in the request, such as `jev-latest`.
        model: String,
        /// Bearer token, read from the environment variable named in the config.
        token: ApiToken,
    },
}

/// Configuration for one site, selected by the request `Host`.
#[derive(Debug, Clone, PartialEq)]
pub struct SiteConfig {
    /// Host names that select this site, as written in the configuration (normalized).
    pub hosts: Vec<String>,
    /// Whether this site takes the requests whose host matches no site.
    pub default_server: bool,
    /// The response to a blocked request, unless a location overrides it.
    pub block: BlockResponse,
    /// The `proxy_set_header` operations applied to forwarded requests, unless a location overrides them.
    pub(crate) proxy_headers: Vec<HeaderOp>,
    /// Whether Upgrade requests are tunnelled (`proxy_websocket on`), unless a location overrides it.
    pub websocket: bool,
    /// The parsed host names, in configuration order.
    pub(crate) host_patterns: Vec<HostPattern>,
    /// Absolute `http://` URI requests are forwarded to.
    pub upstream: Uri,
    /// Whether verdicts are enforced or only recorded.
    pub mode: Mode,
    /// What happens to a request that is judged to be an attack.
    pub action: SiteAction,
    /// Attack score at or above which the request is judged an attack.
    pub block_threshold: f64,
    /// AI instruction score at or above which the request is judged an attack.
    pub instruction_threshold: f64,
    /// Path prefixes that are always blocked without calling the backend.
    pub deny_paths: Vec<String>,
    /// Path prefixes that are always blocked when the decision fails.
    pub fail_closed_paths: Vec<String>,
    /// What happens when the backend rate-limits the request or no slot is free in time.
    pub on_rate_limit: FailureAction,
    /// What happens when the backend fails in any other way.
    pub on_decision_error: FailureAction,
    /// File extensions that may skip the backend, lowercased.
    pub static_extensions: Vec<String>,
    /// Whether responses carry the `x-vigilant-heron` header.
    pub debug_headers: bool,
    /// The site's own access logs. `None` inherits the top-level ones; `Some(empty)` is `access_log off`.
    pub access_logs: Option<Vec<AccessLogConfig>>,
    /// Body and upstream timers and the body size limit of this site.
    pub timeouts: SiteTimeouts,
    /// The access list in force for this site: its own, or the top-level one when it has none.
    pub access: Vec<AccessEntry>,
    /// The rules this site runs, in evaluation order.
    pub(crate) rules: SiteRules,
    /// The limits of the site, before any location is selected.
    pub(crate) limits: LimitSet,
    /// The site's location blocks, in configuration order.
    pub(crate) locations: Vec<LocationConfig>,
}

/// One access-log destination with its format.
#[derive(Debug, Clone, PartialEq)]
pub struct AccessLogConfig {
    /// Where the lines go.
    pub destination: Destination,
    /// How each line is formatted.
    pub format: LogFormat,
}

/// Where operational messages go, and how much is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorLogConfig {
    /// Standard error, standard output or a file.
    pub destination: Destination,
    /// Least severe message that is written.
    pub level: LogLevel,
}

/// Severity of operational messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    /// Only errors.
    Error,
    /// Warnings and errors.
    Warn,
    /// Normal operation, warnings and errors.
    Info,
    /// Everything.
    Debug,
}

/// Whether a site enforces its verdicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Blocks or redirects attacks.
    Enforce,
    /// Forwards everything and records what would have happened.
    Shadow,
}

/// The response given to a request that is judged to be an attack.
#[derive(Debug, Clone, PartialEq)]
pub enum SiteAction {
    /// Respond with 403.
    Block,
    /// Respond with 302 and this `Location` value.
    Redirect(HeaderValue),
}

/// What a site does with a request whose decision could not be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FailureAction {
    /// Forward the request to the upstream.
    #[default]
    Allow,
    /// Apply the site's `action`: block with 403, or redirect.
    Block,
}

impl Config {
    /// Reads the configuration file at `path`, following its includes.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Read`] when a file cannot be read, and the syntax,
    /// include and validation errors otherwise.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let directives = conf::load_file(path)?;
        build(&directives, &|name| std::env::var(name).ok())
    }

    /// Parses configuration text, named `origin` in error messages. Includes are
    /// resolved against the current directory. Tokens come from the environment.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Config::load`].
    pub fn parse_str(input: &str, origin: &str) -> Result<Self, ConfigError> {
        Self::parse_str_with_lookup(input, origin, |name| std::env::var(name).ok())
    }

    /// Parses configuration text, reading token variables through `lookup`.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Config::load`], and an error for a token
    /// variable that `lookup` does not give.
    pub fn parse_str_with_lookup<F>(
        input: &str,
        origin: &str,
        lookup: F,
    ) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let directives = conf::parse_source(input, origin)?;
        build(&directives, &lookup)
    }
}

/// Where a directive came from, for error messages.
fn at(directive: &Directive) -> (String, usize) {
    (directive.file.to_string(), directive.line)
}

pub(crate) fn invalid(directive: &Directive, message: impl Into<String>) -> ConfigError {
    let (file, line) = at(directive);
    ConfigError::Invalid {
        file,
        line,
        message: message.into(),
    }
}

/// An error at the top of the file, for something that has no directive to point at.
fn invalid_at_top(directives: &[Directive], message: &str) -> ConfigError {
    let (file, line) = directives
        .first()
        .map_or(("configuration".to_owned(), 1), at);
    ConfigError::Invalid {
        file,
        line,
        message: message.to_owned(),
    }
}

pub(crate) fn one_arg(directive: &Directive) -> Result<&str, ConfigError> {
    match directive.args.as_slice() {
        [value] => Ok(value.as_str()),
        _ => Err(invalid(
            directive,
            format!("\"{}\" takes exactly one argument", directive.name),
        )),
    }
}

pub(crate) fn block(directive: &Directive) -> Result<&[Directive], ConfigError> {
    directive.children.as_deref().ok_or_else(|| {
        invalid(
            directive,
            format!("\"{}\" must be followed by a block", directive.name),
        )
    })
}

fn parse_uint(directive: &Directive, text: &str) -> Result<u64, ConfigError> {
    text.parse::<u64>().map_err(|_| {
        invalid(
            directive,
            format!(
                "\"{}\" must be a whole number, got \"{text}\"",
                directive.name
            ),
        )
    })
}

fn parse_usize(directive: &Directive, text: &str) -> Result<usize, ConfigError> {
    text.parse::<usize>().map_err(|_| {
        invalid(
            directive,
            format!(
                "\"{}\" must be a whole number, got \"{text}\"",
                directive.name
            ),
        )
    })
}

/// Parses a time: a number with `ms`, `s`, `m` or `h`. A bare number is seconds, as in nginx.
fn parse_time(directive: &Directive, text: &str) -> Result<Duration, ConfigError> {
    let (digits, unit) = split_unit(text);
    let value: u64 = digits.parse().map_err(|_| {
        invalid(
            directive,
            format!("\"{}\" is not a time: \"{text}\"", directive.name),
        )
    })?;
    let duration = match unit.to_ascii_lowercase().as_str() {
        "ms" => Duration::from_millis(value),
        "" | "s" => Duration::from_secs(value),
        "m" => Duration::from_secs(value.saturating_mul(60)),
        "h" => Duration::from_secs(value.saturating_mul(3600)),
        _ => {
            return Err(invalid(
                directive,
                format!(
                    "\"{}\" has an unknown time unit in \"{text}\"",
                    directive.name
                ),
            ));
        }
    };
    Ok(duration)
}

/// Parses a size: a number with `k`, `m` or `g` (any case). A bare number is bytes.
pub(crate) fn parse_size(directive: &Directive, text: &str) -> Result<usize, ConfigError> {
    let (digits, unit) = split_unit(text);
    let value: usize = digits.parse().map_err(|_| {
        invalid(
            directive,
            format!("\"{}\" is not a size: \"{text}\"", directive.name),
        )
    })?;
    let multiplier: usize = match unit.to_ascii_lowercase().as_str() {
        "" => 1,
        "k" => 1024,
        "m" => 1024 * 1024,
        "g" => 1024 * 1024 * 1024,
        _ => {
            return Err(invalid(
                directive,
                format!(
                    "\"{}\" has an unknown size unit in \"{text}\"",
                    directive.name
                ),
            ));
        }
    };
    value.checked_mul(multiplier).ok_or_else(|| {
        invalid(
            directive,
            format!("\"{}\" is too large: \"{text}\"", directive.name),
        )
    })
}

/// Splits `12ms` into `12` and `ms`.
fn split_unit(text: &str) -> (&str, &str) {
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    text.split_at(split)
}

pub(crate) fn parse_bool(directive: &Directive, text: &str) -> Result<bool, ConfigError> {
    match text {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => Err(invalid(
            directive,
            format!("\"{}\" must be \"on\" or \"off\"", directive.name),
        )),
    }
}

/// Parses `lingering_close`: `on`, `always` or `off`.
fn parse_lingering_close(directive: &Directive, text: &str) -> Result<LingeringClose, ConfigError> {
    match text {
        "on" => Ok(LingeringClose::On),
        "always" => Ok(LingeringClose::Always),
        "off" => Ok(LingeringClose::Off),
        _ => Err(invalid(
            directive,
            format!(
                "\"{}\" must be \"on\", \"always\" or \"off\"",
                directive.name
            ),
        )),
    }
}

fn parse_failure(directive: &Directive, text: &str) -> Result<FailureAction, ConfigError> {
    match text {
        "allow" => Ok(FailureAction::Allow),
        "block" => Ok(FailureAction::Block),
        _ => Err(invalid(
            directive,
            format!("\"{}\" must be \"allow\" or \"block\"", directive.name),
        )),
    }
}

fn parse_threshold(directive: &Directive, text: &str) -> Result<f64, ConfigError> {
    let value: f64 = text.parse().map_err(|_| {
        invalid(
            directive,
            format!("\"{}\" must be a number between 0 and 1", directive.name),
        )
    })?;
    if (0.0..=1.0).contains(&value) {
        Ok(value)
    } else {
        Err(invalid(
            directive,
            format!("\"{}\" must be between 0 and 1, got {text}", directive.name),
        ))
    }
}

/// Parses a time that must be greater than zero.
fn parse_positive_time(directive: &Directive, text: &str) -> Result<Duration, ConfigError> {
    let duration = parse_time(directive, text)?;
    if duration.is_zero() {
        return Err(invalid(
            directive,
            format!("\"{}\" must be greater than 0", directive.name),
        ));
    }
    Ok(duration)
}

/// Parses `client_max_body_size`: `0` means unlimited and gives `None`.
fn parse_body_limit(directive: &Directive, text: &str) -> Result<Option<usize>, ConfigError> {
    let size = parse_size(directive, text)?;
    Ok((size > 0).then_some(size))
}

/// Parses `large_client_header_buffers <number> <size>`.
fn parse_header_buffers(directive: &Directive) -> Result<HeaderBuffers, ConfigError> {
    let [count, size] = directive.args.as_slice() else {
        return Err(invalid(
            directive,
            "\"large_client_header_buffers\" takes two arguments: a number and a size",
        ));
    };
    let count = parse_usize(directive, count)?;
    let size = parse_size(directive, size)?;
    if count == 0 || size == 0 {
        return Err(invalid(
            directive,
            "\"large_client_header_buffers\" needs a number and a size of at least 1",
        ));
    }
    Ok(HeaderBuffers { count, size })
}

/// Timers that a site may override, and the top-level directives that set them.
const SITE_TIMEOUT_NAMES: [&str; 5] = [
    "client_body_timeout",
    "client_max_body_size",
    "proxy_connect_timeout",
    "proxy_read_timeout",
    "proxy_send_timeout",
];

/// Connection timers that apply before a site is chosen, so only the top level may set them.
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
fn set_site_timeout(directive: &Directive, timeouts: &mut SiteTimeouts) -> Result<(), ConfigError> {
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

fn parse_absolute_uri(text: &str, schemes: &[&str]) -> Option<Uri> {
    let uri = text.parse::<Uri>().ok()?;
    let scheme_ok = uri
        .scheme_str()
        .is_some_and(|scheme| schemes.contains(&scheme));
    (scheme_ok && uri.authority().is_some()).then_some(uri)
}

/// Returns true for a model identifier of 1 to 100 characters from `[A-Za-z0-9._-]`.
fn is_valid_model_id(value: &str) -> bool {
    (1..=100).contains(&value.len())
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Records a directive that may appear only once.
pub(crate) fn once(seen: &mut HashSet<String>, directive: &Directive) -> Result<(), ConfigError> {
    if seen.insert(directive.name.clone()) {
        Ok(())
    } else {
        Err(invalid(
            directive,
            format!("duplicate directive \"{}\"", directive.name),
        ))
    }
}

/// Builds the whole configuration from the directive tree.
#[expect(
    clippy::too_many_lines,
    reason = "one arm per directive keeps each name and its check together"
)]
fn build<F>(directives: &[Directive], lookup: &F) -> Result<Config, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let mut seen = HashSet::new();
    let builtin = rules::builtin_rules()?;
    // Every rule id in use, built-in ids included, with the place it was written.
    let mut claimed: HashMap<String, String> = builtin
        .iter()
        .map(|rule| (rule.id.to_string(), "the built-in rules".to_owned()))
        .collect();
    let mut builtin_top = true;
    let mut disabled_top: Vec<String> = Vec::new();
    let mut top_access: Vec<AccessEntry> = Vec::new();
    let mut top_block = BlockOverrides::default();
    let mut top_headers: Option<Vec<HeaderOp>> = None;
    let mut top_rules: Vec<ParsedRule> = Vec::new();
    let mut listen = None;
    let mut worker_threads = None;
    let mut max_connections = DEFAULT_MAX_CONNECTIONS;
    let mut worker_shutdown_timeout = None;
    let mut request_id_header = None;
    let mut trusted = Vec::new();
    let mut real_ip_header = HeaderName::from_static("x-real-ip");
    let mut recursive = false;
    let mut default_status = DEFAULT_STATUS;
    let mut decision_directive = None;
    let mut site_directives = Vec::new();
    let mut error_log = ErrorLogConfig {
        destination: Destination::Stderr,
        level: LogLevel::Info,
    };
    let mut access_directives = Vec::new();
    let mut format_directives = Vec::new();
    let mut zone_directives: Vec<&Directive> = Vec::new();
    let mut top_limit_directives: Vec<&Directive> = Vec::new();
    let mut connection = ConnectionConfig {
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
    };
    // The top-level values of the site-overridable timers, inherited by every site.
    let mut site_timeouts = SiteTimeouts {
        client_body_timeout: DEFAULT_CLIENT_BODY_TIMEOUT,
        max_body_bytes: Some(DEFAULT_CLIENT_MAX_BODY),
        proxy_connect_timeout: DEFAULT_PROXY_CONNECT_TIMEOUT,
        proxy_read_timeout: DEFAULT_PROXY_READ_TIMEOUT,
        proxy_send_timeout: DEFAULT_PROXY_SEND_TIMEOUT,
    };

    // Pass one: formats first, so access logs can refer to them.
    for directive in directives {
        if directive.name == "log_format" {
            format_directives.push(directive);
        }
        if limits::ZONE_NAMES.contains(&directive.name.as_str()) {
            zone_directives.push(directive);
        }
    }
    let formats = collect_formats(&format_directives)?;

    for directive in directives {
        if !TOP_LEVEL_DIRECTIVES.contains(&directive.name.as_str()) {
            return Err(invalid(
                directive,
                format!("unknown directive \"{}\"", directive.name),
            ));
        }
        match directive.name.as_str() {
            "log_format" => {}
            name if limits::ZONE_NAMES.contains(&name) => {}
            name if limits::LIMIT_NAMES.contains(&name) => top_limit_directives.push(directive),
            "listen" => {
                once(&mut seen, directive)?;
                listen = Some(one_arg(directive)?.to_owned());
            }
            "worker_threads" => {
                once(&mut seen, directive)?;
                let count = parse_usize(directive, one_arg(directive)?)?;
                if count == 0 {
                    return Err(invalid(directive, "\"worker_threads\" must be at least 1"));
                }
                worker_threads = Some(count);
            }
            "max_connections" => {
                once(&mut seen, directive)?;
                let count = parse_usize(directive, one_arg(directive)?)?;
                if count == 0 {
                    return Err(invalid(directive, "\"max_connections\" must be at least 1"));
                }
                max_connections = count;
            }
            "worker_shutdown_timeout" => {
                once(&mut seen, directive)?;
                worker_shutdown_timeout =
                    Some(parse_positive_time(directive, one_arg(directive)?)?);
            }
            "default_status" => {
                once(&mut seen, directive)?;
                let status = parse_uint(directive, one_arg(directive)?)?;
                let valid = u16::try_from(status)
                    .ok()
                    .and_then(|code| StatusCode::from_u16(code).ok())
                    .filter(|code| code.is_client_error() || code.is_server_error());
                default_status = valid.map(|code| code.as_u16()).ok_or_else(|| {
                    invalid(
                        directive,
                        format!("\"default_status\" must be a 4xx or 5xx code, got {status}"),
                    )
                })?;
            }
            "request_id_header" => {
                once(&mut seen, directive)?;
                let text = one_arg(directive)?;
                request_id_header = Some(HeaderName::from_str(text).map_err(|_| {
                    invalid(
                        directive,
                        format!("\"request_id_header\" is not a header name: {text}"),
                    )
                })?);
            }
            "real_ip_from" => {
                if directive.args.is_empty() {
                    return Err(invalid(
                        directive,
                        "\"real_ip_from\" needs at least one address or network",
                    ));
                }
                for text in &directive.args {
                    let net = IpNet::parse(text).ok_or_else(|| {
                        invalid(
                            directive,
                            format!("\"real_ip_from\" is not an address or network: {text}"),
                        )
                    })?;
                    trusted.push(net);
                }
            }
            "real_ip_header" => {
                once(&mut seen, directive)?;
                let text = one_arg(directive)?;
                real_ip_header = HeaderName::from_str(text).map_err(|_| {
                    invalid(
                        directive,
                        format!("\"real_ip_header\" is not a header name: {text}"),
                    )
                })?;
            }
            "real_ip_recursive" => {
                once(&mut seen, directive)?;
                recursive = parse_bool(directive, one_arg(directive)?)?;
            }
            "decision" => {
                once(&mut seen, directive)?;
                block(directive)?;
                decision_directive = Some(directive);
            }
            "client_header_timeout" => {
                once(&mut seen, directive)?;
                connection.client_header_timeout =
                    parse_positive_time(directive, one_arg(directive)?)?;
            }
            "keepalive_timeout" => {
                once(&mut seen, directive)?;
                connection.keepalive_timeout = parse_time(directive, one_arg(directive)?)?;
            }
            "keepalive_requests" => {
                once(&mut seen, directive)?;
                let count = parse_usize(directive, one_arg(directive)?)?;
                if count == 0 {
                    return Err(invalid(
                        directive,
                        "\"keepalive_requests\" must be at least 1",
                    ));
                }
                connection.keepalive_requests = count;
            }
            "send_timeout" => {
                once(&mut seen, directive)?;
                connection.send_timeout = parse_positive_time(directive, one_arg(directive)?)?;
            }
            "large_client_header_buffers" => {
                once(&mut seen, directive)?;
                connection.large_header_buffers = parse_header_buffers(directive)?;
            }
            "lingering_close" => {
                once(&mut seen, directive)?;
                connection.lingering_close = parse_lingering_close(directive, one_arg(directive)?)?;
            }
            "lingering_time" => {
                once(&mut seen, directive)?;
                connection.lingering_time = parse_positive_time(directive, one_arg(directive)?)?;
            }
            "lingering_timeout" => {
                once(&mut seen, directive)?;
                connection.lingering_timeout = parse_positive_time(directive, one_arg(directive)?)?;
            }
            "client_body_timeout"
            | "client_max_body_size"
            | "proxy_connect_timeout"
            | "proxy_read_timeout"
            | "proxy_send_timeout" => {
                once(&mut seen, directive)?;
                set_site_timeout(directive, &mut site_timeouts)?;
            }
            "max_body" => {
                return Err(invalid(
                    directive,
                    "\"max_body\" was replaced by \"client_max_body_size\", which is set at the top level",
                ));
            }
            "allow" | "deny" => top_access.push(access_entry(directive)?),
            name if BLOCK_NAMES.contains(&name) => top_block.apply(directive, &mut seen)?,
            "proxy_set_header" => top_headers
                .get_or_insert_with(Vec::new)
                .push(HeaderOp::parse(directive)?),
            "builtin_rules" => {
                once(&mut seen, directive)?;
                builtin_top = parse_bool(directive, one_arg(directive)?)?;
            }
            "disable_rule" => disabled_top.extend(rules::disabled_ids(directive, builtin)?),
            "rule" => {
                let parsed = rules::parse_rule(directive, Scope::Top)?;
                rules::claim_id(&mut claimed, &parsed)?;
                top_rules.push(parsed);
            }
            "site" => site_directives.push(directive),
            "error_log" => {
                once(&mut seen, directive)?;
                error_log = parse_error_log(directive)?;
            }
            "access_log" => access_directives.push(directive),
            "include" => {
                return Err(invalid(directive, "\"include\" was not expanded"));
            }
            other => {
                return Err(invalid(directive, format!("unknown directive \"{other}\"")));
            }
        }
    }

    let listen = listen.ok_or_else(|| invalid_at_top(directives, "\"listen\" is required"))?;
    let decision_directive = decision_directive
        .ok_or_else(|| invalid_at_top(directives, "a \"decision\" block is required"))?;
    let decision = parse_decision(decision_directive, lookup)?;
    let redact = decision.redact_headers.clone();
    let formats = compile_formats(formats, &redact)?;
    let zones = limits::build_zones(&zone_directives, &redact)?;
    let mut top_overrides = LimitOverrides::default();
    for directive in &top_limit_directives {
        top_overrides.apply(directive, &zones, &mut seen)?;
    }
    let top_limits = top_overrides.resolve(&LimitSet::default());
    let top_block = top_block.resolve(&BlockResponse::default());
    let top_headers = top_headers.unwrap_or_default();
    let access_logs = resolve_top_access(&access_directives, &formats)?;

    if site_directives.is_empty() {
        return Err(invalid_at_top(
            directives,
            "at least one \"site\" block is required",
        ));
    }
    let top = Top {
        timeouts: site_timeouts,
        access: &top_access,
        builtin,
        builtin_enabled: builtin_top,
        disabled: &disabled_top,
        rules: &top_rules,
        zones: &zones,
        limits: &top_limits,
        block: &top_block,
        headers: &top_headers,
    };
    let mut sites = Vec::new();
    let mut hosts_seen: HashSet<String> = HashSet::new();
    let mut default_seen = false;
    for site in site_directives {
        let parsed = parse_site(site, &formats, &top, &mut claimed)?;
        for pattern in &parsed.host_patterns {
            for claim in pattern.claims() {
                if !hosts_seen.insert(claim) {
                    return Err(invalid(
                        site,
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
                return Err(invalid(site, "only one site may be marked default_server"));
            }
            default_seen = true;
        }
        sites.push(parsed);
    }
    for parsed in &top_rules {
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

    Ok(Config {
        listen,
        worker_threads,
        max_connections,
        worker_shutdown_timeout,
        request_id_header,
        realip: RealIp {
            trusted,
            header: real_ip_header,
            recursive,
        },
        default_status: StatusCode::from_u16(default_status)
            .unwrap_or(StatusCode::MISDIRECTED_REQUEST),
        decision,
        sites,
        access_logs,
        error_log,
        connection,
        access: top_access,
        zones,
        limits: top_limits,
    })
}

fn parse_error_log(directive: &Directive) -> Result<ErrorLogConfig, ConfigError> {
    let (destination_text, level_text) = match directive.args.as_slice() {
        [destination] => (destination.as_str(), None),
        [destination, level] => (destination.as_str(), Some(level.as_str())),
        _ => {
            return Err(invalid(
                directive,
                "\"error_log\" takes a destination and an optional level",
            ));
        }
    };
    let destination = match destination_text {
        "stderr" => Destination::Stderr,
        "stdout" => Destination::Stdout,
        text if text.starts_with("syslog:") => {
            return Err(invalid(
                directive,
                "\"error_log\" cannot write to syslog; use stderr, stdout or a file",
            ));
        }
        path => Destination::File(path.into()),
    };
    let level = match level_text.unwrap_or("info") {
        "error" => LogLevel::Error,
        "warn" => LogLevel::Warn,
        "info" => LogLevel::Info,
        "debug" => LogLevel::Debug,
        other => {
            return Err(invalid(
                directive,
                format!("\"error_log\" level must be error, warn, info or debug, got {other}"),
            ));
        }
    };
    Ok(ErrorLogConfig { destination, level })
}

/// A `log_format` directive before its variables are checked.
struct RawFormat<'a> {
    name: &'a str,
    escape: Escape,
    // nginx concatenates the strings of a log_format, so a long format can be
    // split over several lines.
    text: String,
    directive: &'a Directive,
}

fn collect_formats<'a>(directives: &[&'a Directive]) -> Result<Vec<RawFormat<'a>>, ConfigError> {
    let mut formats: Vec<RawFormat<'a>> = Vec::new();
    for directive in directives {
        let (name, rest) = match directive.args.split_first() {
            Some((name, rest)) => (name.as_str(), rest),
            None => {
                return Err(invalid(
                    directive,
                    "\"log_format\" needs a name and a format string",
                ));
            }
        };
        if name == "json" || name == "main" {
            return Err(invalid(
                directive,
                format!("\"{name}\" is a built-in log format and cannot be redefined"),
            ));
        }
        if formats.iter().any(|f| f.name == name) {
            return Err(invalid(
                directive,
                format!("duplicate log_format \"{name}\""),
            ));
        }
        let (escape, strings) = match rest {
            [option, strings @ ..] if option.starts_with("escape=") => (
                parse_escape(directive, option.get(7..).unwrap_or_default())?,
                strings,
            ),
            strings => (Escape::Default, strings),
        };
        if strings.is_empty() {
            return Err(invalid(
                directive,
                "\"log_format\" takes a name, an optional escape=default|json, and one or more quoted format strings",
            ));
        }
        let text = strings.concat();
        formats.push(RawFormat {
            name,
            escape,
            text,
            directive,
        });
    }
    Ok(formats)
}

fn parse_escape(directive: &Directive, text: &str) -> Result<Escape, ConfigError> {
    match text {
        "default" => Ok(Escape::Default),
        "json" => Ok(Escape::Json),
        other => Err(invalid(
            directive,
            format!("log escape must be default or json, got {other}"),
        )),
    }
}

/// Compiled named formats, looked up by name.
struct Formats {
    named: Vec<LogFormat>,
}

fn compile_formats(raw: Vec<RawFormat<'_>>, redact: &[String]) -> Result<Formats, ConfigError> {
    let mut named = Vec::new();
    for format in raw {
        let compiled = LogFormat::compile(format.name, format.escape, &format.text, redact)
            .map_err(|message| invalid(format.directive, message))?;
        named.push(compiled);
    }
    Ok(Formats { named })
}

impl Formats {
    fn find(&self, name: &str) -> Option<LogFormat> {
        match name {
            "json" => Some(LogFormat::json()),
            "main" => Some(LogFormat::main()),
            other => self.named.iter().find(|f| f.name == other).cloned(),
        }
    }
}

/// Parses the destination and optional format of an `access_log` directive.
/// Returns `None` for `access_log off`.
fn parse_access(
    directive: &Directive,
    formats: &Formats,
) -> Result<Option<AccessLogConfig>, ConfigError> {
    let (destination_text, format_name) = match directive.args.as_slice() {
        [destination] => (destination.as_str(), None),
        [destination, format] => (destination.as_str(), Some(format.as_str())),
        _ => {
            return Err(invalid(
                directive,
                "\"access_log\" takes a destination and an optional format",
            ));
        }
    };
    if destination_text == "off" {
        if format_name.is_some() {
            return Err(invalid(directive, "\"access_log off\" takes no format"));
        }
        return Ok(None);
    }
    let destination = parse_destination(directive, destination_text)?;
    let format = match format_name {
        None => LogFormat::json(),
        Some(name) => formats
            .find(name)
            .ok_or_else(|| invalid(directive, format!("unknown log format \"{name}\"")))?,
    };
    Ok(Some(AccessLogConfig {
        destination,
        format,
    }))
}

fn parse_destination(directive: &Directive, text: &str) -> Result<Destination, ConfigError> {
    match text {
        "stdout" => Ok(Destination::Stdout),
        "stderr" => Ok(Destination::Stderr),
        _ => {
            if let Some(rest) = text.strip_prefix("syslog:") {
                let mut server = None;
                let mut tag = "vigilant-heron".to_owned();
                for option in rest.split(',') {
                    match option.split_once('=') {
                        Some(("server", value)) => server = Some(value.to_owned()),
                        Some(("tag", value)) if !value.is_empty() => value.clone_into(&mut tag),
                        _ => {
                            return Err(invalid(
                                directive,
                                format!("invalid syslog option \"{option}\""),
                            ));
                        }
                    }
                }
                let server =
                    server.ok_or_else(|| invalid(directive, "syslog needs server=<host:port>"))?;
                if !server.contains(':') {
                    return Err(invalid(
                        directive,
                        format!("syslog server needs a port: {server}"),
                    ));
                }
                return Ok(Destination::Syslog { server, tag });
            }
            if text.is_empty() {
                return Err(invalid(directive, "\"access_log\" needs a destination"));
            }
            Ok(Destination::File(text.into()))
        }
    }
}

/// Resolves the top-level `access_log` directives. With none, `stdout json` is the default.
fn resolve_top_access(
    directives: &[&Directive],
    formats: &Formats,
) -> Result<Vec<AccessLogConfig>, ConfigError> {
    if directives.is_empty() {
        return Ok(vec![AccessLogConfig {
            destination: Destination::Stdout,
            format: LogFormat::json(),
        }]);
    }
    let mut logs = Vec::new();
    let mut off = false;
    for directive in directives {
        match parse_access(directive, formats)? {
            Some(log) => logs.push(log),
            None => off = true,
        }
    }
    if let Some(first) = directives.first().filter(|_| off && !logs.is_empty()) {
        return Err(invalid(
            first,
            "\"access_log off\" cannot be combined with other access_log directives",
        ));
    }
    Ok(logs)
}

#[expect(
    clippy::too_many_lines,
    reason = "one arm per directive keeps each name and its check together"
)]
fn parse_decision<F>(directive: &Directive, lookup: &F) -> Result<DecisionConfig, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let mut seen = HashSet::new();
    let mut backend_name = "jev";
    let mut url_text = None;
    let mut model = None;
    let mut token_env = None;
    let mut timeout = DEFAULT_TIMEOUT;
    let mut queue_timeout = Duration::ZERO;
    let mut max_concurrency = DEFAULT_MAX_CONCURRENCY;
    let mut inspect_body = DEFAULT_INSPECT_BODY;
    let mut redact_headers = Vec::new();
    let mut backend_line = directive;
    let mut token_line = directive;
    let mut model_line = directive;

    for child in block(directive)? {
        if !DECISION_DIRECTIVES.contains(&child.name.as_str()) {
            return Err(invalid(
                child,
                format!("unknown directive \"{}\" in decision", child.name),
            ));
        }
        match child.name.as_str() {
            "backend" => {
                once(&mut seen, child)?;
                backend_line = child;
                backend_name = match one_arg(child)? {
                    name @ ("jev" | "clef" | "http") => name,
                    other => {
                        return Err(invalid(
                            child,
                            format!("\"backend\" must be jev, clef or http, got {other}"),
                        ));
                    }
                };
            }
            "url" => {
                once(&mut seen, child)?;
                url_text = Some((one_arg(child)?.to_owned(), child));
            }
            "model" => {
                once(&mut seen, child)?;
                model_line = child;
                model = Some(one_arg(child)?.to_owned());
            }
            "api_token_env" => {
                once(&mut seen, child)?;
                token_line = child;
                token_env = Some(one_arg(child)?.to_owned());
            }
            "timeout" => {
                once(&mut seen, child)?;
                timeout = parse_time(child, one_arg(child)?)?;
            }
            "queue_timeout" => {
                once(&mut seen, child)?;
                queue_timeout = parse_time(child, one_arg(child)?)?;
            }
            "max_concurrency" => {
                once(&mut seen, child)?;
                max_concurrency = parse_usize(child, one_arg(child)?)?;
            }
            "inspect_body" => {
                once(&mut seen, child)?;
                inspect_body = parse_size(child, one_arg(child)?)?;
            }
            "max_body" => {
                return Err(invalid(
                    child,
                    "\"max_body\" was replaced by \"client_max_body_size\", which is set at the top level",
                ));
            }
            "redact_header" => {
                if child.args.is_empty() {
                    return Err(invalid(
                        child,
                        "\"redact_header\" needs at least one header name",
                    ));
                }
                redact_headers.extend(child.args.iter().map(|h| h.to_ascii_lowercase()));
            }
            other => {
                return Err(invalid(
                    child,
                    format!("unknown directive \"{other}\" in decision"),
                ));
            }
        }
    }

    if timeout.is_zero() {
        return Err(invalid(directive, "\"timeout\" must be greater than 0"));
    }
    if queue_timeout > timeout {
        return Err(invalid(
            directive,
            "\"queue_timeout\" must not exceed \"timeout\"".to_owned(),
        ));
    }
    if max_concurrency == 0 {
        return Err(invalid(directive, "\"max_concurrency\" must be at least 1"));
    }

    let (url_text, url_line) = match url_text {
        Some((text, line)) => (text, line),
        None if backend_name == "jev" => (JEV_URL.to_owned(), directive),
        None => {
            return Err(invalid(
                backend_line,
                format!("\"url\" is required with backend {backend_name}"),
            ));
        }
    };
    let url = parse_absolute_uri(&url_text, &["http", "https"]).ok_or_else(|| {
        invalid(
            url_line,
            format!("\"url\" must be an absolute http:// or https:// URI, got {url_text}"),
        )
    })?;

    let backend = match backend_name {
        "http" => {
            if model.is_some() {
                return Err(invalid(
                    model_line,
                    "\"model\" is not valid with backend http",
                ));
            }
            if token_env.is_some() {
                return Err(invalid(
                    token_line,
                    "\"api_token_env\" is not valid with backend http",
                ));
            }
            BackendConfig::Http
        }
        "clef" => {
            let model_text = model
                .ok_or_else(|| invalid(backend_line, "\"model\" is required with backend clef"))?;
            let model = ClefModel::from_name(&model_text).ok_or_else(|| {
                invalid(
                    model_line,
                    format!(
                        "\"model\" must be clef-flash or clef for backend clef, got {model_text}"
                    ),
                )
            })?;
            let env_name = token_env.ok_or_else(|| {
                invalid(
                    backend_line,
                    "\"api_token_env\" is required with backend clef",
                )
            })?;
            BackendConfig::Clef {
                model,
                token: read_token(token_line, &env_name, lookup)?,
            }
        }
        _ => {
            let model_text = model.unwrap_or_else(|| JEV_MODEL.to_owned());
            if !is_valid_model_id(&model_text) {
                return Err(invalid(
                    model_line,
                    format!(
                        "\"model\" must be 1 to 100 characters from [A-Za-z0-9._-], got {model_text}"
                    ),
                ));
            }
            let env_name = token_env.unwrap_or_else(|| JEV_TOKEN_ENV.to_owned());
            BackendConfig::Jev {
                model: model_text,
                token: read_token(token_line, &env_name, lookup)?,
            }
        }
    };

    Ok(DecisionConfig {
        url,
        backend,
        timeout,
        queue_timeout,
        max_concurrency,
        inspect_body_bytes: inspect_body,
        redact_headers,
    })
}

/// Reads the token from the variable `name`. A missing or blank value is an error at `directive`.
fn read_token<F>(directive: &Directive, name: &str, lookup: &F) -> Result<ApiToken, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let value = lookup(name).ok_or_else(|| {
        invalid(
            directive,
            format!("environment variable {name} (api_token_env) is not set"),
        )
    })?;
    let token = value.trim();
    if token.is_empty() {
        return Err(invalid(
            directive,
            format!("environment variable {name} (api_token_env) is empty"),
        ));
    }
    Ok(ApiToken::new(token.to_owned()))
}

/// The top-level settings that a site inherits, or extends with its own rules.
struct Top<'a> {
    /// Timers and body limit that a site starts from.
    timeouts: SiteTimeouts,
    /// The top-level access list.
    access: &'a [AccessEntry],
    /// The built-in rules.
    builtin: &'a [Arc<Rule>],
    /// Whether the built-in rules are on at the top level.
    builtin_enabled: bool,
    /// Built-in rule ids disabled at the top level.
    disabled: &'a [String],
    /// Top-level rules, each with the sites it applies to.
    rules: &'a [ParsedRule],
    /// The limit zones.
    zones: &'a [LimitZone],
    /// The limits of the top level.
    limits: &'a LimitSet,
    /// The top-level block response, inherited by every site.
    block: &'a BlockResponse,
    /// The top-level `proxy_set_header` operations, inherited by every site.
    headers: &'a [HeaderOp],
}

/// Reads one `allow` or `deny` directive.
fn access_entry(directive: &Directive) -> Result<AccessEntry, ConfigError> {
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
fn parse_site(
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
    let mut on_decision_error = FailureAction::Allow;
    let mut static_extensions: Option<Vec<String>> = None;
    let mut debug_headers = false;
    let mut access_logs: Option<Vec<AccessLogConfig>> = None;
    let mut access_off = false;
    let mut timeouts = top.timeouts;
    let mut own_access: Vec<AccessEntry> = Vec::new();
    let mut builtin_enabled: Option<bool> = None;
    let mut own_disabled: Vec<String> = Vec::new();
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
            "disable_rule" => own_disabled.extend(rules::disabled_ids(child, top.builtin)?),
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
        let duplicate = locations.iter().any(|earlier| {
            earlier.matcher == pending.matcher
                && !matches!(pending.matcher, limits::Matcher::Regex(_))
        });
        if duplicate {
            return Err(invalid(
                pending.directive,
                "duplicate \"location\" with the same modifier and path",
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
    let disabled: Vec<String> = top
        .disabled
        .iter()
        .chain(own_disabled.iter())
        .cloned()
        .collect();
    let rules = rules::site_rules(
        &hosts,
        top.builtin,
        builtin_enabled.unwrap_or(top.builtin_enabled),
        &disabled,
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
        deny_paths,
        fail_closed_paths,
        on_rate_limit,
        on_decision_error,
        static_extensions: static_extensions.unwrap_or_else(|| {
            DEFAULT_STATIC_EXTENSIONS
                .iter()
                .map(|e| (*e).to_owned())
                .collect()
        }),
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
    use std::time::Duration;

    use rstest::rstest;

    use super::*;

    /// A configuration that is valid as written.
    const BASE: &str = "listen 127.0.0.1:8080;\n\
        decision {\n    backend http;\n    url http://stub-decider:9000/decide;\n}\n\
        site example.com {\n    upstream http://upstream:80;\n}\n";

    fn lookup(name: &str) -> Option<String> {
        (name == "TEST_TOKEN").then(|| " tok-123 ".to_owned())
    }

    fn parse(text: &str) -> Result<Config, ConfigError> {
        Config::parse_str_with_lookup(text, "test.conf", lookup)
    }

    /// The message of an error, which always starts with `file:line:` for file errors.
    fn message<T>(result: Result<T, ConfigError>) -> String {
        match result {
            Ok(_) => String::new(),
            Err(error) => error.to_string(),
        }
    }

    fn with_decision(lines: &str) -> String {
        format!(
            "listen 127.0.0.1:8080;\ndecision {{\n    url http://stub-decider:9000/decide;\n{lines}}}\n\
             site example.com {{\n    upstream http://upstream:80;\n}}\n"
        )
    }

    fn with_site(lines: &str) -> String {
        format!(
            "listen 127.0.0.1:8080;\ndecision {{\n    backend http;\n    url http://stub-decider:9000/decide;\n}}\n\
             site example.com {{\n    upstream http://upstream:80;\n{lines}}}\n"
        )
    }

    fn first_site(config: &Config) -> Result<&SiteConfig, ConfigError> {
        config.sites.first().ok_or_else(|| ConfigError::Invalid {
            file: "test.conf".to_owned(),
            line: 1,
            message: "no site".to_owned(),
        })
    }

    #[test]
    fn minimal_configuration_gets_the_documented_defaults() -> Result<(), ConfigError> {
        let config = parse(BASE)?;
        assert_eq!(config.listen, "127.0.0.1:8080");
        assert_eq!(config.worker_threads, None);
        assert_eq!(config.max_connections, 1024);
        assert_eq!(config.default_status, StatusCode::MISDIRECTED_REQUEST);
        assert_eq!(config.decision.timeout, Duration::from_millis(300));
        assert_eq!(config.decision.queue_timeout, Duration::ZERO);
        assert_eq!(config.decision.max_concurrency, 64);
        assert_eq!(config.decision.inspect_body_bytes, 8192);
        assert_eq!(
            config.connection.client_header_timeout,
            Duration::from_secs(60)
        );
        assert_eq!(config.sites[0].timeouts.max_body_bytes, Some(1024 * 1024));
        assert_eq!(config.realip.header, HeaderName::from_static("x-real-ip"));
        assert!(!config.realip.recursive);
        assert_eq!(config.realip.trusted.len(), 0);
        assert_eq!(config.error_log.destination, Destination::Stderr);
        assert_eq!(config.error_log.level, LogLevel::Info);
        assert_eq!(config.access_logs.len(), 1);
        let site = first_site(&config)?;
        assert_eq!(site.block_threshold, 0.87);
        assert_eq!(site.instruction_threshold, 0.8);
        assert_eq!(site.on_rate_limit, FailureAction::Allow);
        assert_eq!(site.on_decision_error, FailureAction::Allow);
        assert_eq!(site.mode, Mode::Enforce);
        assert_eq!(site.action, SiteAction::Block);
        assert!(site.static_extensions.contains(&"woff2".to_owned()));
        assert_eq!(site.static_extensions.len(), 13);
        assert_eq!(site.access_logs, None);
        Ok(())
    }

    #[test]
    fn a_decision_without_a_backend_is_jev_and_needs_its_token() {
        let text = "listen 127.0.0.1:8080;\ndecision {\n    url https://api.typesafe.ai/v1/systemone;\n}\n\
                    site example.com {\n    upstream http://upstream:80;\n}\n";
        let result = Config::parse_str_with_lookup(text, "test.conf", |_| None);
        assert!(message(result).contains("test.conf:2:"));
    }

    #[test]
    fn jev_defaults_apply_when_only_the_token_is_given() -> Result<(), ConfigError> {
        let text = "listen 127.0.0.1:8080;\ndecision {\n    api_token_env TEST_TOKEN;\n}\n\
                    site example.com {\n    upstream http://upstream:80;\n}\n";
        let config = parse(text)?;
        assert!(matches!(
            &config.decision.backend,
            BackendConfig::Jev { model, token } if model == "jev-latest" && token.expose() == "tok-123"
        ));
        assert_eq!(
            config.decision.url.to_string(),
            "https://api.typesafe.ai/v1/systemone"
        );
        Ok(())
    }

    #[test]
    fn jev_defaults_read_the_default_token_variable() {
        let text = "listen 127.0.0.1:8080;\ndecision {\n}\n\
                    site example.com {\n    upstream http://upstream:80;\n}\n";
        let result = Config::parse_str_with_lookup(text, "test.conf", |name| {
            (name == "TYPESAFE_API_KEY").then(|| "jev-token".to_owned())
        });
        assert!(result.is_ok());
    }

    #[test]
    fn a_token_variable_that_is_not_set_names_it_and_its_line() {
        let text = "listen 127.0.0.1:8080;\ndecision {\n    api_token_env ABSENT;\n}\n\
                    site example.com {\n    upstream http://upstream:80;\n}\n";
        let result = parse(text);
        assert!(message(result).contains("test.conf:3: environment variable ABSENT"));
    }

    #[test]
    fn a_blank_token_is_rejected() {
        let text = "listen 127.0.0.1:8080;\ndecision {\n    api_token_env BLANK;\n}\n\
                    site example.com {\n    upstream http://upstream:80;\n}\n";
        let result = Config::parse_str_with_lookup(text, "test.conf", |_| Some("   ".to_owned()));
        assert!(message(result).contains("is empty"));
    }

    #[rstest]
    #[case::clef_flash("clef-flash")]
    #[case::clef("clef")]
    fn clef_accepts_its_two_models(#[case] model: &str) {
        let text = with_decision(&format!(
            "    backend clef;\n    model {model};\n    api_token_env TEST_TOKEN;\n"
        ));
        assert!(parse(&text).is_ok());
    }

    #[test]
    fn clef_rejects_other_models_with_the_directive_line() {
        let text = with_decision(
            "    backend clef;\n    model jev-latest;\n    api_token_env TEST_TOKEN;\n",
        );
        // Line 1 listen, 2 decision, 3 url, 4 backend, 5 model.
        assert!(message(parse(&text)).contains("test.conf:5:"));
    }

    #[test]
    fn clef_requires_a_model_and_a_token_variable() {
        let no_model = with_decision("    backend clef;\n    api_token_env TEST_TOKEN;\n");
        assert!(message(parse(&no_model)).contains("\"model\" is required with backend clef"));
        let no_token = with_decision("    backend clef;\n    model clef;\n");
        assert!(
            message(parse(&no_token)).contains("\"api_token_env\" is required with backend clef")
        );
    }

    #[test]
    fn http_rejects_model_and_token_variable() {
        let model = with_decision("    backend http;\n    model clef;\n");
        assert!(message(parse(&model)).contains("\"model\" is not valid with backend http"));
        let token = with_decision("    backend http;\n    api_token_env TEST_TOKEN;\n");
        assert!(
            message(parse(&token)).contains("\"api_token_env\" is not valid with backend http")
        );
    }

    #[test]
    fn a_jev_model_must_be_a_safe_identifier() {
        let text = with_decision(
            "    backend jev;\n    model \"jev latest\";\n    api_token_env TEST_TOKEN;\n",
        );
        assert!(message(parse(&text)).contains("1 to 100 characters"));
    }

    #[rstest]
    #[case::bare_is_seconds("2", Duration::from_secs(2))]
    #[case::milliseconds("250ms", Duration::from_millis(250))]
    #[case::minutes("2m", Duration::from_secs(120))]
    #[case::hours("1h", Duration::from_secs(3600))]
    #[case::uppercase_unit("3S", Duration::from_secs(3))]
    fn time_units_follow_nginx(
        #[case] text: &str,
        #[case] expected: Duration,
    ) -> Result<(), ConfigError> {
        let config = parse(&with_decision(&format!(
            "    backend http;\n    timeout {text};\n"
        )))?;
        assert_eq!(config.decision.timeout, expected);
        Ok(())
    }

    #[test]
    fn an_unknown_time_unit_is_rejected() {
        let text = with_decision("    backend http;\n    timeout 5x;\n");
        assert!(message(parse(&text)).contains("unknown time unit"));
    }

    #[rstest]
    #[case::bytes("100", 100)]
    #[case::kilobytes("8k", 8 * 1024)]
    #[case::uppercase_megabytes("1M", 1024 * 1024)]
    #[case::gigabytes("1g", 1024 * 1024 * 1024)]
    fn size_units_follow_nginx(
        #[case] text: &str,
        #[case] expected: usize,
    ) -> Result<(), ConfigError> {
        let config = parse(&with_decision(&format!(
            "    backend http;\n    inspect_body {text};\n"
        )))?;
        assert_eq!(config.decision.inspect_body_bytes, expected);
        Ok(())
    }

    #[test]
    fn timeout_zero_queue_longer_than_timeout_and_zero_concurrency_are_rejected() {
        assert!(
            message(parse(&with_decision("    backend http;\n    timeout 0;\n")))
                .contains("\"timeout\" must be greater than 0")
        );
        assert!(
            message(parse(&with_decision(
                "    backend http;\n    timeout 100ms;\n    queue_timeout 200ms;\n"
            )))
            .contains("must not exceed")
        );
        assert!(
            message(parse(&with_decision(
                "    backend http;\n    max_concurrency 0;\n"
            )))
            .contains("at least 1")
        );
    }

    #[test]
    fn max_body_in_decision_is_replaced_by_client_max_body_size() {
        let text = with_decision("    backend http;\n    max_body 1m;\n");
        assert!(message(parse(&text)).contains("replaced by \"client_max_body_size\""));
    }

    #[test]
    fn missing_listen_is_reported_at_the_top_of_the_file() {
        let text = "decision {\n    backend http;\n    url http://stub:9000/decide;\n}\nsite example.com {\n    upstream http://upstream:80;\n}\n";
        assert!(message(parse(text)).contains("test.conf:1: \"listen\" is required"));
    }

    #[test]
    fn a_configuration_without_a_site_is_rejected() {
        let text = "listen 127.0.0.1:8080;\ndecision {\n    backend http;\n    url http://stub:9000/decide;\n}\n";
        assert!(message(parse(text)).contains("at least one \"site\" block"));
    }

    #[test]
    fn unknown_directives_are_reported_with_their_line() {
        let text = "listen 127.0.0.1:8080;\nfrobnicate yes;\n";
        assert!(message(parse(text)).contains("test.conf:2: unknown directive \"frobnicate\""));
    }

    #[test]
    fn a_decision_directive_in_the_wrong_context_is_unknown() {
        let text = format!("{BASE}url http://elsewhere;\n");
        assert!(message(parse(&text)).contains("unknown directive \"url\""));
    }

    #[test]
    fn duplicate_single_directives_are_rejected_at_the_second_line() {
        let text = "listen 127.0.0.1:1;\nlisten 127.0.0.1:2;\n";
        assert!(message(parse(text)).contains("test.conf:2: duplicate directive \"listen\""));
    }

    #[test]
    fn a_directive_that_needs_a_block_says_so() {
        assert!(
            message(parse("listen 127.0.0.1:1;\ndecision;\n"))
                .contains("must be followed by a block")
        );
    }

    #[test]
    fn a_site_needs_an_upstream_and_reports_its_line() {
        let text = "listen 127.0.0.1:8080;\ndecision {\n    backend http;\n    url http://stub:9000/decide;\n}\nsite example.com {\n    mode enforce;\n}\n";
        assert!(message(parse(text)).contains("test.conf:6: \"upstream\" is required"));
    }

    #[test]
    fn a_host_listed_by_two_sites_is_rejected() {
        let text = format!("{BASE}site example.com {{\n    upstream http://other:80;\n}}\n");
        assert!(
            message(parse(&text)).contains("host \"example.com\" is listed by more than one site")
        );
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
    fn realip_directives_build_the_trust_list() -> Result<(), ConfigError> {
        let config = parse(&format!(
            "real_ip_from 10.0.0.0/8 192.0.2.1;\nreal_ip_from 2001:db8::/32;\nreal_ip_header X-Forwarded-For;\nreal_ip_recursive on;\n{BASE}"
        ))?;
        assert_eq!(config.realip.trusted.len(), 3);
        assert_eq!(
            config.realip.header,
            HeaderName::from_static("x-forwarded-for")
        );
        assert!(config.realip.recursive);
        Ok(())
    }

    #[test]
    fn a_bad_real_ip_network_is_rejected_with_its_line() {
        let text = format!("real_ip_from 10.0.0.0/99;\n{BASE}");
        assert!(
            message(parse(&text))
                .contains("test.conf:1: \"real_ip_from\" is not an address or network")
        );
    }

    #[test]
    fn worker_shutdown_timeout_is_a_positive_time_and_unset_by_default() -> Result<(), ConfigError>
    {
        let set = parse(&format!("worker_shutdown_timeout 5s;\n{BASE}"))?;
        assert_eq!(set.worker_shutdown_timeout, Some(Duration::from_secs(5)));
        let unset = parse(BASE)?;
        assert_eq!(unset.worker_shutdown_timeout, None);
        assert!(
            message(parse(&format!("worker_shutdown_timeout 0;\n{BASE}")))
                .contains("\"worker_shutdown_timeout\" must be greater than 0")
        );
        assert!(
            message(parse(&format!("worker_shutdown_timeout soon;\n{BASE}")))
                .contains("is not a time")
        );
        Ok(())
    }

    #[test]
    fn error_log_takes_a_destination_and_a_level() -> Result<(), ConfigError> {
        let config = parse(&format!("error_log /var/log/vh/error.log warn;\n{BASE}"))?;
        assert_eq!(
            config.error_log.destination,
            Destination::File("/var/log/vh/error.log".into())
        );
        assert_eq!(config.error_log.level, LogLevel::Warn);
        assert!(
            message(parse(&format!("error_log syslog:server=h:514;\n{BASE}")))
                .contains("cannot write to syslog")
        );
        assert!(
            message(parse(&format!("error_log stderr loud;\n{BASE}"))).contains("level must be")
        );
        Ok(())
    }

    #[test]
    fn access_log_default_is_stdout_json() -> Result<(), ConfigError> {
        let config = parse(BASE)?;
        assert_eq!(
            config.access_logs.first().map(|l| l.destination.clone()),
            Some(Destination::Stdout)
        );
        assert_eq!(
            config.access_logs.first().map(|l| l.format.name.clone()),
            Some("json".to_owned())
        );
        Ok(())
    }

    #[test]
    fn top_level_access_log_off_leaves_no_default_writer() -> Result<(), ConfigError> {
        let config = parse(&format!("access_log off;\n{BASE}"))?;
        assert_eq!(config.access_logs.len(), 0);
        Ok(())
    }

    #[test]
    fn a_site_access_log_replaces_the_inherited_ones() -> Result<(), ConfigError> {
        let config = parse(&format!(
            "access_log /var/log/vh/all.log;\n{}",
            with_site("    access_log /var/log/vh/site.log main;\n")
        ))?;
        assert_eq!(config.access_logs.len(), 1);
        let site = first_site(&config)?;
        let own = site.access_logs.as_deref().unwrap_or_default();
        assert_eq!(own.len(), 1);
        assert_eq!(
            own.first().map(|l| l.destination.clone()),
            Some(Destination::File("/var/log/vh/site.log".into()))
        );
        Ok(())
    }

    #[test]
    fn site_access_log_off_disables_inherited_logs() -> Result<(), ConfigError> {
        let config = parse(&with_site("    access_log off;\n"))?;
        assert_eq!(first_site(&config)?.access_logs, Some(Vec::new()));
        Ok(())
    }

    #[test]
    fn access_log_off_cannot_be_combined_with_a_destination() {
        let text = with_site("    access_log off;\n    access_log stdout;\n");
        assert!(message(parse(&text)).contains("cannot be combined"));
    }

    #[test]
    fn syslog_destinations_need_a_server_and_accept_a_tag() -> Result<(), ConfigError> {
        let config = parse(&format!(
            "access_log syslog:server=192.0.2.10:514,tag=router;\n{BASE}"
        ))?;
        assert_eq!(
            config.access_logs.first().map(|l| l.destination.clone()),
            Some(Destination::Syslog {
                server: "192.0.2.10:514".to_owned(),
                tag: "router".to_owned()
            })
        );
        assert!(
            message(parse(&format!("access_log syslog:tag=x;\n{BASE}")))
                .contains("syslog needs server")
        );
        assert!(
            message(parse(&format!("access_log syslog:server=nohost;\n{BASE}")))
                .contains("needs a port")
        );
        Ok(())
    }

    #[test]
    fn named_log_formats_are_used_by_access_log_and_may_come_later() -> Result<(), ConfigError> {
        let config = parse(&format!(
            "access_log stdout short;\nlog_format short \"$client_ip $status\";\n{BASE}"
        ))?;
        assert_eq!(
            config.access_logs.first().map(|l| l.format.name.clone()),
            Some("short".to_owned())
        );
        Ok(())
    }

    #[test]
    fn an_unknown_log_format_name_is_rejected() {
        let text = format!("access_log stdout nosuch;\n{BASE}");
        assert!(message(parse(&text)).contains("unknown log format \"nosuch\""));
    }

    #[test]
    fn log_format_checks_its_variables_and_headers() {
        assert!(
            message(parse(&format!("log_format bad \"$nosuch\";\n{BASE}")))
                .contains("unknown variable $nosuch")
        );
        assert!(
            message(parse(&format!("log_format bad \"$http_cookie\";\n{BASE}")))
                .contains("never logged")
        );
        let redact = format!(
            "log_format bad \"$http_x_session\";\n{}",
            with_decision("    backend http;\n    redact_header X-Session;\n")
        );
        assert!(message(parse(&redact)).contains("never logged"));
    }

    #[test]
    fn log_format_names_must_be_unique_and_not_built_in() {
        assert!(
            message(parse(&format!("log_format json \"$client_ip\";\n{BASE}")))
                .contains("built-in")
        );
        let duplicate = format!("log_format x \"$client_ip\";\nlog_format x \"$site\";\n{BASE}");
        assert!(message(parse(&duplicate)).contains("duplicate log_format"));
    }

    #[test]
    fn log_format_escape_option_is_checked() -> Result<(), ConfigError> {
        parse(&format!("log_format j escape=json \"$client_ip\";\n{BASE}"))?;
        assert!(
            message(parse(&format!(
                "log_format j escape=none \"$client_ip\";\n{BASE}"
            )))
            .contains("escape must be default or json")
        );
        Ok(())
    }

    #[test]
    fn log_format_concatenates_several_strings() -> Result<(), ConfigError> {
        parse(&format!(
            "log_format split escape=json '{{\"ip\":\"$client_ip\",' '\"site\":\"$site\"}}';\n{BASE}"
        ))?;
        parse(&format!("log_format plain '$client_ip ' '$site';\n{BASE}"))?;
        Ok(())
    }

    #[test]
    fn log_format_without_a_string_is_an_error() {
        assert!(
            message(parse(&format!("log_format empty escape=json;\n{BASE}")))
                .contains("one or more quoted format strings")
        );
    }

    #[test]
    fn include_loads_files_and_globs_and_rejects_missing_ones()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!("vh-config-include-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("sites.d"))?;
        std::fs::write(
            dir.join("sites.d/a.conf"),
            "site a.example {\n    upstream http://a:80;\n}\n",
        )?;
        std::fs::write(
            dir.join("sites.d/b.conf"),
            "site b.example {\n    upstream http://b:80;\n}\n",
        )?;
        let main = dir.join("main.conf");
        std::fs::write(
            &main,
            format!(
                "include sites.d/*.conf;\n{}",
                BASE.replace(
                    "site example.com {\n    upstream http://upstream:80;\n}\n",
                    ""
                )
            ),
        )?;
        let config = Config::load(&main)?;
        let mut hosts: Vec<String> = config.sites.iter().flat_map(|s| s.hosts.clone()).collect();
        hosts.sort();
        assert_eq!(hosts, ["a.example", "b.example"]);

        std::fs::write(&main, "include missing.conf;\n")?;
        assert!(
            message(Config::load(&main).map(|_| ()))
                .contains("main.conf:1: include file not found")
        );

        std::fs::write(&main, "include main.conf;\n")?;
        assert!(message(Config::load(&main).map(|_| ())).contains("include cycle"));
        Ok(())
    }

    #[test]
    fn a_missing_file_is_a_read_error() {
        let result = Config::load(Path::new("/nonexistent/vigilant-heron/vigilant-heron.conf"));
        assert!(matches!(result, Err(ConfigError::Read { .. })));
    }

    #[test]
    fn the_shipped_example_configuration_loads() -> Result<(), ConfigError> {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/vigilant-heron.conf"
        ))
        .map_err(|source| ConfigError::Read {
            path: "examples/vigilant-heron.conf".into(),
            source,
        })?;
        Config::parse_str_with_lookup(&text, "examples/vigilant-heron.conf", |_| {
            Some("token".to_owned())
        })?;
        Ok(())
    }

    proptest::proptest! {
        #[test]
        fn parsing_arbitrary_text_never_panics(text in "[a-z0-9 ;{}\"'#$=/:.,\n-]{0,300}") {
            let _ = Config::parse_str_with_lookup(&text, "fuzz.conf", |_| None);
        }
    }

    /// A configuration with the given site blocks after the decision block.
    fn with_sites(sites: &str) -> String {
        format!(
            "listen 127.0.0.1:8080;\ndecision {{\n    backend http;\n    url http://stub-decider:9000/decide;\n}}\n{sites}"
        )
    }

    #[rstest]
    #[case::domain_and_exact(
        "site .example.com {\n    upstream http://u:80;\n}\nsite example.com {\n    upstream http://u:80;\n}\n"
    )]
    #[case::leading_twice(
        "site *.example.com {\n    upstream http://u:80;\n}\nsite *.example.com {\n    upstream http://u:80;\n}\n"
    )]
    #[case::same_regex_in_two_sites(
        "site ~^a\\.test$ {\n    upstream http://u:80;\n}\nsite ~^a\\.test$ {\n    upstream http://u:80;\n}\n"
    )]
    #[case::name_twice_in_one_site("site x.test x.test {\n    upstream http://u:80;\n}\n")]
    fn a_name_claimed_by_two_sites_is_rejected(#[case] sites: &str) {
        let result = Config::parse_str(&with_sites(sites), "hosts.conf");
        assert!(message(result.map(|_| ())).contains("is listed by more than one site"));
    }

    #[test]
    fn a_wildcard_and_its_bare_name_in_different_sites_do_not_clash() -> Result<(), ConfigError> {
        let config = Config::parse_str(
            &with_sites(
                "site *.example.com {\n    upstream http://u:80;\n}\nsite example.com {\n    upstream http://u:80;\n}\n",
            ),
            "hosts.conf",
        )?;
        assert_eq!(config.sites.len(), 2);
        Ok(())
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
    fn a_second_default_server_is_rejected_at_its_site() {
        let result = Config::parse_str(
            &with_sites(
                "site a.test {\n    upstream http://u:80;\n    default_server;\n}\nsite b.test {\n    upstream http://u:80;\n    default_server;\n}\n",
            ),
            "default.conf",
        );
        let text = message(result.map(|_| ()));
        assert!(text.contains("default.conf:10:"), "{text}");
        assert!(
            text.contains("only one site may be marked default_server"),
            "{text}"
        );
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
}

#[cfg(test)]
mod connection_limit_tests {
    use std::time::Duration;

    use rstest::rstest;

    use super::*;

    const DECISION: &str =
        "decision {\n    backend http;\n    url http://stub-decider:9000/decide;\n}\n";
    const SITE: &str = "site example.com {\n    upstream http://upstream:80;\n}\n";

    fn parse(top: &str, site: &str) -> Result<Config, ConfigError> {
        let text = format!(
            "listen 127.0.0.1:8080;\n{top}{DECISION}site example.com {{\n    upstream http://upstream:80;\n{site}}}\n"
        );
        Config::parse_str_with_lookup(&text, "test.conf", |_| None)
    }

    fn message(result: Result<Config, ConfigError>) -> String {
        match result {
            Ok(_) => String::new(),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn every_connection_directive_has_the_nginx_default() -> Result<(), ConfigError> {
        let config = Config::parse_str(
            &format!("listen 127.0.0.1:8080;\n{DECISION}{SITE}"),
            "t.conf",
        )?;
        let connection = &config.connection;
        assert_eq!(connection.client_header_timeout, Duration::from_secs(60));
        assert_eq!(connection.keepalive_timeout, Duration::from_secs(75));
        assert_eq!(connection.keepalive_requests, 1000);
        assert_eq!(connection.send_timeout, Duration::from_secs(60));
        assert_eq!(
            connection.large_header_buffers,
            HeaderBuffers {
                count: 4,
                size: 8192
            }
        );
        let timeouts = config.sites[0].timeouts;
        assert_eq!(timeouts.client_body_timeout, Duration::from_secs(60));
        assert_eq!(timeouts.max_body_bytes, Some(1024 * 1024));
        assert_eq!(timeouts.proxy_connect_timeout, Duration::from_secs(60));
        assert_eq!(timeouts.proxy_read_timeout, Duration::from_secs(60));
        assert_eq!(timeouts.proxy_send_timeout, Duration::from_secs(60));
        Ok(())
    }

    #[rstest]
    #[case::milliseconds("200ms", Duration::from_millis(200))]
    #[case::bare_seconds("5", Duration::from_secs(5))]
    #[case::seconds("5s", Duration::from_secs(5))]
    #[case::minutes("2m", Duration::from_secs(120))]
    #[case::hours("1h", Duration::from_secs(3600))]
    fn client_header_timeout_takes_nginx_time_units(
        #[case] text: &str,
        #[case] expected: Duration,
    ) -> Result<(), ConfigError> {
        let config = parse(&format!("client_header_timeout {text};\n"), "")?;
        assert_eq!(config.connection.client_header_timeout, expected);
        Ok(())
    }

    #[test]
    fn keepalive_timeout_zero_disables_keep_alive() -> Result<(), ConfigError> {
        let config = parse("keepalive_timeout 0;\n", "")?;
        assert_eq!(config.connection.keepalive_timeout, Duration::ZERO);
        Ok(())
    }

    #[test]
    fn keepalive_timeout_and_send_timeout_take_their_values() -> Result<(), ConfigError> {
        let config = parse("keepalive_timeout 30s;\nsend_timeout 250ms;\n", "")?;
        assert_eq!(config.connection.keepalive_timeout, Duration::from_secs(30));
        assert_eq!(config.connection.send_timeout, Duration::from_millis(250));
        Ok(())
    }

    #[test]
    fn lingering_defaults_match_nginx() -> Result<(), ConfigError> {
        let config = parse("", "")?;
        assert_eq!(config.connection.lingering_close, LingeringClose::On);
        assert_eq!(config.connection.lingering_time, Duration::from_secs(30));
        assert_eq!(config.connection.lingering_timeout, Duration::from_secs(5));
        Ok(())
    }

    #[rstest]
    #[case::on("on", LingeringClose::On)]
    #[case::always("always", LingeringClose::Always)]
    #[case::off("off", LingeringClose::Off)]
    fn lingering_close_takes_its_three_values(
        #[case] text: &str,
        #[case] expected: LingeringClose,
    ) -> Result<(), ConfigError> {
        let config = parse(
            &format!("lingering_close {text};\nlingering_time 2s;\nlingering_timeout 250ms;\n"),
            "",
        )?;
        assert_eq!(config.connection.lingering_close, expected);
        assert_eq!(config.connection.lingering_time, Duration::from_secs(2));
        assert_eq!(
            config.connection.lingering_timeout,
            Duration::from_millis(250)
        );
        Ok(())
    }

    #[test]
    fn keepalive_requests_and_header_buffers_are_read() -> Result<(), ConfigError> {
        let config = parse(
            "keepalive_requests 5;\nlarge_client_header_buffers 2 16k;\n",
            "",
        )?;
        assert_eq!(config.connection.keepalive_requests, 5);
        assert_eq!(
            config.connection.large_header_buffers,
            HeaderBuffers {
                count: 2,
                size: 16 * 1024
            }
        );
        Ok(())
    }

    #[rstest]
    #[case::client_header_zero("client_header_timeout 0;\n", "must be greater than 0")]
    #[case::send_zero("send_timeout 0s;\n", "must be greater than 0")]
    #[case::keepalive_requests_zero("keepalive_requests 0;\n", "must be at least 1")]
    #[case::lingering_time_zero("lingering_time 0s;\n", "must be greater than 0")]
    #[case::lingering_timeout_zero("lingering_timeout 0;\n", "must be greater than 0")]
    #[case::lingering_close_unknown(
        "lingering_close maybe;\n",
        "must be \"on\", \"always\" or \"off\""
    )]
    #[case::buffers_missing_size("large_client_header_buffers 4;\n", "takes two arguments")]
    #[case::buffers_zero_count("large_client_header_buffers 0 8k;\n", "at least 1")]
    #[case::buffers_bad_size("large_client_header_buffers 4 8q;\n", "unknown size unit")]
    #[case::bad_time("client_header_timeout soon;\n", "is not a time")]
    #[case::bad_time_unit("client_header_timeout 3d;\n", "unknown time unit")]
    #[case::duplicate(
        "client_header_timeout 1s;\nclient_header_timeout 2s;\n",
        "duplicate directive"
    )]
    fn invalid_connection_values_name_the_directive_and_its_line(
        #[case] line: &str,
        #[case] expected: &str,
    ) {
        let text = message(parse(line, ""));
        assert!(text.contains(expected), "{text}");
        assert!(text.contains("test.conf:"), "{text}");
    }

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

    #[rstest]
    #[case::zero_is_unlimited("0", None)]
    #[case::bytes("512", Some(512))]
    #[case::kilobytes("8k", Some(8 * 1024))]
    #[case::megabytes("10m", Some(10 * 1024 * 1024))]
    fn client_max_body_size_takes_nginx_size_units(
        #[case] text: &str,
        #[case] expected: Option<usize>,
    ) -> Result<(), ConfigError> {
        let config = parse(&format!("client_max_body_size {text};\n"), "")?;
        assert_eq!(config.sites[0].timeouts.max_body_bytes, expected);
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

    #[test]
    fn max_body_is_replaced_by_client_max_body_size() {
        let text = message(Config::parse_str_with_lookup(
            &format!(
                "listen 127.0.0.1:8080;\ndecision {{\n    backend http;\n    url http://stub:9000/decide;\n    max_body 1m;\n}}\n{SITE}"
            ),
            "test.conf",
            |_| None,
        ));
        assert!(
            text.contains("replaced by \"client_max_body_size\""),
            "{text}"
        );
        assert!(text.contains("test.conf:5:"), "{text}");
    }
}
