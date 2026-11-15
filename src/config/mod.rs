//! Building the configuration from the directive tree.
//!
//! The tree is read in two passes. The first collects `log_format` so that the
//! second can resolve `access_log` formats and check `$http_*` variables against
//! the header names the decision block redacts. Every error names the file and
//! line of the directive that caused it.

mod decision;
mod logs;
mod names;
mod site;
#[cfg(test)]
mod test_helpers;
mod top;
mod value;

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::time::Duration;

use http::{HeaderName, HeaderValue, StatusCode, Uri};

use crate::access::AccessEntry;
use crate::accesslog::LogFormat;
use crate::backend::system_one::{ApiToken, ClefModel};
use crate::block::BlockResponse;
use crate::conf::{self, Directive, one_arg, parse_positive_time};
use crate::error::ConfigError;
use crate::limits::{LimitSet, LimitZone, LocationConfig};
use crate::proxy::HeaderOp;
use crate::realip::RealIp;
use crate::router::HostPattern;
use crate::rules::SiteRules;

use top::build;

pub use names::{
    DECISION_DIRECTIVES, SITE_DIRECTIVES, STARTUP_ONLY_DIRECTIVES, TOP_LEVEL_DIRECTIVES,
};

/// Default HTTP status for hosts that match no site.
const DEFAULT_STATUS: u16 = 421;
/// Default connection cap.
const DEFAULT_MAX_CONNECTIONS: usize = 1024;

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
/// Default `pid` path, where the router writes its process id.
const DEFAULT_PID_FILE: &str = "/run/vigilant-heron.pid";

/// Validated configuration for the whole proxy.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    /// Socket address the binary binds, such as `0.0.0.0:8080`.
    pub listen: String,
    /// File where the router writes its process id while it runs, read by `-s`.
    pub pid_file: PathBuf,
    /// Runtime worker threads. `None` means one per CPU core (tokio's default).
    pub worker_threads: Option<usize>,
    /// Most connections served at the same time.
    pub max_connections: usize,
    /// How long a shutdown waits for open connections and WebSocket tunnels before
    /// closing them. `None` waits for them indefinitely, as nginx does by default.
    pub worker_shutdown_timeout: Option<Duration>,
    /// Header whose value is logged as `$request_id`. It is not sent to the decision backend.
    /// A missing or unusable value is replaced by a generated id.
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
    /// Most decision-backend calls in flight for one client address, keyed by the
    /// realip-resolved address. A request beyond it is `client_busy` without waiting.
    pub max_concurrency_per_client: usize,
    /// Bytes of the request body that are sent to the backend.
    pub inspect_body_bytes: usize,
    /// Extra header names to drop before sending, lowercased.
    pub redact_headers: Vec<String>,
    /// Extra body field names to redact before sending, lowercased. Each name is
    /// matched exactly, with the field name compared case-insensitively.
    pub redact_fields: Vec<String>,
    /// Whether the content of a multipart file part is replaced by `[REDACTED]`.
    pub redact_file_parts: bool,
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
    /// Strands Decider, a self-hosted server that speaks the System One protocol.
    /// The server has no authentication, so the token is optional.
    Strands {
        /// Model identifier sent in the request, such as `strands-decider`.
        model: String,
        /// Bearer token, read from the environment variable named in the config.
        /// `None` when `api_token_env` is omitted, and no `Authorization` header is sent.
        token: Option<ApiToken>,
    },
}

/// Configuration for one site, selected by the request `Host`.
#[derive(Debug, Clone, PartialEq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each site switch is its own on/off directive, read and checked independently"
)]
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
    /// `deny_paths` in lowercase, in the same order, for matching against lowercase views.
    pub(crate) deny_paths_lowered: Vec<String>,
    /// Path prefixes that are always blocked when the decision fails.
    pub fail_closed_paths: Vec<String>,
    /// `fail_closed_paths` in lowercase, in the same order, for matching against lowercase views.
    pub(crate) fail_closed_lowered: Vec<String>,
    /// What happens when the backend rate-limits the request or no slot is free in time.
    pub on_rate_limit: FailureAction,
    /// What happens when a client already holds its `max_concurrency_per_client` share.
    pub on_client_busy: FailureAction,
    /// What happens when the backend fails in any other way.
    pub on_decision_error: FailureAction,
    /// File extensions that may skip the backend, lowercased.
    pub static_extensions: Vec<String>,
    /// Path prefixes under which a static skip may apply, lowercased. Empty means anywhere.
    pub static_locations: Vec<String>,
    /// Query parameters, such as `ver`, that a static asset request may carry and still skip.
    pub static_query_params: Vec<String>,
    /// Whether a static asset request whose query is one bare token (`?wp-mce-49110-20250317`) may skip.
    pub static_query_token: bool,
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

/// Where an access log or the error log is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
    /// A file, appended to and reopened on SIGUSR1.
    File(PathBuf),
    /// A syslog server over UDP, in RFC 3164 form.
    Syslog {
        /// `host:port` of the server.
        server: String,
        /// The tag that starts each message, `vigilant-heron` by default.
        tag: String,
    },
}

impl Destination {
    /// A name for the destination in messages.
    pub(crate) fn label(&self) -> String {
        match self {
            Self::Stdout => "stdout".to_owned(),
            Self::Stderr => "stderr".to_owned(),
            Self::File(path) => path.display().to_string(),
            Self::Syslog { server, .. } => format!("syslog:{server}"),
        }
    }
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

/// A configuration read for a check that calls no backend: `-t`, `-T` and `test-request`.
///
/// It is for checks only. Do not serve from it: a token that is not set holds a
/// placeholder, and the router would start without a real token.
#[derive(Debug, Clone, PartialEq)]
pub struct CheckedConfig {
    /// The configuration.
    pub config: Config,
    /// The token variable that is not set, when the configuration names one. The router
    /// will not start without it.
    pub unset_token: Option<String>,
}

/// The token a check uses for a variable that is not set. A check calls no backend, so
/// the placeholder is never sent.
const UNSET_TOKEN_PLACEHOLDER: &str = "not-set-for-check";

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

    /// Reads the configuration file at `path` for a check that calls no backend, as
    /// `-t`, `-T` and `test-request` do. A token variable that is not set is not an
    /// error here: its name is returned in [`CheckedConfig::unset_token`], and the
    /// check passes on the rest of the file. A variable that is set but blank is still
    /// an error. [`Config::load`] is unchanged, so starting the router still needs it.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Config::load`], except for an unset token variable.
    pub fn load_for_check(path: &Path) -> Result<CheckedConfig, ConfigError> {
        let directives = conf::load_file(path)?;
        check_directives(&directives, &|name| std::env::var(name).ok())
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

/// The settings a process command needs, read without validating the whole file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSettings {
    /// Where the router writes its process id. The `pid` directive, or the default.
    pub pid_file: PathBuf,
    /// The `worker_shutdown_timeout` directive, when one is set.
    pub worker_shutdown_timeout: Option<Duration>,
}

/// Reads the `pid` and `worker_shutdown_timeout` settings of the configuration at `path`.
///
/// Only the file and its includes are read: the rest of the configuration is not
/// validated, so `-s`, `stop` and `restart` work even when the token variables are
/// not set in their shell.
///
/// # Errors
///
/// Returns the read, syntax and include errors of the file, and an error for a
/// `worker_shutdown_timeout` value that is not a positive time.
pub fn process_settings(path: &Path) -> Result<ProcessSettings, ConfigError> {
    let directives = conf::load_file(path)?;
    let mut settings = ProcessSettings {
        pid_file: PathBuf::from(DEFAULT_PID_FILE),
        worker_shutdown_timeout: None,
    };
    for directive in &directives {
        match directive.name.as_str() {
            "pid" => settings.pid_file = PathBuf::from(one_arg(directive)?),
            "worker_shutdown_timeout" => {
                settings.worker_shutdown_timeout =
                    Some(parse_positive_time(directive, one_arg(directive)?)?);
            }
            _ => {}
        }
    }
    Ok(settings)
}

/// Returns the configuration at `path` as text, with each top-level include
/// expanded in place. Each file starts with a `# configuration file <path>:` line.
///
/// The text is the file as written, so comments stay. Directives hold the names
/// of token variables, never their values, so nothing secret is printed.
///
/// # Errors
///
/// Returns the same errors as [`Config::load`] for reading and parsing, and an
/// include error when an include is not written on one line.
pub fn dump_configuration(path: &Path) -> Result<String, ConfigError> {
    conf::dump_file(path)
}

/// Builds the configuration for a check. A token variable that `lookup` does not give is
/// replaced by [`UNSET_TOKEN_PLACEHOLDER`] and recorded, so the build goes on.
fn check_directives<F>(directives: &[Directive], lookup: &F) -> Result<CheckedConfig, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let unset = RefCell::new(None);
    let config = build(directives, &|name: &str| {
        lookup(name).or_else(|| {
            *unset.borrow_mut() = Some(name.to_owned());
            Some(UNSET_TOKEN_PLACEHOLDER.to_owned())
        })
    })?;
    Ok(CheckedConfig {
        config,
        unset_token: unset.into_inner(),
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rstest::rstest;

    use super::*;
    use crate::config::test_helpers::{BASE, first_site, message, parse, with_sites};

    #[test]
    fn minimal_configuration_gets_the_documented_defaults() -> Result<(), ConfigError> {
        let config = parse(BASE)?;
        assert_eq!(config.listen, "127.0.0.1:8080");
        assert_eq!(config.worker_threads, None);
        assert_eq!(config.max_connections, 1024);
        assert_eq!(config.default_status, StatusCode::MISDIRECTED_REQUEST);
        assert_eq!(config.decision.timeout, Duration::from_millis(2000));
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
        // Restored to allow: the fail-closed default was reverted (see CHANGELOG).
        assert_eq!(site.on_rate_limit, FailureAction::Allow);
        assert_eq!(site.on_client_busy, FailureAction::Block);
        assert_eq!(site.on_decision_error, FailureAction::Allow);
        assert_eq!(site.mode, Mode::Enforce);
        assert_eq!(site.action, SiteAction::Block);
        assert!(site.static_extensions.contains(&"woff2".to_owned()));
        assert_eq!(site.static_extensions.len(), 13);
        assert_eq!(site.access_logs, None);
        Ok(())
    }

    /// Reads `text` for a check, with the token variables read through `lookup`.
    fn check(
        text: &str,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<CheckedConfig, ConfigError> {
        let directives = conf::parse_source(text, "test.conf")?;
        check_directives(&directives, &lookup)
    }

    const UNSET_TOKEN_TEXT: &str = "listen 127.0.0.1:8080;\ndecision {\n    api_token_env ABSENT;\n}\n\
                                    site example.com {\n    upstream http://upstream:80;\n}\n";

    #[test]
    fn a_check_names_an_unset_token_variable_and_still_loads() -> Result<(), ConfigError> {
        let checked = check(UNSET_TOKEN_TEXT, |_| None)?;
        assert_eq!(checked.unset_token.as_deref(), Some("ABSENT"));
        assert!(matches!(
            &checked.config.decision.backend,
            BackendConfig::Jev { token, .. } if token.expose() == UNSET_TOKEN_PLACEHOLDER
        ));
        Ok(())
    }

    #[test]
    fn a_check_names_no_token_variable_when_the_variable_is_set() -> Result<(), ConfigError> {
        let checked = check(UNSET_TOKEN_TEXT, |_| Some("tok-123".to_owned()))?;
        assert_eq!(checked.unset_token, None);
        assert!(matches!(
            &checked.config.decision.backend,
            BackendConfig::Jev { token, .. } if token.expose() == "tok-123"
        ));
        Ok(())
    }

    #[test]
    fn a_check_still_rejects_a_blank_token_variable() {
        let result = check(UNSET_TOKEN_TEXT, |_| Some("   ".to_owned()));
        assert!(message(result).contains("ABSENT (api_token_env) is empty"));
    }

    #[test]
    fn a_check_still_reports_other_errors_with_their_line() {
        let text = "listen 127.0.0.1:8080;\ndecision {\n    backend nope;\n}\n\
                    site example.com {\n    upstream http://upstream:80;\n}\n";
        assert!(message(check(text, |_| None)).contains("test.conf:3:"));
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
    fn a_host_listed_by_two_sites_is_rejected() {
        let text = format!("{BASE}site example.com {{\n    upstream http://other:80;\n}}\n");
        assert!(
            message(parse(&text)).contains("host \"example.com\" is listed by more than one site")
        );
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
}

#[cfg(test)]
mod connection_limit_tests {
    use std::time::Duration;

    use rstest::rstest;

    use super::*;
    use crate::config::test_helpers::connection_limit::{
        DECISION, PLAIN_BASE, SITE, message, parse, parse_plain,
    };

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
    fn max_connections_must_be_at_least_one_and_is_taken_as_written() -> Result<(), ConfigError> {
        assert!(
            message(parse_plain(&format!("max_connections 0;\n{PLAIN_BASE}")))
                .contains("\"max_connections\" must be at least 1")
        );
        assert_eq!(
            parse_plain(&format!("max_connections 5;\n{PLAIN_BASE}"))?.max_connections,
            5
        );
        Ok(())
    }

    #[test]
    fn process_settings_reads_the_worker_shutdown_timeout() -> Result<(), std::io::Error> {
        let dir = std::env::temp_dir().join(format!("vh-process-settings-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("router.conf");
        std::fs::write(&path, format!("worker_shutdown_timeout 7s;\n{PLAIN_BASE}"))?;
        let settings = process_settings(&path);
        let _ = std::fs::remove_dir_all(&dir);
        let settings = settings.map_err(|error| std::io::Error::other(error.to_string()))?;
        assert_eq!(
            settings.worker_shutdown_timeout,
            Some(Duration::from_secs(7))
        );
        Ok(())
    }
}
