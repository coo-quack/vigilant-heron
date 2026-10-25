//! Error types shared across the crate.

use http::StatusCode;

/// Errors found while loading or validating a configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The configuration file could not be read.
    #[error("cannot read config file {}: {source}", path.display())]
    Read {
        /// Path that was read.
        path: std::path::PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The text is not valid TOML or does not match the expected shape.
    #[error("config is not valid TOML for this schema: {0}")]
    Parse(#[from] toml::de::Error),
    /// No `[[sites]]` table was given.
    #[error("config must declare at least one [[sites]] table")]
    NoSites,
    /// A site has an empty `hosts` list.
    #[error("sites[{site}] has no hosts")]
    EmptyHosts {
        /// Zero-based index into `sites`.
        site: usize,
    },
    /// A site lists a host that normalizes to nothing.
    #[error("sites[{site}] has an invalid host {value:?}")]
    InvalidHost {
        /// Zero-based index into `sites`.
        site: usize,
        /// Host exactly as written in the config.
        value: String,
    },
    /// The same normalized host appears twice.
    #[error("host {host:?} is listed more than once")]
    DuplicateHost {
        /// Normalized host name.
        host: String,
    },
    /// A threshold is outside `0..=1` or is NaN.
    #[error("sites[{site}].{name} must be between 0 and 1, got {value}")]
    ThresholdOutOfRange {
        /// Zero-based index into `sites`.
        site: usize,
        /// Name of the threshold key.
        name: &'static str,
        /// Value that was rejected.
        value: f64,
    },
    /// `action = "redirect"` without `redirect_to`.
    #[error("sites[{site}] uses action = \"redirect\" and needs redirect_to")]
    MissingRedirectTo {
        /// Zero-based index into `sites`.
        site: usize,
    },
    /// `redirect_to` given together with `action = "block"`.
    #[error("sites[{site}] sets redirect_to but action is \"block\"")]
    UnexpectedRedirectTo {
        /// Zero-based index into `sites`.
        site: usize,
    },
    /// `redirect_to` cannot be sent as a `Location` header value.
    #[error("sites[{site}].redirect_to is not a valid header value: {value:?}")]
    InvalidRedirectTo {
        /// Zero-based index into `sites`.
        site: usize,
        /// Value that was rejected.
        value: String,
    },
    /// An upstream is not an absolute `http://` URI.
    #[error("sites[{site}].upstream must be an absolute http:// URI, got {value:?}")]
    InvalidUpstream {
        /// Zero-based index into `sites`.
        site: usize,
        /// Value that was rejected.
        value: String,
    },
    /// `decision.url` is not an absolute `http://` URI.
    #[error("decision.url must be an absolute http:// URI, got {value:?}")]
    InvalidDecisionUrl {
        /// Value that was rejected.
        value: String,
    },
    /// `client_ip_header` is not a valid header name.
    #[error("client_ip_header is not a valid header name: {value:?}")]
    InvalidClientIpHeader {
        /// Value that was rejected.
        value: String,
    },
    /// `decision.timeout_ms` is zero.
    #[error("decision.timeout_ms must be greater than 0")]
    ZeroTimeout,
    /// `decision.inspect_body_bytes` is larger than `decision.max_body_bytes`.
    #[error(
        "decision.inspect_body_bytes ({inspect}) must not exceed decision.max_body_bytes ({max})"
    )]
    InspectExceedsMax {
        /// Configured inspection size.
        inspect: usize,
        /// Configured body size limit.
        max: usize,
    },
    /// `default.status` is not a 4xx or 5xx code.
    #[error("default.status must be a 4xx or 5xx code, got {status}")]
    InvalidDefaultStatus {
        /// Status that was rejected.
        status: u16,
    },
}

/// Errors that stop the server loop.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// The listener failed to accept a connection.
    #[error("accepting a connection failed")]
    Accept(#[source] std::io::Error),
}

/// A value that is not a probability.
#[derive(Debug, Clone, Copy, PartialEq, thiserror::Error)]
#[error("probability {value} is outside 0..=1")]
pub(crate) struct ProbabilityError {
    /// Value that was rejected.
    pub(crate) value: f64,
}

/// Why the decision backend did not give a usable verdict.
#[derive(Debug, thiserror::Error)]
pub(crate) enum DecisionError {
    /// The backend did not answer in time.
    #[error("decision backend did not answer within the timeout")]
    Timeout,
    /// The HTTP exchange failed before a response arrived.
    #[error("decision backend request failed")]
    Transport(#[source] hyper_util::client::legacy::Error),
    /// The backend answered with a non-2xx status.
    #[error("decision backend answered with status {0}")]
    Status(StatusCode),
    /// The response body could not be read.
    #[error("decision backend body could not be read")]
    Body(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The request or response JSON is malformed.
    #[error("decision backend JSON is invalid")]
    Json(#[from] serde_json::Error),
    /// The decision request could not be built.
    #[error("decision backend request could not be built")]
    Request(#[from] http::Error),
    /// A returned score is not a probability.
    #[error(transparent)]
    Probability(#[from] ProbabilityError),
}

/// Why an upstream request could not be sent.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ProxyError {
    /// The request target built from the upstream is not a valid URI.
    #[error("upstream request target is invalid")]
    Target(#[from] http::uri::InvalidUri),
    /// The upstream could not be reached or did not answer.
    #[error("upstream request failed")]
    Request(#[source] hyper_util::client::legacy::Error),
}
