//! Error types shared across the crate.

use http::StatusCode;

/// Errors found while loading or validating a configuration.
///
/// Every error that comes from the file names the file and the line, so the
/// message reads `file:line: problem`.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A configuration file could not be read.
    #[error("cannot read configuration file {}: {source}", path.display())]
    Read {
        /// Path that was read.
        path: std::path::PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The text is not valid configuration syntax.
    #[error("{file}:{line}: {message}")]
    Syntax {
        /// File the text came from, as named by the user.
        file: String,
        /// One-based line number.
        line: usize,
        /// What is wrong.
        message: String,
    },
    /// An `include` names a missing file, is nested too deeply, or forms a cycle.
    #[error("{file}:{line}: {message}")]
    Include {
        /// File that holds the `include` directive.
        file: String,
        /// One-based line number of the directive.
        line: usize,
        /// What is wrong.
        message: String,
    },
    /// A directive has a value or context the configuration does not allow.
    #[error("{file}:{line}: {message}")]
    Invalid {
        /// File that holds the directive.
        file: String,
        /// One-based line number of the directive.
        line: usize,
        /// What is wrong, naming the directive.
        message: String,
    },
}

/// Errors that stop the server loop.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// The listener failed to accept a connection.
    #[error("accepting a connection failed")]
    Accept(#[source] std::io::Error),
    /// The TLS client for the decision backend could not be set up.
    #[error("TLS setup for the decision backend failed")]
    Tls(#[source] rustls::Error),
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
    /// No local concurrency slot became free within the timeout.
    #[error("no decision slot became free within the timeout")]
    Busy,
    /// The backend answered HTTP 429. `Retry-After` is kept for the log only.
    #[error("decision backend rate-limited the request")]
    RateLimited {
        /// Raw `Retry-After` header, when the backend sent one.
        retry_after: Option<String>,
    },
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
    /// The backend reported `success: false`.
    #[error("decision backend reported success = false")]
    Rejected,
    /// The response has no answer with this id.
    #[error("decision backend returned no answer for {id}")]
    MissingAnswer {
        /// Question id that was expected.
        id: &'static str,
    },
    /// An answer has a different type than its question.
    #[error("decision backend returned the wrong answer type for {id}")]
    AnswerType {
        /// Question id whose answer was malformed.
        id: &'static str,
    },
}

impl DecisionError {
    /// Returns the specific cause written to the decision log.
    pub(crate) fn cause(&self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Busy => "backend_busy",
            Self::RateLimited { .. } => "rate_limited",
            Self::Transport(_) => "connection",
            Self::Status(_) => "http_status",
            Self::Body(_) => "body",
            Self::Json(_) => "parse",
            Self::Request(_) => "request",
            Self::Probability(_) => "invalid_score",
            Self::Rejected => "rejected",
            Self::MissingAnswer { .. } | Self::AnswerType { .. } => "invalid_response",
        }
    }
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
