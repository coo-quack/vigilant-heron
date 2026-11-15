//! A reverse proxy that screens web requests before they reach the site.
//!
//! Each request is matched to a site by its `Host` header. Requests that match
//! a block rule or a `deny_path` entry are blocked without asking the decision
//! backend. Static assets are forwarded without asking it either. Every other
//! request is sent, with credentials removed, to the decision backend, which
//! returns two scores. The policy turns the scores into a block, a redirect or
//! a forward to the upstream.
//!
//! Shadow mode forwards every request and only records what would have happened.
//! The configuration uses nginx-style directives. [`serve`] runs the proxy on a
//! listener that the caller binds.

mod access;
mod accesslog;
mod backend;
mod block;
mod body;
mod conf;
mod config;
mod error;
mod finish;
mod limits;
mod log_lines;
mod logsink;
mod phase;
mod policy;
mod prefilter;
mod proxy;
mod realip;
mod request_check;
mod request_id;
mod router;
mod rules;
mod server;
mod shadow_report;
mod skip_suggest;
mod sync;
#[cfg(test)]
mod test_support;
mod transport;
mod tunnel;

pub use accesslog::LogFormat;
pub use backend::system_one::{ApiToken, ClefModel};
pub use block::{BlockResponse, BlockStatus};
pub use config::{
    AccessLogConfig, BackendConfig, CheckedConfig, Config, ConnectionConfig, DecisionConfig,
    Destination, ErrorLogConfig, FailureAction, HeaderBuffers, LingeringClose, LogLevel, Mode,
    ProcessSettings, SiteAction, SiteConfig, SiteTimeouts, dump_configuration, process_settings,
};
pub use error::{ConfigError, ServeError};
pub use logsink::{ErrorLogHandle, install_error_log};
pub use realip::{IpNet, RealIp};
pub use request_check::{CheckError, Outcome, RequestCheck, check_request, check_request_with};
pub use server::{serve, serve_reloadable};
pub use shadow_report::{ShadowOptions, ShadowReport};
pub use skip_suggest::{Candidate, SuggestOptions, SuggestReport, suggest_skip_rules};

/// The directive names the configuration builder accepts, read by the documentation drift
/// check in `tests/docs.rs`.
#[doc(hidden)]
pub mod directives {
    pub use crate::config::{
        DECISION_DIRECTIVES, SITE_DIRECTIVES, STARTUP_ONLY_DIRECTIVES, TOP_LEVEL_DIRECTIVES,
    };
}
