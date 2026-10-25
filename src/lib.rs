//! A reverse proxy that screens web requests before they reach the site.
//!
//! Each request is matched to a site by its `Host` header. Requests that match
//! a deny rule are blocked without asking the decision backend. Static assets
//! are forwarded without asking it either. Every other request is sent, with
//! credentials removed, to the decision backend, which returns two scores. The
//! policy turns the scores into a block, a redirect or a forward to the upstream.
//!
//! Shadow mode forwards every request and only records what would have happened.
//! The configuration uses nginx-style directives. [`serve`] runs the proxy on a
//! listener that the caller binds.

mod access;
mod accesslog;
mod body;
mod conf;
mod config;
mod decision;
mod error;
mod logsink;
mod policy;
mod prefilter;
mod proxy;
mod realip;
mod router;
mod rules;
mod sanitize;
mod server;
mod system_one;
#[cfg(test)]
mod test_support;
mod transport;

pub use accesslog::LogFormat;
pub use config::{
    AccessLogConfig, BackendConfig, Config, ConnectionConfig, DecisionConfig, ErrorLogConfig,
    FailureAction, HeaderBuffers, LingeringClose, LogLevel, Mode, SiteAction, SiteConfig,
    SiteTimeouts,
};
pub use error::{ConfigError, ServeError};
pub use logsink::{Destination, ErrorLogHandle, install_error_log};
pub use realip::{IpNet, RealIp};
pub use server::serve;
pub use system_one::{ApiToken, ClefModel};
