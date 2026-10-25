//! A reverse proxy that screens web requests before they reach the site.
//!
//! Each request is matched to a site by its `Host` header. Requests that match
//! a deny rule are blocked without asking the decision backend. Static assets
//! are forwarded without asking it either. Every other request is sent, with
//! credentials removed, to the decision backend, which returns two scores. The
//! policy turns the scores into a block, a redirect or a forward to the upstream.
//!
//! Shadow mode forwards every request and only records what would have happened.
//! The [`serve`] function runs the proxy on a listener that the caller binds.

mod clef;
mod config;
mod decision;
mod error;
mod policy;
mod prefilter;
mod proxy;
mod router;
mod sanitize;
mod server;
#[cfg(test)]
mod test_support;

pub use clef::{ApiToken, ClefModel};
pub use config::{BackendConfig, Config, DecisionConfig, LogFormat, Mode, SiteAction, SiteConfig};
pub use error::{ConfigError, ServeError};
pub use server::serve;
