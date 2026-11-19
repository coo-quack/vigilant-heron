//! The decision backends: the sanitized event sent to them (`sanitize`), the
//! transport and limits shared by all of them and the JSON HTTP backend
//! (`decision`), the System One protocol (`system_one`), and the configured
//! backend that the server calls.
//!
//! The three are modules rather than re-exports, so a path such as
//! `backend::decision::Limits` says which of them an item belongs to.

pub(crate) mod decision;
pub(crate) mod sanitize;
pub(crate) mod system_one;

use crate::error::DecisionError;

use decision::{HttpDecisionBackend, Verdict};
use sanitize::DecisionEvent;
use system_one::SystemOneBackend;

/// The configured decision backend.
pub(crate) enum Backend {
    /// The JSON protocol over HTTP.
    Http(HttpDecisionBackend),
    /// The System One protocol: Cloudflare Clef, `TypeSafe` Jev, Strands Decider, or a server that speaks it.
    SystemOne(SystemOneBackend),
}

impl Backend {
    /// Asks the configured backend for a verdict on `event`.
    pub(crate) async fn decide(&self, event: &DecisionEvent) -> Result<Verdict, DecisionError> {
        match self {
            Self::Http(backend) => backend.decide(event).await,
            Self::SystemOne(backend) => backend.decide(event).await,
        }
    }
}
