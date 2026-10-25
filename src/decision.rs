//! The decision backend: the model-facing HTTP call and its verdict type.

use std::future::Future;
use std::time::Duration;

use bytes::Bytes;
use http::header::CONTENT_TYPE;
use http::{Method, Request, Uri};
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde::Deserialize;

use crate::error::{DecisionError, ProbabilityError};
use crate::sanitize::DecisionEvent;

/// Largest decision response body that is read.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// A number in `0..=1`, validated on construction.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Probability(f64);

impl Probability {
    /// Accepts `value` only when it lies in `0..=1`; NaN is rejected.
    pub(crate) fn new(value: f64) -> Result<Self, ProbabilityError> {
        if (0.0..=1.0).contains(&value) {
            Ok(Self(value))
        } else {
            Err(ProbabilityError { value })
        }
    }

    /// Returns the wrapped value.
    pub(crate) fn value(self) -> f64 {
        self.0
    }
}

/// The two scores returned by the decision backend.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Verdict {
    /// Probability that the request is an attack.
    pub(crate) attack: Probability,
    /// Probability that the request tries to instruct the AI.
    pub(crate) ai_instruction: Probability,
}

#[derive(Deserialize)]
struct RawVerdict {
    attack: f64,
    ai_instruction: f64,
}

/// Something that can score a sanitized event.
pub(crate) trait DecisionBackend: Send + Sync + 'static {
    /// Asks the backend for a verdict on `event`.
    fn decide(
        &self,
        event: &DecisionEvent,
    ) -> impl Future<Output = Result<Verdict, DecisionError>> + Send;
}

/// Calls the decision backend over HTTP with a JSON body.
pub(crate) struct HttpDecisionBackend {
    client: Client<HttpConnector, Full<Bytes>>,
    url: Uri,
    timeout: Duration,
}

impl HttpDecisionBackend {
    /// Creates a backend that posts to `url` and gives up after `timeout`.
    pub(crate) fn new(url: Uri, timeout: Duration) -> Self {
        Self {
            client: Client::builder(TokioExecutor::new()).build_http(),
            url,
            timeout,
        }
    }

    async fn exchange(&self, event: &DecisionEvent) -> Result<Verdict, DecisionError> {
        let payload = serde_json::to_vec(event)?;
        let request = Request::builder()
            .method(Method::POST)
            .uri(self.url.clone())
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(payload)))?;
        let response = self
            .client
            .request(request)
            .await
            .map_err(DecisionError::Transport)?;
        let status = response.status();
        if !status.is_success() {
            return Err(DecisionError::Status(status));
        }
        let body = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
            .collect()
            .await
            .map_err(DecisionError::Body)?
            .to_bytes();
        let raw: RawVerdict = serde_json::from_slice(&body)?;
        Ok(Verdict {
            attack: Probability::new(raw.attack)?,
            ai_instruction: Probability::new(raw.ai_instruction)?,
        })
    }
}

impl DecisionBackend for HttpDecisionBackend {
    async fn decide(&self, event: &DecisionEvent) -> Result<Verdict, DecisionError> {
        match tokio::time::timeout(self.timeout, self.exchange(event)).await {
            Ok(result) => result,
            Err(_elapsed) => Err(DecisionError::Timeout),
        }
    }
}

/// Builds a verdict from literals; only for values inside `0..=1`.
#[cfg(test)]
pub(crate) fn verdict(attack: f64, ai_instruction: f64) -> Verdict {
    Verdict {
        attack: Probability(attack),
        ai_instruction: Probability(ai_instruction),
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::lower_bound(0.0)]
    #[case::upper_bound(1.0)]
    #[case::middle(0.5)]
    #[case::tiny(f64::MIN_POSITIVE)]
    fn probability_accepts_values_in_the_unit_interval(#[case] value: f64) {
        assert_eq!(
            Probability::new(value).map(Probability::value).ok(),
            Some(value)
        );
    }

    #[rstest]
    #[case::nan(f64::NAN)]
    #[case::negative(-0.1)]
    #[case::above_one(1.1)]
    #[case::infinity(f64::INFINITY)]
    #[case::negative_infinity(f64::NEG_INFINITY)]
    fn probability_rejects_nan_and_values_outside_the_unit_interval(#[case] value: f64) {
        assert!(Probability::new(value).is_err());
    }
}
