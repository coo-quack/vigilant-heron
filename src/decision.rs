//! The decision backends: the transport shared by all of them, the JSON HTTP
//! protocol, the System One protocol in [`crate::system_one`], and the backend enum.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{AUTHORIZATION, CONTENT_TYPE, RETRY_AFTER};
use http::{Method, Request, StatusCode, Uri};
use http_body_util::{BodyExt, Full, Limited};
use hyper_rustls::HttpsConnector;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rustls::{ClientConfig, RootCertStore};
use serde::Deserialize;
use tokio::sync::Semaphore;

use crate::error::{DecisionError, ProbabilityError, ServeError};
use crate::sanitize::DecisionEvent;
use crate::system_one::SystemOneBackend;

/// Largest decision response body that is read.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// The client used for every decision request, with TLS for `https` URIs.
pub(crate) type DecisionClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

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

/// The scores returned by a decision backend.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Verdict {
    /// Probability that the request is an attack.
    pub(crate) attack: Probability,
    /// Probability that the request tries to instruct the AI.
    pub(crate) ai_instruction: Probability,
    /// Kind of attack, when the backend names one. Logged only.
    pub(crate) category: Option<String>,
    /// Input tokens the backend billed for the request, when it reports them. Logged only.
    pub(crate) input_tokens: Option<u64>,
}

#[derive(Deserialize)]
struct RawVerdict {
    attack: f64,
    ai_instruction: f64,
    #[serde(default)]
    category: Option<String>,
}

/// Something that can score a sanitized event.
pub(crate) trait DecisionBackend: Send + Sync + 'static {
    /// Asks the backend for a verdict on `event`.
    fn decide(
        &self,
        event: &DecisionEvent,
    ) -> impl Future<Output = Result<Verdict, DecisionError>> + Send;
}

/// Builds the HTTP client. TLS uses the operating system's root certificates.
pub(crate) fn decision_client() -> Result<DecisionClient, ServeError> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for certificate in native.certs {
        // A certificate the store rejects is skipped; the others still apply.
        let _ = roots.add(certificate);
    }
    if roots.is_empty() {
        tracing::warn!(
            "no operating system root certificates were loaded; https decision backends will fail"
        );
    }
    let tls =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(ServeError::Tls)?
            .with_root_certificates(roots)
            .with_no_client_auth();
    let connector = HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .build();
    Ok(Client::builder(TokioExecutor::new()).build(connector))
}

/// Posts a JSON payload and returns the response body, bounded in size and time.
///
/// `bearer` is sent as an `Authorization: Bearer` header when given. Waiting for a
/// slot in `slots` counts against the same `timeout`; running out of time while
/// waiting is [`DecisionError::Busy`], and running out during the exchange is
/// [`DecisionError::Timeout`].
pub(crate) async fn post_json(
    client: &DecisionClient,
    url: &Uri,
    bearer: Option<&str>,
    payload: Vec<u8>,
    timeout: Duration,
    slots: &Semaphore,
) -> Result<Bytes, DecisionError> {
    let deadline = tokio::time::Instant::now() + timeout;
    let Ok(Ok(_slot)) = tokio::time::timeout_at(deadline, slots.acquire()).await else {
        return Err(DecisionError::Busy);
    };
    match tokio::time::timeout_at(deadline, exchange(client, url, bearer, payload)).await {
        Ok(result) => result,
        Err(_elapsed) => Err(DecisionError::Timeout),
    }
}

async fn exchange(
    client: &DecisionClient,
    url: &Uri,
    bearer: Option<&str>,
    payload: Vec<u8>,
) -> Result<Bytes, DecisionError> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(url.clone())
        .header(CONTENT_TYPE, "application/json");
    if let Some(token) = bearer {
        builder = builder.header(AUTHORIZATION, format!("Bearer {token}"));
    }
    let request = builder.body(Full::new(Bytes::from(payload)))?;
    let response = client
        .request(request)
        .await
        .map_err(DecisionError::Transport)?;
    let status = response.status();
    if status == StatusCode::TOO_MANY_REQUESTS {
        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.chars().take(64).collect());
        return Err(DecisionError::RateLimited { retry_after });
    }
    if !status.is_success() {
        return Err(DecisionError::Status(status));
    }
    let body = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
        .collect()
        .await
        .map_err(DecisionError::Body)?
        .to_bytes();
    Ok(body)
}

/// Calls a backend that speaks the JSON protocol documented in the README.
pub(crate) struct HttpDecisionBackend {
    client: DecisionClient,
    url: Uri,
    timeout: Duration,
    slots: Arc<Semaphore>,
}

impl HttpDecisionBackend {
    /// Creates a backend that posts to `url`, gives up after `timeout`, and takes
    /// a slot from `slots` for each call.
    pub(crate) fn new(
        client: DecisionClient,
        url: Uri,
        timeout: Duration,
        slots: Arc<Semaphore>,
    ) -> Self {
        Self {
            client,
            url,
            timeout,
            slots,
        }
    }
}

impl DecisionBackend for HttpDecisionBackend {
    async fn decide(&self, event: &DecisionEvent) -> Result<Verdict, DecisionError> {
        let payload = serde_json::to_vec(event)?;
        let body = post_json(
            &self.client,
            &self.url,
            None,
            payload,
            self.timeout,
            &self.slots,
        )
        .await?;
        let raw: RawVerdict = serde_json::from_slice(&body)?;
        Ok(Verdict {
            attack: Probability::new(raw.attack)?,
            ai_instruction: Probability::new(raw.ai_instruction)?,
            category: raw.category,
            input_tokens: None,
        })
    }
}

/// The configured decision backend.
pub(crate) enum Backend {
    /// The JSON protocol over HTTP.
    Http(HttpDecisionBackend),
    /// The System One protocol: Cloudflare Clef, `TypeSafe` Jev, or a server that speaks it.
    SystemOne(SystemOneBackend),
}

impl DecisionBackend for Backend {
    async fn decide(&self, event: &DecisionEvent) -> Result<Verdict, DecisionError> {
        match self {
            Self::Http(backend) => backend.decide(event).await,
            Self::SystemOne(backend) => backend.decide(event).await,
        }
    }
}

#[cfg(test)]
pub(crate) fn verdict(attack: f64, ai_instruction: f64) -> Verdict {
    Verdict {
        attack: Probability(attack),
        ai_instruction: Probability(ai_instruction),
        category: None,
        input_tokens: None,
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[tokio::test]
    async fn post_json_reports_busy_when_no_slot_frees_within_the_timeout()
    -> Result<(), Box<dyn std::error::Error>> {
        let client = decision_client()?;
        let url: Uri = "http://127.0.0.1:9/decide".parse()?;
        let slots = Semaphore::new(1);
        // Hold the only slot for the whole test, so the call can only wait.
        let _held = slots.acquire().await?;
        let result = post_json(
            &client,
            &url,
            None,
            Vec::new(),
            Duration::from_millis(50),
            &slots,
        )
        .await;
        assert!(matches!(result, Err(DecisionError::Busy)));
        Ok(())
    }

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
