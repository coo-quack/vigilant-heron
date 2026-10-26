//! The decision backends: the transport shared by all of them, the JSON HTTP
//! protocol, the System One protocol in [`crate::system_one`], and the backend enum.

use std::future::Future;
use std::net::IpAddr;
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
use tokio::sync::{Semaphore, SemaphorePermit};

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

/// The limits that bound one decision call, shared by all calls of a backend.
#[derive(Clone)]
pub(crate) struct Limits {
    /// Total time for one call, including any wait for a slot.
    pub(crate) timeout: Duration,
    /// Longest wait for a slot. Zero means a call fails at once when no slot is free.
    pub(crate) queue_timeout: Duration,
    /// Concurrent calls allowed.
    pub(crate) slots: Arc<Semaphore>,
}

/// Decision calls in flight per client address, bounded by `max_concurrency_per_client`.
///
/// A client that already holds its share is refused at once, so it cannot take the
/// global slots that other clients need. The key is the client address chosen by the
/// realip settings. A distributed attack from many addresses is not limited by this.
pub(crate) struct ClientSlots {
    /// The most calls one address may have in flight.
    limit: usize,
    /// Calls in flight per address. An address with none is removed.
    held: std::sync::Mutex<std::collections::HashMap<IpAddr, usize>>,
}

impl ClientSlots {
    /// Creates a table that allows `limit` calls per address.
    pub(crate) fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            held: std::sync::Mutex::new(std::collections::HashMap::new()),
        })
    }

    /// The most calls one address may have in flight.
    pub(crate) fn limit(&self) -> usize {
        self.limit
    }

    /// Takes one call for `client`, or returns `None` when the client already holds its share.
    pub(crate) fn take(self: &Arc<Self>, client: IpAddr) -> Option<ClientSlot> {
        let mut held = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = held.entry(client).or_insert(0);
        if *count >= self.limit {
            return None;
        }
        *count += 1;
        Some(ClientSlot {
            table: Arc::clone(self),
            client,
        })
    }
}

/// One call of a client, released when dropped.
pub(crate) struct ClientSlot {
    /// The table the call was taken from.
    table: Arc<ClientSlots>,
    /// The client address that holds the call.
    client: IpAddr,
}

impl Drop for ClientSlot {
    fn drop(&mut self) {
        let mut held = self
            .table
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = held.get_mut(&self.client) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                held.remove(&self.client);
            }
        }
    }
}

/// Posts a JSON payload and returns the response body, bounded in size and time.
///
/// `bearer` is sent as an `Authorization: Bearer` header when given. The wait for
/// a slot is bounded by `queue_timeout` only: if no slot is obtained in that
/// window the result is always [`DecisionError::Busy`]. The exchange then gets
/// the rest of `timeout`, and running out there is [`DecisionError::Timeout`].
pub(crate) async fn post_json(
    client: &DecisionClient,
    url: &Uri,
    bearer: Option<&str>,
    payload: Vec<u8>,
    limits: &Limits,
) -> Result<Bytes, DecisionError> {
    let started = tokio::time::Instant::now();
    let _slot = acquire_slot(limits).await?;
    let remaining = limits.timeout.saturating_sub(started.elapsed());
    match tokio::time::timeout(remaining, exchange(client, url, bearer, payload)).await {
        Ok(result) => result,
        Err(_elapsed) => Err(DecisionError::Timeout),
    }
}

async fn acquire_slot(limits: &Limits) -> Result<SemaphorePermit<'_>, DecisionError> {
    if limits.queue_timeout.is_zero() {
        return limits.slots.try_acquire().map_err(|_| DecisionError::Busy);
    }
    match tokio::time::timeout(limits.queue_timeout, limits.slots.acquire()).await {
        Ok(Ok(permit)) => Ok(permit),
        Ok(Err(_)) | Err(_) => Err(DecisionError::Busy),
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
    limits: Limits,
}

impl HttpDecisionBackend {
    /// Creates a backend that posts to `url` under `limits`.
    pub(crate) fn new(client: DecisionClient, url: Uri, limits: Limits) -> Self {
        Self {
            client,
            url,
            limits,
        }
    }
}

impl DecisionBackend for HttpDecisionBackend {
    async fn decide(&self, event: &DecisionEvent) -> Result<Verdict, DecisionError> {
        let payload = serde_json::to_vec(event)?;
        let body = post_json(&self.client, &self.url, None, payload, &self.limits).await?;
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
mod client_slot_tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::ClientSlots;

    #[test]
    fn a_client_is_refused_beyond_its_share_and_regains_it_on_drop() {
        let table = ClientSlots::new(2);
        let client = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let other = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));
        let first = table.take(client);
        let second = table.take(client);
        assert!(first.is_some() && second.is_some());
        assert!(table.take(client).is_none());
        assert!(
            table.take(other).is_some(),
            "another client is not affected"
        );
        drop(first);
        assert!(table.take(client).is_some());
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    fn limits(queue_ms: u64, slots: Arc<Semaphore>) -> Limits {
        Limits {
            timeout: Duration::from_millis(500),
            queue_timeout: Duration::from_millis(queue_ms),
            slots,
        }
    }

    fn closed_url() -> Result<Uri, Box<dyn std::error::Error>> {
        Ok("http://127.0.0.1:9/decide".parse()?)
    }

    #[tokio::test]
    async fn no_free_slot_with_no_queue_is_busy_at_once() -> Result<(), Box<dyn std::error::Error>>
    {
        let client = decision_client()?;
        let slots = Arc::new(Semaphore::new(1));
        // Hold the only slot for the whole test.
        let _held = slots.acquire().await?;
        let result = post_json(
            &client,
            &closed_url()?,
            None,
            Vec::new(),
            &limits(0, Arc::clone(&slots)),
        )
        .await;
        assert!(matches!(result, Err(DecisionError::Busy)));
        Ok(())
    }

    #[tokio::test]
    async fn no_slot_within_the_queue_window_is_busy() -> Result<(), Box<dyn std::error::Error>> {
        let client = decision_client()?;
        let slots = Arc::new(Semaphore::new(1));
        let _held = slots.acquire().await?;
        let result = post_json(
            &client,
            &closed_url()?,
            None,
            Vec::new(),
            &limits(30, Arc::clone(&slots)),
        )
        .await;
        assert!(matches!(result, Err(DecisionError::Busy)));
        Ok(())
    }

    #[tokio::test]
    async fn slot_freed_within_the_queue_window_proceeds_to_the_exchange()
    -> Result<(), Box<dyn std::error::Error>> {
        let client = decision_client()?;
        let slots = Arc::new(Semaphore::new(1));
        let held = Arc::clone(&slots).acquire_owned().await?;
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            drop(held);
        });
        let result = post_json(
            &client,
            &closed_url()?,
            None,
            Vec::new(),
            &limits(500, slots),
        )
        .await;
        // The exchange runs against a closed port, so it fails, but not as busy.
        assert!(matches!(result, Err(DecisionError::Transport(_))));
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
