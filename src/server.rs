//! The accept loop and the per-request pipeline.
//!
//! The order is fixed: site lookup, body limit, deterministic rules, backend
//! call, policy. Rules are decided before the backend is called, so no failure
//! setting can turn a rule block into an allow.

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http::header::{HOST, HeaderName, HeaderValue, LOCATION};
use http::request::Parts;
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::JoinSet;

use crate::config::{BackendConfig, Config, DecisionConfig, MAX_REQUEST_ID_BYTES, SiteConfig};
use crate::decision::{Backend, DecisionBackend, HttpDecisionBackend, decision_client};
use crate::error::{DecisionError, ServeError};
use crate::policy::{self, Action, Assessment, Decision};
use crate::prefilter::{self, Screening};
use crate::proxy::Proxy;
use crate::router::{Router, normalize_host};
use crate::sanitize::{self, EventInput, truncate_utf8};
use crate::system_one::SystemOneBackend;

const DEBUG_HEADER: HeaderName = HeaderName::from_static("x-vigilant-heron");

type ResponseBody = BoxBody<Bytes, hyper::Error>;

/// Shared state for every connection.
pub(crate) struct AppState<B> {
    router: Router,
    sites: Vec<SiteConfig>,
    decision: DecisionConfig,
    /// Header names dropped before the event is sent to the backend.
    backend_redact: Vec<String>,
    backend: B,
    proxy: Proxy,
    default_status: StatusCode,
    client_ip_header: Option<HeaderName>,
    request_id_header: Option<HeaderName>,
}

impl AppState<Backend> {
    fn from_config(config: Config) -> Result<Self, ServeError> {
        let client = decision_client()?;
        let url = config.decision.url.clone();
        let timeout = config.decision.timeout;
        let slots = Arc::new(Semaphore::new(config.decision.max_concurrency));
        let backend = match &config.decision.backend {
            BackendConfig::Http => Backend::Http(HttpDecisionBackend::new(
                client,
                url,
                timeout,
                Arc::clone(&slots),
            )),
            BackendConfig::Clef { model, token } => Backend::SystemOne(SystemOneBackend::new(
                client,
                url,
                model.as_str().to_owned(),
                token.clone(),
                timeout,
                Arc::clone(&slots),
            )),
            BackendConfig::Jev { model, token } => Backend::SystemOne(SystemOneBackend::new(
                client,
                url,
                model.clone(),
                token.clone(),
                timeout,
                Arc::clone(&slots),
            )),
        };
        // The request-id header identifies the request to the proxy's log only.
        let mut backend_redact = config.decision.redact_headers.clone();
        if let Some(name) = &config.request_id_header {
            backend_redact.push(name.as_str().to_owned());
        }
        Ok(Self {
            router: Router::new(&config.sites),
            sites: config.sites,
            decision: config.decision,
            backend_redact,
            backend,
            proxy: Proxy::new(),
            default_status: config.default_status,
            client_ip_header: config.client_ip_header,
            request_id_header: config.request_id_header,
        })
    }
}

/// Serves requests on `listener` until `shutdown` completes.
///
/// At most `max_connections` connections are open at once. Requests in flight
/// when `shutdown` completes are finished before this returns.
///
/// # Errors
///
/// Returns [`ServeError::Accept`] when the listener fails to accept a connection.
pub async fn serve(
    listener: TcpListener,
    config: Config,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ServeError> {
    let max_connections = config.max_connections;
    let state = Arc::new(AppState::from_config(config)?);
    let (stop_tx, stop_rx) = watch::channel(false);
    let slots = Arc::new(Semaphore::new(max_connections));
    let mut shutdown = pin!(shutdown);
    let mut connections = JoinSet::new();
    loop {
        // Both waits race with shutdown, so a full connection limit cannot block the stop.
        let permit = tokio::select! {
            () = &mut shutdown => break,
            permit = Arc::clone(&slots).acquire_owned() => {
                permit.map_err(|_| ServeError::Accept(std::io::Error::other("connection limiter closed")))?
            }
        };
        let (stream, peer) = tokio::select! {
            () = &mut shutdown => break,
            accepted = listener.accept() => accepted.map_err(ServeError::Accept)?,
        };
        connections.spawn(serve_connection(
            Arc::clone(&state),
            stream,
            peer,
            stop_rx.clone(),
            permit,
        ));
        while connections.try_join_next().is_some() {}
    }
    // Ignoring the send result is fine: it only fails when no connection is listening.
    let _ = stop_tx.send(true);
    while connections.join_next().await.is_some() {}
    Ok(())
}

async fn serve_connection<B: DecisionBackend>(
    state: Arc<AppState<B>>,
    stream: TcpStream,
    peer: SocketAddr,
    mut stop: watch::Receiver<bool>,
    _permit: OwnedSemaphorePermit,
) {
    let service = service_fn(move |request| {
        let state = Arc::clone(&state);
        async move { Ok::<_, Infallible>(handle(&state, peer, request).await) }
    });
    let connection = http1::Builder::new().serve_connection(TokioIo::new(stream), service);
    let mut connection = pin!(connection);
    tokio::select! {
        result = connection.as_mut() => {
            if let Err(error) = result {
                tracing::debug!(%error, %peer, "connection closed with an error");
            }
        }
        _ = stop.changed() => {
            connection.as_mut().graceful_shutdown();
            if let Err(error) = connection.as_mut().await {
                tracing::debug!(%error, %peer, "connection closed with an error during shutdown");
            }
        }
    }
}

/// What the log records about the request before a decision is made.
struct Trace<'a> {
    client_ip: &'a str,
    request_id: Option<&'a str>,
    started: Instant,
}

async fn handle<B: DecisionBackend>(
    state: &AppState<B>,
    peer: SocketAddr,
    request: Request<Incoming>,
) -> Response<ResponseBody> {
    let started = Instant::now();
    let client_ip = client_ip(state, request.headers(), peer);
    let request_id = request_id(state, request.headers());
    let (parts, body) = request.into_parts();
    let trace = Trace {
        client_ip: &client_ip,
        request_id: request_id.as_deref(),
        started,
    };
    let Some(site) = state
        .router
        .lookup(parts.headers.get(HOST))
        .and_then(|index| state.sites.get(index))
    else {
        let host = parts
            .headers
            .get(HOST)
            .and_then(|value| value.to_str().ok())
            .map(normalize_host)
            .unwrap_or_default();
        return reject(&parts, &trace, &host, state.default_status, "unknown_host");
    };
    let body = match Limited::new(body, state.decision.max_body_bytes)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(error) if error.is::<LengthLimitError>() => {
            return reject(
                &parts,
                &trace,
                site_name(site),
                StatusCode::PAYLOAD_TOO_LARGE,
                "body_too_large",
            );
        }
        Err(_) => {
            return reject(
                &parts,
                &trace,
                site_name(site),
                StatusCode::BAD_REQUEST,
                "unreadable_body",
            );
        }
    };

    let raw_path = parts.uri.path();
    let path = prefilter::normalized_path(raw_path);
    let screening = prefilter::screen(
        site,
        &parts.method,
        &path,
        parts.uri.query().is_some(),
        body.is_empty(),
    );
    let assessment = assess(state, site, &parts, &body, &client_ip, screening).await;
    let decision = policy::decide(site, &path, &assessment);
    let mut response = respond(state, site, &parts, body, peer, &decision).await;
    if site.debug_headers {
        add_debug_header(response.headers_mut(), &decision);
    }
    emit(&LogRecord {
        site: site_name(site),
        method: &parts.method,
        path: raw_path,
        action: decision.action.name(),
        reason: decision.reason.name(),
        would_have: decision.would_have.as_ref().map_or("none", Action::name),
        verdict: verdict_fields(&assessment),
        trace,
    });
    response
}

async fn respond<B>(
    state: &AppState<B>,
    site: &SiteConfig,
    parts: &Parts,
    body: Bytes,
    peer: SocketAddr,
    decision: &Decision,
) -> Response<ResponseBody> {
    match &decision.action {
        Action::Allow => {
            let path_and_query = parts
                .uri
                .path_and_query()
                .map_or("/", |value| value.as_str());
            match state
                .proxy
                .forward(
                    parts.method.clone(),
                    &parts.headers,
                    path_and_query,
                    body,
                    &site.upstream,
                    peer.ip(),
                )
                .await
            {
                Ok(upstream) => {
                    let (mut upstream_parts, upstream_body) = upstream.into_parts();
                    crate::proxy::strip_hop_by_hop(&mut upstream_parts.headers);
                    Response::from_parts(upstream_parts, upstream_body.boxed())
                }
                Err(_) => status_response(StatusCode::BAD_GATEWAY, ""),
            }
        }
        Action::Block => status_response(StatusCode::FORBIDDEN, "Forbidden\n"),
        Action::Redirect(location) => {
            let mut response = status_response(StatusCode::FOUND, "");
            response.headers_mut().insert(LOCATION, location.clone());
            response
        }
    }
}

async fn assess<B: DecisionBackend>(
    state: &AppState<B>,
    site: &SiteConfig,
    parts: &Parts,
    body: &Bytes,
    client_ip: &str,
    screening: Screening,
) -> Assessment {
    match screening {
        Screening::Rule => Assessment::Rule,
        Screening::Skip => Assessment::Skip,
        Screening::Inspect => {
            let host = site.hosts.first().map_or("", String::as_str);
            let event = sanitize::build_event(&EventInput {
                method: &parts.method,
                path: parts.uri.path(),
                query: parts.uri.query(),
                headers: &parts.headers,
                body,
                host,
                client_ip,
                redact_headers: &state.backend_redact,
                inspect_body_bytes: state.decision.inspect_body_bytes,
            });
            match state.backend.decide(&event).await {
                Ok(verdict) => Assessment::Model(verdict),
                Err(DecisionError::Busy) => Assessment::RateLimited {
                    cause: "backend_busy",
                    retry_after: None,
                },
                Err(DecisionError::RateLimited { retry_after }) => Assessment::RateLimited {
                    cause: "rate_limited",
                    retry_after,
                },
                Err(error) => Assessment::DecisionFailed {
                    cause: error.cause(),
                },
            }
        }
    }
}

fn client_ip<B>(state: &AppState<B>, headers: &HeaderMap, peer: SocketAddr) -> String {
    state
        .client_ip_header
        .as_ref()
        .and_then(|name| headers.get(name))
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map_or_else(|| peer.ip().to_string(), str::to_owned)
}

/// Reads the configured request-id header, lossily decoded and cut to 128 bytes.
fn request_id<B>(state: &AppState<B>, headers: &HeaderMap) -> Option<String> {
    let name = state.request_id_header.as_ref()?;
    let value = String::from_utf8_lossy(headers.get(name)?.as_bytes()).into_owned();
    let (value, _cut) = truncate_utf8(value, MAX_REQUEST_ID_BYTES);
    (!value.is_empty()).then_some(value)
}

fn site_name(site: &SiteConfig) -> &str {
    site.hosts.first().map_or("", String::as_str)
}

/// The verdict fields written to the decision event. Each is empty when no backend answered.
struct VerdictFields<'a> {
    attack: Option<f64>,
    ai_instruction: Option<f64>,
    category: Option<&'a str>,
    input_tokens: Option<u64>,
    decision_error: Option<&'a str>,
    retry_after: Option<&'a str>,
}

fn verdict_fields(assessment: &Assessment) -> VerdictFields<'_> {
    let mut fields = VerdictFields {
        attack: None,
        ai_instruction: None,
        category: None,
        input_tokens: None,
        decision_error: None,
        retry_after: None,
    };
    match assessment {
        Assessment::Model(verdict) => {
            fields.attack = Some(verdict.attack.value());
            fields.ai_instruction = Some(verdict.ai_instruction.value());
            fields.category = verdict.category.as_deref();
            fields.input_tokens = verdict.input_tokens;
        }
        Assessment::RateLimited { cause, retry_after } => {
            fields.decision_error = Some(cause);
            fields.retry_after = retry_after.as_deref();
        }
        Assessment::DecisionFailed { cause } => fields.decision_error = Some(cause),
        Assessment::Rule | Assessment::Skip => {}
    }
    fields
}

/// Answers a request that never reached a decision, and logs it as a rejection.
fn reject(
    parts: &Parts,
    trace: &Trace<'_>,
    site: &str,
    status: StatusCode,
    reason: &str,
) -> Response<ResponseBody> {
    emit(&LogRecord {
        site,
        method: &parts.method,
        path: parts.uri.path(),
        action: "reject",
        reason,
        would_have: "none",
        verdict: VerdictFields {
            attack: None,
            ai_instruction: None,
            category: None,
            input_tokens: None,
            decision_error: None,
            retry_after: None,
        },
        trace: Trace {
            client_ip: trace.client_ip,
            request_id: trace.request_id,
            started: trace.started,
        },
    });
    status_response(status, "")
}

fn add_debug_header(headers: &mut HeaderMap, decision: &Decision) {
    let would_have = decision.would_have.as_ref().map_or("none", Action::name);
    let value = format!(
        "action={}; reason={}; would_have={would_have}",
        decision.action.name(),
        decision.reason.name()
    );
    if let Ok(value) = HeaderValue::from_str(&value) {
        headers.insert(DEBUG_HEADER, value);
    }
}

/// The fields of the one `vigilant_heron::decision` event written per request.
struct LogRecord<'a> {
    site: &'a str,
    method: &'a Method,
    path: &'a str,
    action: &'a str,
    reason: &'a str,
    would_have: &'a str,
    verdict: VerdictFields<'a>,
    trace: Trace<'a>,
}

fn emit(record: &LogRecord<'_>) {
    let latency_ms = u64::try_from(record.trace.started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let verdict = &record.verdict;
    tracing::info!(
        target: "vigilant_heron::decision",
        site = record.site,
        method = %record.method,
        path = record.path,
        action = record.action,
        reason = record.reason,
        would_have = record.would_have,
        attack = verdict.attack,
        ai_instruction = verdict.ai_instruction,
        category = verdict.category,
        input_tokens = verdict.input_tokens,
        decision_error = verdict.decision_error,
        retry_after = verdict.retry_after,
        request_id = record.trace.request_id,
        latency_ms,
        client_ip = record.trace.client_ip,
    );
}

fn status_response(status: StatusCode, body: &'static str) -> Response<ResponseBody> {
    let mut response = Response::new(
        Full::new(Bytes::from_static(body.as_bytes()))
            .map_err(|never: Infallible| match never {})
            .boxed(),
    );
    *response.status_mut() = status;
    response
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::time::Duration;

    use tokio::net::TcpStream;
    use tokio::sync::oneshot;

    use super::*;

    const CONFIG: &str = r#"
listen = "127.0.0.1:0"
max_connections = 1

[decision]
backend = "http"
url = "http://127.0.0.1:9/decide"
timeout_ms = 150
inspect_body_bytes = 512
max_body_bytes = 1024

[default]
status = 421

[[sites]]
hosts = ["example.com"]
upstream = "http://127.0.0.1:9"
mode = "enforce"
action = "block"
block_threshold = 0.9
instruction_threshold = 0.5
"#;

    #[tokio::test]
    async fn shutdown_returns_promptly_while_every_connection_slot_is_busy()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let config = Config::from_toml_str(CONFIG)?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        // An idle connection takes the only slot and never sends a request.
        let _idle = TcpStream::connect(addr).await?;
        let (stop, stop_rx) = oneshot::channel::<()>();
        let task = tokio::spawn(serve(listener, config, async {
            let _ = stop_rx.await;
        }));
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = stop.send(());
        let joined = tokio::time::timeout(Duration::from_secs(5), task).await?;
        joined??;
        Ok(())
    }
}
