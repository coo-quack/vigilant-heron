//! The accept loop and the per-request pipeline.
//!
//! The order is fixed: site lookup, body limit, body sniff, deterministic rules,
//! backend call, policy, forwarding. Rules are decided before the backend is
//! called, so no failure setting can turn a rule block into an allow. Only the
//! first `inspect_body` bytes of a body reach the backend; the rest is streamed
//! to the upstream after the decision.

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use http::header::{CONNECTION, CONTENT_LENGTH, HOST, HeaderName, HeaderValue, LOCATION};
use http::request::Parts;
use http::{HeaderMap, Request, Response, StatusCode};
use http_body::Body;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::JoinSet;

use crate::accesslog::{AccessRecord, LogFormat};
use crate::body::{BodyFault, BodyTooLarge, BoxError, ClientBody, Finish, Sniffed};
use crate::config::{AccessLogConfig, BackendConfig, Config, MAX_REQUEST_ID_BYTES, SiteConfig};
use crate::decision::{Backend, DecisionBackend, HttpDecisionBackend, Limits, decision_client};
use crate::error::{DecisionError, ProxyError, ServeError};
use crate::logsink::{Writer, spawn_writer};
use crate::policy::{self, Action, Assessment, Decision};
use crate::prefilter::{self, Screening};
use crate::proxy::Proxy;
use crate::realip::RealIp;
use crate::router::{Router, normalize_host};
use crate::sanitize::{self, EventInput, truncate_utf8};
use crate::system_one::SystemOneBackend;
use crate::transport::{
    ClientIo, ClientTimers, HYPER_DEFAULT_BUFFER, Phase, PhaseCell, Rejection, RejectionSlot, lock,
};

const DEBUG_HEADER: HeaderName = HeaderName::from_static("x-vigilant-heron");

type ResponseBody = BoxBody<Bytes, BoxError>;

/// A destination's writer with the format its lines use.
struct Sink {
    writer: Writer,
    format: LogFormat,
}

/// Shared state for every connection.
pub(crate) struct AppState<B> {
    router: Router,
    sites: Vec<SiteConfig>,
    /// Upstream client of each site, in site order.
    proxies: Vec<Proxy>,
    /// Bytes of the request body read for the decision.
    inspect_body_bytes: usize,
    /// Connection timers and header limits.
    timers: ClientTimers,
    /// Requests per connection before it is closed.
    keepalive_requests: usize,
    /// Header names dropped before the event is sent to the backend.
    backend_redact: Vec<String>,
    backend: B,
    default_status: StatusCode,
    realip: RealIp,
    request_id_header: Option<HeaderName>,
    /// Access logs of each site, in site order.
    site_sinks: Vec<Vec<Sink>>,
    /// Access logs of requests that match no site, and of connections closed by the transport.
    global_sinks: Vec<Sink>,
}

impl AppState<Backend> {
    fn from_config(config: Config) -> Result<Self, ServeError> {
        let client = decision_client()?;
        let url = config.decision.url.clone();
        let limits = Limits {
            timeout: config.decision.timeout,
            queue_timeout: config.decision.queue_timeout,
            slots: Arc::new(Semaphore::new(config.decision.max_concurrency)),
        };
        let backend = match &config.decision.backend {
            BackendConfig::Http => Backend::Http(HttpDecisionBackend::new(client, url, limits)),
            BackendConfig::Clef { model, token } => Backend::SystemOne(SystemOneBackend::new(
                client,
                url,
                model.as_str().to_owned(),
                token.clone(),
                limits,
            )),
            BackendConfig::Jev { model, token } => Backend::SystemOne(SystemOneBackend::new(
                client,
                url,
                model.clone(),
                token.clone(),
                limits,
            )),
        };
        // The request-id header identifies the request to the log only.
        let mut backend_redact = config.decision.redact_headers.clone();
        if let Some(name) = &config.request_id_header {
            backend_redact.push(name.as_str().to_owned());
        }
        let mut writers: HashMap<String, Writer> = HashMap::new();
        let mut sinks_for = |logs: &[AccessLogConfig]| -> Vec<Sink> {
            logs.iter()
                .map(|log| {
                    let writer = writers
                        .entry(log.destination.label())
                        .or_insert_with(|| spawn_writer(log.destination.clone()))
                        .clone();
                    Sink {
                        writer,
                        format: log.format.clone(),
                    }
                })
                .collect()
        };
        let global_sinks = sinks_for(&config.access_logs);
        let site_sinks = config
            .sites
            .iter()
            .map(|site| {
                let logs = site.access_logs.as_deref().unwrap_or(&config.access_logs);
                sinks_for(logs)
            })
            .collect();
        let proxies = config
            .sites
            .iter()
            .map(|site| Proxy::new(&site.timeouts))
            .collect();
        Ok(Self {
            router: Router::new(&config.sites),
            sites: config.sites,
            proxies,
            inspect_body_bytes: config.decision.inspect_body_bytes,
            timers: ClientTimers::from_config(&config.connection),
            keepalive_requests: config.connection.keepalive_requests,
            backend_redact,
            backend,
            default_status: config.default_status,
            realip: config.realip,
            request_id_header: config.request_id_header,
            site_sinks,
            global_sinks,
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

/// State of one connection that its requests share.
struct Connection {
    phase: Arc<PhaseCell>,
    /// Requests started on this connection.
    served: AtomicUsize,
}

async fn serve_connection<B: DecisionBackend>(
    state: Arc<AppState<B>>,
    stream: TcpStream,
    peer: SocketAddr,
    mut stop: watch::Receiver<bool>,
    _permit: OwnedSemaphorePermit,
) {
    let started = Instant::now();
    let phase = Arc::new(PhaseCell::new());
    let rejection: RejectionSlot = Arc::new(Mutex::new(None));
    let io = TokioIo::new(ClientIo::new(
        stream,
        Arc::clone(&phase),
        state.timers,
        Arc::clone(&rejection),
    ));
    let connection = Arc::new(Connection {
        phase,
        served: AtomicUsize::new(0),
    });
    let mut builder = http1::Builder::new();
    builder.keep_alive(state.timers.keep_alive > Duration::ZERO);
    if state.timers.head.total > HYPER_DEFAULT_BUFFER {
        builder.max_buf_size(state.timers.head.total);
    }
    let service_state = Arc::clone(&state);
    let service = service_fn(move |request| {
        let state = Arc::clone(&service_state);
        let connection = Arc::clone(&connection);
        async move { Ok::<_, Infallible>(handle(&state, &connection, peer, request).await) }
    });
    let connection_future = builder.serve_connection(io, service);
    let mut connection_future = pin!(connection_future);
    tokio::select! {
        result = connection_future.as_mut() => {
            if let Err(error) = result {
                tracing::debug!(%error, %peer, "connection closed with an error");
            }
        }
        _ = stop.changed() => {
            connection_future.as_mut().graceful_shutdown();
            if let Err(error) = connection_future.as_mut().await {
                tracing::debug!(%error, %peer, "connection closed with an error during shutdown");
            }
        }
    }
    let rejected = lock(&rejection).take();
    if let Some(rejection) = rejected {
        write_rejection(&state.global_sinks, rejection, peer, started);
    }
}

/// Facts about a request that are known before its decision.
struct Trace<'a> {
    client_ip: &'a str,
    remote_addr: &'a str,
    request_id: Option<&'a str>,
    started: Instant,
}

/// Answers one request on a connection and records it.
async fn handle<B: DecisionBackend>(
    state: &AppState<B>,
    connection: &Connection,
    peer: SocketAddr,
    request: Request<Incoming>,
) -> Response<ResponseBody> {
    let started = Instant::now();
    connection.phase.set(Phase::Busy);
    let served = connection
        .served
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    let client = client_ip(state, request.headers(), peer);
    let request_id = request_id(state, request.headers());
    let remote = peer.ip().to_string();
    let (parts, body) = request.into_parts();
    let done = Arc::new(AtomicBool::new(body.is_end_stream()));
    let trace = Trace {
        client_ip: &client,
        remote_addr: &remote,
        request_id: request_id.as_deref(),
        started,
    };
    let mut response = pipeline(state, &parts, body, &done, &trace, peer).await;
    if served >= state.keepalive_requests {
        response
            .headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("close"));
    }
    let (parts, body) = response.into_parts();
    Response::from_parts(
        parts,
        Finish::new(body, Arc::clone(&connection.phase), done).boxed(),
    )
}

#[expect(
    clippy::too_many_lines,
    reason = "the per-request pipeline reads top to bottom; splitting it would scatter the rule-first order"
)]
async fn pipeline<B: DecisionBackend>(
    state: &AppState<B>,
    parts: &Parts,
    body: Incoming,
    done: &Arc<AtomicBool>,
    trace: &Trace<'_>,
    peer: SocketAddr,
) -> Response<ResponseBody> {
    let Some(index) = state.router.lookup(parts.headers.get(HOST)) else {
        let host = parts
            .headers
            .get(HOST)
            .and_then(|value| value.to_str().ok())
            .map(normalize_host)
            .unwrap_or_default();
        return reject(
            parts,
            trace,
            &host,
            state.default_status,
            "unknown_host",
            &state.global_sinks,
            !done.load(Ordering::Acquire),
        );
    };
    let Some(site) = state.sites.get(index) else {
        return status_response(state.default_status, "");
    };
    let Some(proxy) = state.proxies.get(index) else {
        return status_response(state.default_status, "");
    };
    let sinks = state
        .site_sinks
        .get(index)
        .map_or(&state.global_sinks[..], Vec::as_slice);
    let timeouts = site.timeouts;

    // A Content-Length over the limit is refused before any of the body is read.
    if let (Some(max), Some(length)) = (timeouts.max_body_bytes, content_length(&parts.headers))
        && length > u64::try_from(max).unwrap_or(u64::MAX)
    {
        return reject(
            parts,
            trace,
            site_name(site),
            StatusCode::PAYLOAD_TOO_LARGE,
            "body_too_large",
            sinks,
            true,
        );
    }

    let mut body = ClientBody::new(
        body,
        timeouts.client_body_timeout,
        timeouts.max_body_bytes,
        Arc::clone(done),
    );
    let sniffed = match body.sniff(state.inspect_body_bytes).await {
        Ok(sniffed) => sniffed,
        Err(error) => {
            let (status, reason) = body_failure(error.as_ref());
            return reject(parts, trace, site_name(site), status, reason, sinks, true);
        }
    };

    let raw_path = parts.uri.path();
    let path = prefilter::normalized_path(raw_path);
    let screening = prefilter::screen(
        site,
        &parts.method,
        &path,
        parts.uri.query().is_some(),
        sniffed.is_empty_body(),
    );
    let assessment = assess(state, site, parts, &sniffed, trace.client_ip, screening).await;
    let decision = policy::decide(site, &path, &assessment);
    let outcome = respond(proxy, site, parts, body, peer, &decision).await;
    let mut response = outcome.response;
    if site.debug_headers {
        add_debug_header(response.headers_mut(), &decision);
    }
    let fields = verdict_fields(&assessment);
    let (action, reason) = match outcome.rejected {
        Some(reason) => ("reject", reason),
        None => (decision.action.name(), decision.reason.name()),
    };
    let record = AccessRecord {
        time: SystemTime::now(),
        request_id: trace.request_id,
        client_ip: trace.client_ip,
        remote_addr: trace.remote_addr,
        site: site_name(site),
        host: parts
            .headers
            .get(HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
        method: parts.method.as_str(),
        path: raw_path,
        status: response.status().as_u16(),
        action,
        reason,
        would_have: decision.would_have.as_ref().map(Action::name),
        attack: fields.attack,
        ai_instruction: fields.ai_instruction,
        category: fields.category,
        decision_error: fields.decision_error,
        retry_after: fields.retry_after,
        input_tokens: fields.input_tokens,
        upstream_status: outcome.upstream_status,
        upstream_error: outcome.upstream_error,
        latency_ms: latency(trace.started),
    };
    write_access(sinks, &record, &parts.headers);
    response
}

/// What a request was answered with, for the access log.
struct Outcome {
    response: Response<ResponseBody>,
    /// Status the upstream answered with, when it answered.
    upstream_status: Option<u16>,
    /// Why the upstream gave no response.
    upstream_error: Option<&'static str>,
    /// Set when the request body caused the answer, which then replaces the decision's reason.
    rejected: Option<&'static str>,
}

impl Outcome {
    fn answered(response: Response<ResponseBody>) -> Self {
        Self {
            response,
            upstream_status: None,
            upstream_error: None,
            rejected: None,
        }
    }
}

fn latency(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Queues one line per destination. A destination whose queue is full drops the line.
fn write_access(sinks: &[Sink], record: &AccessRecord<'_>, headers: &HeaderMap) {
    for sink in sinks {
        sink.writer.send(sink.format.render(record, headers));
    }
}

/// Adds `Connection: close` to a response that ends the connection.
fn close(response: &mut Response<ResponseBody>) {
    response
        .headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("close"));
}

/// Forwards an allowed request, or answers a block or redirect.
///
/// `complete` says whether the request body was read in full. When it was not,
/// the response closes the connection, because the rest of the body would
/// otherwise be read as the next request.
async fn respond(
    proxy: &Proxy,
    site: &SiteConfig,
    parts: &Parts,
    body: ClientBody,
    peer: SocketAddr,
    decision: &Decision,
) -> Outcome {
    let complete = body.is_complete();
    match &decision.action {
        Action::Allow => {
            let path_and_query = parts
                .uri
                .path_and_query()
                .map_or("/", |value| value.as_str());
            match proxy
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
                    let status = upstream.status().as_u16();
                    let (mut upstream_parts, upstream_body) = upstream.into_parts();
                    crate::proxy::strip_hop_by_hop(&mut upstream_parts.headers);
                    Outcome {
                        response: Response::from_parts(upstream_parts, upstream_body.boxed()),
                        upstream_status: Some(status),
                        upstream_error: None,
                        rejected: None,
                    }
                }
                Err(error) => failure(&error, complete),
            }
        }
        Action::Block => {
            let mut response = status_response(StatusCode::FORBIDDEN, "Forbidden\n");
            if !complete {
                close(&mut response);
            }
            Outcome::answered(response)
        }
        Action::Redirect(location) => {
            let mut response = status_response(StatusCode::FOUND, "");
            response.headers_mut().insert(LOCATION, location.clone());
            if !complete {
                close(&mut response);
            }
            Outcome::answered(response)
        }
    }
}

/// Maps a failed forward to the status nginx would send. Upstream timeouts are 504,
/// connection errors 502, and a client body that failed answers 413, 408 or 400.
fn failure(error: &ProxyError, complete: bool) -> Outcome {
    let (status, upstream_error, rejected) = match error {
        ProxyError::Target(_) | ProxyError::Request(_) => {
            (StatusCode::BAD_GATEWAY, Some("upstream_failed"), None)
        }
        ProxyError::Connect(_) => (StatusCode::BAD_GATEWAY, Some("connect_failed"), None),
        ProxyError::ReadTimeout => (StatusCode::GATEWAY_TIMEOUT, Some("read_timeout"), None),
        ProxyError::ConnectTimeout => (StatusCode::GATEWAY_TIMEOUT, Some("connect_timeout"), None),
        ProxyError::SendTimeout(_) => (StatusCode::GATEWAY_TIMEOUT, Some("send_timeout"), None),
        ProxyError::Body(BodyFault::TooLarge) => {
            (StatusCode::PAYLOAD_TOO_LARGE, None, Some("body_too_large"))
        }
        ProxyError::Body(BodyFault::TimedOut) => {
            (StatusCode::REQUEST_TIMEOUT, None, Some("body_timeout"))
        }
        ProxyError::Body(BodyFault::Failed) => {
            (StatusCode::BAD_REQUEST, None, Some("unreadable_body"))
        }
    };
    let mut response = status_response(status, "");
    // A request body that did not arrive in full cannot be followed by another request.
    if !complete || rejected.is_some() {
        close(&mut response);
    }
    Outcome {
        response,
        upstream_status: None,
        upstream_error,
        rejected,
    }
}

/// The status and reason for a request body that could not be read.
fn body_failure(
    error: &(dyn std::error::Error + Send + Sync + 'static),
) -> (StatusCode, &'static str) {
    if error.downcast_ref::<BodyTooLarge>().is_some() {
        return (StatusCode::PAYLOAD_TOO_LARGE, "body_too_large");
    }
    let timed_out = error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|io| io.kind() == std::io::ErrorKind::TimedOut);
    if timed_out {
        (StatusCode::REQUEST_TIMEOUT, "body_timeout")
    } else {
        (StatusCode::BAD_REQUEST, "unreadable_body")
    }
}

async fn assess<B: DecisionBackend>(
    state: &AppState<B>,
    site: &SiteConfig,
    parts: &Parts,
    sniffed: &Sniffed,
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
                body: &sniffed.prefix,
                body_continues: sniffed.truncated,
                host,
                client_ip,
                redact_headers: &state.backend_redact,
                inspect_body_bytes: state.inspect_body_bytes,
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
    let header = headers
        .get(&state.realip.header)
        .and_then(|value| value.to_str().ok());
    state.realip.client_ip(peer.ip(), header).to_string()
}

/// Reads the configured request-id header, lossily decoded and cut to 128 bytes.
fn request_id<B>(state: &AppState<B>, headers: &HeaderMap) -> Option<String> {
    let name = state.request_id_header.as_ref()?;
    let value = String::from_utf8_lossy(headers.get(name)?.as_bytes()).into_owned();
    let (value, _cut) = truncate_utf8(value, MAX_REQUEST_ID_BYTES);
    (!value.is_empty()).then_some(value)
}

/// The value of a valid `Content-Length` header.
fn content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn site_name(site: &SiteConfig) -> &str {
    site.hosts.first().map_or("", String::as_str)
}

/// The verdict fields of an access record. Each is empty when no backend answered.
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
///
/// `closing` adds `Connection: close`, for a request whose body was not read in full.
fn reject(
    parts: &Parts,
    trace: &Trace<'_>,
    site: &str,
    status: StatusCode,
    reason: &str,
    sinks: &[Sink],
    closing: bool,
) -> Response<ResponseBody> {
    let record = AccessRecord {
        time: SystemTime::now(),
        request_id: trace.request_id,
        client_ip: trace.client_ip,
        remote_addr: trace.remote_addr,
        site,
        host: parts
            .headers
            .get(HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
        method: parts.method.as_str(),
        path: parts.uri.path(),
        status: status.as_u16(),
        action: "reject",
        reason,
        would_have: None,
        attack: None,
        ai_instruction: None,
        category: None,
        decision_error: None,
        retry_after: None,
        input_tokens: None,
        upstream_status: None,
        upstream_error: None,
        latency_ms: latency(trace.started),
    };
    write_access(sinks, &record, &parts.headers);
    let mut response = status_response(status, "");
    if closing {
        close(&mut response);
    }
    response
}

/// Logs a response the transport sent on its own, such as a 408 or a 414.
fn write_rejection(sinks: &[Sink], rejection: Rejection, peer: SocketAddr, started: Instant) {
    let remote = peer.ip().to_string();
    let record = AccessRecord {
        time: SystemTime::now(),
        request_id: None,
        client_ip: &remote,
        remote_addr: &remote,
        site: "",
        host: "",
        method: "",
        path: "",
        status: rejection.status,
        action: "reject",
        reason: rejection.reason,
        would_have: None,
        attack: None,
        ai_instruction: None,
        category: None,
        decision_error: None,
        retry_after: None,
        input_tokens: None,
        upstream_status: None,
        upstream_error: None,
        latency_ms: latency(started),
    };
    write_access(sinks, &record, &HeaderMap::new());
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

    const CONFIG: &str = r"
listen 127.0.0.1:0;
max_connections 1;

decision {
    backend http;
    url http://127.0.0.1:9/decide;
    timeout 150ms;
    inspect_body 512;
}

default_status 421;

client_max_body_size 1024;

site example.com {
    upstream http://127.0.0.1:9;
    mode enforce;
    action block;
    block_threshold 0.9;
    instruction_threshold 0.5;
}
";

    #[tokio::test]
    async fn shutdown_returns_promptly_while_every_connection_slot_is_busy()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let config = Config::parse_str(CONFIG, "test.conf")?;
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
