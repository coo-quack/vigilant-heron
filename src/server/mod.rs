//! The accept loop and the per-request pipeline.
//!
//! The order is fixed: site lookup, limits, Host check, access list, body limit,
//! body sniff, deterministic rules, backend call, policy, forwarding. Limits and
//! the access list run before the body is read. Rules are decided before the
//! backend is called, so no failure setting can turn a rule block into an allow.
//! Only the first `inspect_body` bytes of a body reach the backend; the rest is
//! streamed to the upstream after the decision.

mod record;
mod reload;
mod respond;
mod state;

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use http::header::{CONNECTION, CONTENT_LENGTH, HOST, HeaderValue};
use http::request::Parts;
use http::{HeaderMap, Request, Response, StatusCode};
use http_body::Body;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio::task::JoinSet;

use crate::access;
use crate::accesslog::AccessRecord;
use crate::backend::sanitize::{self, EventInput};
use crate::block::BlockResponse;
use crate::body::{ClientBody, Sniffed};
use crate::config::{Config, Mode, SiteConfig};
use crate::error::{ConfigError, DecisionError, ServeError};
use crate::finish::Finish;
use crate::limits::{self, ConnPermit, ConnStatus, KeyVars, LimitSet, ReqStatus};
use crate::phase::{Phase, PhaseCell};
use crate::policy::{self, Action, Assessment};
use crate::prefilter::{self, Screening};
use crate::proxy::HeaderContext;
use crate::request_id;
use crate::router::{is_valid_host, normalize_host};
use crate::rules::RuleInput;
use crate::sync::lock;
use crate::transport::{ClientIo, ClientTimers, HYPER_DEFAULT_BUFFER, RejectionSlot};
use crate::tunnel;

use record::{latency, raw_host, reject, verdict_fields, write_access, write_rejection};
use reload::{Startup, next_reload, reload};
use respond::{
    CloseWithoutResponse, Delivery, ResponseBody, add_debug_header, body_failure, empty_answer,
    respond,
};
use state::{AppState, ConnectionSettings};

/// Where a reload gets its configuration: a function that reads and validates it.
type Loader = Box<dyn Fn() -> Result<Config, ConfigError> + Send>;

/// Called with a reloaded configuration once it is in service, for the settings
/// that live outside the server (the error log).
type Applied = Box<dyn Fn(&Config) + Send>;

/// Serves requests on `listener` until `shutdown` completes.
///
/// At most `max_connections` connections are open at once. Requests in flight
/// when `shutdown` completes are finished before this returns.
///
/// # Errors
///
/// Returns [`ServeError::Accept`] when the listener fails to accept a connection,
/// and an error when the configuration cannot be put into service.
pub async fn serve(
    listener: TcpListener,
    config: Config,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ServeError> {
    run(listener, config, shutdown, None).await
}

/// Serves like [`serve`], and reloads the configuration each time `reloads` receives a message.
///
/// `load` reads and validates the configuration. A reload that fails is logged at
/// error level, and the previous configuration keeps serving. A reload that
/// succeeds applies to the requests that start after it; requests in flight finish
/// with the configuration they started with. Zones keep their counts when a zone
/// with the same name and size exists. `pid`, the listen address, `worker_threads`,
/// `max_connections`, `worker_shutdown_timeout` and the connection settings apply
/// only at startup.
///
/// `applied` is called with the new configuration after it is in service, and
/// before the reload is logged. It is not called for a reload that fails, so the
/// caller can stage a change in `load` and apply it here.
///
/// # Errors
///
/// Returns the same errors as [`serve`].
pub async fn serve_reloadable(
    listener: TcpListener,
    config: Config,
    shutdown: impl Future<Output = ()>,
    reloads: mpsc::Receiver<()>,
    load: impl Fn() -> Result<Config, ConfigError> + Send + 'static,
    applied: impl Fn(&Config) + Send + 'static,
) -> Result<(), ServeError> {
    run(
        listener,
        config,
        shutdown,
        Some((reloads, Box::new(load), Box::new(applied))),
    )
    .await
}

async fn run(
    listener: TcpListener,
    config: Config,
    shutdown: impl Future<Output = ()>,
    reloads: Option<(mpsc::Receiver<()>, Loader, Applied)>,
) -> Result<(), ServeError> {
    let max_connections = config.max_connections;
    let shutdown_timeout = config.worker_shutdown_timeout;
    let settings = ConnectionSettings {
        timers: ClientTimers::from_config(&config.connection),
        keepalive_requests: config.connection.keepalive_requests,
    };
    let startup = Startup::of(&config);
    let initial = Arc::new(AppState::from_config(config, None)?);
    let (current_tx, current_rx) = watch::channel(initial);
    let (stop_tx, stop_rx) = watch::channel(false);
    let (open_tx, mut open_rx) = mpsc::channel::<()>(1);
    let (force_tx, force_rx) = watch::channel(false);
    let slots = Arc::new(Semaphore::new(max_connections));
    let mut shutdown = pin!(shutdown);
    let mut connections = JoinSet::new();
    let (mut requests, load, applied) = match reloads {
        Some((requests, load, applied)) => (Some(requests), Some(load), Some(applied)),
        None => (None, None, None),
    };
    loop {
        // Both waits race with shutdown, so a full connection limit cannot block the stop.
        // A reload is applied while waiting too, and then the loop starts again.
        let permit = tokio::select! {
            () = &mut shutdown => break,
            Some(()) = next_reload(&mut requests) => {
                if let (Some(load), Some(applied)) = (&load, &applied) {
                    reload(load.as_ref(), applied.as_ref(), &startup, &current_tx);
                }
                continue;
            }
            permit = Arc::clone(&slots).acquire_owned() => {
                permit.map_err(|_| ServeError::Accept(std::io::Error::other("connection limiter closed")))?
            }
        };
        let (stream, peer) = tokio::select! {
            () = &mut shutdown => break,
            Some(()) = next_reload(&mut requests) => {
                if let (Some(load), Some(applied)) = (&load, &applied) {
                    reload(load.as_ref(), applied.as_ref(), &startup, &current_tx);
                }
                continue;
            }
            accepted = listener.accept() => accepted.map_err(ServeError::Accept)?,
        };
        let lifetime = tunnel::Lifetime {
            open: open_tx.clone(),
            force: force_rx.clone(),
        };
        connections.spawn(serve_connection(
            current_rx.clone(),
            settings,
            stream,
            peer,
            stop_rx.clone(),
            lifetime,
            permit,
        ));
        while connections.try_join_next().is_some() {}
    }
    // Ignoring the send result is fine: it only fails when no connection is listening.
    let _ = stop_tx.send(true);
    drop(open_tx);
    match shutdown_timeout {
        None => drain(&mut connections, &mut open_rx).await,
        Some(limit) => {
            let drained = tokio::time::timeout(limit, drain(&mut connections, &mut open_rx))
                .await
                .is_ok();
            if !drained {
                tracing::warn!(
                    "worker_shutdown_timeout expired; closing the connections and tunnels still open"
                );
                connections.abort_all();
                let _ = force_tx.send(true);
                drain(&mut connections, &mut open_rx).await;
            }
        }
    }
    Ok(())
}

/// Waits until every connection has finished and every tunnel has closed.
async fn drain(connections: &mut JoinSet<()>, open: &mut mpsc::Receiver<()>) {
    while connections.join_next().await.is_some() {}
    // Nothing is ever sent, so this returns once every sender is dropped.
    let _ = open.recv().await;
}

/// State of one connection that its requests share.
struct Connection {
    phase: Arc<PhaseCell>,
    /// Requests started on this connection.
    served: AtomicUsize,
    /// Shutdown bookkeeping that a tunnel started by one of its requests holds.
    lifetime: tunnel::Lifetime,
}

async fn serve_connection(
    current: watch::Receiver<Arc<AppState>>,
    settings: ConnectionSettings,
    stream: TcpStream,
    peer: SocketAddr,
    mut stop: watch::Receiver<bool>,
    lifetime: tunnel::Lifetime,
    _permit: OwnedSemaphorePermit,
) {
    let started = Instant::now();
    let phase = Arc::new(PhaseCell::new());
    let rejection: RejectionSlot = Arc::new(Mutex::new(None));
    let io = TokioIo::new(ClientIo::new(
        stream,
        Arc::clone(&phase),
        settings.timers,
        Arc::clone(&rejection),
    ));
    let connection = Arc::new(Connection {
        phase,
        served: AtomicUsize::new(0),
        lifetime,
    });
    let mut builder = http1::Builder::new();
    builder.keep_alive(settings.timers.keep_alive > Duration::ZERO);
    if settings.timers.head.total > HYPER_DEFAULT_BUFFER {
        builder.max_buf_size(settings.timers.head.total);
    }
    let service_current = current.clone();
    let service = service_fn(move |request| {
        // Each request takes the configuration that is current when it starts.
        let state = service_current.borrow().clone();
        let connection = Arc::clone(&connection);
        async move {
            handle(
                &state,
                &connection,
                peer,
                request,
                settings.keepalive_requests,
            )
            .await
        }
    });
    // `with_upgrades` keeps the connection driven until an upgraded tunnel takes it over.
    let connection_future = builder.serve_connection(io, service).with_upgrades();
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
        let state = current.borrow().clone();
        write_rejection(&state.global_sinks, rejection, peer, started);
    }
}

/// Facts about a request that are known before its decision.
struct Trace<'a> {
    /// The upgrade of the client connection, taken by a tunnel that the request starts.
    upgrade: Mutex<Option<OnUpgrade>>,
    client_addr: IpAddr,
    client_ip: &'a str,
    remote_addr: &'a str,
    request_id: &'a str,
    started: Instant,
    /// `$limit_req_status`, set once the limits have run.
    limit_req: Mutex<Option<&'static str>>,
    /// `$limit_conn_status`, set once the limits have run.
    limit_conn: Mutex<Option<&'static str>>,
    /// The connection's shutdown bookkeeping, given to a tunnel this request starts.
    tunnels: tunnel::Lifetime,
    /// The phase of the client connection, set to tunnelling when this request starts a tunnel.
    phase: &'a PhaseCell,
}

/// Answers one request on a connection and records it.
///
/// An error ends the connection without a response. It is returned for a block
/// with `block_status 444`, after the request has been logged.
async fn handle(
    state: &AppState,
    connection: &Connection,
    peer: SocketAddr,
    mut request: Request<Incoming>,
    keepalive_requests: usize,
) -> Result<Response<ResponseBody>, std::io::Error> {
    let started = Instant::now();
    connection.phase.set(Phase::Busy);
    let served = connection
        .served
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    let client_addr = client_addr(state, request.headers(), peer);
    let client = client_addr.to_string();
    let request_id = request_id_for(state, request.headers());
    let remote = peer.ip().to_string();
    let client_upgrade = hyper::upgrade::on(&mut request);
    let (parts, body) = request.into_parts();
    let done = Arc::new(AtomicBool::new(body.is_end_stream()));
    let trace = Trace {
        upgrade: Mutex::new(Some(client_upgrade)),
        client_addr,
        client_ip: &client,
        remote_addr: &remote,
        request_id: &request_id,
        started,
        limit_req: Mutex::new(None),
        limit_conn: Mutex::new(None),
        tunnels: connection.lifetime.clone(),
        phase: connection.phase.as_ref(),
    };
    let mut held = Vec::new();
    let mut response = pipeline(state, &parts, body, &done, &trace, peer, &mut held).await;
    if response
        .extensions()
        .get::<CloseWithoutResponse>()
        .is_some()
    {
        return Err(std::io::Error::other(
            "blocked with block_status 444: closed without a response",
        ));
    }
    if served >= keepalive_requests {
        response
            .headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("close"));
    }
    let (parts, body) = response.into_parts();
    Ok(Response::from_parts(
        parts,
        Finish::new(body, Arc::clone(&connection.phase), done)
            .holding(held)
            .boxed(),
    ))
}

#[expect(
    clippy::too_many_lines,
    reason = "the per-request pipeline reads top to bottom; splitting it would scatter the rule-first order"
)]
async fn pipeline(
    state: &AppState,
    parts: &Parts,
    body: Incoming,
    done: &Arc<AtomicBool>,
    trace: &Trace<'_>,
    peer: SocketAddr,
    held: &mut Vec<ConnPermit>,
) -> Response<ResponseBody> {
    // The limits come first, before the access list, the body and the rules.
    let index = state.router.lookup(parts.headers.get(HOST));
    let matched = index.and_then(|index| state.sites.get(index));
    let decoded = prefilter::decoded_path(parts.uri.path());
    let views = prefilter::path_views(parts.uri.path());
    // The lowercase views are computed once, for the screening and the policy.
    let lowered: Vec<String> = views.iter().map(|view| view.to_lowercase()).collect();
    // The location of the decoded path sets the block response, the headers and the tunnel.
    let location = matched.and_then(|site| limits::select_location(&site.locations, &decoded));
    // Every location that any reading of the path selects is limited.
    let selected = matched.map_or_else(Vec::new, |site| {
        limits::select_locations(&site.locations, &views)
    });
    let limit_sets: Vec<&LimitSet> = if selected.is_empty() {
        vec![matched.map_or(&state.top_limits, |site| &site.limits)]
    } else {
        selected.iter().map(|location| &location.limits).collect()
    };
    let host = host_name(parts);
    let key_vars = KeyVars {
        client_ip: trace.client_ip,
        remote_addr: trace.remote_addr,
        site: matched.map_or("", site_name),
        host: &host,
        method: parts.method.as_str(),
        path: &decoded,
        headers: &parts.headers,
    };
    // The block response of the location that was selected, else of the site.
    let site_block = matched.map(|site| &site.block);
    let block = location.map(|location| &location.block).or(site_block);
    let shadow = matched.is_some_and(|site| site.mode == Mode::Shadow);
    let screened = limits::screen(&state.zones, &limit_sets, shadow, &key_vars, held).await;
    *lock(&trace.limit_req) = screened.req_status.map(ReqStatus::name);
    *lock(&trace.limit_conn) = screened.conn_status.map(ConnStatus::name);
    if let Some(refusal) = screened.refusal {
        // A refused request keeps no count, and its body is not read.
        held.clear();
        let limit_sinks = index
            .and_then(|index| state.site_sinks.get(index))
            .map_or(state.global_sinks.as_slice(), Vec::as_slice);
        return reject(
            parts,
            trace,
            matched.map_or("", site_name),
            refusal.status,
            refusal.reason,
            limit_sinks,
            true,
        );
    }
    // A Host that is not a hostname or a literal is refused before it is routed.
    let host_header = parts.headers.get(HOST);
    if host_header.is_some_and(|value| !value.to_str().is_ok_and(is_valid_host)) {
        return reject(
            parts,
            trace,
            "",
            StatusCode::BAD_REQUEST,
            "invalid_host",
            &state.global_sinks,
            !done.load(Ordering::Acquire),
        );
    }
    // The access list comes next, before the body is read and before an unknown host is refused.
    let entries = matched.map_or(state.access.as_slice(), |site| site.access.as_slice());
    let access_denied = !access::permits(entries, trace.client_addr);
    if access_denied && matched.is_none() {
        // No site means no mode, so a refusal with no site is final.
        return reject(
            parts,
            trace,
            &host_name(parts),
            StatusCode::FORBIDDEN,
            "access_denied",
            &state.global_sinks,
            !done.load(Ordering::Acquire),
        );
    }
    let Some(index) = index else {
        return reject(
            parts,
            trace,
            &host_name(parts),
            state.default_status,
            "unknown_host",
            &state.global_sinks,
            !done.load(Ordering::Acquire),
        );
    };
    let Some(site) = state.sites.get(index) else {
        return empty_answer(state.default_status, trace.request_id);
    };
    let Some(proxy) = state.proxies.get(index) else {
        return empty_answer(state.default_status, trace.request_id);
    };
    let sinks = state
        .site_sinks
        .get(index)
        .map_or(&state.global_sinks[..], Vec::as_slice);
    let timeouts = site.timeouts;

    // A Content-Length over the limit is refused before any of the body is read.
    // A denied client is decided from its headers alone, so this check waits for it.
    if let (false, Some(max), Some(length)) = (
        access_denied,
        timeouts.max_body_bytes,
        content_length(&parts.headers),
    ) && length > u64::try_from(max).unwrap_or(u64::MAX)
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
    let sniffed = if access_denied {
        // The body of a denied request is not read: it is refused, or in shadow mode forwarded as it is.
        Sniffed {
            prefix: Bytes::new(),
            truncated: false,
        }
    } else {
        match body.sniff(state.inspect_body_bytes).await {
            Ok(sniffed) => sniffed,
            Err(error) => {
                let (status, reason) = body_failure(error.as_ref());
                return reject(parts, trace, site_name(site), status, reason, sinks, true);
            }
        }
    };

    let raw_path = parts.uri.path();
    let (assessment, rule_id) = if access_denied {
        (Assessment::AccessDenied, None)
    } else {
        let input = RuleInput::with_views(
            &parts.method,
            raw_path,
            &views,
            parts.uri.query(),
            &parts.headers,
            sniffed.prefix.as_ref(),
            trace.client_addr,
        );
        let screening = prefilter::screen(site, &input, &lowered, sniffed.is_empty_body());
        let rule_id = match &screening {
            Screening::Rule(id) => id.clone(),
            Screening::SkipRule(id) => Some(Arc::clone(id)),
            Screening::Skip | Screening::Inspect => None,
        };
        let assessment = assess(
            state,
            parts,
            &sniffed,
            trace.client_ip,
            trace.client_addr,
            site_name(site),
            &screening,
        )
        .await;
        (assessment, rule_id)
    };
    let mut decision = policy::decide(site, &lowered, &assessment);
    if decision.would_have.is_none() {
        decision.would_have = screened.would_have.map(Action::Reject);
    }
    // Access-list denials keep 403 as nginx's `deny` does, whatever block_status says.
    let access_block = BlockResponse::default();
    let block = if access_denied {
        &access_block
    } else {
        block.unwrap_or(&access_block)
    };
    // The proxy_set_header operations of the level in effect.
    let header_ops = location
        .map(|location| location.proxy_headers.as_slice())
        .or_else(|| matched.map(|site| site.proxy_headers.as_slice()))
        .unwrap_or_default();
    // The request values that proxy_set_header values may use.
    let ctx = HeaderContext {
        client_ip: trace.client_ip,
        remote_addr: trace.remote_addr,
        host: &host,
        site: site_name(site),
        method: parts.method.as_str(),
        path: parts.uri.path(),
        request_id: trace.request_id,
        headers: &parts.headers,
    };
    let delivery = Delivery {
        proxy,
        tunnels: &trace.tunnels,
        upstream: &site.upstream,
        headers: header_ops,
        block,
        ctx,
        websocket: location.map_or(site.websocket, |location| location.websocket),
        client_upgrade: &trace.upgrade,
        phase: trace.phase,
    };
    let outcome = respond(&delivery, parts, body, peer, &decision, held).await;
    let mut response = outcome.response;
    if site.debug_headers {
        add_debug_header(response.headers_mut(), &decision);
    }
    let fields = verdict_fields(&assessment);
    let (action, reason) = match outcome.rejected {
        Some(reason) => ("reject", reason),
        None => (decision.action.name(), decision.reason.name()),
    };
    // `$block_query` is logged when the decision blocked the request (a request that a limit or
    // the body refused is logged as `reject`, so it is not counted), or when shadow mode
    // recorded a block that it did not enforce.
    let log_block_query = (outcome.rejected.is_none() && decision.action == Action::Block)
        || decision.would_have == Some(Action::Block);
    let record = AccessRecord {
        time: SystemTime::now(),
        request_id: Some(trace.request_id),
        client_ip: trace.client_ip,
        remote_addr: trace.remote_addr,
        site: site_name(site),
        host: raw_host(parts),
        method: parts.method.as_str(),
        path: raw_path,
        query: parts.uri.query(),
        block_query: log_block_query
            .then(|| sanitize::block_query(parts.uri.query(), &state.backend_redact_fields))
            .flatten(),
        status: response.status().as_u16(),
        action,
        reason,
        rule_id: rule_id.as_deref().unwrap_or(""),
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
        limit_req_status: *lock(&trace.limit_req),
        limit_conn_status: *lock(&trace.limit_conn),
    };
    write_access(sinks, &record, &parts.headers);
    response
}

async fn assess(
    state: &AppState,
    parts: &Parts,
    sniffed: &Sniffed,
    client_ip: &str,
    client: IpAddr,
    site: &str,
    screening: &Screening,
) -> Assessment {
    match screening {
        Screening::Rule(_) => Assessment::Rule,
        Screening::SkipRule(_) => Assessment::SkipRule,
        Screening::Skip => Assessment::Skip,
        Screening::Inspect => {
            // A client that holds its share of decision calls is refused without waiting,
            // so its excess is a rate limit for that client alone (`client_busy`).
            let Some(_client_slot) = state.client_slots.take(client) else {
                return Assessment::ClientBusy;
            };
            // The event carries the name of the matched site, never the client's Host. The
            // Host the client sent stays in the untrusted headers.
            let event = sanitize::build_event(&EventInput {
                method: &parts.method,
                path: parts.uri.path(),
                query: parts.uri.query(),
                headers: &parts.headers,
                body: &sniffed.prefix,
                body_continues: sniffed.truncated,
                host: site,
                client_ip,
                redact_headers: &state.backend_redact,
                redact_fields: &state.backend_redact_fields,
                redact_file_parts: state.backend_redact_file_parts,
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

/// The client address chosen by the realip settings.
///
/// Every line of the realip header is read, in the order received, and joined with
/// commas, so a trusted proxy that appends its own line is seen after the client's
/// lines. A line that is not valid text makes the whole header untrusted.
fn client_addr(state: &AppState, headers: &HeaderMap, peer: SocketAddr) -> IpAddr {
    let lines: Option<Vec<&str>> = headers
        .get_all(&state.realip.header)
        .iter()
        .map(|value| value.to_str().ok())
        .collect();
    let joined = lines.map(|lines| lines.join(", "));
    state.realip.client_ip(peer.ip(), joined.as_deref())
}

/// The host of the request, normalized, or an empty string when it has none.
fn host_name(parts: &Parts) -> String {
    parts
        .headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .map_or_default(normalize_host)
}

/// The request id: the configured request-id header when its value is usable, else a generated id.
fn request_id_for(state: &AppState, headers: &HeaderMap) -> String {
    state
        .request_id_header
        .as_ref()
        .and_then(|name| headers.get(name))
        .and_then(|value| request_id::from_header(value.as_bytes()))
        .unwrap_or_else(request_id::generate)
}

/// The value of a valid `Content-Length` header.
pub(crate) fn content_length(headers: &HeaderMap) -> Option<u64> {
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
