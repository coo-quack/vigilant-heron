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
use std::net::{IpAddr, SocketAddr};
use std::pin::pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use http::header::{
    CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HOST, HeaderName, HeaderValue, LOCATION, UPGRADE,
};
use http::request::Parts;
use http::{HeaderMap, Request, Response, StatusCode};
use http_body::Body;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio::task::JoinSet;

use crate::access::{self, AccessEntry};
use crate::accesslog::{AccessRecord, LogFormat};
use crate::block::{BlockResponse, BlockStatus};
use crate::body::{BodyFault, BodyTooLarge, BoxError, ClientBody, Finish, Sniffed};
use crate::config::{
    AccessLogConfig, BackendConfig, Config, ConnectionConfig, MAX_REQUEST_ID_BYTES, Mode,
    SiteConfig,
};
use crate::decision::{
    Backend, ClientSlots, DecisionBackend, HttpDecisionBackend, Limits, decision_client,
};
use crate::error::ConfigError;
use crate::error::{DecisionError, ProxyError, ServeError};
use crate::limits::{self, ConnPermit, ConnStatus, KeyVars, LimitSet, ReqStatus, ZoneStore};
use crate::logsink::{Writer, spawn_writer};
use crate::policy::{self, Action, Assessment, Decision};
use crate::prefilter::{self, Screening};
use crate::proxy::{HeaderContext, HeaderOp, Proxy, upgrade_request, upstream_headers};
use crate::realip::RealIp;
use crate::router::{Router, is_valid_host, normalize_host};
use crate::rules::RuleInput;
use crate::sanitize::{self, EventInput, truncate_utf8};
use crate::system_one::SystemOneBackend;
use crate::transport::{
    ClientIo, ClientTimers, HYPER_DEFAULT_BUFFER, Phase, PhaseCell, Rejection, RejectionSlot, lock,
};
use crate::tunnel;

const DEBUG_HEADER: HeaderName = HeaderName::from_static("x-vigilant-heron");

/// Marks a response whose connection must close without the response being written (`block_status 444`).
#[derive(Debug, Clone, Copy)]
struct CloseWithoutResponse;

type ResponseBody = BoxBody<Bytes, BoxError>;

/// A destination's writer with the format its lines use.
struct Sink {
    writer: Writer,
    format: LogFormat,
}

/// Shared state for every connection.
pub(crate) struct AppState<B> {
    router: Router,
    /// The top-level access list, used for requests that match no site.
    access: Vec<AccessEntry>,
    sites: Vec<SiteConfig>,
    /// Upstream client of each site, in site order.
    proxies: Vec<Proxy>,
    /// Bytes of the request body read for the decision.
    inspect_body_bytes: usize,
    /// Header names dropped before the event is sent to the backend.
    backend_redact: Vec<String>,
    /// Body field names redacted before the event is sent to the backend (`redact_field`).
    backend_redact_fields: Vec<String>,
    /// The decision slots shared by all calls, and the `max_concurrency` they were built with.
    slots: Arc<Semaphore>,
    slots_limit: usize,
    /// Decision calls in flight per client address (`max_concurrency_per_client`).
    client_slots: Arc<ClientSlots>,
    backend: B,
    default_status: StatusCode,
    realip: RealIp,
    request_id_header: Option<HeaderName>,
    /// Access logs of each site, in site order.
    site_sinks: Vec<Vec<Sink>>,
    /// Access logs of requests that match no site, and of connections closed by the transport.
    global_sinks: Vec<Sink>,
    /// Runtime state of the `limit_req_zone` and `limit_conn_zone` zones, in definition order.
    zones: Vec<Arc<ZoneStore>>,
    /// The limits of requests that match no site.
    top_limits: LimitSet,
}

impl AppState<Backend> {
    /// Builds the state of `config`. A reload (`previous` is the state it replaces)
    /// keeps the decision slots while `max_concurrency` is unchanged, and the
    /// per-client table while `max_concurrency_per_client` is unchanged, so calls
    /// admitted before the reload still count against the limits. Zones named like a
    /// zone of `previous`, with the same size, keep their counts.
    fn from_config(config: Config, previous: Option<&Self>) -> Result<Self, ServeError> {
        let client = decision_client()?;
        let url = config.decision.url.clone();
        let (slots, client_slots) = decision_slots(&config, previous);
        let previous_zones = previous.map_or(&[][..], |old| old.zones.as_slice());
        let limits = Limits {
            timeout: config.decision.timeout,
            queue_timeout: config.decision.queue_timeout,
            slots: Arc::clone(&slots),
        };
        let backend =
            match &config.decision.backend {
                BackendConfig::Http => Backend::Http(HttpDecisionBackend::new(client, url, limits)),
                BackendConfig::Clef { model, token } => Backend::SystemOne(SystemOneBackend::new(
                    client,
                    url,
                    model.as_str().to_owned(),
                    Some(token.clone()),
                    limits,
                )),
                BackendConfig::Jev { model, token } => Backend::SystemOne(SystemOneBackend::new(
                    client,
                    url,
                    model.clone(),
                    Some(token.clone()),
                    limits,
                )),
                BackendConfig::Strands { model, token } => Backend::SystemOne(
                    SystemOneBackend::new(client, url, model.clone(), token.clone(), limits),
                ),
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
            access: config.access,
            sites: config.sites,
            proxies,
            inspect_body_bytes: config.decision.inspect_body_bytes,
            backend_redact,
            backend_redact_fields: config.decision.redact_fields.clone(),
            slots,
            slots_limit: config.decision.max_concurrency,
            client_slots,
            backend,
            default_status: config.default_status,
            realip: config.realip,
            request_id_header: config.request_id_header,
            site_sinks,
            global_sinks,
            zones: config
                .zones
                .into_iter()
                .map(|zone| {
                    let shared = previous_zones.iter().find(|old| {
                        old.name() == zone.name.as_str() && old.capacity() == zone.capacity
                    });
                    Arc::new(match shared {
                        Some(old) => ZoneStore::sharing(zone, old),
                        None => ZoneStore::new(zone),
                    })
                })
                .collect(),
            top_limits: config.limits,
        })
    }
}

/// The decision slots of a state built from `config`. A reload reuses the previous
/// slots of each limit whose value is unchanged, so calls in flight still count.
fn decision_slots(
    config: &Config,
    previous: Option<&AppState<Backend>>,
) -> (Arc<Semaphore>, Arc<ClientSlots>) {
    let slots = match previous {
        Some(old) if old.slots_limit == config.decision.max_concurrency => Arc::clone(&old.slots),
        _ => Arc::new(Semaphore::new(config.decision.max_concurrency)),
    };
    let client_slots = match previous {
        Some(old) if old.client_slots.limit() == config.decision.max_concurrency_per_client => {
            Arc::clone(&old.client_slots)
        }
        _ => ClientSlots::new(config.decision.max_concurrency_per_client),
    };
    (slots, client_slots)
}

/// Connection settings that stay the same for the whole run: a reload does not change them.
#[derive(Debug, Clone, Copy)]
struct ConnectionSettings {
    /// Connection timers and header limits.
    timers: ClientTimers,
    /// Requests per connection before it is closed.
    keepalive_requests: usize,
}

/// The settings that a reload cannot change. A reload that changes one logs a warning.
struct Startup {
    pid_file: std::path::PathBuf,
    listen: String,
    worker_threads: Option<usize>,
    max_connections: usize,
    worker_shutdown_timeout: Option<Duration>,
    connection: ConnectionConfig,
}

impl Startup {
    fn of(config: &Config) -> Self {
        Self {
            pid_file: config.pid_file.clone(),
            listen: config.listen.clone(),
            worker_threads: config.worker_threads,
            max_connections: config.max_connections,
            worker_shutdown_timeout: config.worker_shutdown_timeout,
            connection: config.connection.clone(),
        }
    }

    /// Warns about each setting of `config` that differs from the startup value.
    fn report_changes(&self, config: &Config) {
        if config.pid_file != self.pid_file {
            tracing::warn!(path = %config.pid_file.display(), "pid changed; a restart is needed for it to take effect");
        }
        if config.listen != self.listen {
            tracing::warn!(listen = %config.listen, "listen changed; a restart is needed for it to take effect");
        }
        if config.worker_threads != self.worker_threads {
            tracing::warn!("worker_threads changed; a restart is needed for it to take effect");
        }
        if config.max_connections != self.max_connections {
            tracing::warn!("max_connections changed; a restart is needed for it to take effect");
        }
        if config.worker_shutdown_timeout != self.worker_shutdown_timeout {
            tracing::warn!(
                "worker_shutdown_timeout changed; a restart is needed for it to take effect"
            );
        }
        if config.connection != self.connection {
            tracing::warn!(
                "connection timers and header limits changed; a restart is needed for them to take effect"
            );
        }
    }
}

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
/// with the same name and size exists. The listen address, `worker_threads`,
/// `max_connections` and the connection timers apply only at startup.
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
    // Each connection and each tunnel holds a clone of `open_tx`; the drain ends when none is left.
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

/// Waits for the next reload request. Without a reload source it never completes,
/// and a closed source ends the wait for good.
async fn next_reload(requests: &mut Option<mpsc::Receiver<()>>) -> Option<()> {
    match requests {
        Some(requests) => requests.recv().await,
        None => std::future::pending().await,
    }
}

/// Builds the state of a new configuration and publishes it to new requests. A
/// failure is logged and leaves the current state in place.
fn reload(
    load: &dyn Fn() -> Result<Config, ConfigError>,
    applied: &dyn Fn(&Config),
    startup: &Startup,
    current: &watch::Sender<Arc<AppState<Backend>>>,
) {
    let config = match load() {
        Ok(config) => config,
        Err(error) => {
            tracing::error!(%error, "configuration reload failed; keeping the previous configuration");
            return;
        }
    };
    startup.report_changes(&config);
    let previous = current.borrow().clone();
    match AppState::from_config(config.clone(), Some(previous.as_ref())) {
        Ok(state) => {
            current.send_replace(Arc::new(state));
            applied(&config);
            tracing::info!("configuration reloaded");
        }
        Err(error) => {
            tracing::error!(%error, "configuration reload failed; keeping the previous configuration");
        }
    }
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
    current: watch::Receiver<Arc<AppState<Backend>>>,
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
    request_id: Option<&'a str>,
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
async fn handle<B: DecisionBackend>(
    state: &AppState<B>,
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
    let request_id = request_id(state, request.headers());
    let remote = peer.ip().to_string();
    let client_upgrade = hyper::upgrade::on(&mut request);
    let (parts, body) = request.into_parts();
    let done = Arc::new(AtomicBool::new(body.is_end_stream()));
    let trace = Trace {
        upgrade: Mutex::new(Some(client_upgrade)),
        client_addr,
        client_ip: &client,
        remote_addr: &remote,
        request_id: request_id.as_deref(),
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
async fn pipeline<B: DecisionBackend>(
    state: &AppState<B>,
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
    // The access list comes next, before the body is read and before the host is judged.
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
        let input = RuleInput::new(
            &parts.method,
            raw_path,
            parts.uri.query(),
            &parts.headers,
            sniffed.prefix.as_ref(),
            trace.client_addr,
        );
        let screening = prefilter::screen(site, &input, sniffed.is_empty_body());
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
    let lowered: Vec<String> = views.iter().map(|view| view.to_lowercase()).collect();
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
    // The request headers that proxy_set_header values may use, and the operations of the level in effect.
    let header_ops = location
        .map(|location| location.proxy_headers.as_slice())
        .or_else(|| matched.map(|site| site.proxy_headers.as_slice()))
        .unwrap_or_default();
    let ctx = HeaderContext {
        client_ip: trace.client_ip,
        remote_addr: trace.remote_addr,
        host: &host,
        site: site_name(site),
        method: parts.method.as_str(),
        path: parts.uri.path(),
        request_id: trace.request_id.unwrap_or_default(),
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
        query: parts.uri.query(),
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

/// Where an allowed request is forwarded, and what a block answers with.
struct Delivery<'a> {
    /// The upstream client of the site.
    proxy: &'a Proxy,
    /// The shutdown bookkeeping of the connection, held by a tunnel that the request starts.
    tunnels: &'a tunnel::Lifetime,
    /// The site's upstream URI.
    upstream: &'a http::Uri,
    /// The `proxy_set_header` operations of the level in effect.
    headers: &'a [HeaderOp],
    /// The block response of the level in effect.
    block: &'a BlockResponse,
    /// The values `proxy_set_header` values may use.
    ctx: HeaderContext<'a>,
    /// Whether an Upgrade request is tunnelled (`proxy_websocket on`).
    websocket: bool,
    /// The client connection's upgrade, which the tunnel takes when the upstream switches protocols.
    client_upgrade: &'a Mutex<Option<OnUpgrade>>,
    /// The phase of the client connection, which a started tunnel moves to tunnelling.
    phase: &'a PhaseCell,
}

/// Forwards an allowed request, or answers a block or redirect.
///
/// `complete` says whether the request body was read in full. When it was not,
/// the response closes the connection, because the rest of the body would
/// otherwise be read as the next request.
async fn respond(
    delivery: &Delivery<'_>,
    parts: &Parts,
    body: ClientBody,
    peer: SocketAddr,
    decision: &Decision,
    held: &mut Vec<ConnPermit>,
) -> Outcome {
    let complete = body.is_complete();
    let block = delivery.block;
    match &decision.action {
        Action::Allow => {
            let path_and_query = parts
                .uri
                .path_and_query()
                .map_or("/", |value| value.as_str());
            // An Upgrade request keeps its Upgrade and Connection headers only when the site tunnels them.
            let upgrade = if delivery.websocket {
                upgrade_request(&parts.headers)
            } else {
                None
            };
            let mut headers =
                upstream_headers(&parts.headers, peer.ip(), delivery.headers, &delivery.ctx);
            if let Some(protocol) = &upgrade {
                headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
                headers.insert(UPGRADE, protocol.clone());
            }
            match delivery
                .proxy
                .forward(
                    parts.method.clone(),
                    headers,
                    path_and_query,
                    body,
                    delivery.upstream,
                )
                .await
            {
                Ok(mut upstream) => {
                    let status = upstream.status().as_u16();
                    // A 101 answer to an Upgrade request starts a tunnel; its headers are kept.
                    let switching = upgrade.is_some() && status == 101;
                    let client_upgrade = if switching {
                        lock(delivery.client_upgrade).take()
                    } else {
                        None
                    };
                    let upstream_upgrade = client_upgrade
                        .as_ref()
                        .map(|_| hyper::upgrade::on(&mut upstream));
                    let tunnel = upstream_upgrade.is_some();
                    let (mut upstream_parts, upstream_body) = upstream.into_parts();
                    if !tunnel {
                        crate::proxy::strip_hop_by_hop(&mut upstream_parts.headers);
                    }
                    if let (Some(client), Some(upstream)) = (client_upgrade, upstream_upgrade) {
                        // From here on the client connection carries tunnel bytes, not requests:
                        // its reads are neither timed nor scanned, and no response is written to it.
                        delivery.phase.set(Phase::Tunnelling);
                        tunnel::spawn(
                            client,
                            upstream,
                            delivery.proxy.read_timeout(),
                            std::mem::take(held),
                            delivery.tunnels.clone(),
                        );
                    }
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
            let mut response = match block.status {
                BlockStatus::Respond(status) => block_response(status, block.page.as_ref()),
                BlockStatus::Close => {
                    // The status is only logged: the connection closes without writing it.
                    let mut response = status_response(close_status(), "");
                    response.extensions_mut().insert(CloseWithoutResponse);
                    response
                }
            };
            if !complete {
                close(&mut response);
            }
            Outcome::answered(response)
        }
        Action::Reject(status) => {
            let mut response = status_response(*status, "");
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
fn client_addr<B>(state: &AppState<B>, headers: &HeaderMap, peer: SocketAddr) -> IpAddr {
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
        .map(normalize_host)
        .unwrap_or_default()
}

/// Reads the configured request-id header, lossily decoded and cut to 128 bytes.
fn request_id<B>(state: &AppState<B>, headers: &HeaderMap) -> Option<String> {
    let name = state.request_id_header.as_ref()?;
    let value = String::from_utf8_lossy(headers.get(name)?.as_bytes()).into_owned();
    let (value, _cut) = truncate_utf8(value, MAX_REQUEST_ID_BYTES);
    (!value.is_empty()).then_some(value)
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
        Assessment::ClientBusy => fields.decision_error = Some("client_busy"),
        Assessment::DecisionFailed { cause } => fields.decision_error = Some(cause),
        Assessment::Rule | Assessment::Skip | Assessment::SkipRule | Assessment::AccessDenied => {}
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
        query: parts.uri.query(),
        status: status.as_u16(),
        action: "reject",
        reason,
        rule_id: "",
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
        limit_req_status: *lock(&trace.limit_req),
        limit_conn_status: *lock(&trace.limit_conn),
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
        query: None,
        status: rejection.status,
        action: "reject",
        reason: rejection.reason,
        rule_id: "",
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
        limit_req_status: None,
        limit_conn_status: None,
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

/// The status of a 444 block, which is logged and never sent.
fn close_status() -> StatusCode {
    StatusCode::from_u16(444).unwrap_or(StatusCode::FORBIDDEN)
}

/// A block response: the configured page as HTML when there is one, else the short text of nginx's 403.
fn block_response(status: StatusCode, page: Option<&Bytes>) -> Response<ResponseBody> {
    match page {
        Some(page) => {
            let mut response = Response::new(
                Full::new(page.clone())
                    .map_err(|never: Infallible| match never {})
                    .boxed(),
            );
            *response.status_mut() = status;
            response.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            );
            response
        }
        None if status == StatusCode::FORBIDDEN => status_response(status, "Forbidden\n"),
        None => status_response(status, ""),
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
