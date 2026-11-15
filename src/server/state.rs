//! The state built from a configuration, which every connection shares: the sites, the
//! backend, the log sinks and the limit zones. Also the settings of a client connection.

use std::collections::HashMap;
use std::sync::Arc;

use http::StatusCode;
use http::header::HeaderName;
use tokio::sync::Semaphore;

use crate::access::AccessEntry;
use crate::accesslog::LogFormat;
use crate::backend::Backend;
use crate::backend::decision::{ClientSlots, HttpDecisionBackend, Limits, decision_client};
use crate::backend::system_one::SystemOneBackend;
use crate::config::{AccessLogConfig, BackendConfig, Config, SiteConfig};
use crate::error::ServeError;
use crate::limits::{LimitSet, LimitZone, ZoneStore};
use crate::logsink::{Writer, spawn_writer};
use crate::proxy::Proxy;
use crate::realip::RealIp;
use crate::router::Router;
use crate::transport::ClientTimers;

/// A destination's writer with the format its lines use.
pub(crate) struct Sink {
    pub(crate) writer: Writer,
    pub(crate) format: LogFormat,
}

/// Shared state for every connection.
pub(crate) struct AppState {
    pub(crate) router: Router,
    /// The top-level access list, used for requests that match no site.
    pub(crate) access: Vec<AccessEntry>,
    pub(crate) sites: Vec<SiteConfig>,
    /// Upstream client of each site, in site order.
    pub(crate) proxies: Vec<Proxy>,
    /// Bytes of the request body read for the decision.
    pub(crate) inspect_body_bytes: usize,
    /// Header names dropped before the event is sent to the backend.
    pub(crate) backend_redact: Vec<String>,
    /// Body field names redacted before the event is sent to the backend (`redact_field`).
    pub(crate) backend_redact_fields: Vec<String>,
    /// Whether multipart file content is replaced before the event is sent (`redact_file_parts`).
    pub(crate) backend_redact_file_parts: bool,
    /// The decision slots shared by all calls, and the `max_concurrency` they were built with.
    slots: Arc<Semaphore>,
    slots_limit: usize,
    /// Decision calls in flight per client address (`max_concurrency_per_client`).
    pub(crate) client_slots: Arc<ClientSlots>,
    pub(crate) backend: Backend,
    pub(crate) default_status: StatusCode,
    pub(crate) realip: RealIp,
    pub(crate) request_id_header: Option<HeaderName>,
    /// Access logs of each site, in site order.
    pub(crate) site_sinks: Vec<Vec<Sink>>,
    /// Access logs of requests that match no site, and of connections closed by the transport.
    pub(crate) global_sinks: Vec<Sink>,
    /// Runtime state of the `limit_req_zone` and `limit_conn_zone` zones, in definition order.
    pub(crate) zones: Vec<Arc<ZoneStore>>,
    /// The limits of requests that match no site.
    pub(crate) top_limits: LimitSet,
}

impl AppState {
    /// Builds the state of `config`. A reload (`previous` is the state it replaces)
    /// keeps the decision slots while `max_concurrency` is unchanged, and the
    /// per-client table while `max_concurrency_per_client` is unchanged, so calls
    /// admitted before the reload still count against the limits. Zones named like a
    /// zone of `previous`, with the same size, keep their counts.
    pub(crate) fn from_config(config: Config, previous: Option<&Self>) -> Result<Self, ServeError> {
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
        let (global_sinks, site_sinks) = access_sinks(&config);
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
            backend_redact_file_parts: config.decision.redact_file_parts,
            slots,
            slots_limit: config.decision.max_concurrency,
            client_slots,
            backend,
            default_status: config.default_status,
            realip: config.realip,
            request_id_header: config.request_id_header,
            site_sinks,
            global_sinks,
            zones: zone_stores(config.zones, previous_zones),
            top_limits: config.limits,
        })
    }
}

/// The access-log sinks of `config`: those of requests that match no site, and those of
/// each site, in the order of `config.sites`. Sinks with the same destination share one
/// writer.
fn access_sinks(config: &Config) -> (Vec<Sink>, Vec<Vec<Sink>>) {
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
    let site_sinks: Vec<Vec<Sink>> = config
        .sites
        .iter()
        .map(|site| {
            let logs = site.access_logs.as_deref().unwrap_or(&config.access_logs);
            sinks_for(logs)
        })
        .collect();
    (global_sinks, site_sinks)
}

/// The stores of `zones`. A zone named like one of `previous`, with the same size, shares
/// its counts.
fn zone_stores(zones: Vec<LimitZone>, previous: &[Arc<ZoneStore>]) -> Vec<Arc<ZoneStore>> {
    zones
        .into_iter()
        .map(|zone| {
            let shared = previous
                .iter()
                .find(|old| old.name() == zone.name.as_str() && old.capacity() == zone.capacity);
            Arc::new(match shared {
                Some(old) => ZoneStore::sharing(zone, old),
                None => ZoneStore::new(zone),
            })
        })
        .collect()
}

/// The decision slots of a state built from `config`. A reload reuses the previous
/// slots of each limit whose value is unchanged, so calls in flight still count.
fn decision_slots(
    config: &Config,
    previous: Option<&AppState>,
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
pub(crate) struct ConnectionSettings {
    /// Connection timers and header limits.
    pub(crate) timers: ClientTimers,
    /// Requests per connection before it is closed.
    pub(crate) keepalive_requests: usize,
}
