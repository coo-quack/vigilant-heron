//! The screening of one request against the limits that apply to it, and the log line of a
//! limit event.

use std::sync::Arc;
use std::time::Duration;

use http::{HeaderMap, StatusCode};
use tokio::time::Instant;

use super::config::{KeyPart, KeyVar, LimitLog, LimitSet};
use super::state::{ConnPermit, ConnStatus, Pending, ReqStatus, ZoneStore};

/// The request values a limit key can use.
#[derive(Debug, Clone, Copy)]
pub(crate) struct KeyVars<'a> {
    /// The client address after real-IP selection.
    pub(crate) client_ip: &'a str,
    /// The address of the connection's peer.
    pub(crate) remote_addr: &'a str,
    /// The first host of the matched site, or empty.
    pub(crate) site: &'a str,
    /// The normalized `Host` header.
    pub(crate) host: &'a str,
    /// The request method.
    pub(crate) method: &'a str,
    /// The decoded path, case kept.
    pub(crate) path: &'a str,
    /// The request headers.
    pub(crate) headers: &'a HeaderMap,
}

/// Renders a limit key, or returns `None` when it is empty, which nginx does not count.
pub(crate) fn render_key(parts: &[KeyPart], vars: &KeyVars<'_>) -> Option<String> {
    let mut key = String::new();
    for part in parts {
        match part {
            KeyPart::Literal(text) => key.push_str(text),
            KeyPart::Var(KeyVar::ClientIp) => key.push_str(vars.client_ip),
            KeyPart::Var(KeyVar::RemoteAddr) => key.push_str(vars.remote_addr),
            KeyPart::Var(KeyVar::Site) => key.push_str(vars.site),
            KeyPart::Var(KeyVar::Host) => key.push_str(vars.host),
            KeyPart::Var(KeyVar::Method) => key.push_str(vars.method),
            KeyPart::Var(KeyVar::Path) => key.push_str(vars.path),
            KeyPart::Var(KeyVar::Header(name)) => {
                if let Some(value) = vars.headers.get(name) {
                    key.push_str(&String::from_utf8_lossy(value.as_bytes()));
                }
            }
        }
    }
    (!key.is_empty()).then_some(key)
}

/// A request the limits refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Refusal {
    /// `limit_req` or `limit_conn`, the reason in the access log.
    pub(crate) reason: &'static str,
    /// The status to answer with.
    pub(crate) status: StatusCode,
}

/// What the limits decided for one request.
#[derive(Debug, Default)]
pub(crate) struct Screened {
    /// The worst `limit_req` outcome, when a zone applied.
    pub(crate) req_status: Option<ReqStatus>,
    /// The worst `limit_conn` outcome, when a zone applied.
    pub(crate) conn_status: Option<ConnStatus>,
    /// A rejection that is enforced. The request must not go on.
    pub(crate) refusal: Option<Refusal>,
    /// The status a rejection would have had in dry run or shadow mode.
    pub(crate) would_have: Option<StatusCode>,
}

/// Runs the `limit_req` and `limit_conn` checks of one request.
///
/// `shadow` makes every check a dry run. The `limit_req` checks run first, and
/// the delay of the request is waited for once all of them have passed. The
/// `limit_conn` permits are pushed onto `permits`, which the caller keeps until
/// the response body is done. A refused request keeps no permit.
///
/// `sets` holds the limits of every location the request selects. Each set is
/// checked in turn, so a request cannot escape one location's limits by selecting
/// another, and the longest delay of the sets is waited for once.
pub(crate) async fn screen(
    zones: &[Arc<ZoneStore>],
    sets: &[&LimitSet],
    shadow: bool,
    vars: &KeyVars<'_>,
    permits: &mut Vec<ConnPermit>,
) -> Screened {
    let mut screened = Screened::default();
    let mut wait = Duration::ZERO;
    let mut held: Vec<Pending> = Vec::new();
    for limits in sets {
        let (set_wait, set_held) = screen_req(zones, limits, shadow, vars, &mut screened);
        wait = wait.max(set_wait);
        held.extend(set_held);
        if screened.refusal.is_some() {
            break;
        }
    }
    if screened.refusal.is_none() {
        for limits in sets {
            screen_conn(zones, limits, shadow, vars, permits, &mut screened);
            if screened.refusal.is_some() {
                break;
            }
        }
    }
    if screened.refusal.is_none() && !wait.is_zero() {
        tokio::time::sleep(wait).await;
    }
    // The delayed states stay in use until the wait is over.
    drop(held);
    screened
}

/// The `limit_req` checks. Returns how long the request waits, and the delayed
/// states, which the caller holds until the wait is over.
fn screen_req(
    zones: &[Arc<ZoneStore>],
    limits: &LimitSet,
    shadow: bool,
    vars: &KeyVars<'_>,
    screened: &mut Screened,
) -> (Duration, Vec<Pending>) {
    let now = Instant::now();
    let dry_run = limits.req_dry_run || shadow;
    let mut wait = Duration::ZERO;
    let mut held: Vec<Pending> = Vec::new();
    for limit in &limits.req {
        let Some(zone) = zones.get(limit.zone) else {
            continue;
        };
        let Some(key) = render_key(&zone.def.key, vars) else {
            continue;
        };
        let Ok(admission) = zone.admit(&key, limit, dry_run, now) else {
            // nginx treats an allocation failure like a rejection, with the same status.
            log_exhausted(limits.req_log, zone.name(), vars.client_ip);
            let status = if dry_run {
                ReqStatus::RejectedDryRun
            } else {
                ReqStatus::Rejected
            };
            screened.req_status = Some(worst(screened.req_status, status));
            if dry_run {
                screened.would_have.get_or_insert(limits.req_status);
                continue;
            }
            screened.refusal = Some(Refusal {
                reason: "limit_req",
                status: limits.req_status,
            });
            break;
        };
        let status = admission.status;
        screened.req_status = Some(worst(screened.req_status, status));
        if status != ReqStatus::Passed {
            log_event(limits.req_log, zone.name(), vars.client_ip, status.name());
        }
        match status {
            ReqStatus::Passed | ReqStatus::Delayed | ReqStatus::DelayedDryRun => {}
            ReqStatus::RejectedDryRun => {
                screened.would_have.get_or_insert(limits.req_status);
            }
            ReqStatus::Rejected => {
                screened.refusal = Some(Refusal {
                    reason: "limit_req",
                    status: limits.req_status,
                });
                break;
            }
        }
        wait = wait.max(admission.wait);
        held.extend(admission.pending);
    }
    (wait, held)
}

/// The `limit_conn` checks. Each counted request is pushed onto `permits`.
fn screen_conn(
    zones: &[Arc<ZoneStore>],
    limits: &LimitSet,
    shadow: bool,
    vars: &KeyVars<'_>,
    permits: &mut Vec<ConnPermit>,
    screened: &mut Screened,
) {
    let now = Instant::now();
    let dry_run = limits.conn_dry_run || shadow;
    for limit in &limits.conn {
        let Some(zone) = zones.get(limit.zone) else {
            continue;
        };
        let Some(key) = render_key(&zone.def.key, vars) else {
            continue;
        };
        let Ok(admission) = zone.acquire(&key, limit.max, dry_run, now) else {
            // nginx releases what the request holds and treats it like a rejection.
            log_exhausted(limits.conn_log, zone.name(), vars.client_ip);
            let status = if dry_run {
                ConnStatus::RejectedDryRun
            } else {
                ConnStatus::Rejected
            };
            screened.conn_status = Some(match screened.conn_status {
                Some(previous) => previous.max(status),
                None => status,
            });
            if dry_run {
                screened.would_have.get_or_insert(limits.conn_status);
                continue;
            }
            screened.refusal = Some(Refusal {
                reason: "limit_conn",
                status: limits.conn_status,
            });
            break;
        };
        let status = admission.status;
        screened.conn_status = Some(match screened.conn_status {
            Some(previous) => previous.max(status),
            None => status,
        });
        if status != ConnStatus::Passed {
            log_event(limits.conn_log, zone.name(), vars.client_ip, status.name());
        }
        if let Some(permit) = admission.permit {
            permits.push(permit);
        }
        match status {
            ConnStatus::Passed => {}
            ConnStatus::RejectedDryRun => {
                screened.would_have.get_or_insert(limits.conn_status);
            }
            ConnStatus::Rejected => {
                screened.refusal = Some(Refusal {
                    reason: "limit_conn",
                    status: limits.conn_status,
                });
                break;
            }
        }
    }
}

fn worst(previous: Option<ReqStatus>, status: ReqStatus) -> ReqStatus {
    previous.map_or(status, |previous| previous.max(status))
}

/// Writes a zone-exhaustion event, distinct from an ordinary excess, to the error log.
fn log_exhausted(level: LimitLog, zone: &str, client: &str) {
    match level {
        LimitLog::Error => {
            tracing::error!(zone, client, limit_error = "zone_exhausted", "limit event");
        }
        LimitLog::Warn => {
            tracing::warn!(zone, client, limit_error = "zone_exhausted", "limit event");
        }
        LimitLog::Info | LimitLog::Notice => {
            tracing::info!(zone, client, limit_error = "zone_exhausted", "limit event");
        }
    }
}

/// Writes one limit event to the error log at the configured severity.
fn log_event(level: LimitLog, zone: &str, client: &str, event: &str) {
    match level {
        LimitLog::Error => tracing::error!(zone, client, event, "limit event"),
        LimitLog::Warn => tracing::warn!(zone, client, event, "limit event"),
        LimitLog::Info | LimitLog::Notice => tracing::info!(zone, client, event, "limit event"),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use http::{HeaderMap, HeaderName, HeaderValue};
    use rstest::rstest;
    use tokio::time::Instant;

    use super::*;
    use crate::error::ConfigError;
    use crate::limits::config::{ConnLimit, LimitZone, ReqLimit, ZoneKind};
    use crate::limits::test_helpers::{ONE, TWO, conn_store, parse, req, store};

    #[test]
    fn a_key_renders_its_variables_and_an_empty_key_is_not_counted() {
        let mut headers = HeaderMap::new();
        headers.insert("x-tenant", HeaderValue::from_static("acme"));
        let vars = KeyVars {
            client_ip: "203.0.113.7",
            remote_addr: "10.0.0.2",
            site: "example.com",
            host: "example.com",
            method: "POST",
            path: "/wp-login.php",
            headers: &headers,
        };
        let key = |text: &str| -> Option<String> {
            let parts = parse_key_for_test(text);
            render_key(&parts, &vars)
        };
        assert_eq!(key("$client_ip").as_deref(), Some("203.0.113.7"));
        assert_eq!(
            key("$site|$method|$path").as_deref(),
            Some("example.com|POST|/wp-login.php")
        );
        assert_eq!(key("$http_x_tenant").as_deref(), Some("acme"));
        assert_eq!(key("$http_x_missing"), None);
        // Literal text keeps the key non-empty, so the key is counted as "-".
        assert_eq!(key("$http_x_missing-").as_deref(), Some("-"));
    }

    fn parse_key_for_test(text: &str) -> Vec<KeyPart> {
        let config = parse(
            &format!("limit_req_zone \"{text}\" zone=k:1m rate=1r/s;"),
            "",
        );
        config
            .ok()
            .and_then(|config| config.zones.into_iter().next())
            .map_or_default(|zone| zone.key)
    }

    /// Everything the process-wide error log test subscriber has written.
    static CAPTURED: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());

    /// Serializes the tests that read `CAPTURED`, so each reads only its own lines.
    static CAPTURE_TURN: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[derive(Clone, Copy)]
    struct CaptureWriter;

    impl std::io::Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            CAPTURED
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Runs `f` with the error log's formatting on and returns the lines it wrote
    /// that contain `marker`. Each test uses a marker unique to itself, since other
    /// tests may log at the same time.
    fn log_lines_for(marker: &str, f: impl FnOnce()) -> Vec<String> {
        static INSTALL: std::sync::Once = std::sync::Once::new();
        INSTALL.call_once(|| {
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_ansi(false)
                .without_time()
                .with_writer(|| CaptureWriter)
                .finish();
            let _ = tracing::subscriber::set_global_default(subscriber);
        });
        let _turn = CAPTURE_TURN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = CAPTURED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len();
        f();
        let bytes = CAPTURED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        String::from_utf8_lossy(bytes.get(before..).unwrap_or_default())
            .lines()
            .filter(|line| line.contains(marker))
            .map(str::to_owned)
            .collect()
    }

    fn named_store(name: &str, capacity: usize, interval_ns: u64) -> Arc<ZoneStore> {
        Arc::new(ZoneStore::new(LimitZone {
            name: name.to_owned(),
            key: vec![KeyPart::Var(KeyVar::ClientIp)],
            capacity,
            kind: ZoneKind::Req { interval_ns },
        }))
    }

    fn named_conn_store(name: &str, capacity: usize) -> Arc<ZoneStore> {
        Arc::new(ZoneStore::new(LimitZone {
            name: name.to_owned(),
            key: vec![KeyPart::Var(KeyVar::ClientIp)],
            capacity,
            kind: ZoneKind::Conn,
        }))
    }

    /// Runs `screen` for one request on a fresh current-thread runtime.
    fn screen_now(
        zones: &[Arc<ZoneStore>],
        set: &LimitSet,
        vars: &KeyVars<'_>,
        permits: &mut Vec<ConnPermit>,
    ) -> Option<Screened> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .ok()?;
        Some(runtime.block_on(screen(zones, &[set], false, vars, permits)))
    }

    #[rstest]
    #[case(LimitLog::Info, "INFO")]
    #[case(LimitLog::Notice, "INFO")]
    #[case(LimitLog::Warn, "WARN")]
    #[case(LimitLog::Error, "ERROR")]
    fn a_limit_event_is_written_at_the_configured_severity(
        #[case] level: LimitLog,
        #[case] severity: &str,
    ) {
        let zone = format!("sev-{level:?}");
        let lines = log_lines_for(&zone, || {
            log_event(level, &zone, "203.0.113.7", "REJECTED");
        });
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines.first().is_some_and(|line| line.contains(severity)),
            "{lines:?}"
        );
        assert!(
            lines
                .first()
                .is_some_and(|line| line.contains("event=\"REJECTED\"")),
            "{lines:?}"
        );
    }

    #[rstest]
    #[case(LimitLog::Info, "INFO")]
    #[case(LimitLog::Notice, "INFO")]
    #[case(LimitLog::Warn, "WARN")]
    #[case(LimitLog::Error, "ERROR")]
    fn a_zone_exhaustion_is_written_at_the_configured_severity(
        #[case] level: LimitLog,
        #[case] severity: &str,
    ) {
        let zone = format!("exh-{level:?}");
        let lines = log_lines_for(&zone, || {
            log_exhausted(level, &zone, "203.0.113.7");
        });
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines.first().is_some_and(|line| line.contains(severity)),
            "{lines:?}"
        );
        assert!(
            lines
                .first()
                .is_some_and(|line| line.contains("limit_error=\"zone_exhausted\"")),
            "{lines:?}"
        );
    }

    #[rstest]
    #[case("info", "INFO")]
    #[case("notice", "INFO")]
    #[case("warn", "WARN")]
    #[case("error", "ERROR")]
    fn a_limit_log_level_word_sets_the_severity_of_limit_events(
        #[case] word: &str,
        #[case] severity: &str,
    ) -> Result<(), ConfigError> {
        let config = parse(&format!("{ONE}\n{TWO}\nlimit_req_log_level {word};"), "")?;
        let level = config.limits.req_log;
        let zone = format!("word-{word}");
        let lines = log_lines_for(&zone, || {
            log_event(level, &zone, "203.0.113.7", "REJECTED");
        });
        assert!(
            lines.first().is_some_and(|line| line.contains(severity)),
            "{lines:?}"
        );
        Ok(())
    }

    #[test]
    fn a_request_that_passes_the_limits_writes_nothing_to_the_error_log() {
        let zones = vec![named_store("pass-quiet", 100, 1_000_000_000)];
        let set = LimitSet {
            req: vec![req(5, 5)],
            ..LimitSet::default()
        };
        let headers = HeaderMap::new();
        let vars = vars_for("203.0.113.7", &headers);
        let mut permits = Vec::new();
        let mut refusal = None;
        let lines = log_lines_for("pass-quiet", || {
            refusal = screen_now(&zones, &set, &vars, &mut permits).and_then(|s| s.refusal);
        });
        assert_eq!(refusal, None);
        assert!(lines.is_empty(), "{lines:?}");
    }

    #[test]
    fn a_rejected_request_writes_one_limit_event_naming_its_zone() {
        let zones = vec![named_store("reject-once", 100, 1_000_000_000)];
        let set = LimitSet {
            req: vec![req(0, 0)],
            ..LimitSet::default()
        };
        let headers = HeaderMap::new();
        let vars = vars_for("203.0.113.7", &headers);
        let mut permits = Vec::new();
        let mut second_refusal = None;
        let lines = log_lines_for("reject-once", || {
            let _ = screen_now(&zones, &set, &vars, &mut permits);
            second_refusal = screen_now(&zones, &set, &vars, &mut permits).and_then(|s| s.refusal);
        });
        assert_eq!(second_refusal.map(|r| r.reason), Some("limit_req"));
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines.first().is_some_and(|line| line.contains("ERROR")),
            "{lines:?}"
        );
        assert!(
            lines
                .first()
                .is_some_and(|line| line.contains("event=\"REJECTED\"")),
            "{lines:?}"
        );
    }

    #[test]
    fn a_connection_limit_writes_an_event_only_when_it_rejects() {
        let zones = vec![named_conn_store("conn-once", 100)];
        let set = LimitSet {
            conn: vec![ConnLimit { zone: 0, max: 1 }],
            ..LimitSet::default()
        };
        let headers = HeaderMap::new();
        let vars = vars_for("203.0.113.7", &headers);
        let mut permits = Vec::new();
        let lines = log_lines_for("conn-once", || {
            screen_now(&zones, &set, &vars, &mut permits);
            screen_now(&zones, &set, &vars, &mut permits);
        });
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines
                .first()
                .is_some_and(|line| line.contains("event=\"REJECTED\"")),
            "{lines:?}"
        );
    }

    #[test]
    fn an_exhausted_zone_writes_a_zone_exhausted_event_naming_its_zone() {
        // One state, held by a delayed request, so the second client finds no state to evict.
        let zone = named_store("exhaust-zone", 1, 1_000_000_000);
        let now = Instant::now();
        let first = zone.admit("a", &req(1, 0), false, now).ok();
        let held = zone.admit("a", &req(1, 0), false, now).ok();
        assert!(first.is_some());
        assert!(
            held.as_ref()
                .is_some_and(|admission| admission.status == ReqStatus::Delayed)
        );
        let zones = vec![zone];
        let set = LimitSet {
            req: vec![req(1, 0)],
            ..LimitSet::default()
        };
        let headers = HeaderMap::new();
        let vars = vars_for("198.51.100.9", &headers);
        let mut permits = Vec::new();
        let mut refusal = None;
        let lines = log_lines_for("exhaust-zone", || {
            refusal = screen_now(&zones, &set, &vars, &mut permits).and_then(|s| s.refusal);
        });
        assert!(refusal.is_some());
        assert!(
            lines
                .first()
                .is_some_and(|line| line.contains("limit_error=\"zone_exhausted\"")),
            "{lines:?}"
        );
    }

    #[rstest]
    #[case("$client_ip", "203.0.113.7")]
    #[case("$remote_addr", "10.0.0.2")]
    #[case("$site", "example.com")]
    #[case("$host", "www.example.com")]
    #[case("$method", "POST")]
    #[case("$path", "/login")]
    fn each_limit_key_variable_renders_its_own_request_value(
        #[case] text: &str,
        #[case] value: &str,
    ) {
        let headers = HeaderMap::new();
        let vars = KeyVars {
            client_ip: "203.0.113.7",
            remote_addr: "10.0.0.2",
            site: "example.com",
            host: "www.example.com",
            method: "POST",
            path: "/login",
            headers: &headers,
        };
        let parts = parse_key_for_test(text);
        assert_eq!(render_key(&parts, &vars).as_deref(), Some(value));
    }

    #[tokio::test(start_paused = true)]
    async fn a_refused_request_keeps_no_connection_count() {
        let zones = vec![store(10, 1_000_000_000), conn_store(10)];
        let limits = LimitSet {
            req: vec![req(0, 0)],
            conn: vec![ConnLimit { zone: 1, max: 5 }],
            ..LimitSet::default()
        };
        let headers = HeaderMap::new();
        let vars = KeyVars {
            client_ip: "203.0.113.7",
            remote_addr: "10.0.0.2",
            site: "example.com",
            host: "example.com",
            method: "GET",
            path: "/",
            headers: &headers,
        };
        let mut permits = Vec::new();
        let first = screen(&zones, &[&limits], false, &vars, &mut permits).await;
        assert!(first.refusal.is_none());
        let second = screen(&zones, &[&limits], false, &vars, &mut permits).await;
        assert_eq!(second.refusal.map(|r| r.reason), Some("limit_req"));
        assert_eq!(second.req_status, Some(ReqStatus::Rejected));
        assert_eq!(permits.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_delayed_request_waits_and_a_shadow_request_is_not_delayed() {
        let zones = vec![store(10, 1_000_000_000)];
        let limits = LimitSet {
            req: vec![req(2, 0)],
            ..LimitSet::default()
        };
        let headers = HeaderMap::new();
        let vars = KeyVars {
            client_ip: "203.0.113.7",
            remote_addr: "10.0.0.2",
            site: "example.com",
            host: "example.com",
            method: "GET",
            path: "/",
            headers: &headers,
        };
        let mut permits = Vec::new();
        let _first = screen(&zones, &[&limits], false, &vars, &mut permits).await;
        let started = Instant::now();
        let second = screen(&zones, &[&limits], false, &vars, &mut permits).await;
        assert_eq!(second.req_status, Some(ReqStatus::Delayed));
        assert_eq!(started.elapsed(), Duration::from_secs(1));
        let shadow = screen(&zones, &[&limits], true, &vars, &mut permits).await;
        assert_eq!(shadow.req_status, Some(ReqStatus::DelayedDryRun));
        assert!(shadow.refusal.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn a_key_that_is_empty_is_not_counted_at_all() {
        let zones = vec![store(10, 1_000_000_000)];
        let limits = LimitSet {
            req: vec![ReqLimit {
                zone: 0,
                burst: 0,
                undelayed: 0,
            }],
            ..LimitSet::default()
        };
        let headers = HeaderMap::new();
        let zone = Arc::new(ZoneStore::new(LimitZone {
            name: "h".to_owned(),
            key: vec![KeyPart::Var(KeyVar::Header(HeaderName::from_static(
                "x-missing",
            )))],
            capacity: 10,
            kind: ZoneKind::Req {
                interval_ns: 1_000_000_000,
            },
        }));
        let vars = KeyVars {
            client_ip: "203.0.113.7",
            remote_addr: "10.0.0.2",
            site: "",
            host: "",
            method: "GET",
            path: "/",
            headers: &headers,
        };
        let mut permits = Vec::new();
        let zones_with_header = vec![zone];
        for _ in 0..3 {
            let screened = screen(&zones_with_header, &[&limits], false, &vars, &mut permits).await;
            assert!(screened.req_status.is_none());
            assert!(screened.refusal.is_none());
        }
        let _ = zones;
    }

    #[test]
    fn a_limited_request_gets_its_status_and_the_refusal_names_its_limit() {
        let refusal = Refusal {
            reason: "limit_req",
            status: StatusCode::TOO_MANY_REQUESTS,
        };
        assert_eq!(refusal.status.as_u16(), 429);
        assert_eq!(ReqStatus::RejectedDryRun.name(), "REJECTED_DRY_RUN");
        assert_eq!(ConnStatus::RejectedDryRun.name(), "REJECTED_DRY_RUN");
    }

    fn vars_for<'a>(client: &'a str, headers: &'a HeaderMap) -> KeyVars<'a> {
        KeyVars {
            client_ip: client,
            remote_addr: "10.0.0.2",
            site: "example.com",
            host: "example.com",
            method: "GET",
            path: "/",
            headers,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_exhausted_req_zone_answers_with_the_configured_status() {
        let zones = vec![store(1, 1_000_000_000)];
        let limit = req(1, 0);
        let limits = LimitSet {
            req: vec![limit.clone()],
            req_status: StatusCode::TOO_MANY_REQUESTS,
            ..LimitSet::default()
        };
        // One delayed request holds the only state of the zone.
        let now = Instant::now();
        let _first = zones
            .first()
            .map(|zone| zone.admit("held", &limit, false, now));
        let _holder = zones
            .first()
            .map(|zone| zone.admit("held", &limit, false, now));
        let headers = HeaderMap::new();
        let mut permits = Vec::new();
        let screened = screen(
            &zones,
            &[&limits],
            false,
            &vars_for("other", &headers),
            &mut permits,
        )
        .await;
        assert_eq!(screened.req_status, Some(ReqStatus::Rejected));
        assert_eq!(
            screened.refusal,
            Some(Refusal {
                reason: "limit_req",
                status: StatusCode::TOO_MANY_REQUESTS,
            })
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_exhausted_req_zone_in_dry_run_lets_the_request_through() {
        let zones = vec![store(1, 1_000_000_000)];
        let limit = req(1, 0);
        let limits = LimitSet {
            req: vec![limit.clone()],
            req_status: StatusCode::TOO_MANY_REQUESTS,
            req_dry_run: true,
            ..LimitSet::default()
        };
        let now = Instant::now();
        let _first = zones
            .first()
            .map(|zone| zone.admit("held", &limit, false, now));
        let _holder = zones
            .first()
            .map(|zone| zone.admit("held", &limit, false, now));
        let headers = HeaderMap::new();
        let mut permits = Vec::new();
        let screened = screen(
            &zones,
            &[&limits],
            false,
            &vars_for("other", &headers),
            &mut permits,
        )
        .await;
        assert_eq!(screened.req_status, Some(ReqStatus::RejectedDryRun));
        assert!(screened.refusal.is_none());
        assert_eq!(screened.would_have, Some(StatusCode::TOO_MANY_REQUESTS));
    }

    #[tokio::test(start_paused = true)]
    async fn an_exhausted_conn_zone_answers_with_the_configured_status_and_keeps_no_count() {
        let zones = vec![conn_store(1)];
        let limits = LimitSet {
            conn: vec![ConnLimit { zone: 0, max: 5 }],
            conn_status: StatusCode::TOO_MANY_REQUESTS,
            ..LimitSet::default()
        };
        let now = Instant::now();
        let _holder = zones
            .first()
            .map(|zone| zone.acquire("held", 5, false, now));
        let headers = HeaderMap::new();
        let mut permits = Vec::new();
        let screened = screen(
            &zones,
            &[&limits],
            false,
            &vars_for("other", &headers),
            &mut permits,
        )
        .await;
        assert_eq!(screened.conn_status, Some(ConnStatus::Rejected));
        assert_eq!(
            screened.refusal,
            Some(Refusal {
                reason: "limit_conn",
                status: StatusCode::TOO_MANY_REQUESTS,
            })
        );
        assert!(permits.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn an_exhausted_conn_zone_in_dry_run_lets_the_request_through() {
        let zones = vec![conn_store(1)];
        let limits = LimitSet {
            conn: vec![ConnLimit { zone: 0, max: 5 }],
            conn_status: StatusCode::TOO_MANY_REQUESTS,
            conn_dry_run: true,
            ..LimitSet::default()
        };
        let now = Instant::now();
        let _holder = zones
            .first()
            .map(|zone| zone.acquire("held", 5, false, now));
        let headers = HeaderMap::new();
        let mut permits = Vec::new();
        let screened = screen(
            &zones,
            &[&limits],
            false,
            &vars_for("other", &headers),
            &mut permits,
        )
        .await;
        assert_eq!(screened.conn_status, Some(ConnStatus::RejectedDryRun));
        assert!(screened.refusal.is_none());
        assert_eq!(screened.would_have, Some(StatusCode::TOO_MANY_REQUESTS));
    }
}
