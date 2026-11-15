//! The access records of requests, and the answer to a request that is rejected before a
//! decision.

use std::net::SocketAddr;
use std::time::{Instant, SystemTime};

use http::header::HOST;
use http::request::Parts;
use http::{HeaderMap, Response, StatusCode};

use crate::accesslog::AccessRecord;
use crate::policy::Assessment;
use crate::sync::lock;
use crate::transport::Rejection;

use super::Trace;
use super::respond::{ResponseBody, close, empty_answer};
use super::state::Sink;

pub(crate) fn latency(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Queues one line per destination. A destination whose queue is full drops the line.
pub(crate) fn write_access(sinks: &[Sink], record: &AccessRecord<'_>, headers: &HeaderMap) {
    for sink in sinks {
        sink.writer.send(sink.format.render(record, headers));
    }
}

/// The verdict fields of an access record. Each is empty when no backend answered.
pub(crate) struct VerdictFields<'a> {
    pub(crate) attack: Option<f64>,
    pub(crate) ai_instruction: Option<f64>,
    pub(crate) category: Option<&'a str>,
    pub(crate) input_tokens: Option<u64>,
    pub(crate) decision_error: Option<&'a str>,
    pub(crate) retry_after: Option<&'a str>,
}

pub(crate) fn verdict_fields(assessment: &Assessment) -> VerdictFields<'_> {
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

/// The record of a request answered before a decision. Only the status, the reason and
/// the latency are set; a caller fills in the request fields with struct update syntax.
fn rejection_record(status: u16, reason: &str, started: Instant) -> AccessRecord<'_> {
    AccessRecord {
        time: SystemTime::now(),
        request_id: None,
        client_ip: "",
        remote_addr: "",
        site: "",
        host: "",
        method: "",
        path: "",
        query: None,
        block_query: None,
        status,
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
        latency_ms: latency(started),
        limit_req_status: None,
        limit_conn_status: None,
    }
}

/// The `Host` header as sent, or an empty string when it is missing or not text.
pub(crate) fn raw_host(parts: &Parts) -> &str {
    parts
        .headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
}

/// Answers a request that never reached a decision, and logs it as a rejection.
///
/// `closing` adds `Connection: close`, for a request whose body was not read in full.
pub(crate) fn reject(
    parts: &Parts,
    trace: &Trace<'_>,
    site: &str,
    status: StatusCode,
    reason: &str,
    sinks: &[Sink],
    closing: bool,
) -> Response<ResponseBody> {
    let record = AccessRecord {
        request_id: Some(trace.request_id),
        client_ip: trace.client_ip,
        remote_addr: trace.remote_addr,
        site,
        host: raw_host(parts),
        method: parts.method.as_str(),
        path: parts.uri.path(),
        query: parts.uri.query(),
        limit_req_status: *lock(&trace.limit_req),
        limit_conn_status: *lock(&trace.limit_conn),
        ..rejection_record(status.as_u16(), reason, trace.started)
    };
    write_access(sinks, &record, &parts.headers);
    let mut response = empty_answer(status, trace.request_id);
    if closing {
        close(&mut response);
    }
    response
}

/// Logs a response the transport sent on its own, such as a 408 or a 414.
pub(crate) fn write_rejection(
    sinks: &[Sink],
    rejection: Rejection,
    peer: SocketAddr,
    started: Instant,
) {
    let remote = peer.ip().to_string();
    let record = AccessRecord {
        client_ip: &remote,
        remote_addr: &remote,
        ..rejection_record(rejection.status, rejection.reason, started)
    };
    write_access(sinks, &record, &HeaderMap::new());
}
