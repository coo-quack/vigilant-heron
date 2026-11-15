//! The responses of a request: forwarding, blocks, redirects and failures.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Mutex;

use bytes::Bytes;
use http::header::{
    CONNECTION, CONTENT_TYPE, HeaderName, HeaderValue, LOCATION, UPGRADE, X_CONTENT_TYPE_OPTIONS,
};
use http::request::Parts;
use http::{HeaderMap, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::upgrade::OnUpgrade;

use crate::block::{BlockResponse, BlockStatus};
use crate::body::{BodyFault, BodyTooLarge, BoxError, ClientBody};
use crate::error::ProxyError;
use crate::limits::ConnPermit;
use crate::phase::{Phase, PhaseCell};
use crate::policy::{Action, Decision};
use crate::proxy::{HeaderContext, HeaderOp, Proxy, upgrade_request, upstream_headers};
use crate::request_id;
use crate::sync::lock;
use crate::tunnel;

const DEBUG_HEADER: HeaderName = HeaderName::from_static("x-vigilant-heron");

/// Marks a response whose connection must close without the response being written (`block_status 444`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct CloseWithoutResponse;

pub(crate) type ResponseBody = BoxBody<Bytes, BoxError>;

/// What a request was answered with, for the access log.
pub(crate) struct Outcome {
    pub(crate) response: Response<ResponseBody>,
    /// Status the upstream answered with, when it answered.
    pub(crate) upstream_status: Option<u16>,
    /// Why the upstream gave no response.
    pub(crate) upstream_error: Option<&'static str>,
    /// Set when the request body caused the answer, which then replaces the decision's reason.
    pub(crate) rejected: Option<&'static str>,
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

/// Adds `Connection: close` to a response that ends the connection.
pub(crate) fn close(response: &mut Response<ResponseBody>) {
    response
        .headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("close"));
}

/// Where an allowed request is forwarded, and what a block answers with.
pub(crate) struct Delivery<'a> {
    /// The upstream client of the site.
    pub(crate) proxy: &'a Proxy,
    /// The shutdown bookkeeping of the connection, held by a tunnel that the request starts.
    pub(crate) tunnels: &'a tunnel::Lifetime,
    /// The site's upstream URI.
    pub(crate) upstream: &'a http::Uri,
    /// The `proxy_set_header` operations of the level in effect.
    pub(crate) headers: &'a [HeaderOp],
    /// The block response of the level in effect.
    pub(crate) block: &'a BlockResponse,
    /// The values `proxy_set_header` values may use.
    pub(crate) ctx: HeaderContext<'a>,
    /// Whether an Upgrade request is tunnelled (`proxy_websocket on`).
    pub(crate) websocket: bool,
    /// The client connection's upgrade, which the tunnel takes when the upstream switches protocols.
    pub(crate) client_upgrade: &'a Mutex<Option<OnUpgrade>>,
    /// The phase of the client connection, which a started tunnel moves to tunnelling.
    pub(crate) phase: &'a PhaseCell,
}

/// Forwards an allowed request, or answers a block or redirect.
///
/// When the request body was not read in full, the response closes the
/// connection, because the rest of the body would otherwise be read as the next
/// request.
pub(crate) async fn respond(
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
                        // From here on the client connection carries tunnel bytes, not requests,
                        // and no response is written to it.
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
                Err(error) => {
                    let mut outcome = failure(&error, complete);
                    outcome.response = with_request_id(outcome.response, delivery.ctx.request_id);
                    outcome
                }
            }
        }
        Action::Block => block_outcome(block, delivery.ctx.request_id, complete),
        Action::Reject(status) => {
            let mut response = empty_answer(*status, delivery.ctx.request_id);
            if !complete {
                close(&mut response);
            }
            Outcome::answered(response)
        }
        Action::Redirect(location) => {
            let mut response = empty_answer(StatusCode::FOUND, delivery.ctx.request_id);
            response.headers_mut().insert(LOCATION, location.clone());
            if !complete {
                close(&mut response);
            }
            Outcome::answered(response)
        }
    }
}

/// The answer to a block: the block response, or a 444 that closes the connection without one.
fn block_outcome(block: &BlockResponse, request_id: &str, complete: bool) -> Outcome {
    let mut response = match block.status {
        BlockStatus::Respond(status) => block_response(status, block.page.as_ref(), request_id),
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
pub(crate) fn body_failure(
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

/// An answer without a body, with the given status and the request id.
pub(crate) fn empty_answer(status: StatusCode, request_id: &str) -> Response<ResponseBody> {
    with_request_id(status_response(status, ""), request_id)
}

/// Adds the `X-Request-ID` header to a response the router generated itself.
fn with_request_id(mut response: Response<ResponseBody>, id: &str) -> Response<ResponseBody> {
    if let Ok(value) = HeaderValue::from_str(id) {
        response
            .headers_mut()
            .insert(request_id::RESPONSE_HEADER, value);
    }
    response
}

pub(crate) fn add_debug_header(headers: &mut HeaderMap, decision: &Decision) {
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

/// A block response: the configured page as HTML when there is one, else a plain-text line
/// with the request id, so that the client can report the request.
fn block_response(
    status: StatusCode,
    page: Option<&Bytes>,
    request_id: &str,
) -> Response<ResponseBody> {
    let response = match page {
        Some(page) => typed_response(status, page.clone(), "text/html; charset=utf-8"),
        None => typed_response(
            status,
            Bytes::from(format!("Request blocked. Request ID: {request_id}\n")),
            "text/plain; charset=utf-8",
        ),
    };
    with_request_id(response, request_id)
}

fn typed_response(
    status: StatusCode,
    body: Bytes,
    content_type: &'static str,
) -> Response<ResponseBody> {
    let mut response = Response::new(
        Full::new(body)
            .map_err(|never: Infallible| match never {})
            .boxed(),
    );
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
        .headers_mut()
        .insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    response
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
