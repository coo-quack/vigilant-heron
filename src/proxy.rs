//! Forwarding allowed requests to the site's upstream.
//!
//! Each site has its own client, so `proxy_connect_timeout` and
//! `proxy_send_timeout` can differ per site. The connection pool is per site too.

use std::error::Error as StdError;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::header::{CONNECTION, HeaderMap, HeaderName, HeaderValue};
use http::{Request, Response, Uri};
use http_body_util::combinators::UnsyncBoxBody;
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpStream;
use tower_service::Service;

use crate::body::{BoxError, ClientBody, FaultSlot, FrameTimeout};
use crate::config::SiteTimeouts;
use crate::error::ProxyError;
use crate::transport::UpstreamIo;

const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");

/// Headers that describe a single connection and must not be forwarded.
const HOP_BY_HOP: [&str; 7] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// The client that sends requests to one site's upstream.
pub(crate) type UpstreamClient = Client<UpstreamConnector, UnsyncBoxBody<Bytes, BoxError>>;

/// Opens upstream connections, bounding the connect time and the wait between writes.
#[derive(Clone)]
pub(crate) struct UpstreamConnector {
    http: HttpConnector,
    send_timeout: Duration,
}

impl Service<Uri> for UpstreamConnector {
    type Response = TokioIo<UpstreamIo<TcpStream>>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        self.http
            .poll_ready(cx)
            .map_err(|error| -> BoxError { Box::new(error) })
    }

    fn call(&mut self, target: Uri) -> Self::Future {
        let connecting = self.http.call(target);
        let send_timeout = self.send_timeout;
        Box::pin(async move {
            let stream = connecting
                .await
                .map_err(|error| -> BoxError { Box::new(error) })?;
            Ok(TokioIo::new(UpstreamIo::new(
                stream.into_inner(),
                send_timeout,
            )))
        })
    }
}

/// Sends requests to one site's upstream over its connection pool.
pub(crate) struct Proxy {
    client: UpstreamClient,
    read_timeout: Duration,
}

impl Proxy {
    /// Creates the client for a site with its `proxy_*` timers.
    pub(crate) fn new(timeouts: &SiteTimeouts) -> Self {
        let mut http = HttpConnector::new();
        http.set_connect_timeout(Some(timeouts.proxy_connect_timeout));
        let connector = UpstreamConnector {
            http,
            send_timeout: timeouts.proxy_send_timeout,
        };
        Self {
            client: Client::builder(TokioExecutor::new()).build(connector),
            read_timeout: timeouts.proxy_read_timeout,
        }
    }

    /// Forwards a request with the same method, path, query and `Host` to `upstream`.
    ///
    /// The body is streamed: the bytes already sniffed go first, then the rest
    /// as the upstream reads them. The wait for the response head, from the
    /// start of the request, is bounded by `proxy_read_timeout`.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::ReadTimeout`] when no response head arrives in time,
    /// [`ProxyError::Body`] when the client body fails, and the connection errors otherwise.
    pub(crate) async fn forward(
        &self,
        method: http::Method,
        headers: &HeaderMap,
        path_and_query: &str,
        body: ClientBody,
        upstream: &Uri,
        peer: IpAddr,
    ) -> Result<Response<FrameTimeout<Incoming>>, ProxyError> {
        let target: Uri = format!(
            "{}{path_and_query}",
            upstream.to_string().trim_end_matches('/')
        )
        .parse()?;
        let faults = body.fault_slot();
        let mut request = Request::new(body.into_unsync());
        *request.method_mut() = method;
        *request.uri_mut() = target;
        *request.headers_mut() = forwarded_headers(headers, peer);
        let response =
            match tokio::time::timeout(self.read_timeout, self.client.request(request)).await {
                Ok(result) => result.map_err(|error| classify(error, &faults))?,
                Err(_elapsed) => return Err(ProxyError::ReadTimeout),
            };
        let (parts, body) = response.into_parts();
        Ok(Response::from_parts(
            parts,
            FrameTimeout::new(body, self.read_timeout),
        ))
    }
}

/// Sorts a failed upstream request into its cause. A fault of the client body wins.
fn classify(error: hyper_util::client::legacy::Error, faults: &FaultSlot) -> ProxyError {
    let fault = *faults
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(fault) = fault {
        return ProxyError::Body(fault);
    }
    let timed_out = has_timed_out(&error);
    if error.is_connect() {
        if timed_out {
            ProxyError::ConnectTimeout
        } else {
            ProxyError::Connect(error)
        }
    } else if timed_out {
        ProxyError::SendTimeout(error)
    } else {
        ProxyError::Request(error)
    }
}

/// Whether a timeout error appears anywhere in the error's chain of sources.
fn has_timed_out(error: &(dyn StdError + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(next) = current {
        if next
            .downcast_ref::<io::Error>()
            .is_some_and(|io| io.kind() == io::ErrorKind::TimedOut)
        {
            return true;
        }
        current = next.source();
    }
    false
}

/// Copies request headers for the upstream and appends the peer to `x-forwarded-for`.
pub(crate) fn forwarded_headers(original: &HeaderMap, peer: IpAddr) -> HeaderMap {
    let mut headers = original.clone();
    strip_hop_by_hop(&mut headers);
    let mut chain: Vec<String> = original
        .get_all(X_FORWARDED_FOR)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    chain.push(peer.to_string());
    if let Ok(value) = HeaderValue::from_str(&chain.join(", ")) {
        headers.insert(X_FORWARDED_FOR, value);
    }
    headers
}

/// Removes hop-by-hop headers, including those named in `Connection`.
pub(crate) fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let listed: Vec<String> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect();
    let removed: Vec<HeaderName> = headers
        .keys()
        .filter(|name| {
            let name = name.as_str();
            HOP_BY_HOP.contains(&name) || listed.iter().any(|token| token == name)
        })
        .cloned()
        .collect();
    for name in removed {
        headers.remove(name);
    }
}
