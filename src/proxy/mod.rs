//! Forwarding allowed requests to the site's upstream.
//!
//! Each site has its own client, so `proxy_connect_timeout` and
//! `proxy_send_timeout` can differ per site. The connection pool is per site too.

mod set_header;

use std::error::Error as StdError;
use std::future::Future;
use std::io::{self, IoSlice};
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::header::{CONNECTION, HeaderMap, HeaderName, HeaderValue, UPGRADE};
use http::{Request, Response, Uri};
use http_body_util::combinators::UnsyncBoxBody;
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::Sleep;
use tower_service::Service;

use crate::body::{BoxError, ClientBody, FaultSlot, FrameTimeout};
use crate::config::SiteTimeouts;
use crate::error::ProxyError;
use crate::transport::expired;

pub(crate) use set_header::{HeaderContext, HeaderOp};

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

/// An upstream socket that bounds the wait between writes (`proxy_send_timeout`).
pub(crate) struct UpstreamIo<S> {
    inner: S,
    send: Duration,
    write_timer: Option<Pin<Box<Sleep>>>,
}

impl<S> UpstreamIo<S> {
    /// Wraps `inner`, a connected upstream socket.
    pub(crate) fn new(inner: S, send: Duration) -> Self {
        Self {
            inner,
            send,
            write_timer: None,
        }
    }

    /// Applies `proxy_send_timeout` to one write attempt.
    fn timed_write(
        &mut self,
        cx: &mut Context<'_>,
        attempt: Poll<io::Result<usize>>,
    ) -> Poll<io::Result<usize>> {
        match attempt {
            Poll::Pending => {
                if expired(&mut self.write_timer, self.send, cx) {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "upstream send timeout",
                    )))
                } else {
                    Poll::Pending
                }
            }
            Poll::Ready(result) => {
                self.write_timer = None;
                Poll::Ready(result)
            }
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for UpstreamIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for UpstreamIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let attempt = Pin::new(&mut this.inner).poll_write(cx, buf);
        this.timed_write(cx, attempt)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let attempt = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        this.timed_write(cx, attempt)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S> Connection for UpstreamIo<S> {
    fn connected(&self) -> Connected {
        Connected::new()
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

    /// The `proxy_read_timeout` of the site: the wait for a response head, and the idle limit of a tunnel.
    pub(crate) fn read_timeout(&self) -> Duration {
        self.read_timeout
    }

    /// Forwards a request with `method`, `path_and_query` and the given `headers` to `upstream`.
    ///
    /// The headers are the ones [`upstream_headers`] builds. The body is streamed:
    /// the bytes already sniffed go first, then the rest as the upstream reads
    /// them. The wait for the response head, from the start of the request, is
    /// bounded by `proxy_read_timeout`.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::ReadTimeout`] when no response head arrives in time,
    /// [`ProxyError::Body`] when the client body fails, and the connection errors otherwise.
    pub(crate) async fn forward(
        &self,
        method: http::Method,
        headers: HeaderMap,
        path_and_query: &str,
        body: ClientBody,
        upstream: &Uri,
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
        *request.headers_mut() = headers;
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

/// Builds the headers sent upstream: the client's headers without hop-by-hop
/// ones, with the peer appended to `x-forwarded-for`, then each `proxy_set_header`
/// applied in order. A header whose value is empty, or cannot be a header value,
/// is removed.
pub(crate) fn upstream_headers(
    original: &HeaderMap,
    peer: IpAddr,
    ops: &[HeaderOp],
    ctx: &HeaderContext<'_>,
) -> HeaderMap {
    let mut headers = forwarded_headers(original, peer);
    for op in ops {
        let value = op.render(ctx);
        match HeaderValue::from_str(&value) {
            Ok(value) if !value.is_empty() => {
                headers.insert(op.name.clone(), value);
            }
            _ => {
                headers.remove(&op.name);
            }
        }
    }
    headers
}

/// The trimmed, comma-separated tokens of every `Connection` header, in the order received.
/// A header that is not valid text contributes nothing.
fn connection_tokens(headers: &HeaderMap) -> impl Iterator<Item = &str> {
    headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
}

/// The `Upgrade` value of a request that asks to switch protocols: its `Connection`
/// header lists `upgrade` and it has a non-empty `Upgrade` header.
pub(crate) fn upgrade_request(headers: &HeaderMap) -> Option<HeaderValue> {
    let asks = connection_tokens(headers).any(|token| token.eq_ignore_ascii_case("upgrade"));
    if !asks {
        return None;
    }
    headers
        .get(UPGRADE)
        .filter(|value| !value.is_empty())
        .cloned()
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
    let listed: Vec<String> = connection_tokens(headers)
        .map(str::to_ascii_lowercase)
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

#[cfg(test)]
mod header_tests {
    use std::net::IpAddr;

    use http::{HeaderMap, HeaderValue};
    use rstest::rstest;

    use super::*;
    use crate::error::ConfigError;
    use crate::proxy::test_helpers::op;

    /// The TCP peer used by these tests.
    fn peer_addr() -> IpAddr {
        IpAddr::from([10, 0, 0, 2])
    }

    fn context(headers: &HeaderMap) -> HeaderContext<'_> {
        HeaderContext {
            client_ip: "203.0.113.7",
            remote_addr: "10.0.0.2",
            host: "example.com",
            site: "example.com",
            method: "GET",
            path: "/shop/item",
            request_id: "req-1",
            headers,
        }
    }

    #[test]
    fn variables_take_their_values_from_the_request() -> Result<(), ConfigError> {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        let ctx = context(&headers);
        let ops = [
            op("proxy_set_header X-Real-IP $client_ip;")?,
            op("proxy_set_header X-Proto \"${http_x_forwarded_proto}\";")?,
            op("proxy_set_header X-Note $method-$path-$request_id-$site-$remote_addr;")?,
        ];
        let out = upstream_headers(&HeaderMap::new(), peer_addr(), &ops, &ctx);
        assert_eq!(
            out.get("x-real-ip").map(HeaderValue::as_bytes),
            Some(&b"203.0.113.7"[..])
        );
        assert_eq!(
            out.get("x-proto").map(HeaderValue::as_bytes),
            Some(&b"https"[..])
        );
        assert_eq!(
            out.get("x-note").map(HeaderValue::as_bytes),
            Some(&b"GET-/shop/item-req-1-example.com-10.0.0.2"[..])
        );
        Ok(())
    }

    #[test]
    fn an_empty_value_removes_the_header_the_client_sent() -> Result<(), ConfigError> {
        let mut original = HeaderMap::new();
        original.insert("x-debug", HeaderValue::from_static("1"));
        let headers = HeaderMap::new();
        let ctx = context(&headers);
        let ops = [op("proxy_set_header X-Debug \"\";")?];
        let out = upstream_headers(&original, peer_addr(), &ops, &ctx);
        assert!(!out.contains_key("x-debug"));
        Ok(())
    }

    #[test]
    fn a_variable_with_no_value_removes_the_header() -> Result<(), ConfigError> {
        let headers = HeaderMap::new();
        let ctx = context(&headers);
        let ops = [op("proxy_set_header X-Proto $http_x_forwarded_proto;")?];
        let out = upstream_headers(&HeaderMap::new(), peer_addr(), &ops, &ctx);
        assert!(!out.contains_key("x-proto"));
        Ok(())
    }

    #[test]
    fn without_operations_the_peer_is_appended_to_x_forwarded_for() {
        let mut original = HeaderMap::new();
        original.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.1"));
        let headers = HeaderMap::new();
        let ctx = context(&headers);
        let out = upstream_headers(&original, peer_addr(), &[], &ctx);
        assert_eq!(
            out.get("x-forwarded-for").map(HeaderValue::as_bytes),
            Some(&b"198.51.100.1, 10.0.0.2"[..])
        );
    }

    #[test]
    fn an_operation_can_replace_x_forwarded_for() -> Result<(), ConfigError> {
        let headers = HeaderMap::new();
        let ctx = context(&headers);
        let ops = [op("proxy_set_header X-Forwarded-For $client_ip;")?];
        let out = upstream_headers(&HeaderMap::new(), peer_addr(), &ops, &ctx);
        assert_eq!(
            out.get("x-forwarded-for").map(HeaderValue::as_bytes),
            Some(&b"203.0.113.7"[..])
        );
        Ok(())
    }

    #[rstest]
    #[case::upgrade_listed("upgrade", "websocket", true)]
    #[case::listed_among_others("keep-alive, Upgrade", "websocket", true)]
    #[case::no_connection_upgrade("keep-alive", "websocket", false)]
    #[case::upgrade_without_header("upgrade", "", false)]
    fn upgrade_requests_need_both_headers(
        #[case] connection: &str,
        #[case] upgrade: &str,
        #[case] expected: bool,
    ) {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONNECTION,
            HeaderValue::from_str(connection).unwrap_or_else(|_| HeaderValue::from_static("")),
        );
        if !upgrade.is_empty() {
            headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
        }
        assert_eq!(upgrade_request(&headers).is_some(), expected);
    }

    #[test]
    fn text_after_a_braced_variable_is_kept() -> Result<(), ConfigError> {
        let headers = HeaderMap::new();
        let ctx = context(&headers);
        let ops = [op("proxy_set_header X-Braced \"${client_ip}-end\";")?];
        let out = upstream_headers(&HeaderMap::new(), peer_addr(), &ops, &ctx);
        assert_eq!(
            out.get("x-braced").map(HeaderValue::as_bytes),
            Some(&b"203.0.113.7-end"[..])
        );
        Ok(())
    }

    #[test]
    fn a_header_named_in_connection_is_removed_and_other_headers_stay() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, HeaderValue::from_static("X-Trace"));
        headers.insert("x-trace", HeaderValue::from_static("1"));
        headers.insert("x-keep", HeaderValue::from_static("2"));
        strip_hop_by_hop(&mut headers);
        assert!(!headers.contains_key("x-trace"));
        assert!(!headers.contains_key(CONNECTION));
        assert!(headers.contains_key("x-keep"));
    }
}

#[cfg(test)]
mod upstream_io_tests {
    use rstest::rstest;
    use tokio::io::AsyncWriteExt as _;

    use super::*;
    use crate::test_support::Recorder;

    #[rstest]
    #[case::vectored(true)]
    #[case::not_vectored(false)]
    fn an_upstream_socket_reports_whether_its_inner_socket_writes_vectored(#[case] vectored: bool) {
        let mut recorder = Recorder::new();
        recorder.vectored = vectored;
        let io = UpstreamIo::new(recorder, Duration::from_secs(5));
        assert_eq!(io.is_write_vectored(), vectored);
    }

    #[tokio::test]
    async fn an_upstream_flush_and_shutdown_reach_the_upstream_socket() -> Result<(), BoxError> {
        let mut io = UpstreamIo::new(Recorder::new(), Duration::from_secs(5));
        io.flush().await?;
        io.shutdown().await?;
        assert_eq!((io.inner.flushes, io.inner.shutdowns), (1, 1));
        Ok(())
    }
}

#[cfg(test)]
/// A helper that the tests of the submodules share.
mod test_helpers {
    use crate::conf::parse_source;
    use crate::error::ConfigError;
    use crate::proxy::HeaderOp;

    /// Parses one `proxy_set_header` line.
    pub(crate) fn op(line: &str) -> Result<HeaderOp, ConfigError> {
        let directives = parse_source(line, "header.conf")?;
        let first = directives.first().ok_or_else(|| ConfigError::Invalid {
            file: "header.conf".to_owned(),
            line: 1,
            message: "no directive".to_owned(),
        })?;
        HeaderOp::parse(first)
    }
}
