//! Connection timers, header limits, the client body limit and upstream timeouts,
//! run against in-process servers. Timeouts are short so the tests stay fast.

mod common;

use std::convert::Infallible;
use std::error::Error;
use std::fmt::Write as _;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use common::{
    BoxError, StubBehavior, StubDecider, TestResult, closed_port_url, json_response, send,
    spawn_server, start_proxy,
};
use http::{Method, Request, Response, StatusCode};
use http_body::{Body, Frame};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// Time the tests give the proxy to act. Well above the short timers below.
const SETTLE: Duration = Duration::from_secs(2);

/// Builds a configuration for one enforce site on `example.com`.
///
/// `top` holds top-level directives and `site` holds the site's own ones.
fn config(decide_url: &str, upstream_url: &str, top: &str, site: &str) -> String {
    format!(
        r#"
listen 127.0.0.1:0;
{top}

decision {{
    backend http;
    url "{decide_url}";
    timeout 2000ms;
    inspect_body 512;
}}

default_status 421;

site example.com {{
    upstream "{upstream_url}";
    mode enforce;
    action block;
    block_threshold 0.9;
    instruction_threshold 0.5;
    deny_path /blocked;
    {site}
}}
"#
    )
}

/// What a raw connection received before the proxy closed it, or before `limit` passed.
struct Received {
    bytes: Vec<u8>,
    closed: bool,
}

/// Reads until the peer closes the connection, or until `limit` passes.
async fn read_until_closed(stream: &mut TcpStream, limit: Duration) -> Received {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 8192];
    let outcome = tokio::time::timeout(limit, async {
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return true,
                Ok(read) => bytes.extend_from_slice(chunk.get(..read).unwrap_or_default()),
            }
        }
    })
    .await;
    Received {
        bytes,
        closed: outcome.unwrap_or(false),
    }
}

/// The status code in the first line of a response.
fn status_of(bytes: &[u8]) -> Option<u16> {
    let line = std::str::from_utf8(bytes).ok()?.lines().next()?;
    line.split_whitespace().nth(1)?.parse().ok()
}

/// Reads a response head, up to and including the blank line, one byte at a time.
async fn read_head<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    limit: Duration,
) -> Result<Vec<u8>, BoxError> {
    let mut buffer = Vec::new();
    let mut byte = [0u8; 1];
    while !buffer.ends_with(b"\r\n\r\n") {
        let read = tokio::time::timeout(limit, reader.read(&mut byte)).await??;
        if read == 0 {
            return Err("connection closed before the response head".into());
        }
        buffer.extend_from_slice(&byte);
    }
    Ok(buffer)
}

/// Reads one complete response with a `Content-Length` from `stream`.
async fn read_response(stream: &mut TcpStream) -> Result<(u16, String, Vec<u8>), BoxError> {
    let buffer = read_head(stream, SETTLE).await?;
    let head = String::from_utf8_lossy(&buffer).into_owned();
    let length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    tokio::time::timeout(SETTLE, stream.read_exact(&mut body)).await??;
    Ok((status_of(&buffer).unwrap_or(0), head, body))
}

/// Opens a connection to the proxy.
async fn connect(base: &str) -> Result<TcpStream, BoxError> {
    let address = base.trim_start_matches("http://");
    Ok(TcpStream::connect(address).await?)
}

/// Starts an HTTP/1 server whose handler may stream any body.
fn spawn_streaming<B, H, Fut>(listener: TcpListener, handler: H) -> JoinHandle<()>
where
    H: Fn(Request<Incoming>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Response<B>> + Send + 'static,
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
{
    tokio::spawn(async move {
        while let Ok((stream, _peer)) = listener.accept().await {
            let handler = handler.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request| {
                    let handler = handler.clone();
                    async move { Ok::<_, Infallible>(handler(request).await) }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    })
}

/// A body of `'a'` bytes that never ends.
struct Endless;

static CHUNK: [u8; 16 * 1024] = [b'a'; 16 * 1024];

impl Body for Endless {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        std::task::Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(&CHUNK)))))
    }
}

/// FNV-1a over `bytes`, to compare a body without holding both copies in the test.
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// A deterministic 5 MB body of ASCII text.
fn five_megabytes() -> Vec<u8> {
    (0..5 * 1024 * 1024)
        .map(|index: usize| b'a' + u8::try_from(index % 26).unwrap_or(0))
        .collect()
}

/// An upstream that reads the whole body and answers with its length and FNV-1a hash.
async fn start_hashing_upstream() -> Result<(String, JoinHandle<()>), BoxError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let task = spawn_server(listener, |request: Request<Incoming>| async move {
        let body = match request.into_body().collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => return json_response(StatusCode::BAD_REQUEST, &json!({})),
        };
        json_response(
            StatusCode::OK,
            &json!({"length": body.len(), "hash": fnv1a(&body).to_string()}),
        )
    });
    Ok((url, task))
}

/// An upstream that answers after a delay, without reading the request body.
async fn start_slow_upstream(delay: Duration) -> Result<(String, JoinHandle<()>), BoxError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let task = spawn_server(listener, move |_request: Request<Incoming>| async move {
        tokio::time::sleep(delay).await;
        json_response(StatusCode::OK, &json!({"late": true}))
    });
    Ok((url, task))
}

/// An upstream that answers at once with a small body and counts requests.
async fn start_counting_upstream() -> Result<(String, Arc<AtomicUsize>, JoinHandle<()>), BoxError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    let task = spawn_server(listener, move |_request: Request<Incoming>| {
        let counter = Arc::clone(&counter);
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
            json_response(StatusCode::OK, &json!({"ok": true}))
        }
    });
    Ok((url, hits, task))
}

/// Writes `head` and `body` to the proxy, then reads what comes back until it closes.
async fn raw_request(base: &str, head: &str, body: &[u8]) -> Result<Received, BoxError> {
    let mut stream = connect(base).await?;
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    Ok(read_until_closed(&mut stream, SETTLE).await)
}

#[tokio::test]
async fn slow_header_past_client_header_timeout_gets_408_and_the_connection_closes() -> TestResult {
    let (upstream, _hits, _task) = start_counting_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream,
        "client_header_timeout 200ms;",
        "",
    ))
    .await?;
    let mut stream = connect(&proxy.base()).await?;
    // One byte every 50 ms: the header never completes within 200 ms of its first byte.
    let head = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Slow: ";
    for byte in head.iter().chain(b"aaaaaaaaaaaaaaaaaaaaaa") {
        if stream.write_all(&[*byte]).await.is_err() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let received = read_until_closed(&mut stream, SETTLE).await;
    assert_eq!(status_of(&received.bytes), Some(408));
    assert!(received.closed, "the connection must close after the 408");
    assert_eq!(
        stub.calls(),
        0,
        "a request that never completed reaches no backend"
    );
    proxy.stop().await
}

#[tokio::test]
async fn silent_connection_is_closed_without_a_response_after_the_header_timeout() -> TestResult {
    let (upstream, _hits, _task) = start_counting_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream,
        "client_header_timeout 200ms;",
        "",
    ))
    .await?;
    let mut stream = connect(&proxy.base()).await?;
    let started = Instant::now();
    let received = read_until_closed(&mut stream, SETTLE).await;
    assert!(received.closed);
    assert!(
        received.bytes.is_empty(),
        "nothing was sent, so nothing is answered"
    );
    assert!(started.elapsed() < SETTLE);
    proxy.stop().await
}

#[tokio::test]
async fn slow_body_past_client_body_timeout_gets_408_and_the_connection_closes() -> TestResult {
    let (upstream, hits, _task) = start_counting_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream,
        "",
        "client_body_timeout 200ms;",
    ))
    .await?;
    let mut stream = connect(&proxy.base()).await?;
    stream
        .write_all(
            b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 100\r\n\r\n0123456789",
        )
        .await?;
    // The client now stops for longer than client_body_timeout.
    let received = read_until_closed(&mut stream, SETTLE).await;
    assert_eq!(status_of(&received.bytes), Some(408));
    assert!(received.closed);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    proxy.stop().await
}

#[tokio::test]
async fn idle_keep_alive_connection_is_closed_after_keepalive_timeout() -> TestResult {
    let (upstream, _hits, _task) = start_counting_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream,
        "keepalive_timeout 200ms;",
        "",
    ))
    .await?;
    let mut stream = connect(&proxy.base()).await?;
    stream
        .write_all(b"GET /first HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await?;
    let (status, head, _) = read_response(&mut stream).await?;
    assert_eq!(status, 200);
    assert!(!head.to_ascii_lowercase().contains("connection: close"));
    let started = Instant::now();
    let received = read_until_closed(&mut stream, SETTLE).await;
    assert!(received.closed, "the idle connection must be closed");
    assert_eq!(received.bytes, Vec::<u8>::new());
    assert!(started.elapsed() < SETTLE);
    proxy.stop().await
}

#[tokio::test]
async fn keepalive_requests_closes_the_connection_after_the_last_allowed_request() -> TestResult {
    let (upstream, hits, _task) = start_counting_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream,
        "keepalive_requests 2;",
        "",
    ))
    .await?;
    let mut stream = connect(&proxy.base()).await?;
    stream
        .write_all(b"GET /one HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await?;
    let (first, first_head, _) = read_response(&mut stream).await?;
    assert_eq!(first, 200);
    assert!(
        !first_head
            .to_ascii_lowercase()
            .contains("connection: close")
    );

    stream
        .write_all(b"GET /two HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await?;
    let (second, second_head, _) = read_response(&mut stream).await?;
    assert_eq!(second, 200);
    assert!(
        second_head
            .to_ascii_lowercase()
            .contains("connection: close")
    );

    let received = read_until_closed(&mut stream, SETTLE).await;
    assert!(received.closed, "the connection must close after request 2");
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    proxy.stop().await
}

#[tokio::test]
async fn keepalive_timeout_zero_serves_one_request_per_connection() -> TestResult {
    let (upstream, _hits, _task) = start_counting_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream,
        "keepalive_timeout 0;",
        "",
    ))
    .await?;
    let mut stream = connect(&proxy.base()).await?;
    stream
        .write_all(b"GET /one HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await?;
    let (status, head, _) = read_response(&mut stream).await?;
    assert_eq!(status, 200);
    assert!(head.to_ascii_lowercase().contains("connection: close"));
    let received = read_until_closed(&mut stream, SETTLE).await;
    assert!(received.closed);
    proxy.stop().await
}

#[tokio::test]
async fn slow_upstream_past_proxy_read_timeout_gets_504() -> TestResult {
    let (upstream, _task) = start_slow_upstream(Duration::from_secs(3)).await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream,
        "",
        "proxy_read_timeout 200ms;",
    ))
    .await?;
    let started = Instant::now();
    let reply = send(
        &proxy.base(),
        Method::GET,
        "/slow",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;
    assert_eq!(reply.status, StatusCode::GATEWAY_TIMEOUT);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "answered after {:?}",
        started.elapsed()
    );
    proxy.stop().await
}

#[tokio::test]
async fn unroutable_upstream_with_a_short_connect_timeout_gets_504() -> TestResult {
    // TEST-NET-1 is not routed. Where the network refuses it at once, the answer is 502.
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        "http://192.0.2.1:9",
        "",
        "proxy_connect_timeout 200ms;",
    ))
    .await?;
    let started = Instant::now();
    let reply = send(
        &proxy.base(),
        Method::GET,
        "/",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;
    assert_eq!(reply.status, StatusCode::GATEWAY_TIMEOUT);
    assert!(started.elapsed() < Duration::from_secs(2));
    proxy.stop().await
}

#[tokio::test]
async fn refused_upstream_connection_stays_a_502() -> TestResult {
    let upstream = closed_port_url().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(&stub.decide_url(), &upstream, "", "")).await?;
    let reply = send(
        &proxy.base(),
        Method::GET,
        "/",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;
    assert_eq!(reply.status, StatusCode::BAD_GATEWAY);
    proxy.stop().await
}

#[tokio::test]
async fn request_line_longer_than_one_buffer_gets_414_and_the_connection_closes() -> TestResult {
    let (upstream, hits, _task) = start_counting_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(&stub.decide_url(), &upstream, "", "")).await?;
    let long_path = format!("/{}", "a".repeat(9000));
    let head = format!("GET {long_path} HTTP/1.1\r\nHost: example.com\r\n\r\n");
    let received = raw_request(&proxy.base(), &head, b"").await?;
    assert_eq!(status_of(&received.bytes), Some(414));
    assert!(received.closed);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    assert_eq!(stub.calls(), 0);
    proxy.stop().await
}

#[tokio::test]
async fn header_field_longer_than_one_buffer_gets_400_and_the_connection_closes() -> TestResult {
    let (upstream, hits, _task) = start_counting_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(&stub.decide_url(), &upstream, "", "")).await?;
    let head = format!(
        "GET / HTTP/1.1\r\nHost: example.com\r\nX-Big: {}\r\n\r\n",
        "a".repeat(9000)
    );
    let received = raw_request(&proxy.base(), &head, b"").await?;
    assert_eq!(status_of(&received.bytes), Some(400));
    assert!(received.closed);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    proxy.stop().await
}

#[tokio::test]
async fn header_section_beyond_count_times_size_gets_400() -> TestResult {
    let (upstream, _hits, _task) = start_counting_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(&stub.decide_url(), &upstream, "", "")).await?;
    // Five fields of 7000 bytes: each fits one 8k buffer, but 35000 bytes exceed 4 x 8k.
    let mut head = String::from("GET / HTTP/1.1\r\nHost: example.com\r\n");
    for index in 0..5 {
        let _ = write!(head, "X-Fill-{index}: {}\r\n", "a".repeat(7000));
    }
    head.push_str("\r\n");
    let received = raw_request(&proxy.base(), &head, b"").await?;
    assert_eq!(status_of(&received.bytes), Some(400));
    assert!(received.closed);
    proxy.stop().await
}

#[tokio::test]
async fn content_length_over_the_limit_gets_413_before_any_body_is_read() -> TestResult {
    let (upstream, hits, _task) = start_counting_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream,
        "client_max_body_size 1k;",
        "",
    ))
    .await?;
    let mut stream = connect(&proxy.base()).await?;
    // The body is not sent: the answer comes from the Content-Length alone.
    stream
        .write_all(b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 2000\r\n\r\n")
        .await?;
    let received = read_until_closed(&mut stream, SETTLE).await;
    assert_eq!(status_of(&received.bytes), Some(413));
    assert!(received.closed);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "no upstream byte may be sent"
    );
    assert_eq!(stub.calls(), 0);
    proxy.stop().await
}

/// A chunked POST head and body: `chunks` pieces of `size` bytes, then the final chunk.
fn chunked_head(chunks: usize, size: usize) -> (String, Vec<u8>) {
    let head = "POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
        .to_owned();
    let mut body = Vec::new();
    for _ in 0..chunks {
        body.extend_from_slice(format!("{size:x}\r\n").as_bytes());
        body.extend(std::iter::repeat_n(b'b', size));
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"0\r\n\r\n");
    (head, body)
}

#[tokio::test]
async fn chunked_body_over_the_limit_gets_413_when_the_upstream_has_not_answered() -> TestResult {
    // The upstream reads the whole body before it answers, so the 413 comes before any response.
    let (upstream, _task) = start_hashing_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream,
        "client_max_body_size 1k;",
        "",
    ))
    .await?;
    let (head, body) = chunked_head(4, 512);
    let received = raw_request(&proxy.base(), &head, &body).await?;
    assert_eq!(status_of(&received.bytes), Some(413));
    assert!(received.closed);
    proxy.stop().await
}

#[tokio::test]
async fn chunked_body_over_the_limit_closes_the_connection_after_an_early_answer() -> TestResult {
    // The echo upstream answers before it reads the body. The proxy cannot send a 413 any more.
    let (upstream, _hits, _task) = start_counting_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream,
        "client_max_body_size 1k;",
        "",
    ))
    .await?;
    let (head, body) = chunked_head(4, 512);
    let received = raw_request(&proxy.base(), &head, &body).await?;
    assert!(matches!(status_of(&received.bytes), Some(200 | 413)));
    assert!(received.closed, "the connection must close");
    proxy.stop().await
}

#[tokio::test]
async fn five_megabyte_body_is_forwarded_intact_and_the_backend_sees_only_the_prefix() -> TestResult
{
    let (upstream, _task) = start_hashing_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream,
        "client_max_body_size 10m;",
        "",
    ))
    .await?;
    let body = five_megabytes();
    let reply = send(
        &proxy.base(),
        Method::POST,
        "/upload",
        "example.com",
        &[("content-type", "text/plain")],
        Bytes::from(body.clone()),
    )
    .await?;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json()["length"], json!(body.len()));
    assert_eq!(reply.json()["hash"], json!(fnv1a(&body).to_string()));

    let event = stub.last_event().unwrap_or(Value::Null);
    let sent = event["event"]["untrusted"]["body"]
        .as_str()
        .unwrap_or_default();
    assert_eq!(
        sent.len(),
        512,
        "the backend receives only inspect_body bytes"
    );
    assert_eq!(event["event"]["meta"]["body_truncated"], json!(true));
    proxy.stop().await
}

#[tokio::test]
async fn rule_block_with_a_large_body_never_calls_the_backend() -> TestResult {
    let (upstream, hits, _task) = start_counting_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream,
        "client_max_body_size 10m;",
        "",
    ))
    .await?;
    let reply = send(
        &proxy.base(),
        Method::POST,
        "/blocked",
        "example.com",
        &[],
        Bytes::from(five_megabytes()),
    )
    .await?;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(stub.calls(), 0);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    proxy.stop().await
}

#[tokio::test]
async fn a_block_on_an_unread_body_closes_the_connection() -> TestResult {
    let (upstream, _hits, _task) = start_counting_upstream().await?;
    let stub = StubDecider::start().await?;
    stub.set_behavior(StubBehavior {
        attack: 0.95,
        ..StubBehavior::default()
    });
    let proxy = start_proxy(&config(&stub.decide_url(), &upstream, "", "")).await?;
    let mut stream = connect(&proxy.base()).await?;
    stream
        .write_all(b"POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4000\r\n\r\n")
        .await?;
    stream.write_all(&[b'a'; 1000]).await?;
    let (status, head, _) = read_response(&mut stream).await?;
    assert_eq!(status, 403);
    assert!(head.to_ascii_lowercase().contains("connection: close"));
    let received = read_until_closed(&mut stream, SETTLE).await;
    assert!(received.closed);
    proxy.stop().await
}

#[tokio::test]
async fn upstream_that_never_reads_past_proxy_send_timeout_gets_504() -> TestResult {
    // The upstream accepts connections and never reads, so the proxy's writes to it stall.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream = format!("http://{}", listener.local_addr()?);
    let _held = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream,
        "client_max_body_size 128m;",
        "proxy_send_timeout 200ms;",
    ))
    .await?;
    let stream = connect(&proxy.base()).await?;
    let (mut reader, mut writer) = stream.into_split();
    let pusher = tokio::spawn(async move {
        let head = b"POST /big HTTP/1.1\r\nHost: example.com\r\nContent-Length: 67108864\r\n\r\n";
        if writer.write_all(head).await.is_err() {
            return;
        }
        let chunk = vec![b'c'; 64 * 1024];
        for _ in 0..1024 {
            if writer.write_all(&chunk).await.is_err() {
                break;
            }
        }
    });
    let head = read_head(&mut reader, Duration::from_secs(10)).await?;
    assert_eq!(status_of(&head), Some(504));
    pusher.abort();
    proxy.stop().await
}

#[tokio::test]
async fn endless_response_is_cut_off_when_the_client_stops_reading() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream = format!("http://{}", listener.local_addr()?);
    let _task = spawn_streaming(listener, |_request: Request<Incoming>| async {
        Response::new(Endless)
    });
    let stub = StubDecider::start().await?;
    // send_timeout bounds the wait between two writes to the client.
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream,
        "send_timeout 300ms;",
        "",
    ))
    .await?;
    let mut stream = connect(&proxy.base()).await?;
    stream
        .write_all(b"GET /endless HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await?;
    // The client reads nothing for well over send_timeout. The proxy's writes stall, the
    // timer expires, and the proxy closes. Only then does the client drain what the socket
    // buffered, so the stream ends on a close instead of running on.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let mut total = 0usize;
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let Ok(result) =
            tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk)).await
        else {
            panic!("the proxy kept the connection open after the client stopped reading");
        };
        match result {
            Ok(0) | Err(_) => break,
            Ok(read) => total = total.saturating_add(read),
        }
        assert!(total < 256 * 1024 * 1024, "the stream was not cut off");
    }
    proxy.stop().await
}

#[tokio::test]
async fn a_request_just_under_every_limit_is_served() -> TestResult {
    let (upstream, _hits, _task) = start_counting_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream,
        "client_max_body_size 1k;",
        "",
    ))
    .await?;
    let path = format!("/{}", "a".repeat(8000));
    let reply = send(
        &proxy.base(),
        Method::GET,
        &path,
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;
    assert_eq!(reply.status, StatusCode::OK);
    proxy.stop().await
}

/// Reads every line of `path` that contains `needle`, waiting until at least `count` exist.
async fn wait_for_lines(
    path: &std::path::Path,
    needle: &str,
    count: usize,
) -> Result<Vec<String>, BoxError> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let lines: Vec<String> = text
            .lines()
            .filter(|line| line.contains(needle))
            .map(str::to_owned)
            .collect();
        if lines.len() >= count {
            return Ok(lines);
        }
        if Instant::now() > deadline {
            return Err(format!(
                "expected {count} lines with {needle}, found {}",
                lines.len()
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn upstream_timeouts_and_connection_rejections_are_logged_with_their_causes() -> TestResult {
    let path = std::env::temp_dir().join(format!("vh-limits-{}.log", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let (slow, _slow_task) = start_slow_upstream(Duration::from_secs(3)).await?;
    let stub = StubDecider::start().await?;
    let text = config(&stub.decide_url(), &slow, "", "proxy_read_timeout 200ms;").replace(
        "listen 127.0.0.1:0;",
        &format!(
            "listen 127.0.0.1:0;\nlog_format limits \"$status $reason upstream=$upstream_status error=$upstream_error $path\";\naccess_log {} limits;",
            path.display()
        ),
    );
    let proxy = start_proxy(&text).await?;
    let reply = send(
        &proxy.base(),
        Method::GET,
        "/slow-one",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;
    assert_eq!(reply.status, StatusCode::GATEWAY_TIMEOUT);
    let long_path = format!("/{}", "a".repeat(9000));
    let received = raw_request(
        &proxy.base(),
        &format!("GET {long_path} HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        b"",
    )
    .await?;
    assert_eq!(status_of(&received.bytes), Some(414));

    let lines = wait_for_lines(&path, "/slow-one", 1).await?;
    assert_eq!(
        lines.first().map(String::as_str),
        Some("504 below_threshold upstream=- error=read_timeout /slow-one")
    );
    let rejected = wait_for_lines(&path, "uri_too_long", 1).await?;
    assert!(
        rejected
            .first()
            .is_some_and(|line| line.starts_with("414 uri_too_long")),
        "{rejected:?}"
    );
    proxy.stop().await?;
    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[tokio::test]
async fn an_early_answer_with_an_unread_body_closes_the_connection() -> TestResult {
    // The echo upstream answers before it reads the body. The client then sends only part
    // of the declared body, so the connection cannot be reused.
    let (upstream, _hits, _task) = start_counting_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(&stub.decide_url(), &upstream, "", "")).await?;
    let mut stream = connect(&proxy.base()).await?;
    stream
        .write_all(b"POST /early HTTP/1.1\r\nHost: example.com\r\nContent-Length: 100000\r\n\r\n")
        .await?;
    stream.write_all(&[b'a'; 1000]).await?;
    let (status, _head, _) = read_response(&mut stream).await?;
    assert_eq!(status, 200);
    let received = read_until_closed(&mut stream, SETTLE).await;
    assert!(
        received.closed,
        "the connection must close with the body unread"
    );
    proxy.stop().await
}

/// Lingering timers short enough for the tests: silence ends a lingering close after 300 ms.
const LINGER_FAST: &str = "lingering_timeout 300ms;\nlingering_time 3s;";

/// Writes `total` bytes in pieces of `piece` bytes with `pause` between them, as a client
/// still sending its body would. Returns the number of bytes written before a write failed.
async fn trickle(
    stream: &mut TcpStream,
    total: usize,
    piece: usize,
    pause: Duration,
) -> Result<usize, BoxError> {
    let chunk = vec![b'b'; piece];
    let mut sent = 0;
    while sent < total {
        if stream.write_all(&chunk).await.is_err() {
            break;
        }
        sent += piece;
        tokio::time::sleep(pause).await;
    }
    Ok(sent)
}

#[tokio::test]
async fn content_length_over_the_limit_gets_413_while_the_client_keeps_sending() -> TestResult {
    // The router answers from Content-Length and closes with the body unread. A client that is
    // still sending must not be reset before it reads the 413.
    let (upstream, hits, _task) = start_counting_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream,
        &format!("client_max_body_size 1k;\n{LINGER_FAST}"),
        "",
    ))
    .await?;
    let mut stream = connect(&proxy.base()).await?;
    stream
        .write_all(b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 20000\r\n\r\n")
        .await?;
    let sent = trickle(&mut stream, 20_000, 1_000, Duration::from_millis(5)).await?;
    assert_eq!(sent, 20_000, "the client must be able to finish its body");
    let (status, head, _) = read_response(&mut stream).await?;
    assert_eq!(status, 413);
    assert!(head.to_ascii_lowercase().contains("connection: close"));
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    assert_eq!(stub.calls(), 0);
    proxy.stop().await
}

#[tokio::test]
async fn rule_block_with_a_body_gets_403_while_the_client_keeps_sending() -> TestResult {
    // deny_path /blocked is a rule: the body is sniffed, then the block closes with the rest unread.
    let (upstream, hits, _task) = start_counting_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream,
        &format!("client_max_body_size 1m;\n{LINGER_FAST}"),
        "",
    ))
    .await?;
    let mut stream = connect(&proxy.base()).await?;
    stream
        .write_all(b"POST /blocked HTTP/1.1\r\nHost: example.com\r\nContent-Length: 200000\r\n\r\n")
        .await?;
    let sent = trickle(&mut stream, 200_000, 2_000, Duration::from_millis(2)).await?;
    assert_eq!(sent, 200_000, "the client must be able to finish its body");
    let (status, _, _) = read_response(&mut stream).await?;
    assert_eq!(status, 403);
    assert_eq!(stub.calls(), 0);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    proxy.stop().await
}

#[tokio::test]
async fn model_block_with_a_body_gets_403_while_the_client_keeps_sending() -> TestResult {
    let (upstream, hits, _task) = start_counting_upstream().await?;
    let stub = StubDecider::start().await?;
    stub.set_behavior(StubBehavior {
        attack: 0.95,
        ..StubBehavior::default()
    });
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream,
        &format!("client_max_body_size 1m;\n{LINGER_FAST}"),
        "",
    ))
    .await?;
    let mut stream = connect(&proxy.base()).await?;
    stream
        .write_all(b"POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 20000\r\n\r\n")
        .await?;
    let sent = trickle(&mut stream, 20_000, 1_000, Duration::from_millis(5)).await?;
    assert_eq!(sent, 20_000, "the client must be able to finish its body");
    let (status, _, _) = read_response(&mut stream).await?;
    assert_eq!(status, 403);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    proxy.stop().await
}

#[tokio::test]
async fn lingering_close_off_closes_with_the_body_unread() -> TestResult {
    // With lingering off the socket closes at once, so the rest of the body meets a closed
    // socket and the client's writes fail.
    let (upstream, _hits, _task) = start_counting_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream,
        "client_max_body_size 1k;\nlingering_close off;",
        "",
    ))
    .await?;
    let mut stream = connect(&proxy.base()).await?;
    stream
        .write_all(b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 20000\r\n\r\n")
        .await?;
    let sent = trickle(&mut stream, 20_000, 1_000, Duration::from_millis(5)).await?;
    assert!(
        sent < 20_000,
        "with lingering off the router closes before the body is sent"
    );
    proxy.stop().await
}

#[tokio::test]
async fn always_lingers_after_a_normal_response() -> TestResult {
    // keepalive_requests 1 makes the 200 close the connection. A client that sends more after
    // the response is still read, so its second write succeeds and the close is orderly.
    let (upstream, _hits, _task) = start_counting_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream,
        &format!("keepalive_requests 1;\nlingering_close always;\n{LINGER_FAST}"),
        "",
    ))
    .await?;
    let mut stream = connect(&proxy.base()).await?;
    stream
        .write_all(b"GET /one HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await?;
    let (status, _, _) = read_response(&mut stream).await?;
    assert_eq!(status, 200);
    stream.write_all(b"late bytes").await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    stream.write_all(b"more late bytes").await?;
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(SETTLE, stream.read(&mut byte)).await??;
    assert_eq!(read, 0, "the close must be an orderly end of stream");
    proxy.stop().await
}

#[tokio::test]
async fn lingering_close_off_fails_a_client_that_keeps_sending_after_a_normal_response()
-> TestResult {
    // With lingering off the router has closed by the time the late bytes arrive, so the
    // kernel answers them with a reset and the client's next write fails.
    let (upstream, _hits, _task) = start_counting_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream,
        "keepalive_requests 1;\nlingering_close off;",
        "",
    ))
    .await?;
    let mut stream = connect(&proxy.base()).await?;
    stream
        .write_all(b"GET /one HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await?;
    let (status, _, _) = read_response(&mut stream).await?;
    assert_eq!(status, 200);
    // The first write may still succeed: it is the reply to it that resets the connection.
    let _ = stream.write_all(b"late bytes").await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        stream.write_all(b"more late bytes").await.is_err(),
        "the reset must reach the client"
    );
    proxy.stop().await
}

#[tokio::test]
async fn access_list_deny_with_a_body_gets_403_while_the_client_keeps_sending() -> TestResult {
    // The access list refuses before the body is read. The client is still sending, so the
    // router must linger rather than reset the connection before the 403 is read.
    let (upstream, hits, _task) = start_counting_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream,
        &format!("client_max_body_size 1m;\n{LINGER_FAST}"),
        "deny all;",
    ))
    .await?;
    let mut stream = connect(&proxy.base()).await?;
    stream
        .write_all(b"POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 200000\r\n\r\n")
        .await?;
    let sent = trickle(&mut stream, 200_000, 2_000, Duration::from_millis(2)).await?;
    assert_eq!(sent, 200_000, "the client must be able to finish its body");
    let (status, _, _) = read_response(&mut stream).await?;
    assert_eq!(status, 403);
    assert_eq!(stub.calls(), 0);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    proxy.stop().await
}
