//! WebSocket tunnels in-process: an echo upstream that switches protocols, raw
//! client sockets, and the `proxy_websocket` settings.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{StubBehavior, StubDecider, TestResult, send, start_proxy};
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rstest::rstest;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Starts an upstream that answers Upgrade requests with 101 and echoes the bytes after it.
/// A request without Upgrade gets 200 with the body `plain`. Returns its address.
async fn start_echo_upstream() -> Result<std::net::SocketAddr, common::BoxError> {
    Ok(start_recording_upstream().await?.0)
}

/// The headers of each request that an upstream received, in arrival order.
type Received = Arc<Mutex<Vec<HeaderMap>>>;

/// Like [`start_echo_upstream`], and also keeps the headers of every request it receives.
async fn start_recording_upstream() -> Result<(std::net::SocketAddr, Received), common::BoxError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let seen: Received = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let recorded = Arc::clone(&recorded);
            tokio::spawn(async move {
                let service = service_fn(|mut request: Request<Incoming>| {
                    let recorded = Arc::clone(&recorded);
                    async move {
                        if let Ok(mut seen) = recorded.lock() {
                            seen.push(request.headers().clone());
                        }
                        if request.headers().contains_key(http::header::UPGRADE) {
                            let on_upgrade = hyper::upgrade::on(&mut request);
                            tokio::spawn(async move {
                                if let Ok(upgraded) = on_upgrade.await {
                                    let (mut read, mut write) =
                                        tokio::io::split(TokioIo::new(upgraded));
                                    let _ = tokio::io::copy(&mut read, &mut write).await;
                                }
                            });
                            let response = Response::builder()
                                .status(StatusCode::SWITCHING_PROTOCOLS)
                                .header(http::header::UPGRADE, "websocket")
                                .header(http::header::CONNECTION, "Upgrade")
                                .body(Full::new(Bytes::new()))
                                .unwrap_or_default();
                            Ok::<_, std::convert::Infallible>(response)
                        } else {
                            Ok(Response::new(Full::new(Bytes::from_static(b"plain"))))
                        }
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .with_upgrades()
                    .await;
            });
        }
    });
    Ok((addr, seen))
}

/// A configuration for one site with `site_lines`, and `top_lines` at the top level.
fn config(decide_url: &str, upstream: std::net::SocketAddr, top: &str, site: &str) -> String {
    format!(
        r#"
listen 127.0.0.1:0;

decision {{
    backend http;
    url "{decide_url}";
    timeout 2000ms;
    inspect_body 512;
}}

default_status 421;
{top}

site example.com {{
    upstream http://{upstream};
    mode enforce;
    action block;
    block_threshold 0.9;
    instruction_threshold 0.5;
    {site}
}}
"#
    )
}

/// Sends an Upgrade handshake to `addr` and returns the socket and the response head.
async fn handshake(
    addr: std::net::SocketAddr,
    path: &str,
) -> Result<(TcpStream, String), std::io::Error> {
    let mut stream = TcpStream::connect(addr).await?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).await? == 0 {
            break;
        }
        head.push(byte[0]);
    }
    Ok((stream, String::from_utf8_lossy(&head).into_owned()))
}

async fn attack_stub() -> Result<StubDecider, common::BoxError> {
    let stub = StubDecider::start().await?;
    stub.set_behavior(StubBehavior {
        attack: 0.95,
        ..StubBehavior::default()
    });
    Ok(stub)
}

#[tokio::test]
async fn an_allowed_handshake_is_tunnelled_and_bytes_echo() -> TestResult {
    let upstream = start_echo_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        upstream,
        "",
        "proxy_websocket on;",
    ))
    .await?;

    let (mut socket, head) = handshake(proxy.addr, "/chat").await?;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    assert!(
        head.to_ascii_lowercase().contains("upgrade: websocket"),
        "{head}"
    );

    socket.write_all(b"hello tunnel").await?;
    let mut echoed = [0u8; 12];
    tokio::time::timeout(Duration::from_secs(5), socket.read_exact(&mut echoed)).await??;
    assert_eq!(&echoed, b"hello tunnel");
    drop(socket);
    proxy.stop().await
}

#[tokio::test]
async fn a_blocked_handshake_gets_the_block_status_and_no_upgrade() -> TestResult {
    let upstream = start_echo_upstream().await?;
    let stub = attack_stub().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        upstream,
        "",
        "proxy_websocket on;\n    block_status 404;",
    ))
    .await?;

    let (_socket, head) = handshake(proxy.addr, "/chat?q=x").await?;

    assert!(head.starts_with("HTTP/1.1 404"), "{head}");
    assert!(!head.contains(" 101 "), "{head}");
    proxy.stop().await
}

#[tokio::test]
async fn an_idle_tunnel_closes_after_proxy_read_timeout() -> TestResult {
    let upstream = start_echo_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        upstream,
        "",
        "proxy_websocket on;\n    proxy_read_timeout 300ms;",
    ))
    .await?;

    let (mut socket, head) = handshake(proxy.addr, "/idle").await?;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");

    // Nothing is sent: the tunnel closes, so the client reads end of stream.
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut buf)).await??;
    assert_eq!(read, 0);
    proxy.stop().await
}

#[tokio::test]
async fn without_proxy_websocket_an_upgrade_is_forwarded_as_a_plain_request() -> TestResult {
    let upstream = start_echo_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(&stub.decide_url(), upstream, "", "")).await?;

    let (_socket, head) = handshake(proxy.addr, "/chat").await?;

    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    proxy.stop().await
}

#[tokio::test]
async fn an_open_tunnel_counts_against_limit_conn() -> TestResult {
    let upstream = start_echo_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        upstream,
        "limit_conn_zone $client_ip zone=conns:1m;",
        "proxy_websocket on;\n    limit_conn conns 1;\n    limit_conn_status 503;",
    ))
    .await?;

    let (first, first_head) = handshake(proxy.addr, "/one").await?;
    assert!(first_head.starts_with("HTTP/1.1 101"), "{first_head}");
    let (_second, second_head) = handshake(proxy.addr, "/two").await?;
    assert!(second_head.starts_with("HTTP/1.1 503"), "{second_head}");

    drop(first);
    proxy.stop().await
}

#[tokio::test]
async fn shutdown_waits_for_an_open_tunnel_until_the_client_closes() -> TestResult {
    let upstream = start_echo_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        upstream,
        "",
        "proxy_websocket on;",
    ))
    .await?;
    let (socket, head) = handshake(proxy.addr, "/open").await?;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");

    let stopping = tokio::spawn(proxy.stop());
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !stopping.is_finished(),
        "shutdown returned while a tunnel was open"
    );

    drop(socket);
    tokio::time::timeout(Duration::from_secs(5), stopping).await???;
    Ok(())
}

#[tokio::test]
async fn an_expired_worker_shutdown_timeout_closes_the_open_tunnel() -> TestResult {
    let upstream = start_echo_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        upstream,
        "worker_shutdown_timeout 300ms;",
        "proxy_websocket on;",
    ))
    .await?;
    let (mut socket, head) = handshake(proxy.addr, "/open").await?;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");

    let started = std::time::Instant::now();
    let stopping = tokio::spawn(proxy.stop());
    // The client keeps the tunnel open, so only the timeout can close it.
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut buf)).await??;
    assert_eq!(read, 0, "the tunnel was not closed");
    tokio::time::timeout(Duration::from_secs(5), stopping).await???;
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_millis(250),
        "stopped after {waited:?}"
    );
    assert!(waited < Duration::from_secs(4), "stopped after {waited:?}");
    Ok(())
}

#[tokio::test]
async fn an_in_flight_request_finishes_before_shutdown_returns() -> TestResult {
    let upstream = start_echo_upstream().await?;
    let stub = StubDecider::start().await?;
    stub.set_behavior(StubBehavior {
        delay: Duration::from_millis(600),
        ..StubBehavior::default()
    });
    let proxy = start_proxy(&config(&stub.decide_url(), upstream, "", "")).await?;
    let base = proxy.base();
    let request = tokio::spawn(async move {
        send(
            &base,
            Method::GET,
            "/slow",
            "example.com",
            &[],
            Bytes::new(),
        )
        .await
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while stub.calls() == 0 {
        if tokio::time::Instant::now() >= deadline {
            return Err("the request never reached the decision".into());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let stopping = tokio::spawn(proxy.stop());
    let reply = request.await??;
    assert_eq!(reply.status, StatusCode::OK);
    tokio::time::timeout(Duration::from_secs(5), stopping).await???;
    Ok(())
}

#[tokio::test]
async fn a_tunnelled_binary_frame_larger_than_a_header_buffer_passes_through() -> TestResult {
    let upstream = start_echo_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        upstream,
        "",
        "proxy_websocket on;",
    ))
    .await?;

    let (mut socket, head) = handshake(proxy.addr, "/binary").await?;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");

    // One binary frame with no CR or LF, longer than one header buffer: a header scan would refuse it.
    let frame = vec![0xAB_u8; 9000];
    socket.write_all(&frame).await?;
    let mut echoed = vec![0u8; frame.len()];
    tokio::time::timeout(Duration::from_secs(5), socket.read_exact(&mut echoed)).await??;
    assert!(
        echoed == frame,
        "the echoed bytes differ from the frame sent"
    );
    drop(socket);
    proxy.stop().await
}

#[tokio::test]
async fn a_tunnel_outlives_the_client_header_timeout() -> TestResult {
    let upstream = start_echo_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        upstream,
        "client_header_timeout 200ms;",
        "proxy_websocket on;",
    ))
    .await?;

    let (mut socket, head) = handshake(proxy.addr, "/long").await?;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");

    // Six bytes 100 ms apart: the tunnel lives 600 ms, three times the header timeout.
    let mut sent = Vec::new();
    for round in 0..6u8 {
        let byte = [b'a' + round];
        let _ = socket.write_all(&byte).await;
        sent.push(byte[0]);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut echoed = vec![0u8; sent.len()];
    tokio::time::timeout(Duration::from_secs(5), socket.read_exact(&mut echoed)).await??;
    assert_eq!(echoed, sent, "an active tunnel must not receive a 408");
    drop(socket);
    proxy.stop().await
}

#[tokio::test]
async fn upgrade_headers_reach_the_upstream_only_when_proxy_websocket_is_on() -> TestResult {
    let (upstream, seen) = start_recording_upstream().await?;
    let stub = StubDecider::start().await?;
    let on = start_proxy(&config(
        &stub.decide_url(),
        upstream,
        "",
        "proxy_websocket on;",
    ))
    .await?;
    let (socket, head) = handshake(on.addr, "/on").await?;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    drop(socket);
    on.stop().await?;

    let off = start_proxy(&config(&stub.decide_url(), upstream, "", "")).await?;
    let (plain, head) = handshake(off.addr, "/off").await?;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    drop(plain);
    off.stop().await?;

    let requests = seen.lock().map_err(|_| "upstream lock poisoned")?.clone();
    let with = requests
        .first()
        .ok_or("the upstream got no request with proxy_websocket on")?;
    assert_eq!(
        with.get(http::header::UPGRADE)
            .and_then(|v| v.to_str().ok()),
        Some("websocket")
    );
    assert!(
        with.get(http::header::CONNECTION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.to_ascii_lowercase().contains("upgrade")),
        "{with:?}"
    );
    let without = requests
        .get(1)
        .ok_or("the upstream got no request with proxy_websocket off")?;
    assert!(
        !without.contains_key(http::header::UPGRADE),
        "the upgrade header was forwarded with proxy_websocket off: {without:?}"
    );
    Ok(())
}

#[tokio::test]
async fn proxy_websocket_in_a_location_tunnels_only_that_location() -> TestResult {
    let upstream = start_echo_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        upstream,
        "",
        "location /ws {\n        proxy_websocket on;\n    }",
    ))
    .await?;

    let (mut socket, head) = handshake(proxy.addr, "/ws").await?;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    socket.write_all(b"ping").await?;
    let mut echoed = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), socket.read_exact(&mut echoed)).await??;
    assert_eq!(&echoed, b"ping");
    drop(socket);

    let (_other, other_head) = handshake(proxy.addr, "/other").await?;
    assert!(other_head.starts_with("HTTP/1.1 200"), "{other_head}");
    proxy.stop().await
}

/// Reads one HTTP/1.1 response with a Content-Length body and returns its head.
async fn read_one_response(stream: &mut TcpStream) -> Result<String, std::io::Error> {
    let mut raw = Vec::new();
    let mut byte = [0u8; 1];
    while !raw.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).await? == 0 {
            break;
        }
        raw.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&raw).into_owned();
    let length = head
        .lines()
        .find_map(|line| {
            let lower = line.to_ascii_lowercase();
            lower.strip_prefix("content-length: ").map(str::to_owned)
        })
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).await?;
    Ok(head)
}

#[tokio::test]
async fn an_upgrade_the_upstream_answers_with_200_keeps_the_connection_for_ordinary_requests()
-> TestResult {
    // The upstream does not switch protocols, so the connection stays an ordinary keep-alive one.
    let upstream = common::Upstream::start().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        upstream.addr,
        "",
        "proxy_websocket on;",
    ))
    .await?;

    let mut stream = TcpStream::connect(proxy.addr).await?;
    stream
        .write_all(b"GET /chat HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\r\n")
        .await?;
    let first = read_one_response(&mut stream).await?;
    assert!(first.starts_with("HTTP/1.1 200"), "{first}");

    stream
        .write_all(b"GET /again HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await?;
    let second = read_one_response(&mut stream).await?;
    assert!(second.starts_with("HTTP/1.1 200"), "{second}");
    proxy.stop().await
}

#[tokio::test]
async fn an_upgrade_answered_with_200_loses_its_hop_by_hop_headers() -> TestResult {
    // The upstream answers 200 with a hop-by-hop header. The proxy does not tunnel the answer, so it removes the header.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let _task = common::spawn_server(listener, |_request: Request<Incoming>| async move {
        let mut response = common::json_response(StatusCode::OK, &serde_json::json!({"ok": true}));
        response
            .headers_mut()
            .insert("keep-alive", http::HeaderValue::from_static("timeout=5"));
        response
    });
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(&stub.decide_url(), addr, "", "proxy_websocket on;")).await?;

    let mut stream = TcpStream::connect(proxy.addr).await?;
    stream
        .write_all(b"GET /chat HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\r\n")
        .await?;
    let head = read_one_response(&mut stream).await?;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(!head.to_ascii_lowercase().contains("keep-alive:"), "{head}");
    proxy.stop().await
}

/// What a misbehaving upstream saw: the head of each request, every byte that came after a
/// head, and how many connections ended after it had answered.
struct SwitchingUpstream {
    addr: std::net::SocketAddr,
    heads: Arc<Mutex<Vec<String>>>,
    after_head: Arc<Mutex<Vec<u8>>>,
    closed: Arc<AtomicUsize>,
}

const UPSTREAM_MARKER: &[u8] = b"LEAKED-FROM-UPSTREAM";
const CLIENT_MARKER: &[u8] = b"LEAKED-FROM-CLIENT";

/// The most a test waits for an event that the correct code produces (the request head
/// reaching the upstream, the answer reaching the client). It is generous so that a slow
/// machine fails nothing; the tests do not wait that long when nothing is slow.
const EVENT_BOUND: Duration = Duration::from_secs(5);

/// The longest the tests watch for bytes that must not be relayed. A leak crosses the proxy
/// within a few milliseconds; the window is far longer than that, so a leak that a slow run
/// delays is still seen. The watch ends sooner when both ends of the connection have closed,
/// because after that nothing can arrive.
const ABSENCE_WINDOW: Duration = Duration::from_secs(2);

/// Reads byte by byte until the end of a head (`\r\n\r\n`) or end of stream, and returns what
/// was read. It takes nothing after the head off the stream. A read error is returned.
async fn read_head(stream: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>, std::io::Error> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).await? == 0 {
            break;
        }
        head.push(byte[0]);
    }
    Ok(head)
}

/// Starts an upstream that answers the first request of each connection with
/// `101 Switching Protocols` followed by [`UPSTREAM_MARKER`], whether or not the request asked
/// to upgrade. After that answer the connection carries raw bytes, which it records until the
/// client side ends. It is written on raw sockets so that nothing depends on the upgrade rules
/// of an HTTP library.
async fn start_switching_upstream() -> Result<SwitchingUpstream, common::BoxError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let heads = Arc::new(Mutex::new(Vec::new()));
    let after_head = Arc::new(Mutex::new(Vec::new()));
    let closed = Arc::new(AtomicUsize::new(0));
    let (seen_heads, seen_bytes, seen_closed) = (
        Arc::clone(&heads),
        Arc::clone(&after_head),
        Arc::clone(&closed),
    );
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let (seen_heads, seen_bytes, seen_closed) = (
                Arc::clone(&seen_heads),
                Arc::clone(&seen_bytes),
                Arc::clone(&seen_closed),
            );
            tokio::spawn(async move {
                let Ok(head) = read_head(&mut stream).await else {
                    return;
                };
                if !head.ends_with(b"\r\n\r\n") {
                    return;
                }
                if let Ok(mut heads) = seen_heads.lock() {
                    heads.push(String::from_utf8_lossy(&head).into_owned());
                }
                let mut answer = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".to_vec();
                answer.extend_from_slice(UPSTREAM_MARKER);
                if stream.write_all(&answer).await.is_ok() {
                    let mut chunk = [0u8; 1024];
                    while let Ok(read) = stream.read(&mut chunk).await {
                        if read == 0 {
                            break;
                        }
                        if let Ok(mut bytes) = seen_bytes.lock() {
                            bytes.extend_from_slice(chunk.get(..read).unwrap_or_default());
                        }
                    }
                }
                seen_closed.fetch_add(1, Ordering::SeqCst);
            });
        }
    });
    Ok(SwitchingUpstream {
        addr,
        heads,
        after_head,
        closed,
    })
}

impl SwitchingUpstream {
    fn heads_seen(&self) -> usize {
        self.heads.lock().map_or(0, |heads| heads.len())
    }

    fn connections_closed(&self) -> usize {
        self.closed.load(Ordering::SeqCst)
    }

    /// Waits until the upstream has recorded a request head, for at most [`EVENT_BOUND`].
    async fn wait_for_head(&self) -> Result<(), common::BoxError> {
        let deadline = tokio::time::Instant::now() + EVENT_BOUND;
        while self.heads_seen() == 0 {
            if tokio::time::Instant::now() >= deadline {
                return Err(
                    format!("no request head reached the upstream within {EVENT_BOUND:?}").into(),
                );
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        Ok(())
    }
}

/// Appends to `received` what `client` delivers, until [`ABSENCE_WINDOW`] has passed or until
/// the client side has reached end of stream (or failed) and the upstream has seen a
/// connection end.
async fn observe_relay(
    client: &mut TcpStream,
    received: &mut Vec<u8>,
    upstream: &SwitchingUpstream,
) {
    let deadline = tokio::time::Instant::now() + ABSENCE_WINDOW;
    let mut client_closed = false;
    let mut chunk = [0u8; 1024];
    while tokio::time::Instant::now() < deadline {
        if client_closed {
            if upstream.connections_closed() > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        } else if let Ok(read) =
            tokio::time::timeout(Duration::from_millis(20), client.read(&mut chunk)).await
        {
            match read {
                Ok(count) if count > 0 => {
                    received.extend_from_slice(chunk.get(..count).unwrap_or_default());
                }
                _ => client_closed = true,
            }
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Checks that the request reached the upstream and that no byte was relayed in either
/// direction: the client's marker is not among the bytes the upstream received after the head,
/// and the upstream's marker is not among the bytes the client received.
fn assert_nothing_relayed(
    upstream: &SwitchingUpstream,
    client_received: &[u8],
) -> Result<(), common::BoxError> {
    let heads = upstream
        .heads
        .lock()
        .map_err(|_| "upstream lock poisoned")?;
    assert_eq!(
        heads.len(),
        1,
        "the request must reach the upstream: {heads:?}"
    );
    let after_head = upstream
        .after_head
        .lock()
        .map_err(|_| "upstream lock poisoned")?;
    assert!(
        !contains(&after_head, CLIENT_MARKER),
        "the client's bytes reached the upstream: {:?}",
        String::from_utf8_lossy(&after_head)
    );
    assert!(
        !contains(client_received, UPSTREAM_MARKER),
        "the upstream's bytes reached the client: {:?}",
        String::from_utf8_lossy(client_received)
    );
    Ok(())
}

// Only an Upgrade request on a site or location with `proxy_websocket on` is tunnelled
// (docs/configuration.md). The upstream answers 101 to each request here, so a byte that
// crosses in either direction means a tunnel was opened for a request that was not allowed one.
// The first four cases send an `Upgrade` header that is not an allowed Upgrade request, so the
// 101 check in `upstream_outcome` is what stops the tunnel. The last case sends no `Upgrade`
// header at all: hyper never upgrades such a connection, so no byte can flow whatever
// `upstream_outcome` decides. It states the documented behaviour and does not guard that check.
#[rstest]
#[case::site_without_proxy_websocket(
    "",
    b"GET /chat HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\r\n"
)]
#[case::location_with_proxy_websocket_off_under_a_site_with_on(
    "proxy_websocket on;\n    location /chat {\n        proxy_websocket off;\n    }",
    b"GET /chat HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\r\n"
)]
#[case::upgrade_header_without_connection_upgrade(
    "proxy_websocket on;",
    b"GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\r\n"
)]
#[case::connection_upgrade_with_an_empty_upgrade_header(
    "proxy_websocket on;",
    b"GET /chat HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: \r\nSec-WebSocket-Version: 13\r\n\r\n"
)]
#[case::plain_request_without_any_upgrade_header(
    "proxy_websocket on;",
    b"GET /plain HTTP/1.1\r\nHost: example.com\r\n\r\n"
)]
#[tokio::test]
async fn an_upstream_101_relays_no_bytes_unless_an_allowed_upgrade_was_asked_for(
    #[case] site: &str,
    #[case] request: &[u8],
) -> TestResult {
    let upstream = start_switching_upstream().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(&stub.decide_url(), upstream.addr, "", site)).await?;

    let mut client = TcpStream::connect(proxy.addr).await?;
    client.write_all(request).await?;

    // Step 1: the request is at the upstream, so the upstream's answer is on its way.
    upstream.wait_for_head().await?;
    // Step 2: the proxy has processed that answer. This is a positive control: the path a leak
    // would take is open. What the client gets instead of a tunnel is not specified, so only
    // the start of an HTTP response is checked.
    let head = tokio::time::timeout(EVENT_BOUND, read_head(&mut client))
        .await
        .map_err(|_| format!("the proxy sent no complete head within {EVENT_BOUND:?}"))??;
    assert!(
        head.starts_with(b"HTTP/1.1 "),
        "the proxy did not answer with an HTTP response: {:?}",
        String::from_utf8_lossy(&head)
    );
    // Step 3: the client writes what a WebSocket client would write after its handshake. The
    // proxy may already have closed the connection, so a failed write is not an error here.
    let _ = client.write_all(CLIENT_MARKER).await;
    let mut received = head;
    observe_relay(&mut client, &mut received, &upstream).await;

    assert_nothing_relayed(&upstream, &received)?;
    drop(client);
    proxy.stop().await
}
