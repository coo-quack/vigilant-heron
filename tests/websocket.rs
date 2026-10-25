//! WebSocket tunnels in-process: an echo upstream that switches protocols, raw
//! client sockets, and the `proxy_websocket` settings.

mod common;

use std::time::Duration;

use common::{StubBehavior, StubDecider, TestResult, send, start_proxy};
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Starts an upstream that answers Upgrade requests with 101 and echoes the bytes after it.
/// A request without Upgrade gets 200 with the body `plain`. Returns its address.
async fn start_echo_upstream() -> Result<std::net::SocketAddr, common::BoxError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let service = service_fn(|mut request: Request<Incoming>| async move {
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
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .with_upgrades()
                    .await;
            });
        }
    });
    Ok(addr)
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
