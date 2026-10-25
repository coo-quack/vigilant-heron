//! Integration tests for the request pipeline, run against in-process servers.

mod common;

use std::time::Duration;

use bytes::Bytes;
use common::{
    StubBehavior, StubDecider, TestResult, Upstream, closed_port_url, config_text, send,
    start_proxy,
};
use http::{Method, StatusCode};

const SLOW_TIMEOUT_MS: u64 = 150;
const GENEROUS_TIMEOUT_MS: u64 = 2_000;

fn attack_behavior() -> StubBehavior {
    StubBehavior {
        attack: 0.95,
        ..StubBehavior::default()
    }
}

#[tokio::test]
async fn benign_request_reaches_the_upstream_and_returns_its_body() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config_text(
        &stub.decide_url(),
        &upstream.url(),
        GENEROUS_TIMEOUT_MS,
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/hello",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json()["method"], "GET");
    assert_eq!(reply.json()["host"], "example.com");
    assert_eq!(stub.calls(), 1);
    proxy.stop().await
}

#[tokio::test]
async fn attack_is_blocked_with_403_and_no_detail() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = StubDecider::start().await?;
    stub.set_behavior(attack_behavior());
    let proxy = start_proxy(&config_text(
        &stub.decide_url(),
        &upstream.url(),
        GENEROUS_TIMEOUT_MS,
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/search?q=%27%20or%201%3D1",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.text(), "Forbidden\n");
    proxy.stop().await
}

#[tokio::test]
async fn redirect_site_answers_an_attack_with_302_and_location() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = StubDecider::start().await?;
    stub.set_behavior(attack_behavior());
    let proxy = start_proxy(&config_text(
        &stub.decide_url(),
        &upstream.url(),
        GENEROUS_TIMEOUT_MS,
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/?q=x",
        "redirect.test",
        &[],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::FOUND);
    assert_eq!(
        reply
            .headers
            .get(http::header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("https://example.com/blocked")
    );
    proxy.stop().await
}

#[tokio::test]
async fn shadow_site_forwards_an_attack_and_records_the_block_in_the_debug_header() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = StubDecider::start().await?;
    stub.set_behavior(attack_behavior());
    let proxy = start_proxy(&config_text(
        &stub.decide_url(),
        &upstream.url(),
        GENEROUS_TIMEOUT_MS,
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/?q=x",
        "shadow.test",
        &[],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json()["method"], "GET");
    assert_eq!(
        reply
            .headers
            .get("x-vigilant-heron")
            .and_then(|value| value.to_str().ok()),
        Some("action=allow; reason=model; would_have=block")
    );
    proxy.stop().await
}

#[tokio::test]
async fn unknown_host_gets_the_default_status_without_calling_the_backend() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config_text(
        &stub.decide_url(),
        &upstream.url(),
        GENEROUS_TIMEOUT_MS,
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/",
        "unknown.example",
        &[],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::MISDIRECTED_REQUEST);
    assert!(reply.body.is_empty());
    assert_eq!(stub.calls(), 0);
    proxy.stop().await
}

#[tokio::test]
async fn deny_path_is_blocked_without_calling_the_backend() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config_text(
        &stub.decide_url(),
        &upstream.url(),
        GENEROUS_TIMEOUT_MS,
    ))
    .await?;

    let plain = send(
        &proxy.base(),
        Method::POST,
        "/xmlrpc.php",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;
    let encoded = send(
        &proxy.base(),
        Method::POST,
        "/%78MLRPC.php",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;

    assert_eq!(plain.status, StatusCode::FORBIDDEN);
    assert_eq!(encoded.status, StatusCode::FORBIDDEN);
    assert_eq!(stub.calls(), 0);
    proxy.stop().await
}

#[tokio::test]
async fn static_asset_is_forwarded_without_calling_the_backend() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config_text(
        &stub.decide_url(),
        &upstream.url(),
        GENEROUS_TIMEOUT_MS,
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/style.css",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json()["uri"], "/style.css");
    assert_eq!(stub.calls(), 0);
    proxy.stop().await
}

#[tokio::test]
async fn backend_timeout_fails_open_on_an_ordinary_path() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = StubDecider::start().await?;
    stub.set_behavior(StubBehavior {
        delay: Duration::from_millis(1_000),
        ..StubBehavior::default()
    });
    let proxy = start_proxy(&config_text(
        &stub.decide_url(),
        &upstream.url(),
        SLOW_TIMEOUT_MS,
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/articles",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json()["uri"], "/articles");
    assert_eq!(stub.calls(), 1);
    proxy.stop().await
}

#[tokio::test]
async fn backend_timeout_fails_closed_on_a_fail_closed_path() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = StubDecider::start().await?;
    stub.set_behavior(StubBehavior {
        delay: Duration::from_millis(1_000),
        ..StubBehavior::default()
    });
    let proxy = start_proxy(&config_text(
        &stub.decide_url(),
        &upstream.url(),
        SLOW_TIMEOUT_MS,
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::POST,
        "/wp-login.php",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    proxy.stop().await
}

#[tokio::test]
async fn backend_server_error_fails_open() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = StubDecider::start().await?;
    stub.set_behavior(StubBehavior {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        ..StubBehavior::default()
    });
    let proxy = start_proxy(&config_text(
        &stub.decide_url(),
        &upstream.url(),
        GENEROUS_TIMEOUT_MS,
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/articles",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::OK);
    proxy.stop().await
}

#[tokio::test]
async fn body_over_the_limit_gets_413_without_calling_the_backend() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config_text(
        &stub.decide_url(),
        &upstream.url(),
        GENEROUS_TIMEOUT_MS,
    ))
    .await?;

    let body = Bytes::from(vec![b'a'; 2_048]);
    let reply = send(
        &proxy.base(),
        Method::POST,
        "/upload",
        "example.com",
        &[],
        body,
    )
    .await?;

    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(stub.calls(), 0);
    proxy.stop().await
}

#[tokio::test]
async fn backend_never_receives_credentials_and_sees_the_form_password_redacted() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config_text(
        &stub.decide_url(),
        &upstream.url(),
        GENEROUS_TIMEOUT_MS,
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::POST,
        "/login",
        "example.com",
        &[
            ("cookie", "session=abc"),
            ("authorization", "Basic dXNlcjpwYXNz"),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        Bytes::from_static(b"user=alice&password=hunter2"),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::OK);
    // The upstream still needs the cookie; only the decision backend is kept from it.
    assert_eq!(reply.json()["cookie_present"], true);
    let event = stub.last_event().unwrap_or_default();
    let untrusted = &event["event"]["untrusted"];
    let header_names: Vec<&str> = untrusted["headers"]
        .as_array()
        .map(|pairs| pairs.iter().filter_map(|pair| pair[0].as_str()).collect())
        .unwrap_or_default();
    assert!(!header_names.contains(&"cookie"));
    assert!(!header_names.contains(&"authorization"));
    let forwarded_body = untrusted["body"].as_str().unwrap_or_default();
    assert!(!forwarded_body.contains("hunter2"));
    let pairs: Vec<(String, String)> = form_urlencoded::parse(forwarded_body.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    assert!(pairs.contains(&("password".to_owned(), "[REDACTED]".to_owned())));
    assert!(pairs.contains(&("user".to_owned(), "alice".to_owned())));
    proxy.stop().await
}

#[tokio::test]
async fn upstream_that_is_down_gets_502() -> TestResult {
    let stub = StubDecider::start().await?;
    let dead_upstream = closed_port_url().await?;
    let proxy = start_proxy(&config_text(
        &stub.decide_url(),
        &dead_upstream,
        GENEROUS_TIMEOUT_MS,
    ))
    .await?;

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
async fn query_string_reaches_the_upstream_unchanged() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config_text(
        &stub.decide_url(),
        &upstream.url(),
        GENEROUS_TIMEOUT_MS,
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/path/item?a=1&b=two%20words&c=%2F",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.json()["uri"], "/path/item?a=1&b=two%20words&c=%2F");
    proxy.stop().await
}

#[tokio::test]
async fn peer_address_is_appended_to_x_forwarded_for() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config_text(
        &stub.decide_url(),
        &upstream.url(),
        GENEROUS_TIMEOUT_MS,
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/",
        "example.com",
        &[("x-forwarded-for", "198.51.100.9")],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.json()["x_forwarded_for"], "198.51.100.9, 127.0.0.1");
    proxy.stop().await
}

#[tokio::test]
async fn hop_by_hop_headers_are_not_forwarded_to_the_upstream() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config_text(
        &stub.decide_url(),
        &upstream.url(),
        GENEROUS_TIMEOUT_MS,
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/",
        "example.com",
        &[("connection", "close, x-internal"), ("x-internal", "1")],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json()["x_internal_present"], false);
    proxy.stop().await
}

#[tokio::test]
async fn debug_header_is_absent_when_the_site_disables_it() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = StubDecider::start().await?;
    stub.set_behavior(attack_behavior());
    let proxy = start_proxy(&config_text(
        &stub.decide_url(),
        &upstream.url(),
        GENEROUS_TIMEOUT_MS,
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/?q=x",
        "redirect.test",
        &[],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::FOUND);
    assert!(reply.headers.get("x-vigilant-heron").is_none());
    proxy.stop().await
}

#[tokio::test]
async fn debug_header_reports_the_block_on_an_enforcing_site() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = StubDecider::start().await?;
    stub.set_behavior(attack_behavior());
    let proxy = start_proxy(&config_text(
        &stub.decide_url(),
        &upstream.url(),
        GENEROUS_TIMEOUT_MS,
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/?q=x",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(
        reply
            .headers
            .get("x-vigilant-heron")
            .and_then(|value| value.to_str().ok()),
        Some("action=block; reason=model; would_have=none")
    );
    proxy.stop().await
}

#[tokio::test]
async fn unknown_host_with_a_body_still_gets_the_default_status() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config_text(
        &stub.decide_url(),
        &upstream.url(),
        GENEROUS_TIMEOUT_MS,
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::POST,
        "/submit",
        "UNKNOWN.example.:8080",
        &[],
        Bytes::from_static(b"a=1"),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::MISDIRECTED_REQUEST);
    assert_eq!(stub.calls(), 0);
    proxy.stop().await
}

#[tokio::test]
async fn oversized_body_is_rejected_and_the_proxy_keeps_serving() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config_text(
        &stub.decide_url(),
        &upstream.url(),
        GENEROUS_TIMEOUT_MS,
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::POST,
        "/upload",
        "example.com",
        &[],
        Bytes::from(vec![b'x'; 4_096]),
    )
    .await?;
    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);

    let after = send(
        &proxy.base(),
        Method::GET,
        "/after",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;
    assert_eq!(after.status, StatusCode::OK);
    proxy.stop().await
}

#[tokio::test]
async fn malformed_json_with_an_attack_is_blocked() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = StubDecider::start().await?;
    stub.set_behavior(attack_behavior());
    let proxy = start_proxy(&config_text(
        &stub.decide_url(),
        &upstream.url(),
        GENEROUS_TIMEOUT_MS,
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::POST,
        "/api",
        "example.com",
        &[("content-type", "application/json")],
        Bytes::from_static(br#"{"q": "' or 1=1" "#),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    proxy.stop().await
}
