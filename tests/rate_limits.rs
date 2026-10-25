//! Integration tests for `limit_req`, `limit_conn`, locations and their log variables,
//! run against in-process servers with a stub upstream and a stub decision backend.

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use bytes::Bytes;
use common::{
    BoxError, StubDecider, TestResult, Upstream, json_response, send, spawn_server, start_proxy,
};
use http::{Method, Request, StatusCode};
use hyper::body::Incoming;
use serde_json::json;
use tokio::net::TcpListener;

/// A unique log file path under the temp directory.
fn log_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("vh-limits-{}-{name}.log", std::process::id()))
}

/// Builds a configuration with `top` at the top level and `site_lines` inside `example.com`.
/// Every reply carries `x-vigilant-heron`, and the access log uses a format with the limit variables.
fn config(log: &Path, decide_url: &str, upstream_url: &str, top: &str, site_lines: &str) -> String {
    format!(
        r#"
listen 127.0.0.1:0;
access_log "{log}" lim;
log_format lim "$status $action $reason $limit_req_status $limit_conn_status";
client_max_body_size 1024;
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
    action block;
    block_threshold 0.9;
    instruction_threshold 0.5;
    debug_headers on;
    deny_path /blocked;
{site_lines}
}}
"#,
        log = log.display()
    )
}

/// The access-log lines, split into fields, once they contain `needle`.
async fn wait_for_line(path: &Path, needle: &str) -> Result<String, BoxError> {
    for _ in 0..200 {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        if let Some(line) = text.lines().find(|line| line.contains(needle)) {
            return Ok(line.to_owned());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err(format!("no log line containing {needle}").into())
}

const LOGIN: &str = "/wp-login.php";

#[tokio::test]
async fn a_login_location_passes_a_burst_and_answers_429_after_it() -> TestResult {
    let decider = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let log = log_path("login");
    let _ = std::fs::remove_file(&log);
    let top = "limit_req_zone $client_ip zone=login:1m rate=1r/m;";
    let site = "location /wp-login.php {\n        limit_req zone=login burst=2 nodelay;\n        limit_req_status 429;\n    }";
    let proxy = start_proxy(&config(
        &log,
        &decider.decide_url(),
        &upstream.url(),
        top,
        site,
    ))
    .await?;

    let mut statuses = Vec::new();
    for _ in 0..4 {
        let reply = send(
            &proxy.base(),
            Method::POST,
            LOGIN,
            "example.com",
            &[],
            Bytes::from_static(b"log=a&pwd=b"),
        )
        .await?;
        statuses.push(reply.status);
    }
    assert_eq!(
        statuses,
        vec![
            StatusCode::OK,
            StatusCode::OK,
            StatusCode::OK,
            StatusCode::TOO_MANY_REQUESTS
        ]
    );
    // The limited request never reached the decision backend.
    assert_eq!(decider.calls(), 3);
    // Other paths of the same site are not limited.
    let other = send(
        &proxy.base(),
        Method::GET,
        "/",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;
    assert_eq!(other.status, StatusCode::OK);
    proxy.stop().await?;
    Ok(())
}

#[tokio::test]
async fn a_limited_request_is_logged_with_its_reason_and_variables() -> TestResult {
    let decider = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let log = log_path("logged");
    let _ = std::fs::remove_file(&log);
    let top = "limit_req_zone $client_ip zone=login:1m rate=1r/m;";
    let site = "location /wp-login.php {\n        limit_req zone=login burst=0;\n        limit_req_status 429;\n    }";
    let proxy = start_proxy(&config(
        &log,
        &decider.decide_url(),
        &upstream.url(),
        top,
        site,
    ))
    .await?;
    let _ = send(
        &proxy.base(),
        Method::POST,
        LOGIN,
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;
    let limited = send(
        &proxy.base(),
        Method::POST,
        LOGIN,
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    let line = wait_for_line(&log, "limit_req REJECTED").await?;
    assert_eq!(line, "429 reject limit_req REJECTED -", "{line}");
    let passed = wait_for_line(&log, "200 allow").await?;
    assert_eq!(
        passed,
        "200 allow model PASSED -".replace("model", "below_threshold"),
        "{passed}"
    );
    proxy.stop().await?;
    Ok(())
}

#[tokio::test]
async fn limits_run_before_the_rules_so_a_rule_blocked_request_still_counts() -> TestResult {
    let decider = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let log = log_path("order");
    let _ = std::fs::remove_file(&log);
    let top = "limit_req_zone $client_ip zone=all:1m rate=1r/m;";
    let site = "limit_req zone=all burst=0;\n    limit_req_status 429;";
    let proxy = start_proxy(&config(
        &log,
        &decider.decide_url(),
        &upstream.url(),
        top,
        site,
    ))
    .await?;
    let first = send(
        &proxy.base(),
        Method::GET,
        "/blocked/x",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;
    assert_eq!(first.status, StatusCode::FORBIDDEN);
    let second = send(
        &proxy.base(),
        Method::GET,
        "/blocked/x",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;
    assert_eq!(second.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(decider.calls(), 0);
    proxy.stop().await?;
    Ok(())
}

#[tokio::test]
async fn a_top_level_limit_applies_to_a_host_that_matches_no_site() -> TestResult {
    let decider = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let log = log_path("unknown");
    let _ = std::fs::remove_file(&log);
    let top = "limit_req_zone $client_ip zone=all:1m rate=1r/m;\nlimit_req zone=all burst=0;\nlimit_req_status 429;";
    let proxy = start_proxy(&config(
        &log,
        &decider.decide_url(),
        &upstream.url(),
        top,
        "",
    ))
    .await?;
    let first = send(
        &proxy.base(),
        Method::GET,
        "/",
        "unknown.test",
        &[],
        Bytes::new(),
    )
    .await?;
    assert_eq!(first.status, StatusCode::MISDIRECTED_REQUEST);
    let second = send(
        &proxy.base(),
        Method::GET,
        "/",
        "unknown.test",
        &[],
        Bytes::new(),
    )
    .await?;
    assert_eq!(second.status, StatusCode::TOO_MANY_REQUESTS);
    proxy.stop().await?;
    Ok(())
}

#[tokio::test]
async fn a_shadow_site_forwards_a_limited_request_and_records_would_have() -> TestResult {
    let decider = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let log = log_path("shadow");
    let _ = std::fs::remove_file(&log);
    let top = "limit_req_zone $client_ip zone=login:1m rate=1r/m;";
    let site = "mode shadow;\n    limit_req zone=login burst=0;";
    let proxy = start_proxy(&config(
        &log,
        &decider.decide_url(),
        &upstream.url(),
        top,
        site,
    ))
    .await?;
    let _ = send(
        &proxy.base(),
        Method::GET,
        "/",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;
    let second = send(
        &proxy.base(),
        Method::GET,
        "/",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;
    assert_eq!(second.status, StatusCode::OK);
    let header = second
        .headers
        .get("x-vigilant-heron")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert!(header.contains("would_have=reject"), "{header}");
    proxy.stop().await?;
    Ok(())
}

#[tokio::test]
async fn a_dry_run_site_passes_the_request_and_logs_the_dry_run_status() -> TestResult {
    let decider = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let log = log_path("dry");
    let _ = std::fs::remove_file(&log);
    let top = "limit_req_zone $client_ip zone=login:1m rate=1r/m;";
    let site = "limit_req zone=login burst=0;\n    limit_req_dry_run on;";
    let proxy = start_proxy(&config(
        &log,
        &decider.decide_url(),
        &upstream.url(),
        top,
        site,
    ))
    .await?;
    let _ = send(
        &proxy.base(),
        Method::GET,
        "/",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;
    let second = send(
        &proxy.base(),
        Method::GET,
        "/",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;
    assert_eq!(second.status, StatusCode::OK);
    let line = wait_for_line(&log, "REJECTED_DRY_RUN").await?;
    assert_eq!(
        line, "200 allow below_threshold REJECTED_DRY_RUN -",
        "{line}"
    );
    proxy.stop().await?;
    Ok(())
}

/// Starts an upstream that holds `/slow` for half a second before it answers, and returns its URL.
///
/// The server runs detached until the test process exits.
async fn slow_upstream() -> Result<String, BoxError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let _detached = spawn_server(listener, |request: Request<Incoming>| async move {
        if request.uri().path() == "/slow" {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        json_response(StatusCode::OK, &json!({"ok": true}))
    });
    Ok(format!("http://{addr}"))
}

#[tokio::test]
async fn a_second_concurrent_request_from_the_same_client_gets_503_then_the_count_is_released()
-> TestResult {
    let decider = StubDecider::start().await?;
    let slow_url = slow_upstream().await?;
    let log = log_path("conn");
    let _ = std::fs::remove_file(&log);
    let top = "limit_conn_zone $client_ip zone=perip:1m;";
    let site =
        "location /slow {\n        limit_conn perip 1;\n        limit_conn_status 503;\n    }";
    let proxy = start_proxy(&config(&log, &decider.decide_url(), &slow_url, top, site)).await?;
    let base = proxy.base();
    let first_base = base.clone();
    let first = tokio::spawn(async move {
        send(
            &first_base,
            Method::GET,
            "/slow",
            "example.com",
            &[],
            Bytes::new(),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(150)).await;
    let second = send(
        &base,
        Method::GET,
        "/slow",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;
    assert_eq!(second.status, StatusCode::SERVICE_UNAVAILABLE);
    let first = first.await??;
    assert_eq!(first.status, StatusCode::OK);
    // The first request is finished, so its count is released.
    let third = send(
        &base,
        Method::GET,
        "/slow",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;
    assert_eq!(third.status, StatusCode::OK);
    proxy.stop().await?;
    Ok(())
}

#[tokio::test]
async fn a_client_that_disconnects_mid_request_releases_its_connection_count() -> TestResult {
    let decider = StubDecider::start().await?;
    let slow_url = slow_upstream().await?;
    let log = log_path("disconnect");
    let _ = std::fs::remove_file(&log);
    let top = "limit_conn_zone $client_ip zone=perip:1m;";
    let site =
        "location /slow {\n        limit_conn perip 1;\n        limit_conn_status 503;\n    }";
    let proxy = start_proxy(&config(&log, &decider.decide_url(), &slow_url, top, site)).await?;
    let base = proxy.base();
    let aborted_base = base.clone();
    let aborted = tokio::spawn(async move {
        send(
            &aborted_base,
            Method::GET,
            "/slow",
            "example.com",
            &[],
            Bytes::new(),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(150)).await;
    // The client gives up while the upstream is still holding the request.
    aborted.abort();
    // Once the upstream has answered and the request is gone, the count is free again.
    tokio::time::sleep(Duration::from_millis(900)).await;
    let next = send(
        &base,
        Method::GET,
        "/slow",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;
    assert_eq!(next.status, StatusCode::OK);
    proxy.stop().await?;
    Ok(())
}

/// Sends `/slow` with `key` in the `x-key` header, from a background task.
fn spawn_slow(base: &str, key: &str) -> tokio::task::JoinHandle<Result<common::Reply, BoxError>> {
    let base = base.to_owned();
    let key = key.to_owned();
    tokio::spawn(async move {
        send(
            &base,
            Method::GET,
            "/slow",
            "example.com",
            &[("x-key", key.as_str())],
            Bytes::new(),
        )
        .await
    })
}

#[tokio::test]
async fn an_exhausted_conn_zone_answers_with_the_configured_status() -> TestResult {
    let decider = StubDecider::start().await?;
    let slow_url = slow_upstream().await?;
    let log = log_path("conn-exhausted");
    let _ = std::fs::remove_file(&log);
    // A 64-byte zone holds one state, so a second key has nowhere to go while the first is in progress.
    let top = "limit_conn_zone $http_x_key zone=c:64;";
    let site = "location /slow {\n        limit_conn c 1;\n        limit_conn_status 429;\n    }";
    let proxy = start_proxy(&config(&log, &decider.decide_url(), &slow_url, top, site)).await?;
    let base = proxy.base();
    let first = spawn_slow(&base, "a");
    tokio::time::sleep(Duration::from_millis(150)).await;
    let other = send(
        &base,
        Method::GET,
        "/slow",
        "example.com",
        &[("x-key", "b")],
        Bytes::new(),
    )
    .await?;
    assert_eq!(other.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(first.await??.status, StatusCode::OK);
    proxy.stop().await?;
    Ok(())
}

#[tokio::test]
async fn an_exhausted_conn_zone_in_dry_run_lets_the_request_through() -> TestResult {
    let decider = StubDecider::start().await?;
    let slow_url = slow_upstream().await?;
    let log = log_path("conn-exhausted-dry");
    let _ = std::fs::remove_file(&log);
    let top = "limit_conn_zone $http_x_key zone=c:64;";
    let site = "location /slow {\n        limit_conn c 1;\n        limit_conn_status 429;\n        limit_conn_dry_run on;\n    }";
    let proxy = start_proxy(&config(&log, &decider.decide_url(), &slow_url, top, site)).await?;
    let base = proxy.base();
    let first = spawn_slow(&base, "a");
    tokio::time::sleep(Duration::from_millis(150)).await;
    let other = send(
        &base,
        Method::GET,
        "/slow",
        "example.com",
        &[("x-key", "b")],
        Bytes::new(),
    )
    .await?;
    assert_eq!(other.status, StatusCode::OK);
    let line = wait_for_line(&log, "REJECTED_DRY_RUN").await?;
    assert!(line.starts_with("200 "), "{line}");
    assert_eq!(first.await??.status, StatusCode::OK);
    proxy.stop().await?;
    Ok(())
}

#[tokio::test]
async fn an_exhausted_req_zone_answers_with_the_configured_status() -> TestResult {
    let decider = StubDecider::start().await?;
    let slow_url = slow_upstream().await?;
    let log = log_path("req-exhausted");
    let _ = std::fs::remove_file(&log);
    // One state. The second request of key "a" waits for its turn, and that wait holds the state.
    let top = "limit_req_zone $http_x_key zone=r:128 rate=1r/s;";
    let site =
        "location /slow {\n        limit_req zone=r burst=1;\n        limit_req_status 429;\n    }";
    let proxy = start_proxy(&config(&log, &decider.decide_url(), &slow_url, top, site)).await?;
    let base = proxy.base();
    let first = spawn_slow(&base, "a");
    tokio::time::sleep(Duration::from_millis(100)).await;
    let waiting = spawn_slow(&base, "a");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let other = send(
        &base,
        Method::GET,
        "/slow",
        "example.com",
        &[("x-key", "b")],
        Bytes::new(),
    )
    .await?;
    assert_eq!(other.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(first.await??.status, StatusCode::OK);
    assert_eq!(waiting.await??.status, StatusCode::OK);
    proxy.stop().await?;
    Ok(())
}
