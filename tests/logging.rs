//! Integration tests for the access log: the fields of each line, the request id,
//! the truncation of a long id, the formats, and `access_log off`.

mod common;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use bytes::Bytes;
use common::system_one::{FakeSpec, FakeSystemOne, start_fake};
use common::{BoxError, Reply, StubDecider, TestResult, Upstream, send, start_proxy_config};
use http::{Method, StatusCode};
use serde_json::Value;
use vigilant_heron::Config;

const JEV_PATH: &str = "/v1/systemone";
const TOKEN_ENV: &str = "TEST_JEV_TOKEN";
const GOOD_TOKEN: &str = "test-token";

/// A unique file path under the temp directory.
fn log_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("vh-logging-{}-{name}.log", std::process::id()))
}

/// Waits until a line with `request_id` appears in the file, and returns that line.
async fn wait_for_line(path: &Path, request_id: &str) -> Result<Value, BoxError> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        for line in text.lines() {
            if let Ok(value) = serde_json::from_str::<Value>(line)
                && value.get("request_id").and_then(Value::as_str) == Some(request_id)
            {
                return Ok(value);
            }
        }
        if Instant::now() > deadline {
            return Err(format!("no access log line for {request_id}").into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A configuration whose only site logs JSON lines to `path`.
fn config_for(
    backend: &str,
    decide_url: &str,
    upstream: &str,
    path: &Path,
    site_extra: &str,
) -> Result<Config, BoxError> {
    let backend_lines = if backend == "jev" {
        format!("backend jev;\n        api_token_env {TOKEN_ENV};\n        url {decide_url};")
    } else {
        format!("backend http;\n        url {decide_url};")
    };
    let text = format!(
        r"
listen 127.0.0.1:0;
request_id_header x-request-id;
access_log {log} json;

client_max_body_size 1024;
decision {{
        {backend_lines}
        timeout 300ms;
        inspect_body 512;
}}

site example.com {{
    upstream {upstream};
    mode enforce;
    action block;
    block_threshold 0.9;
    instruction_threshold 0.5;
    {site_extra}
}}
",
        log = path.display(),
    );
    Ok(Config::parse_str_with_lookup(
        &text,
        "logging.conf",
        |name| (name == TOKEN_ENV).then(|| GOOD_TOKEN.to_owned()),
    )?)
}

async fn start_jev_fake() -> Result<FakeSystemOne, BoxError> {
    start_fake(FakeSpec {
        path: JEV_PATH,
        model: "jev-latest",
        token: GOOD_TOKEN,
        envelope: false,
    })
    .await
}

async fn get_with_id(base: &str, path: &str, id: &str) -> Result<Reply, BoxError> {
    send(
        base,
        Method::GET,
        path,
        "example.com",
        &[("x-request-id", id)],
        Bytes::new(),
    )
    .await
}

#[tokio::test]
async fn access_line_has_the_request_fields_and_the_decision() -> TestResult {
    let decider = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let path = log_path("fields");
    let _ = std::fs::remove_file(&path);
    let config = config_for("http", &decider.decide_url(), &upstream.url(), &path, "")?;
    let proxy = start_proxy_config(config).await?;

    let reply = get_with_id(&proxy.base(), "/articles", "fields-1").await?;

    assert_eq!(reply.status, StatusCode::OK);
    let line = wait_for_line(&path, "fields-1").await?;
    assert_eq!(line["method"], "GET");
    assert_eq!(line["path"], "/articles");
    assert_eq!(line["site"], "example.com");
    assert_eq!(line["status"], "200");
    assert_eq!(line["action"], "allow");
    assert_eq!(line["reason"], "below_threshold");
    assert_eq!(line["input_tokens"], "");
    proxy.stop().await
}

#[tokio::test]
async fn query_shape_logs_names_and_value_classes_never_values() -> TestResult {
    let decider = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let path = log_path("query-shape");
    let _ = std::fs::remove_file(&path);
    let config = config_for("http", &decider.decide_url(), &upstream.url(), &path, "")?;
    let proxy = start_proxy_config(config).await?;

    let reply = get_with_id(&proxy.base(), "/search?p=42&s=secret+words", "shape-1").await?;

    assert_eq!(reply.status, StatusCode::OK);
    let line = wait_for_line(&path, "shape-1").await?;
    assert_eq!(line["query_shape"], "p=<num>&s=<text>");
    let text = std::fs::read_to_string(&path)?;
    assert!(
        !text.contains("secret"),
        "query value leaked into the log: {text}"
    );
    proxy.stop().await
}

#[tokio::test]
async fn query_shape_is_empty_when_the_request_has_no_query() -> TestResult {
    let decider = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let path = log_path("query-shape-none");
    let _ = std::fs::remove_file(&path);
    let config = config_for("http", &decider.decide_url(), &upstream.url(), &path, "")?;
    let proxy = start_proxy_config(config).await?;

    let reply = get_with_id(&proxy.base(), "/articles", "shape-2").await?;

    assert_eq!(reply.status, StatusCode::OK);
    let line = wait_for_line(&path, "shape-2").await?;
    assert_eq!(line["query_shape"], "");
    proxy.stop().await
}

#[tokio::test]
async fn long_request_id_is_cut_to_128_bytes_and_not_sent_to_the_backend() -> TestResult {
    let decider = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let path = log_path("truncation");
    let _ = std::fs::remove_file(&path);
    let config = config_for("http", &decider.decide_url(), &upstream.url(), &path, "")?;
    let proxy = start_proxy_config(config).await?;
    let long_id = format!("rid-truncation-{}", "x".repeat(200));

    let reply = get_with_id(&proxy.base(), "/articles", &long_id).await?;

    assert_eq!(reply.status, StatusCode::OK);
    let expected = long_id.get(..128).unwrap_or(&long_id);
    let line = wait_for_line(&path, expected).await?;
    assert_eq!(line["request_id"].as_str().map(str::len), Some(128));
    let event = decider.last_event().unwrap_or_default();
    let names: Vec<&str> = event["event"]["untrusted"]["headers"]
        .as_array()
        .map(|pairs| pairs.iter().filter_map(|pair| pair[0].as_str()).collect())
        .unwrap_or_default();
    assert!(
        !names.contains(&"x-request-id"),
        "the request id must not reach the backend"
    );
    proxy.stop().await
}

#[tokio::test]
async fn rate_limit_is_logged_with_its_cause_and_retry_after() -> TestResult {
    let fake = start_jev_fake().await?;
    let upstream = Upstream::start().await?;
    let path = log_path("rate-limit");
    let _ = std::fs::remove_file(&path);
    let proxy = start_proxy_config(config_for(
        "jev",
        &fake.url,
        &upstream.url(),
        &path,
        "on_rate_limit allow;",
    )?)
    .await?;

    let reply = get_with_id(&proxy.base(), "/articles/ratelimited", "log-rate-1").await?;

    assert_eq!(reply.status, StatusCode::OK);
    let line = wait_for_line(&path, "log-rate-1").await?;
    assert_eq!(line["decision_error"], "rate_limited");
    assert_eq!(line["retry_after"], "2");
    assert_eq!(line["reason"], "rate_limited_allowed");
    proxy.stop().await
}

#[tokio::test]
async fn backend_timeout_is_logged_as_timeout() -> TestResult {
    let fake = start_jev_fake().await?;
    let upstream = Upstream::start().await?;
    let path = log_path("timeout");
    let _ = std::fs::remove_file(&path);
    let proxy = start_proxy_config(config_for(
        "jev",
        &fake.url,
        &upstream.url(),
        &path,
        "on_decision_error allow;",
    )?)
    .await?;

    let reply = get_with_id(&proxy.base(), "/articles/slowanswer", "log-timeout-1").await?;

    assert_eq!(reply.status, StatusCode::OK);
    let line = wait_for_line(&path, "log-timeout-1").await?;
    assert_eq!(line["decision_error"], "timeout");
    assert_eq!(line["reason"], "decision_error_allowed");
    proxy.stop().await
}

#[tokio::test]
async fn server_error_is_logged_as_http_status() -> TestResult {
    let fake = start_jev_fake().await?;
    let upstream = Upstream::start().await?;
    let path = log_path("http-status");
    let _ = std::fs::remove_file(&path);
    let proxy = start_proxy_config(config_for(
        "jev",
        &fake.url,
        &upstream.url(),
        &path,
        "on_decision_error allow;",
    )?)
    .await?;

    let reply = get_with_id(&proxy.base(), "/articles/servererror", "log-500-1").await?;

    assert_eq!(reply.status, StatusCode::OK);
    let line = wait_for_line(&path, "log-500-1").await?;
    assert_eq!(line["decision_error"], "http_status");
    proxy.stop().await
}

#[tokio::test]
async fn saturated_request_is_logged_as_backend_busy() -> TestResult {
    let fake = start_jev_fake().await?;
    let upstream = Upstream::start().await?;
    let path = log_path("busy");
    let _ = std::fs::remove_file(&path);
    let text = format!(
        r"
listen 127.0.0.1:0;
request_id_header x-request-id;
access_log {log} json;
real_ip_from 127.0.0.0/8;
real_ip_header x-real-ip;

client_max_body_size 1024;
decision {{
        backend jev;
        api_token_env {TOKEN_ENV};
        url {url};
        timeout 300ms;
        max_concurrency 1;
        inspect_body 512;
}}

site example.com {{
    upstream {upstream};
    mode enforce;
    action block;
    block_threshold 0.9;
    instruction_threshold 0.5;
    on_rate_limit block;
}}
",
        log = path.display(),
        url = fake.url,
        upstream = upstream.url(),
    );
    let config = Config::parse_str_with_lookup(&text, "busy.conf", |name| {
        (name == TOKEN_ENV).then(|| GOOD_TOKEN.to_owned())
    })?;
    let proxy = start_proxy_config(config).await?;
    let base = proxy.base();
    let holder_base = base.clone();
    let holder = tokio::spawn(async move {
        send(
            &holder_base,
            Method::GET,
            "/articles/slowanswer",
            "example.com",
            &[],
            Bytes::new(),
        )
        .await
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while fake.calls.load(std::sync::atomic::Ordering::SeqCst) == 0 {
        if Instant::now() > deadline {
            return Err("the holding request never reached the backend".into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Another client, so that the per-client share does not apply: the global slot is full.
    let reply = send(
        &base,
        Method::GET,
        "/articles/queued",
        "example.com",
        &[("x-real-ip", "203.0.113.9"), ("x-request-id", "log-busy-1")],
        Bytes::new(),
    )
    .await?;
    holder.await??;

    assert_eq!(
        reply.status,
        StatusCode::FORBIDDEN,
        "on_rate_limit = block applies"
    );
    let line = wait_for_line(&path, "log-busy-1").await?;
    assert_eq!(line["decision_error"], "backend_busy");
    assert_eq!(line["reason"], "rate_limited_blocked");
    proxy.stop().await
}

#[tokio::test]
async fn unknown_host_is_logged_as_a_rejection_with_status_421() -> TestResult {
    let decider = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let path = log_path("reject");
    let _ = std::fs::remove_file(&path);
    let proxy = start_proxy_config(config_for(
        "http",
        &decider.decide_url(),
        &upstream.url(),
        &path,
        "",
    )?)
    .await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/",
        "unknown.example",
        &[("x-request-id", "log-reject-1")],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::MISDIRECTED_REQUEST);
    let line = wait_for_line(&path, "log-reject-1").await?;
    assert_eq!(line["action"], "reject");
    assert_eq!(line["reason"], "unknown_host");
    assert_eq!(line["status"], "421");
    proxy.stop().await
}

#[tokio::test]
async fn access_log_off_writes_nothing_for_the_site() -> TestResult {
    let decider = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let path = log_path("off");
    let _ = std::fs::remove_file(&path);
    let proxy = start_proxy_config(config_for(
        "http",
        &decider.decide_url(),
        &upstream.url(),
        &path,
        "access_log off;",
    )?)
    .await?;

    let reply = get_with_id(&proxy.base(), "/articles", "log-off-1").await?;
    assert_eq!(reply.status, StatusCode::OK);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(!text.contains("log-off-1"));
    proxy.stop().await
}
