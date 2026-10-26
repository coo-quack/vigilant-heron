//! Integration tests for the Strands Decider backend, run against an in-process
//! stub of its System One endpoint. The stub records the `Authorization` header
//! and the request body, and answers in the Strands Decider result shape, with
//! `latency_ms` and `usage.output_tokens`.

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use bytes::Bytes;
use common::{
    BoxError, Reply, TestResult, Upstream, json_response, send, spawn_server, start_proxy_config,
};
use http::header::AUTHORIZATION;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use percent_encoding::percent_decode_str;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use vigilant_heron::Config;

const STRANDS_PATH: &str = "/v1/systemone";
const TOKEN_ENV: &str = "TEST_STRANDS_TOKEN";
const TOKEN: &str = "test-strands-token";

/// One request as the stub received it.
#[derive(Clone)]
struct Seen {
    /// The `Authorization` header, if the request carried one.
    authorization: Option<String>,
    /// The parsed JSON body.
    body: Value,
}

/// A running stub that records every request it receives.
struct StrandsStub {
    /// Full URL of the endpoint.
    url: String,
    /// Requests received so far, in arrival order.
    seen: Arc<Mutex<Vec<Seen>>>,
    task: JoinHandle<()>,
}

impl Drop for StrandsStub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl StrandsStub {
    /// A copy of the recorded requests.
    fn requests(&self) -> Vec<Seen> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

async fn start_strands_stub() -> Result<StrandsStub, BoxError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);
    let task = spawn_server(listener, move |request: Request<Incoming>| {
        let recorder = Arc::clone(&recorder);
        async move { strands_endpoint(&recorder, request).await }
    });
    Ok(StrandsStub {
        url: format!("http://{addr}{STRANDS_PATH}"),
        seen,
        task,
    })
}

/// The attack score of a request, from the same fields the other fakes read.
fn attack_score(body: &Value) -> f64 {
    let untrusted = body
        .get("state")
        .and_then(|state| state.get("untrusted_http_request"))
        .cloned()
        .unwrap_or(Value::Null);
    let field = |key: &str| {
        untrusted
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
    };
    let content = format!("{}\n{}\n{}", field("path"), field("query"), field("body"));
    // Decode once so encoded payloads are visible, as the other fakes do.
    let content = percent_decode_str(&content.replace('+', " "))
        .decode_utf8_lossy()
        .to_lowercase();
    if content.contains("' or 1=1") {
        0.97
    } else {
        0.01
    }
}

async fn strands_endpoint(
    seen: &Mutex<Vec<Seen>>,
    request: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let authorization = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let Ok(collected) = request.into_body().collect().await else {
        return json_response(StatusCode::BAD_REQUEST, &json!({"error": "body"}));
    };
    let body: Value = serde_json::from_slice(&collected.to_bytes()).unwrap_or(Value::Null);
    let attack = attack_score(&body);
    seen.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(Seen {
            authorization,
            body: body.clone(),
        });
    let model = body
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    json_response(
        StatusCode::OK,
        &json!({
            "model": model,
            "answers": {
                "attack": {"type": "noul", "noul": attack},
                "ai_instruction": {"type": "noul", "noul": 0.01},
                "category": {"type": "choice", "choice": if attack > 0.5 { "sql_injection" } else { "none" }},
            },
            "usage": {"input_tokens": 252, "output_tokens": 1},
            "latency_ms": 97.04,
        }),
    )
}

/// A configuration with one enforce site. `token_env` names the token variable, if any.
/// `access_log` is a path for JSON access lines, or `None` for no access log.
fn strands_config(
    decide_url: &str,
    upstream_url: &str,
    token_env: Option<&str>,
    access_log: Option<&Path>,
) -> Result<Config, BoxError> {
    let token_line = token_env
        .map(|name| format!("api_token_env {name};"))
        .unwrap_or_default();
    let log_line = access_log
        .map(|path| format!("access_log {} json;", path.display()))
        .unwrap_or_default();
    let text = format!(
        r#"
listen 127.0.0.1:0;
request_id_header x-request-id;
{log_line}

client_max_body_size 1024;
decision {{
    backend strands;
    url "{decide_url}";
    {token_line}
    timeout 2000ms;
    inspect_body 512;
}}

site example.com {{
    upstream "{upstream_url}";
    mode enforce;
    action block;
    block_threshold 0.9;
    instruction_threshold 0.5;
}}
"#
    );
    Ok(Config::parse_str_with_lookup(&text, "test.conf", |name| {
        (name == TOKEN_ENV).then(|| TOKEN.to_owned())
    })?)
}

/// A unique file path under the temp directory.
fn log_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("vh-strands-{}-{name}.log", std::process::id()))
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

async fn get(base: &str, path: &str) -> Result<Reply, BoxError> {
    send(base, Method::GET, path, "example.com", &[], Bytes::new()).await
}

#[tokio::test]
async fn request_without_a_token_variable_sends_no_authorization_header() -> TestResult {
    let stub = start_strands_stub().await?;
    let upstream = Upstream::start().await?;
    let config = strands_config(&stub.url, &upstream.url(), None, None)?;
    let proxy = start_proxy_config(config).await?;

    let reply = get(&proxy.base(), "/articles").await?;

    assert_eq!(reply.status, StatusCode::OK);
    let requests = stub.requests();
    assert_eq!(requests.len(), 1);
    let first = requests.first().ok_or("no request recorded")?;
    assert_eq!(first.authorization, None);
    assert_eq!(first.body["model"], "strands-decider");
    for id in ["attack", "ai_instruction", "category"] {
        assert!(first.body["questions"].get(id).is_some(), "missing {id}");
    }
    proxy.stop().await
}

#[tokio::test]
async fn request_with_a_token_variable_sends_the_bearer_token() -> TestResult {
    let stub = start_strands_stub().await?;
    let upstream = Upstream::start().await?;
    let config = strands_config(&stub.url, &upstream.url(), Some(TOKEN_ENV), None)?;
    let proxy = start_proxy_config(config).await?;

    let reply = get(&proxy.base(), "/articles").await?;

    assert_eq!(reply.status, StatusCode::OK);
    let requests = stub.requests();
    let first = requests.first().ok_or("no request recorded")?;
    assert_eq!(
        first.authorization.as_deref(),
        Some(format!("Bearer {TOKEN}").as_str())
    );
    proxy.stop().await
}

#[tokio::test]
async fn high_attack_score_from_strands_blocks_an_enforce_site() -> TestResult {
    let stub = start_strands_stub().await?;
    let upstream = Upstream::start().await?;
    let config = strands_config(&stub.url, &upstream.url(), None, None)?;
    let proxy = start_proxy_config(config).await?;

    let reply = get(&proxy.base(), "/search?q=%27%20or%201%3D1").await?;

    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    proxy.stop().await
}

#[tokio::test]
async fn low_attack_score_from_strands_forwards_the_request() -> TestResult {
    let stub = start_strands_stub().await?;
    let upstream = Upstream::start().await?;
    let config = strands_config(&stub.url, &upstream.url(), None, None)?;
    let proxy = start_proxy_config(config).await?;

    let reply = get(&proxy.base(), "/articles").await?;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json()["uri"], "/articles");
    proxy.stop().await
}

#[tokio::test]
async fn access_line_records_the_input_tokens_from_strands() -> TestResult {
    let stub = start_strands_stub().await?;
    let upstream = Upstream::start().await?;
    let path = log_path("tokens");
    let _ = std::fs::remove_file(&path);
    let config = strands_config(&stub.url, &upstream.url(), None, Some(&path))?;
    let proxy = start_proxy_config(config).await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/articles",
        "example.com",
        &[("x-request-id", "strands-tokens-1")],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::OK);
    let line = wait_for_line(&path, "strands-tokens-1").await?;
    assert_eq!(line["input_tokens"], "252");
    proxy.stop().await
}
