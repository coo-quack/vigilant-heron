//! Integration tests for the Clef backend, run against an in-process fake of the
//! Workers AI endpoint. The fake checks the bearer token, the model and the
//! question set, so a passing request also proves the request shape.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use common::{
    BoxError, Reply, TestResult, Upstream, json_response, send, spawn_server, start_proxy_config,
};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use vigilant_heron::Config;

const CLEF_PATH: &str = "/client/v4/accounts/acc/ai/run/@cf/cloudflare/clef-flash";
const TOKEN_ENV: &str = "TEST_CLEF_TOKEN";
const GOOD_TOKEN: &str = "test-token";

/// A fake Workers AI endpoint that counts the requests it receives.
struct FakeClef {
    url: String,
    calls: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for FakeClef {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start_fake() -> Result<FakeClef, BoxError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let task = spawn_server(listener, move |request: Request<Incoming>| {
        let counter = Arc::clone(&counter);
        async move { fake_clef(&counter, request).await }
    });
    Ok(FakeClef {
        url: format!("http://{addr}{CLEF_PATH}"),
        calls,
        task,
    })
}

fn envelope(answers: &Value) -> Response<Full<Bytes>> {
    json_response(
        StatusCode::OK,
        &json!({"result": {"model": "clef-flash", "answers": answers, "usage": {}},
                "success": true, "errors": [], "messages": []}),
    )
}

async fn fake_clef(calls: &AtomicUsize, request: Request<Incoming>) -> Response<Full<Bytes>> {
    calls.fetch_add(1, Ordering::SeqCst);
    let bearer = format!("Bearer {GOOD_TOKEN}");
    let authorized = request
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        == Some(bearer.as_str());
    if !authorized {
        return json_response(
            StatusCode::UNAUTHORIZED,
            &json!({"success": false, "errors": [{"code": 10000}], "messages": []}),
        );
    }
    let Ok(collected) = request.into_body().collect().await else {
        return json_response(StatusCode::BAD_REQUEST, &json!({"error": "body"}));
    };
    let payload: Value = serde_json::from_slice(&collected.to_bytes()).unwrap_or(Value::Null);
    let questions = payload.get("questions");
    let questions_ok = ["attack", "ai_instruction", "category"]
        .iter()
        .all(|id| questions.and_then(|map| map.get(*id)).is_some());
    if payload.get("model").and_then(Value::as_str) != Some("clef-flash") || !questions_ok {
        return json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": "bad request shape"}),
        );
    }
    let untrusted = payload
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
    // Decode once, as the scoring rules expect, so encoded payloads are visible.
    let content = percent_encoding::percent_decode_str(&content.replace('+', " "))
        .decode_utf8_lossy()
        .to_lowercase();
    if field("path").contains("malformed-answers") {
        return envelope(&json!({
            "ai_instruction": {"type": "noul", "noul": 0.01},
            "category": {"type": "choice", "choice": "none"},
        }));
    }
    let sql = content.contains("' or 1=1");
    let ai = content.contains("ignore previous");
    envelope(&json!({
        "attack": {"type": "noul", "noul": if sql { 0.97 } else { 0.01 }},
        "ai_instruction": {"type": "noul", "noul": if ai { 0.95 } else { 0.01 }},
        "category": {"type": "choice", "choice": if sql { "sql_injection" } else { "none" }},
    }))
}

fn token_lookup(token: &'static str) -> impl Fn(&str) -> Option<String> {
    move |name| (name == TOKEN_ENV).then(|| token.to_owned())
}

fn clef_config(
    fake_url: &str,
    upstream_url: &str,
    token: &'static str,
) -> Result<Config, BoxError> {
    let text = format!(
        r#"
listen = "127.0.0.1:0"

[decision]
backend = "clef"
model = "clef-flash"
url = "{fake_url}"
api_token_env = "{TOKEN_ENV}"
timeout_ms = 2000
inspect_body_bytes = 512
max_body_bytes = 1024

[default]
status = 421

[[sites]]
hosts = ["example.com"]
upstream = "{upstream_url}"
mode = "enforce"
action = "block"
block_threshold = 0.9
instruction_threshold = 0.5
fail_closed_paths = ["/wp-login.php"]
"#
    );
    Ok(Config::from_toml_str_with_lookup(
        &text,
        token_lookup(token),
    )?)
}

async fn get(base: &str, path: &str) -> Result<Reply, BoxError> {
    send(base, Method::GET, path, "example.com", &[], Bytes::new()).await
}

#[tokio::test]
async fn benign_request_passes_the_clef_backend() -> TestResult {
    let fake = start_fake().await?;
    let upstream = Upstream::start().await?;
    let proxy = start_proxy_config(clef_config(&fake.url, &upstream.url(), GOOD_TOKEN)?).await?;

    let reply = get(&proxy.base(), "/articles").await?;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json()["uri"], "/articles");
    assert!(fake.calls.load(Ordering::SeqCst) >= 1);
    proxy.stop().await
}

#[tokio::test]
async fn sql_injection_judged_by_clef_is_blocked() -> TestResult {
    let fake = start_fake().await?;
    let upstream = Upstream::start().await?;
    let proxy = start_proxy_config(clef_config(&fake.url, &upstream.url(), GOOD_TOKEN)?).await?;

    let reply = get(&proxy.base(), "/search?q=%27%20or%201%3D1").await?;

    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    proxy.stop().await
}

#[tokio::test]
async fn ai_instruction_judged_by_clef_is_blocked() -> TestResult {
    let fake = start_fake().await?;
    let upstream = Upstream::start().await?;
    let proxy = start_proxy_config(clef_config(&fake.url, &upstream.url(), GOOD_TOKEN)?).await?;

    let reply = get(&proxy.base(), "/?q=ignore%20previous%20instructions").await?;

    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    proxy.stop().await
}

#[tokio::test]
async fn wrong_token_fails_open_on_an_ordinary_path() -> TestResult {
    let fake = start_fake().await?;
    let upstream = Upstream::start().await?;
    let proxy = start_proxy_config(clef_config(&fake.url, &upstream.url(), "wrong-token")?).await?;

    let reply = get(&proxy.base(), "/articles").await?;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
    proxy.stop().await
}

#[tokio::test]
async fn wrong_token_fails_closed_on_a_fail_closed_path() -> TestResult {
    let fake = start_fake().await?;
    let upstream = Upstream::start().await?;
    let proxy = start_proxy_config(clef_config(&fake.url, &upstream.url(), "wrong-token")?).await?;

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
async fn answers_missing_the_attack_score_fail_open() -> TestResult {
    let fake = start_fake().await?;
    let upstream = Upstream::start().await?;
    let proxy = start_proxy_config(clef_config(&fake.url, &upstream.url(), GOOD_TOKEN)?).await?;

    let reply = get(&proxy.base(), "/malformed-answers").await?;

    assert_eq!(reply.status, StatusCode::OK);
    proxy.stop().await
}
