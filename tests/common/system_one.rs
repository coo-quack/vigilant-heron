//! A fake System One endpoint shared by the Clef and Jev integration tests.
//!
//! It checks the bearer token, the model and the question set, so a passing
//! request also proves the request shape. It answers in the Workers AI envelope
//! (Clef) or as a bare result (Jev), as the spec selects.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use super::{BoxError, json_response, spawn_server};

/// How the fake endpoint should behave.
#[derive(Clone)]
pub(crate) struct FakeSpec {
    /// URL path the endpoint serves.
    pub(crate) path: &'static str,
    /// Model that the request must name.
    pub(crate) model: &'static str,
    /// Bearer token that the request must send.
    pub(crate) token: &'static str,
    /// True for the Workers AI envelope, false for a bare result.
    pub(crate) envelope: bool,
}

/// A running fake endpoint that counts the requests it receives.
pub(crate) struct FakeSystemOne {
    /// Full URL of the endpoint.
    pub(crate) url: String,
    /// Number of requests received so far.
    pub(crate) calls: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for FakeSystemOne {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Starts the fake endpoint on an ephemeral loopback port.
pub(crate) async fn start_fake(spec: FakeSpec) -> Result<FakeSystemOne, BoxError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let path = spec.path;
    let task = spawn_server(listener, move |request: Request<Incoming>| {
        let counter = Arc::clone(&counter);
        let spec = spec.clone();
        async move { fake_endpoint(&spec, &counter, request).await }
    });
    Ok(FakeSystemOne {
        url: format!("http://{addr}{path}"),
        calls,
        task,
    })
}

fn answers_response(spec: &FakeSpec, answers: &Value) -> Response<Full<Bytes>> {
    if spec.envelope {
        json_response(
            StatusCode::OK,
            &json!({"result": {"model": spec.model, "answers": answers, "usage": {"input_tokens": 1000}},
                    "success": true, "errors": [], "messages": []}),
        )
    } else {
        json_response(
            StatusCode::OK,
            &json!({"model": spec.model, "answers": answers, "usage": {"input_tokens": 1000, "output_tokens": 0}}),
        )
    }
}

async fn fake_endpoint(
    spec: &FakeSpec,
    calls: &AtomicUsize,
    request: Request<Incoming>,
) -> Response<Full<Bytes>> {
    calls.fetch_add(1, Ordering::SeqCst);
    let bearer = format!("Bearer {}", spec.token);
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
    if payload.get("model").and_then(Value::as_str) != Some(spec.model) || !questions_ok {
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
        return answers_response(
            spec,
            &json!({
                "ai_instruction": {"type": "noul", "noul": 0.01},
                "category": {"type": "choice", "choice": "none"},
            }),
        );
    }
    let sql = content.contains("' or 1=1");
    let ai = content.contains("ignore previous");
    answers_response(
        spec,
        &json!({
            "attack": {"type": "noul", "noul": if sql { 0.97 } else { 0.01 }},
            "ai_instruction": {"type": "noul", "noul": if ai { 0.95 } else { 0.01 }},
            "category": {"type": "choice", "choice": if sql { "sql_injection" } else { "none" }},
        }),
    )
}
