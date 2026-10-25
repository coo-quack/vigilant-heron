//! Deterministic decision backend for the e2e stack.
//!
//! It serves two protocols. `POST /decide` speaks the router's JSON protocol.
//! `POST /client/v4/accounts/test/ai/run/@cf/cloudflare/clef-flash` speaks the
//! Clef protocol, answers in the Workers AI envelope, and requires the bearer
//! token `test-token`. Both use the same fixed substring rules, so the e2e tests
//! see the same scores on every run. Requests whose path contains `/slow` are
//! held for one second before the answer.

use std::convert::Infallible;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use percent_encoding::percent_decode_str;
use serde_json::{Value, json};
use tokio::net::TcpListener;

const LISTEN: &str = "0.0.0.0:9000";
const DECIDE_PATH: &str = "/decide";
const CLEF_PATH: &str = "/client/v4/accounts/test/ai/run/@cf/cloudflare/clef-flash";
const CLEF_TOKEN: &str = "Bearer test-token";
const ATTACK_MARKERS: [&str; 4] = ["' or 1=1", "<script", "../", "union select"];
const INSTRUCTION_MARKERS: [&str; 2] = ["ignore previous", "answer benign"];
const HIGH: f64 = 0.99;
const LOW: f64 = 0.01;
const SLOW_MARKER: &str = "/slow";
const SLOW_DELAY: Duration = Duration::from_secs(1);

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind(LISTEN).await?;
    loop {
        let (stream, _peer) = listener.accept().await?;
        tokio::spawn(async move {
            let service = service_fn(route);
            // A client that hangs up mid-request is not an error for the stub.
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

async fn route(request: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    if request.method() != Method::POST {
        return Ok(reply(
            StatusCode::METHOD_NOT_ALLOWED,
            &json!({"error": "method"}),
        ));
    }
    let clef_authorized = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        == Some(CLEF_TOKEN);
    let path = request.uri().path().to_owned();
    if path != DECIDE_PATH && path != CLEF_PATH {
        return Ok(reply(StatusCode::NOT_FOUND, &json!({"error": "not found"})));
    }
    let Ok(collected) = request.into_body().collect().await else {
        return Ok(reply(
            StatusCode::BAD_REQUEST,
            &json!({"error": "unreadable body"}),
        ));
    };
    let Ok(payload) = serde_json::from_slice::<Value>(&collected.to_bytes()) else {
        return Ok(reply(
            StatusCode::BAD_REQUEST,
            &json!({"error": "invalid JSON"}),
        ));
    };
    if path == DECIDE_PATH {
        return Ok(decide(&payload).await);
    }
    if !clef_authorized {
        return Ok(reply(
            StatusCode::UNAUTHORIZED,
            &json!({"result": null, "success": false,
                    "errors": [{"code": 10000, "message": "Authentication error"}],
                    "messages": []}),
        ));
    }
    Ok(clef(&payload).await)
}

/// The router's JSON protocol: `{"event": {"untrusted": {...}}}` in, scores out.
async fn decide(payload: &Value) -> Response<Full<Bytes>> {
    let Some(untrusted) = payload.pointer("/event/untrusted") else {
        return reply(
            StatusCode::BAD_REQUEST,
            &json!({"error": "missing event.untrusted"}),
        );
    };
    let verdict = score(untrusted).await;
    reply(
        StatusCode::OK,
        &json!({"attack": verdict.attack, "ai_instruction": verdict.ai_instruction}),
    )
}

/// The Clef protocol: the request's `state.untrusted_http_request` is scored and
/// the answers are returned in the Workers AI envelope.
async fn clef(payload: &Value) -> Response<Full<Bytes>> {
    let Some(untrusted) = payload.pointer("/state/untrusted_http_request") else {
        return reply(StatusCode::BAD_REQUEST, &json!({"error": "missing state"}));
    };
    let verdict = score(untrusted).await;
    let answers = json!({
        "attack": {"type": "noul", "noul": verdict.attack},
        "ai_instruction": {"type": "noul", "noul": verdict.ai_instruction},
        "category": {
            "type": "choice",
            "choice": verdict.category,
            "probabilities": {verdict.category: 0.9},
            "confidence": 0.9,
        },
    });
    reply(
        StatusCode::OK,
        &json!({
            // Estimated as one token per four bytes of request, which is enough for offline budget tests.
            "result": {"model": "clef-flash", "answers": answers,
                       "usage": {"input_tokens": payload.to_string().len() / 4, "output_tokens": 0}},
            "success": true,
            "errors": [],
            "messages": [],
        }),
    )
}

struct Verdict {
    attack: f64,
    ai_instruction: f64,
    category: &'static str,
}

/// Applies the fixed rules to the attacker-controlled fields.
async fn score(untrusted: &Value) -> Verdict {
    let path = decode_for_scan(untrusted.get("path").and_then(Value::as_str).unwrap_or(""));
    if path.contains(SLOW_MARKER) {
        tokio::time::sleep(SLOW_DELAY).await;
    }
    let content = decode_for_scan(&scan_text(untrusted));
    let attack = contains_any(&content, &ATTACK_MARKERS);
    let category = if !attack {
        "none"
    } else if content.contains("union select") || content.contains("' or 1=1") {
        "sql_injection"
    } else if content.contains("<script") {
        "xss"
    } else if content.contains("../") {
        "path_traversal"
    } else {
        "other_attack"
    };
    Verdict {
        attack: if attack { HIGH } else { LOW },
        ai_instruction: if contains_any(&content, &INSTRUCTION_MARKERS) {
            HIGH
        } else {
            LOW
        },
        category,
    }
}

/// Joins the attacker-controlled text fields that the rules inspect.
fn scan_text(untrusted: &Value) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for key in ["path", "query", "body"] {
        if let Some(text) = untrusted.get(key).and_then(Value::as_str) {
            parts.push(text);
        }
    }
    if let Some(headers) = untrusted.get("headers").and_then(Value::as_array) {
        parts.extend(headers.iter().filter_map(|pair| pair.get(1)?.as_str()));
    }
    parts.join("\n")
}

/// Undoes form and percent encoding once, then lowercases for matching.
fn decode_for_scan(text: &str) -> String {
    percent_decode_str(&text.replace('+', " "))
        .decode_utf8_lossy()
        .to_lowercase()
}

fn contains_any(content: &str, markers: &[&str]) -> bool {
    markers.iter().any(|marker| content.contains(marker))
}

fn reply(status: StatusCode, body: &Value) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body.to_string())));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}
