//! Deterministic decision backend for the e2e stack.
//!
//! It serves two protocols. `POST /decide` speaks the router's JSON protocol.
//! `POST /client/v4/accounts/test/ai/run/@cf/cloudflare/clef-flash` speaks the
//! Clef protocol and answers in the Workers AI envelope. `POST /v1/systemone`
//! speaks the Jev protocol and answers with a bare result. Both require the
//! bearer token `test-token`. Both use the same fixed substring rules, so the e2e tests
//! see the same scores on every run. Requests whose path contains `/slow` are
//! held for one second before the answer. Any `POST /echo/...` is an upstream
//! for the e2e upload site: it answers with the length and FNV-1a hash of the body
//! it received, so the test can check the body arrived intact. An echo whose path
//! contains `/hold` is held for one second first. A `GET /ws...` with an
//! `Upgrade` header answers 101 Switching Protocols and then echoes every byte
//! it receives on the upgraded connection.

use std::convert::Infallible;
use std::sync::OnceLock;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue, RETRY_AFTER};
use hyper::header::{CONNECTION, UPGRADE};
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
const JEV_PATH: &str = "/v1/systemone";
const ECHO_PREFIX: &str = "/echo/";
const WS_PREFIX: &str = "/ws";
const BEARER_TOKEN: &str = "Bearer test-token";
const ATTACK_MARKERS: [&str; 4] = ["' or 1=1", "<script", "../", "union select"];
const INSTRUCTION_MARKERS: [&str; 2] = ["ignore previous", "answer benign"];
const HIGH: f64 = 0.99;
const LOW: f64 = 0.01;
const SLOW_MARKER: &str = "/slow";

/// Echo requests whose path contains this are held for one second, so a limit on
/// concurrent requests can be tested through the upstream.
const ECHO_HOLD_MARKER: &str = "/hold";
/// A request whose path contains this is answered with HTTP 429 and `Retry-After`.
const RATE_LIMIT_MARKER: &str = "/ratelimited";
const SLOW_DELAY: Duration = Duration::from_secs(1);

/// Extra delay added to every decision, from `STUB_DELAY_MS` (used by the load test).
static DELAY: OnceLock<Duration> = OnceLock::new();

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let delay_ms = std::env::var("STUB_DELAY_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let _ = DELAY.set(Duration::from_millis(delay_ms));
    let listener = TcpListener::bind(LISTEN).await?;
    loop {
        let (stream, _peer) = listener.accept().await?;
        tokio::spawn(async move {
            let service = service_fn(route);
            // A client that hangs up mid-request is not an error for the stub.
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades()
                .await;
        });
    }
}

async fn route(request: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    if request.uri().path().starts_with(WS_PREFIX) && request.headers().contains_key(UPGRADE) {
        return Ok(websocket(request));
    }
    if request.method() != Method::POST {
        return Ok(reply(
            StatusCode::METHOD_NOT_ALLOWED,
            &json!({"error": "method"}),
        ));
    }
    if request.uri().path().starts_with(ECHO_PREFIX) {
        return Ok(echo(request).await);
    }
    let authorized = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        == Some(BEARER_TOKEN);
    let path = request.uri().path().to_owned();
    if path != DECIDE_PATH && path != CLEF_PATH && path != JEV_PATH {
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
    if path != DECIDE_PATH && !authorized {
        return Ok(reply(
            StatusCode::UNAUTHORIZED,
            &json!({"result": null, "success": false,
                    "errors": [{"code": 10000, "message": "Authentication error"}],
                    "messages": []}),
        ));
    }
    if untrusted_path(&payload, &path).is_some_and(|text| text.contains(RATE_LIMIT_MARKER)) {
        return Ok(rate_limited());
    }
    if path == DECIDE_PATH {
        return Ok(decide(&payload).await);
    }
    if path == JEV_PATH {
        return Ok(jev(&payload).await);
    }
    Ok(clef(&payload).await)
}

/// Switches protocols and echoes the upgraded connection until the client closes it.
fn websocket(mut request: Request<Incoming>) -> Response<Full<Bytes>> {
    let on_upgrade = hyper::upgrade::on(&mut request);
    tokio::spawn(async move {
        if let Ok(upgraded) = on_upgrade.await {
            let (mut read, mut write) = tokio::io::split(TokioIo::new(upgraded));
            let _ = tokio::io::copy(&mut read, &mut write).await;
        }
    });
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    response
        .headers_mut()
        .insert(UPGRADE, HeaderValue::from_static("websocket"));
    response
        .headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("Upgrade"));
    response
}

/// Answers with the length and FNV-1a hash of the request body, as a decimal string.
async fn echo(request: Request<Incoming>) -> Response<Full<Bytes>> {
    if request.uri().path().contains(ECHO_HOLD_MARKER) {
        tokio::time::sleep(SLOW_DELAY).await;
    }
    let Ok(collected) = request.into_body().collect().await else {
        return reply(StatusCode::BAD_REQUEST, &json!({"error": "body"}));
    };
    let body = collected.to_bytes();
    let hash = body.iter().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3)
    });
    reply(
        StatusCode::OK,
        &json!({"length": body.len(), "hash": hash.to_string()}),
    )
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
    reply(
        StatusCode::OK,
        &json!({
            // Estimated as one token per four bytes of request, which is enough for offline budget tests.
            "result": {"model": "clef-flash", "answers": answers(&verdict),
                       "usage": {"input_tokens": payload.to_string().len() / 4, "output_tokens": 0}},
            "success": true,
            "errors": [],
            "messages": [],
        }),
    )
}

/// The Jev protocol: the same scoring, answered as a bare result without the envelope.
async fn jev(payload: &Value) -> Response<Full<Bytes>> {
    let Some(untrusted) = payload.pointer("/state/untrusted_http_request") else {
        return reply(StatusCode::BAD_REQUEST, &json!({"error": "missing state"}));
    };
    let verdict = score(untrusted).await;
    reply(
        StatusCode::OK,
        &json!({
            "model": "jev-latest",
            "answers": answers(&verdict),
            "usage": {"input_tokens": payload.to_string().len() / 4, "output_tokens": 0},
        }),
    )
}

fn answers(verdict: &Verdict) -> Value {
    json!({
        "attack": {"type": "noul", "noul": verdict.attack},
        "ai_instruction": {"type": "noul", "noul": verdict.ai_instruction},
        "category": {
            "type": "choice",
            "choice": verdict.category,
            "probabilities": {verdict.category: 0.9},
            "confidence": 0.9,
        },
    })
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
    if let Some(delay) = DELAY.get().filter(|delay| !delay.is_zero()) {
        tokio::time::sleep(*delay).await;
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

/// The path field of the attacker-controlled part of a request, for either protocol.
fn untrusted_path<'a>(payload: &'a Value, route: &str) -> Option<&'a str> {
    let untrusted = if route == DECIDE_PATH {
        payload.pointer("/event/untrusted")
    } else {
        payload.pointer("/state/untrusted_http_request")
    };
    untrusted
        .and_then(|value| value.get("path"))
        .and_then(Value::as_str)
}

fn rate_limited() -> Response<Full<Bytes>> {
    let mut response = reply(
        StatusCode::TOO_MANY_REQUESTS,
        &json!({"error": "rate limited", "success": false}),
    );
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static("2"));
    response
}

fn reply(status: StatusCode, body: &Value) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body.to_string())));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}
