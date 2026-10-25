//! Deterministic decision backend for the e2e stack.
//!
//! The verdict depends only on fixed substrings of the `untrusted` fields, so
//! the e2e tests see the same scores on every run. Requests whose path contains
//! `/slow` are held for one second before the answer.

use std::convert::Infallible;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{CONTENT_TYPE, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use percent_encoding::percent_decode_str;
use serde_json::{Value, json};
use tokio::net::TcpListener;

const LISTEN: &str = "0.0.0.0:9000";
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
            let service = service_fn(decide_request);
            // A client that hangs up mid-request is not an error for the stub.
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

async fn decide_request(request: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    if request.method() != Method::POST || request.uri().path() != "/decide" {
        return Ok(reply(StatusCode::NOT_FOUND, &json!({"error": "not found"})));
    }
    let Ok(collected) = request.into_body().collect().await else {
        return Ok(reply(
            StatusCode::BAD_REQUEST,
            &json!({"error": "unreadable body"}),
        ));
    };
    let Ok(event) = serde_json::from_slice::<Value>(&collected.to_bytes()) else {
        return Ok(reply(
            StatusCode::BAD_REQUEST,
            &json!({"error": "invalid JSON"}),
        ));
    };
    let Some(untrusted) = event.pointer("/event/untrusted") else {
        return Ok(reply(
            StatusCode::BAD_REQUEST,
            &json!({"error": "missing event.untrusted"}),
        ));
    };

    let path = decode_for_scan(untrusted.get("path").and_then(Value::as_str).unwrap_or(""));
    if path.contains(SLOW_MARKER) {
        tokio::time::sleep(SLOW_DELAY).await;
    }
    let content = decode_for_scan(&scan_text(untrusted));
    let attack = if contains_any(&content, &ATTACK_MARKERS) {
        HIGH
    } else {
        LOW
    };
    let ai_instruction = if contains_any(&content, &INSTRUCTION_MARKERS) {
        HIGH
    } else {
        LOW
    };
    Ok(reply(
        StatusCode::OK,
        &json!({"attack": attack, "ai_instruction": ai_instruction}),
    ))
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
