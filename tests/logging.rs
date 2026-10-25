//! Integration tests for the decision log fields: `request_id`, `decision_error`,
//! and `retry_after`. A global subscriber captures the JSON log lines of this
//! test process.

mod common;

use std::io;
use std::sync::{Arc, Mutex, Once, PoisonError};

use bytes::Bytes;
use common::system_one::{FakeSpec, FakeSystemOne, start_fake};
use common::{BoxError, StubDecider, TestResult, Upstream, send, start_proxy_config};
use http::Method;
use serde_json::Value;
use std::time::Duration;
use tracing_subscriber::fmt::MakeWriter;
use vigilant_heron::Config;

const JEV_PATH: &str = "/v1/systemone";
const TOKEN_ENV: &str = "TEST_JEV_TOKEN";
const GOOD_TOKEN: &str = "test-token";

/// Collects everything the subscriber writes.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

/// Buffers one event and appends it to the sink in a single step, so events from
/// different threads never interleave inside a line.
struct EventWriter {
    buffer: Vec<u8>,
    sink: Arc<Mutex<Vec<u8>>>,
}

impl io::Write for EventWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for EventWriter {
    fn drop(&mut self) {
        self.sink
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(&self.buffer);
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = EventWriter;

    fn make_writer(&'a self) -> Self::Writer {
        EventWriter {
            buffer: Vec::new(),
            sink: Arc::clone(&self.0),
        }
    }
}

static CAPTURE: std::sync::OnceLock<Capture> = std::sync::OnceLock::new();
static INSTALL: Once = Once::new();

fn capture() -> &'static Capture {
    INSTALL.call_once(|| {
        let capture = CAPTURE.get_or_init(Capture::default).clone();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::INFO)
            .with_writer(capture)
            .finish();
        // Only this test binary installs a subscriber, so the call cannot conflict.
        let _ = tracing::subscriber::set_global_default(subscriber);
    });
    CAPTURE.get_or_init(Capture::default)
}

/// Returns the `fields` of the decision event for `request_id`, once it is logged.
fn decision_fields(request_id: &str) -> Option<Value> {
    let bytes = capture()
        .0
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    String::from_utf8_lossy(&bytes)
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|entry| entry["target"] == "vigilant_heron::decision")
        .map(|entry| entry.get("fields").cloned().unwrap_or(Value::Null))
        .find(|fields| fields["request_id"] == request_id)
}

fn decision_config(url: &str, backend: &str, upstream: &str) -> Result<Config, BoxError> {
    // Install the capture before any request, so no decision event is missed.
    capture();
    let model = if backend == "jev" {
        "model = \"jev-latest\"\napi_token_env = \"TEST_JEV_TOKEN\""
    } else {
        ""
    };
    let text = format!(
        r#"
listen = "127.0.0.1:0"
request_id_header = "x-request-id"

[decision]
backend = "{backend}"
{model}
url = "{url}"
timeout_ms = 300
inspect_body_bytes = 512
max_body_bytes = 1024

[default]
status = 421

[[sites]]
hosts = ["example.com"]
upstream = "{upstream}"
mode = "enforce"
action = "block"
block_threshold = 0.9
instruction_threshold = 0.5
"#
    );
    Ok(Config::from_toml_str_with_lookup(&text, |name| {
        (name == TOKEN_ENV).then(|| GOOD_TOKEN.to_owned())
    })?)
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

#[tokio::test]
async fn request_id_is_logged_truncated_and_not_sent_to_the_backend() -> TestResult {
    let decider = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let proxy = start_proxy_config(decision_config(
        &decider.decide_url(),
        "http",
        &upstream.url(),
    )?)
    .await?;
    let long_id = format!("rid-truncation-{}", "x".repeat(200));
    let sent_id = long_id.clone();

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/articles",
        "example.com",
        &[("x-request-id", sent_id.as_str())],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, http::StatusCode::OK);
    let expected_id = long_id.get(..128).unwrap_or(&long_id);
    let logged = decision_fields(expected_id).ok_or("no decision event with the request id")?;
    let logged_id = logged["request_id"].as_str().unwrap_or_default();
    assert_eq!(logged_id.len(), 128, "request_id must be cut to 128 bytes");
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
    let proxy = start_proxy_config(decision_config(&fake.url, "jev", &upstream.url())?).await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/articles/ratelimited",
        "example.com",
        &[("x-request-id", "log-rate-limit-1")],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, http::StatusCode::OK);
    let fields = decision_fields("log-rate-limit-1").ok_or("no decision event")?;
    assert_eq!(fields["decision_error"], "rate_limited");
    assert_eq!(fields["retry_after"], "2");
    assert_eq!(fields["reason"], "rate_limited_allowed");
    proxy.stop().await
}

#[tokio::test]
async fn backend_timeout_is_logged_as_timeout_not_as_busy() -> TestResult {
    let fake = start_jev_fake().await?;
    let upstream = Upstream::start().await?;
    let proxy = start_proxy_config(decision_config(&fake.url, "jev", &upstream.url())?).await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/articles/slowanswer",
        "example.com",
        &[("x-request-id", "log-timeout-1")],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, http::StatusCode::OK);
    let fields = decision_fields("log-timeout-1").ok_or("no decision event")?;
    assert_eq!(fields["decision_error"], "timeout");
    assert_eq!(fields["reason"], "decision_error_allowed");
    proxy.stop().await
}

#[tokio::test]
async fn server_error_is_logged_as_http_status() -> TestResult {
    let fake = start_jev_fake().await?;
    let upstream = Upstream::start().await?;
    let proxy = start_proxy_config(decision_config(&fake.url, "jev", &upstream.url())?).await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/articles/servererror",
        "example.com",
        &[("x-request-id", "log-500-1")],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, http::StatusCode::OK);
    let fields = decision_fields("log-500-1").ok_or("no decision event")?;
    assert_eq!(fields["decision_error"], "http_status");
    proxy.stop().await
}

#[tokio::test]
async fn saturated_request_is_logged_as_backend_busy() -> TestResult {
    let fake = start_jev_fake().await?;
    let upstream = Upstream::start().await?;
    capture();
    let text = format!(
        r#"
listen = "127.0.0.1:0"
request_id_header = "x-request-id"

[decision]
backend = "jev"
model = "jev-latest"
api_token_env = "TEST_JEV_TOKEN"
url = "{url}"
timeout_ms = 300
max_concurrency = 1
inspect_body_bytes = 512
max_body_bytes = 1024

[default]
status = 421

[[sites]]
hosts = ["example.com"]
upstream = "{upstream}"
mode = "enforce"
action = "block"
block_threshold = 0.9
instruction_threshold = 0.5
on_rate_limit = "block"
"#,
        url = fake.url,
        upstream = upstream.url()
    );
    let config = Config::from_toml_str_with_lookup(&text, |name| {
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
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while fake.calls.load(std::sync::atomic::Ordering::SeqCst) == 0 {
        if std::time::Instant::now() > deadline {
            return Err("the holding request never reached the backend".into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let reply = send(
        &base,
        Method::GET,
        "/articles/queued",
        "example.com",
        &[("x-request-id", "log-busy-1")],
        Bytes::new(),
    )
    .await?;
    holder.await??;

    assert_eq!(
        reply.status,
        http::StatusCode::FORBIDDEN,
        "on_rate_limit = block applies"
    );
    let fields = decision_fields("log-busy-1").ok_or("no decision event")?;
    assert_eq!(fields["decision_error"], "backend_busy");
    assert_eq!(fields["reason"], "rate_limited_blocked");
    proxy.stop().await
}
