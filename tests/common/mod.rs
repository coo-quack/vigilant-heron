//! Helpers shared by the integration tests: an in-process upstream, a stub
//! decision backend, and a client that talks to the proxy.

#![expect(
    dead_code,
    reason = "each test binary uses a different subset of these helpers"
)]

use std::convert::Infallible;
use std::error::Error;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use http::header::HOST;
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use vigilant_heron::{Config, serve};

/// Error type returned by test helpers.
pub(crate) mod system_one;

pub(crate) type BoxError = Box<dyn Error + Send + Sync>;

/// Result type returned by integration tests.
pub(crate) type TestResult = Result<(), BoxError>;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Serves `handler` on `listener` until the returned task is aborted.
pub(crate) fn spawn_server<H, Fut>(listener: TcpListener, handler: H) -> JoinHandle<()>
where
    H: Fn(Request<Incoming>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Response<Full<Bytes>>> + Send + 'static,
{
    tokio::spawn(async move {
        while let Ok((stream, _peer)) = listener.accept().await {
            let handler = handler.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request| {
                    let handler = handler.clone();
                    async move { Ok::<_, Infallible>(handler(request).await) }
                });
                // Connection errors are the test's concern only through the client side.
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    })
}

pub(crate) fn json_response(status: StatusCode, body: &Value) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body.to_string())));
    *response.status_mut() = status;
    response
}

/// An upstream that echoes what it received as JSON.
pub(crate) struct Upstream {
    /// Address the upstream listens on.
    pub(crate) addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Upstream {
    /// Starts the echo upstream on an ephemeral loopback port.
    pub(crate) async fn start() -> Result<Self, BoxError> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = spawn_server(listener, |request: Request<Incoming>| async move {
            let headers = request.headers();
            let header_text = |name: &str| {
                headers
                    .get(name)
                    .and_then(|value| value.to_str().ok())
                    .map_or(Value::Null, |value| Value::String(value.to_owned()))
            };
            let all_headers: serde_json::Map<String, Value> = headers
                .iter()
                .filter_map(|(name, value)| {
                    value
                        .to_str()
                        .ok()
                        .map(|text| (name.as_str().to_owned(), Value::String(text.to_owned())))
                })
                .collect();
            let echo = json!({
                "headers": Value::Object(all_headers),
                "method": request.method().as_str(),
                "uri": request.uri().path_and_query().map_or("", |value| value.as_str()),
                "host": header_text("host"),
                "x_forwarded_for": header_text("x-forwarded-for"),
                "x_internal_present": headers.contains_key("x-internal"),
                "cookie_present": headers.contains_key("cookie"),
            });
            json_response(StatusCode::OK, &echo)
        });
        Ok(Self { addr, task })
    }

    /// Base URL of the upstream, such as `http://127.0.0.1:4000`.
    pub(crate) fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Returns the address of a loopback port with nothing listening on it.
pub(crate) async fn closed_port_url() -> Result<String, BoxError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    drop(listener);
    Ok(format!("http://{addr}"))
}

/// Behavior the stub decision backend follows for the next request.
#[derive(Debug, Clone)]
pub(crate) struct StubBehavior {
    /// Attack score returned on success.
    pub(crate) attack: f64,
    /// AI instruction score returned on success.
    pub(crate) ai_instruction: f64,
    /// HTTP status returned to the proxy.
    pub(crate) status: StatusCode,
    /// Time the stub waits before answering.
    pub(crate) delay: Duration,
}

impl Default for StubBehavior {
    fn default() -> Self {
        Self {
            attack: 0.01,
            ai_instruction: 0.01,
            status: StatusCode::OK,
            delay: Duration::ZERO,
        }
    }
}

#[derive(Default)]
struct StubState {
    behavior: Mutex<StubBehavior>,
    calls: AtomicUsize,
    last_event: Mutex<Option<Value>>,
}

/// A decision backend that returns a configured verdict and records calls.
pub(crate) struct StubDecider {
    /// Address the stub listens on.
    pub(crate) addr: SocketAddr,
    state: Arc<StubState>,
    task: JoinHandle<()>,
}

impl StubDecider {
    /// Starts the stub on an ephemeral loopback port with the default behavior.
    pub(crate) async fn start() -> Result<Self, BoxError> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let state = Arc::new(StubState::default());
        let handler_state = Arc::clone(&state);
        let task = spawn_server(listener, move |request: Request<Incoming>| {
            let state = Arc::clone(&handler_state);
            async move { decide(&state, request).await }
        });
        Ok(Self { addr, state, task })
    }

    /// URL the proxy should use as `decision.url`.
    pub(crate) fn decide_url(&self) -> String {
        format!("http://{}/decide", self.addr)
    }

    /// Replaces the behavior used for later requests.
    pub(crate) fn set_behavior(&self, behavior: StubBehavior) {
        *lock(&self.state.behavior) = behavior;
    }

    /// Number of decision requests received so far.
    pub(crate) fn calls(&self) -> usize {
        self.state.calls.load(Ordering::SeqCst)
    }

    /// The event body of the most recent decision request.
    pub(crate) fn last_event(&self) -> Option<Value> {
        lock(&self.state.last_event).clone()
    }
}

impl Drop for StubDecider {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn decide(state: &StubState, request: Request<Incoming>) -> Response<Full<Bytes>> {
    let Ok(collected) = request.into_body().collect().await else {
        return json_response(StatusCode::BAD_REQUEST, &json!({"error": "body"}));
    };
    let event: Value = serde_json::from_slice(&collected.to_bytes()).unwrap_or(Value::Null);
    state.calls.fetch_add(1, Ordering::SeqCst);
    *lock(&state.last_event) = Some(event);
    let behavior = lock(&state.behavior).clone();
    if !behavior.delay.is_zero() {
        tokio::time::sleep(behavior.delay).await;
    }
    if !behavior.status.is_success() {
        return json_response(behavior.status, &json!({"error": "configured failure"}));
    }
    json_response(
        StatusCode::OK,
        &json!({"attack": behavior.attack, "ai_instruction": behavior.ai_instruction}),
    )
}

/// A running proxy instance.
pub(crate) struct Proxy {
    /// Address the proxy listens on.
    pub(crate) addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<(), vigilant_heron::ServeError>>,
}

/// Starts the proxy with `config_text` on an ephemeral loopback port.
pub(crate) async fn start_proxy(config_text: &str) -> Result<Proxy, BoxError> {
    start_proxy_config(Config::parse_str(config_text, "test.conf")?).await
}

/// Starts the proxy with an already validated `config` on an ephemeral loopback port.
pub(crate) async fn start_proxy_config(config: Config) -> Result<Proxy, BoxError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (shutdown, shutdown_rx) = oneshot::channel::<()>();
    let task = tokio::spawn(serve(listener, config, async {
        let _ = shutdown_rx.await;
    }));
    Ok(Proxy {
        addr,
        shutdown: Some(shutdown),
        task,
    })
}

impl Proxy {
    /// Base URL of the proxy, such as `http://127.0.0.1:4000`.
    pub(crate) fn base(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Stops the proxy and waits for in-flight requests to finish.
    pub(crate) async fn stop(mut self) -> TestResult {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.await??;
        Ok(())
    }
}

/// A response received from the proxy or the upstream.
pub(crate) struct Reply {
    /// Status code of the response.
    pub(crate) status: StatusCode,
    /// Headers of the response.
    pub(crate) headers: HeaderMap,
    /// Body of the response.
    pub(crate) body: Bytes,
}

impl Reply {
    /// Body decoded as UTF-8, lossily.
    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// Body parsed as JSON; `Null` when it is not JSON.
    pub(crate) fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
}

/// Sends one request to `base` with the given `Host` and extra headers.
pub(crate) async fn send(
    base: &str,
    method: Method,
    path_and_query: &str,
    host: &str,
    headers: &[(&str, &str)],
    body: Bytes,
) -> Result<Reply, BoxError> {
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build_http();
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("{base}{path_and_query}"))
        .header(HOST, host);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder.body(Full::new(body))?;
    let response = client.request(request).await?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await?.to_bytes();
    Ok(Reply {
        status,
        headers,
        body,
    })
}

/// Builds a configuration with three sites that point at `upstream_url`.
///
/// The decision timeout is `timeout_ms`, and `decide_url` is the stub's URL.
pub(crate) fn config_text(decide_url: &str, upstream_url: &str, timeout_ms: u64) -> String {
    format!(
        r#"
listen 127.0.0.1:0;

client_max_body_size 1024;
decision {{
    backend http;
    url "{decide_url}";
    timeout {timeout_ms}ms;
    inspect_body 512;
}}

default_status 421;

site example.com www.example.com {{
    upstream "{upstream_url}";
    mode enforce;
    action block;
    block_threshold 0.9;
    instruction_threshold 0.5;
    deny_path /xmlrpc.php;
    fail_closed_path /wp-login.php;
    debug_headers on;
}}

site redirect.test {{
    upstream "{upstream_url}";
    mode enforce;
    action redirect https://example.com/blocked;
    block_threshold 0.9;
    instruction_threshold 0.5;
}}

site shadow.test {{
    upstream "{upstream_url}";
    mode shadow;
    action block;
    block_threshold 0.9;
    instruction_threshold 0.5;
    debug_headers on;
}}
"#
    )
}
