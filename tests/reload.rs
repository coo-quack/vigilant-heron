//! Configuration reload in-process: new requests see a valid new file, a broken
//! file keeps the old one, zones keep their counts, and in-flight requests finish.

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use bytes::Bytes;
use common::{BoxError, GatedDecider, StubBehavior, StubDecider, TestResult, Upstream, send};
use http::{Method, StatusCode};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use vigilant_heron::{Config, ServeError, serve_reloadable};

/// A proxy started with `serve_reloadable` on a file, and the handles to drive it.
struct Running {
    base: String,
    reload: mpsc::Sender<()>,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<(), ServeError>>,
}

impl Running {
    async fn start(path: &Path) -> Result<Self, BoxError> {
        let config = Config::load(path)?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        let (reload, reloads) = mpsc::channel(1);
        let (stop, stop_rx) = oneshot::channel::<()>();
        let file = path.to_path_buf();
        let task = tokio::spawn(serve_reloadable(
            listener,
            config,
            async {
                let _ = stop_rx.await;
            },
            reloads,
            move || Config::load(&file),
            |_| {},
        ));
        Ok(Self {
            base,
            reload,
            stop: Some(stop),
            task,
        })
    }

    /// Asks for a reload and returns at once.
    async fn request_reload(&self) -> TestResult {
        self.reload.send(()).await?;
        Ok(())
    }

    async fn stop(mut self) -> TestResult {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        self.task.await??;
        Ok(())
    }
}

/// A configuration with one site `example.com` whose upstream is `upstream`, and
/// `default_status` at the top level. `site_lines` go inside the site.
fn config(decide_url: &str, upstream: &str, default_status: u16, site_lines: &str) -> String {
    format!(
        r#"
listen 127.0.0.1:0;

decision {{
    backend http;
    url "{decide_url}";
    timeout 2000ms;
    inspect_body 512;
}}

default_status {default_status};

site example.com {{
    upstream {upstream};
    {site_lines}
}}
"#
    )
}

fn write(path: &Path, text: &str) -> TestResult {
    std::fs::write(path, text)?;
    Ok(())
}

fn temp_file(name: &str) -> Result<PathBuf, BoxError> {
    let dir = std::env::temp_dir().join(format!("vh-reload-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join(name))
}

/// Sends a request for an unknown host, which answers with `default_status`.
async fn unknown_host_status(base: &str) -> Result<StatusCode, BoxError> {
    Ok(
        send(base, Method::GET, "/", "unknown.test", &[], Bytes::new())
            .await?
            .status,
    )
}

/// Polls until the server has taken the reload request that was sent, for up to five seconds.
///
/// The reload channel holds one message. Its slot is free again once the serving task has
/// received the message, and the reload is applied in that same step.
async fn wait_until_reload_taken(running: &Running) -> TestResult {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while running.reload.capacity() == 0 {
        if tokio::time::Instant::now() >= deadline {
            return Err("the reload request was never taken".into());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    Ok(())
}

/// Polls until the unknown-host answer is `expected`, for up to five seconds.
async fn wait_for_status(base: &str, expected: StatusCode) -> TestResult {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if unknown_host_status(base).await? == expected {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("the status never became {expected}").into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn a_successful_reload_changes_the_answer_to_new_requests() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = StubDecider::start().await?;
    let file = temp_file("success.conf")?;
    write(&file, &config(&stub.decide_url(), &upstream.url(), 421, ""))?;
    let running = Running::start(&file).await?;
    assert_eq!(
        unknown_host_status(&running.base).await?,
        StatusCode::MISDIRECTED_REQUEST
    );

    write(&file, &config(&stub.decide_url(), &upstream.url(), 404, ""))?;
    running.request_reload().await?;

    wait_for_status(&running.base, StatusCode::NOT_FOUND).await?;
    running.stop().await
}

#[tokio::test]
async fn a_broken_file_keeps_the_previous_configuration() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = StubDecider::start().await?;
    let file = temp_file("broken.conf")?;
    write(&file, &config(&stub.decide_url(), &upstream.url(), 421, ""))?;
    let running = Running::start(&file).await?;

    write(&file, "listen 127.0.0.1:0;\nunknown_directive 1;\n")?;
    running.request_reload().await?;
    wait_until_reload_taken(&running).await?;
    assert_eq!(
        unknown_host_status(&running.base).await?,
        StatusCode::MISDIRECTED_REQUEST
    );

    // The server is still reloading: a valid file after the broken one takes effect.
    write(&file, &config(&stub.decide_url(), &upstream.url(), 404, ""))?;
    running.request_reload().await?;
    wait_for_status(&running.base, StatusCode::NOT_FOUND).await?;
    running.stop().await
}

#[tokio::test]
async fn a_zone_with_the_same_name_and_size_keeps_its_counts() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = StubDecider::start().await?;
    let file = temp_file("zones.conf")?;
    let zone = "limit_req_zone $http_x_key zone=burst:1m rate=1r/m;";
    let site = "location /p {\n        limit_req zone=burst burst=0;\n        limit_req_status 429;\n    }";
    let text = |status: u16, size: &str| {
        config(&stub.decide_url(), &upstream.url(), status, site)
            .replace("default_status", &format!("{zone}\ndefault_status"))
            .replace("1m", size)
    };
    write(&file, &text(421, "1m"))?;
    let running = Running::start(&file).await?;

    let key = "reload-zone-key";
    let first = send(
        &running.base,
        Method::GET,
        "/p",
        "example.com",
        &[("x-key", key)],
        Bytes::new(),
    )
    .await?;
    assert_eq!(first.status, StatusCode::OK);

    // Same name and size after the reload: the spent bucket is still spent.
    write(&file, &text(404, "1m"))?;
    running.request_reload().await?;
    wait_for_status(&running.base, StatusCode::NOT_FOUND).await?;
    let second = send(
        &running.base,
        Method::GET,
        "/p",
        "example.com",
        &[("x-key", key)],
        Bytes::new(),
    )
    .await?;
    assert_eq!(second.status, StatusCode::TOO_MANY_REQUESTS);

    // A different size starts the zone fresh.
    write(&file, &text(404, "2m"))?;
    running.request_reload().await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let reply = send(
            &running.base,
            Method::GET,
            "/p",
            "example.com",
            &[("x-key", key)],
            Bytes::new(),
        )
        .await?;
        if reply.status == StatusCode::OK {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("a zone of a new size kept its old counts".into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    running.stop().await
}

#[tokio::test]
async fn a_request_in_flight_finishes_with_the_configuration_it_started_with() -> TestResult {
    let upstream_a = Upstream::start().await?;
    let upstream_b = Upstream::start().await?;
    let stub = StubDecider::start().await?;
    stub.set_behavior(StubBehavior {
        delay: Duration::from_millis(600),
        ..StubBehavior::default()
    });
    let file = temp_file("inflight.conf")?;
    write(
        &file,
        &config(
            &stub.decide_url(),
            &upstream_a.url(),
            421,
            "proxy_set_header X-Which \"a\";",
        ),
    )?;
    let running = Running::start(&file).await?;
    let base = running.base.clone();
    let in_flight = tokio::spawn(async move {
        send(
            &base,
            Method::GET,
            "/slow?q=1",
            "example.com",
            &[],
            Bytes::new(),
        )
        .await
    });
    // Wait until the decision has started, so the reload happens while the request is in flight.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while stub.calls() == 0 {
        if tokio::time::Instant::now() >= deadline {
            return Err("the request never reached the decision".into());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    write(
        &file,
        &config(
            &stub.decide_url(),
            &upstream_b.url(),
            421,
            "proxy_set_header X-Which \"b\";",
        ),
    )?;
    running.request_reload().await?;

    let old = in_flight.await??;
    assert_eq!(old.status, StatusCode::OK);
    assert_eq!(old.json()["headers"]["x-which"], "a");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let fresh = send(
            &running.base,
            Method::GET,
            "/",
            "example.com",
            &[],
            Bytes::new(),
        )
        .await?;
        if fresh.json()["headers"]["x-which"] == "b" {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("a new request kept the old configuration".into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    running.stop().await
}

/// A configuration with one decision slot, `on_rate_limit block`, and a decision
/// backend that holds its calls until the test releases them. `realip` trusts the
/// `X-Real-IP` header, so a test can send calls from several client addresses.
fn one_slot_config(decide_url: &str, upstream: &str, status: u16, realip: bool) -> String {
    let trusted = if realip {
        "real_ip_from 127.0.0.0/8;\nreal_ip_header x-real-ip;\n\n"
    } else {
        ""
    };
    config(decide_url, upstream, status, "on_rate_limit block;")
        .replace(
            "inspect_body 512;",
            "inspect_body 512;\n    max_concurrency 1;",
        )
        .replace("default_status", &format!("{trusted}default_status"))
}

/// Waits until the backend has received `count` calls, for up to five seconds.
async fn wait_for_calls(decider: &GatedDecider, count: usize) -> TestResult {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while decider.calls() < count {
        if tokio::time::Instant::now() >= deadline {
            return Err("the request never reached the decision".into());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    Ok(())
}

#[tokio::test]
async fn a_reload_keeps_the_per_client_share_of_a_call_in_flight() -> TestResult {
    let upstream = Upstream::start().await?;
    let decider = GatedDecider::start().await?;
    let file = temp_file("client-share.conf")?;
    write(
        &file,
        &one_slot_config(&decider.decide_url(), &upstream.url(), 421, false),
    )?;
    let running = Running::start(&file).await?;
    let base = running.base.clone();
    let in_flight = tokio::spawn(async move {
        send(&base, Method::GET, "/", "example.com", &[], Bytes::new()).await
    });
    wait_for_calls(&decider, 1).await?;

    // Same file, so the limits are unchanged: the call in flight still holds the share.
    write(
        &file,
        &one_slot_config(&decider.decide_url(), &upstream.url(), 404, false),
    )?;
    running.request_reload().await?;
    wait_for_status(&running.base, StatusCode::NOT_FOUND).await?;
    let queued = send(
        &running.base,
        Method::GET,
        "/",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;
    assert_eq!(
        queued.status,
        StatusCode::TOO_MANY_REQUESTS,
        "the second call is refused as client_busy (429), as it would be without the reload"
    );
    assert_eq!(
        decider.calls(),
        1,
        "the second call never reached the backend"
    );

    decider.release(1);
    assert_eq!(in_flight.await??.status, StatusCode::OK);
    running.stop().await
}

#[tokio::test]
async fn a_reload_keeps_the_decision_slots_of_a_call_in_flight() -> TestResult {
    let upstream = Upstream::start().await?;
    let decider = GatedDecider::start().await?;
    let file = temp_file("decision-slots.conf")?;
    write(
        &file,
        &one_slot_config(&decider.decide_url(), &upstream.url(), 421, true),
    )?;
    let running = Running::start(&file).await?;
    let base = running.base.clone();
    let in_flight = tokio::spawn(async move {
        send(
            &base,
            Method::GET,
            "/",
            "example.com",
            &[("x-real-ip", "203.0.113.1")],
            Bytes::new(),
        )
        .await
    });
    wait_for_calls(&decider, 1).await?;

    // Same file: the one decision slot is still taken, so another client's call is refused.
    write(
        &file,
        &one_slot_config(&decider.decide_url(), &upstream.url(), 404, true),
    )?;
    running.request_reload().await?;
    wait_for_status(&running.base, StatusCode::NOT_FOUND).await?;
    let queued = send(
        &running.base,
        Method::GET,
        "/",
        "example.com",
        &[("x-real-ip", "203.0.113.2")],
        Bytes::new(),
    )
    .await?;
    assert_eq!(
        queued.status,
        StatusCode::FORBIDDEN,
        "the second client is refused as busy, as it would be without the reload"
    );
    assert_eq!(
        decider.calls(),
        1,
        "the second call never reached the backend"
    );

    decider.release(1);
    assert_eq!(in_flight.await??.status, StatusCode::OK);
    running.stop().await
}

/// A configuration with the given decision concurrency limits, and clients told apart by `X-Real-IP`.
fn concurrency_config(
    decide_url: &str,
    upstream: &str,
    status: u16,
    total: usize,
    per_client: usize,
) -> String {
    config(decide_url, upstream, status, "on_rate_limit block;")
        .replace(
            "inspect_body 512;",
            &format!(
                "inspect_body 512;\n    max_concurrency {total};\n    max_concurrency_per_client {per_client};"
            ),
        )
        .replace(
            "default_status",
            "real_ip_from 127.0.0.0/8;\nreal_ip_header x-real-ip;\n\ndefault_status",
        )
}

#[tokio::test]
async fn a_reload_that_raises_max_concurrency_lets_another_client_call_the_backend() -> TestResult {
    let upstream = Upstream::start().await?;
    let decider = GatedDecider::start().await?;
    let file = temp_file("raise-concurrency.conf")?;
    write(
        &file,
        &concurrency_config(&decider.decide_url(), &upstream.url(), 421, 1, 1),
    )?;
    let running = Running::start(&file).await?;
    let base = running.base.clone();
    let first = tokio::spawn(async move {
        send(
            &base,
            Method::GET,
            "/",
            "example.com",
            &[("x-real-ip", "203.0.113.1")],
            Bytes::new(),
        )
        .await
    });
    wait_for_calls(&decider, 1).await?;

    write(
        &file,
        &concurrency_config(&decider.decide_url(), &upstream.url(), 404, 2, 1),
    )?;
    running.request_reload().await?;
    wait_for_status(&running.base, StatusCode::NOT_FOUND).await?;
    let base = running.base.clone();
    let second = tokio::spawn(async move {
        send(
            &base,
            Method::GET,
            "/",
            "example.com",
            &[("x-real-ip", "203.0.113.2")],
            Bytes::new(),
        )
        .await
    });
    wait_for_calls(&decider, 2).await?;

    decider.release(2);
    assert_eq!(first.await??.status, StatusCode::OK);
    assert_eq!(second.await??.status, StatusCode::OK);
    running.stop().await
}

#[tokio::test]
async fn a_reload_that_raises_max_concurrency_per_client_lets_the_same_client_call_again()
-> TestResult {
    let upstream = Upstream::start().await?;
    let decider = GatedDecider::start().await?;
    let file = temp_file("raise-per-client.conf")?;
    write(
        &file,
        &concurrency_config(&decider.decide_url(), &upstream.url(), 421, 4, 1),
    )?;
    let running = Running::start(&file).await?;
    let base = running.base.clone();
    let first = tokio::spawn(async move {
        send(
            &base,
            Method::GET,
            "/",
            "example.com",
            &[("x-real-ip", "203.0.113.1")],
            Bytes::new(),
        )
        .await
    });
    wait_for_calls(&decider, 1).await?;

    write(
        &file,
        &concurrency_config(&decider.decide_url(), &upstream.url(), 404, 4, 2),
    )?;
    running.request_reload().await?;
    wait_for_status(&running.base, StatusCode::NOT_FOUND).await?;
    let base = running.base.clone();
    let second = tokio::spawn(async move {
        send(
            &base,
            Method::GET,
            "/",
            "example.com",
            &[("x-real-ip", "203.0.113.1")],
            Bytes::new(),
        )
        .await
    });
    wait_for_calls(&decider, 2).await?;

    decider.release(2);
    assert_eq!(first.await??.status, StatusCode::OK);
    assert_eq!(second.await??.status, StatusCode::OK);
    running.stop().await
}
