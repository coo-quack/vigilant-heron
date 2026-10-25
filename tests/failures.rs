//! Integration tests for the failure settings and the rule-first guarantee.
//!
//! The fake System One endpoint answers 429 on paths containing `ratelimited`,
//! 500 on `servererror`, and holds the answer for three seconds on `slowanswer`.

mod common;

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use bytes::Bytes;
use common::system_one::{FakeSpec, FakeSystemOne, start_fake};
use common::{BoxError, Reply, TestResult, Upstream, closed_port_url, send, start_proxy_config};
use http::{Method, StatusCode};
use rstest::rstest;
use vigilant_heron::Config;

const JEV_PATH: &str = "/v1/systemone";
const TOKEN_ENV: &str = "TEST_JEV_TOKEN";
const GOOD_TOKEN: &str = "test-token";

/// One site configuration for the failure tests.
struct Setup {
    decide_url: String,
    upstream_url: String,
    on_rate_limit: &'static str,
    on_decision_error: &'static str,
    redirect: bool,
    max_concurrency: usize,
    queue_timeout_ms: u64,
    timeout_ms: u64,
    /// When false, the configuration omits the two failure directives and uses their defaults.
    explicit_failures: bool,
    /// Per-client cap on decision calls, when set.
    per_client: Option<usize>,
    /// Access log file, when set (JSON lines).
    log: Option<std::path::PathBuf>,
}

impl Setup {
    fn new(decide_url: String, upstream_url: String) -> Self {
        Self {
            decide_url,
            upstream_url,
            on_rate_limit: "allow",
            on_decision_error: "allow",
            redirect: false,
            max_concurrency: 64,
            queue_timeout_ms: 0,
            timeout_ms: 2000,
            explicit_failures: true,
            per_client: None,
            log: None,
        }
    }

    fn config(&self) -> Result<Config, BoxError> {
        let action = if self.redirect {
            "action redirect https://example.com/blocked;"
        } else {
            "action block;"
        };
        let access = self.log.as_ref().map_or(String::new(), |path| {
            format!("access_log \"{}\" json;\n", path.display())
        });
        let per_client = self.per_client.map_or(String::new(), |n| {
            format!("    max_concurrency_per_client {n};\n")
        });
        let text = format!(
            r#"
listen 127.0.0.1:0;
{access}request_id_header x-request-id;
real_ip_from 127.0.0.0/8;
real_ip_header x-real-ip;

client_max_body_size 1024;
decision {{
    backend jev;
    model jev-latest;
    url "{url}";
    api_token_env "{TOKEN_ENV}";
    timeout {timeout}ms;
    max_concurrency {concurrency};
{per_client}    queue_timeout {queue}ms;
    inspect_body 512;
}}

default_status 421;

site example.com {{
    upstream "{upstream}";
    mode enforce;
    {action}
    block_threshold 0.9;
    instruction_threshold 0.5;
    deny_path /.env;
    fail_closed_path /wp-login.php;
    {failure_lines}
}}
"#,
            url = self.decide_url,
            timeout = self.timeout_ms,
            concurrency = self.max_concurrency,
            per_client = per_client,
            access = access,
            queue = self.queue_timeout_ms,
            upstream = self.upstream_url,
            failure_lines = if self.explicit_failures {
                format!(
                    "on_rate_limit {};\n    on_decision_error {};",
                    self.on_rate_limit, self.on_decision_error
                )
            } else {
                String::new()
            },
        );
        let token = GOOD_TOKEN;
        Ok(Config::parse_str_with_lookup(
            &text,
            "test.conf",
            move |name| (name == TOKEN_ENV).then(|| token.to_owned()),
        )?)
    }
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

async fn get(base: &str, path: &str) -> Result<Reply, BoxError> {
    send(base, Method::GET, path, "example.com", &[], Bytes::new()).await
}

#[rstest]
#[case::rate_limit_allowed("/articles/ratelimited", "allow", "block", 200)]
#[case::rate_limit_blocked("/articles/ratelimited", "block", "allow", 403)]
#[case::server_error_allowed("/articles/servererror", "block", "allow", 200)]
#[case::server_error_blocked("/articles/servererror", "allow", "block", 403)]
#[tokio::test]
async fn each_failure_group_follows_its_own_setting(
    #[case] path: &str,
    #[case] on_rate_limit: &'static str,
    #[case] on_decision_error: &'static str,
    #[case] expected: u16,
) -> TestResult {
    let fake = start_jev_fake().await?;
    let upstream = Upstream::start().await?;
    let mut setup = Setup::new(fake.url.clone(), upstream.url());
    setup.on_rate_limit = on_rate_limit;
    setup.on_decision_error = on_decision_error;
    let proxy = start_proxy_config(setup.config()?).await?;

    let reply = get(&proxy.base(), path).await?;

    assert_eq!(reply.status.as_u16(), expected);
    proxy.stop().await
}

#[rstest]
#[case::rate_limit("/wp-login.php/ratelimited")]
#[case::server_error("/wp-login.php/servererror")]
#[tokio::test]
async fn fail_closed_path_blocks_whatever_the_failure_settings(#[case] path: &str) -> TestResult {
    let fake = start_jev_fake().await?;
    let upstream = Upstream::start().await?;
    let mut setup = Setup::new(fake.url.clone(), upstream.url());
    setup.on_rate_limit = "allow";
    setup.on_decision_error = "allow";
    let proxy = start_proxy_config(setup.config()?).await?;

    let reply = send(
        &proxy.base(),
        Method::POST,
        path,
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    proxy.stop().await
}

/// The backend states in which a deny rule must still block.
#[derive(Debug, Clone, Copy)]
enum BackendState {
    RateLimited,
    ServerError,
    Unreachable,
    Saturated,
}

#[rstest]
#[case::rate_limited_block(BackendState::RateLimited, false, 403)]
#[case::rate_limited_redirect(BackendState::RateLimited, true, 302)]
#[case::server_error_block(BackendState::ServerError, false, 403)]
#[case::server_error_redirect(BackendState::ServerError, true, 302)]
#[case::unreachable_block(BackendState::Unreachable, false, 403)]
#[case::unreachable_redirect(BackendState::Unreachable, true, 302)]
#[case::saturated_block(BackendState::Saturated, false, 403)]
#[case::saturated_redirect(BackendState::Saturated, true, 302)]
#[tokio::test]
async fn deny_rule_blocks_with_zero_backend_calls_under_allow_settings(
    #[case] state: BackendState,
    #[case] redirect: bool,
    #[case] expected: u16,
) -> TestResult {
    let fake = start_jev_fake().await?;
    let upstream = Upstream::start().await?;
    let decide_url = match state {
        BackendState::Unreachable => format!("{}{JEV_PATH}", closed_port_url().await?),
        _ => fake.url.clone(),
    };
    let mut setup = Setup::new(decide_url, upstream.url());
    setup.on_rate_limit = "allow";
    setup.on_decision_error = "allow";
    setup.redirect = redirect;
    if matches!(state, BackendState::Saturated) {
        // One slot, held by a request that the fake answers only after the timeout.
        setup.max_concurrency = 1;
        setup.timeout_ms = 1000;
    }
    let proxy = start_proxy_config(setup.config()?).await?;
    let base = proxy.base();

    let holder = if matches!(state, BackendState::Saturated) {
        let holder_base = base.clone();
        let task = tokio::spawn(async move { get(&holder_base, "/articles/slowanswer").await });
        // Wait until the holder has reached the backend, so the slot is really taken.
        let deadline = Instant::now() + Duration::from_secs(10);
        while fake.calls.load(Ordering::SeqCst) == 0 {
            if Instant::now() > deadline {
                return Err("the holding request never reached the backend".into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Some(task)
    } else {
        None
    };
    let path = match state {
        BackendState::RateLimited => "/.env/ratelimited",
        BackendState::ServerError => "/.env/servererror",
        BackendState::Unreachable => "/.env",
        BackendState::Saturated => "/.env/articles",
    };
    let calls_before = fake.calls.load(Ordering::SeqCst);
    let reply = get(&base, path).await?;
    let calls_after = fake.calls.load(Ordering::SeqCst);

    assert_eq!(reply.status.as_u16(), expected);
    assert_eq!(
        calls_before, calls_after,
        "a deny rule must not reach the backend"
    );
    if let Some(task) = holder {
        task.await??;
    }
    proxy.stop().await
}

/// Waits until the fake backend has received a request, so a slot is really held.
async fn wait_until_backend_busy(fake: &FakeSystemOne) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(10);
    while fake.calls.load(Ordering::SeqCst) == 0 {
        if Instant::now() > deadline {
            return Err("the holding request never reached the backend".into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Ok(())
}

/// A request that finds no free slot is `backend_busy`, which is a rate limit. The
/// holder's own timeout is a decision error. Each uses its own setting, so the
/// two settings are set to opposite values to show which one applies.
#[rstest]
#[case::no_queue_allow(0, "allow", 200, 403)]
#[case::no_queue_block(0, "block", 403, 200)]
#[case::expired_queue_allow(50, "allow", 200, 403)]
#[case::expired_queue_block(50, "block", 403, 200)]
#[tokio::test]
async fn saturated_request_is_a_rate_limit_and_follows_on_rate_limit(
    #[case] queue_ms: u64,
    #[case] rate_setting: &'static str,
    #[case] queued_expected: u16,
    #[case] holder_expected: u16,
) -> TestResult {
    let fake = start_jev_fake().await?;
    let upstream = Upstream::start().await?;
    let error_setting = if rate_setting == "allow" {
        "block"
    } else {
        "allow"
    };
    let mut setup = Setup::new(fake.url.clone(), upstream.url());
    setup.max_concurrency = 1;
    setup.queue_timeout_ms = queue_ms;
    setup.timeout_ms = 300;
    setup.on_rate_limit = rate_setting;
    setup.on_decision_error = error_setting;
    let proxy = start_proxy_config(setup.config()?).await?;
    let base = proxy.base();

    // The holder takes the only slot and is answered only after the timeout.
    let holder_base = base.clone();
    let holder = tokio::spawn(async move { get(&holder_base, "/articles/slowanswer").await });
    wait_until_backend_busy(&fake).await?;
    let queued = get(&base, "/articles/queued").await?;
    let holder = holder.await??;

    assert_eq!(
        queued.status.as_u16(),
        queued_expected,
        "saturation follows on_rate_limit"
    );
    assert_eq!(
        holder.status.as_u16(),
        holder_expected,
        "the holder's timeout follows on_decision_error"
    );
    proxy.stop().await
}

/// With no failure directives, a saturated backend blocks an ordinary path.
#[tokio::test]
async fn saturated_backend_allows_an_ordinary_path_by_default() -> TestResult {
    let fake = start_jev_fake().await?;
    let upstream = Upstream::start().await?;
    let mut setup = Setup::new(fake.url.clone(), upstream.url());
    setup.explicit_failures = false;
    setup.max_concurrency = 1;
    setup.timeout_ms = 1000;
    let proxy = start_proxy_config(setup.config()?).await?;
    let base = proxy.base();

    let holder_base = base.clone();
    let holder = tokio::spawn(async move { get(&holder_base, "/articles/slowanswer").await });
    wait_until_backend_busy(&fake).await?;
    let queued = get(&base, "/articles/queued").await?;
    holder.await??;

    assert_eq!(
        queued.status.as_u16(),
        200,
        "the default on_rate_limit is allow"
    );
    proxy.stop().await
}

/// With no failure directives, an unreachable backend blocks an ordinary path.
#[tokio::test]
async fn unreachable_backend_allows_an_ordinary_path_by_default() -> TestResult {
    let upstream = Upstream::start().await?;
    let decide_url = format!("{}{JEV_PATH}", closed_port_url().await?);
    let mut setup = Setup::new(decide_url, upstream.url());
    setup.explicit_failures = false;
    let proxy = start_proxy_config(setup.config()?).await?;

    let reply = get(&proxy.base(), "/articles/normal").await?;

    assert_eq!(
        reply.status.as_u16(),
        200,
        "the default on_decision_error is allow"
    );
    proxy.stop().await
}

/// A request that gets a slot within the queue window is judged normally.
#[tokio::test]
async fn request_that_gets_a_slot_within_the_queue_window_is_judged() -> TestResult {
    let fake = start_jev_fake().await?;
    let upstream = Upstream::start().await?;
    let mut setup = Setup::new(fake.url.clone(), upstream.url());
    setup.max_concurrency = 1;
    setup.queue_timeout_ms = 1500;
    setup.timeout_ms = 2000;
    setup.on_rate_limit = "block";
    let proxy = start_proxy_config(setup.config()?).await?;
    let base = proxy.base();

    // The first request is answered 429 at once, so the second gets the slot well inside the window.
    // The two come from different clients: one client may not wait for a slot beyond its share.
    let (first, second) = tokio::join!(
        get_as(&base, "/articles/ratelimited", "203.0.113.1", "queue-first"),
        get_as(&base, "/articles/normal", "203.0.113.2", "queue-second"),
    );

    assert_eq!(
        first?.status.as_u16(),
        403,
        "the rate-limited request follows on_rate_limit"
    );
    assert_eq!(
        second?.status.as_u16(),
        200,
        "the queued request is judged normally"
    );
    assert_eq!(
        fake.calls.load(Ordering::SeqCst),
        2,
        "both requests reached the backend"
    );
    proxy.stop().await
}

/// Sends a GET as the client `address` (through the trusted `X-Real-IP` header), with a request id.
async fn get_as(base: &str, path: &str, address: &str, id: &str) -> Result<Reply, BoxError> {
    send(
        base,
        Method::GET,
        path,
        "example.com",
        &[("x-real-ip", address), ("x-request-id", id)],
        Bytes::new(),
    )
    .await
}

/// The access-log line of `request_id`, parsed as JSON once it has been written.
async fn wait_for_access_line(
    path: &std::path::Path,
    request_id: &str,
) -> Result<serde_json::Value, BoxError> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        for line in text.lines() {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(line)
                && value.get("request_id").and_then(serde_json::Value::as_str) == Some(request_id)
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

/// One client holds its per-client share of the backend while it floods; another client
/// must still be judged by the model, and the flooder's excess must follow `on_rate_limit`.
#[rstest]
#[case::allow_excess("allow", 200)]
#[case::block_excess("block", 403)]
#[tokio::test]
async fn one_client_flooding_cannot_push_another_client_into_busy(
    #[case] on_rate_limit: &'static str,
    #[case] excess_expected: u16,
) -> TestResult {
    let fake = start_jev_fake().await?;
    let upstream = Upstream::start().await?;
    let log = std::env::temp_dir().join(format!(
        "vh-failures-client-{}-{on_rate_limit}.log",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&log);
    let mut setup = Setup::new(fake.url.clone(), upstream.url());
    // Four global slots, of which the flooder may hold one.
    setup.max_concurrency = 4;
    setup.per_client = Some(1);
    setup.timeout_ms = 1000;
    setup.on_rate_limit = on_rate_limit;
    setup.on_decision_error = "allow";
    setup.log = Some(log.clone());
    let proxy = start_proxy_config(setup.config()?).await?;
    let base = proxy.base();

    // The flooder's first call holds its one per-client slot until the timeout.
    let holder_base = base.clone();
    let holder = tokio::spawn(async move {
        get_as(
            &holder_base,
            "/articles/slowanswer",
            "203.0.113.1",
            "flood-holder",
        )
        .await
    });
    wait_until_backend_busy(&fake).await?;

    // The same client again: refused at once, without reaching the backend.
    let calls_before_excess = fake.calls.load(Ordering::SeqCst);
    let excess = get_as(&base, "/articles/normal", "203.0.113.1", "flood-excess").await?;
    assert_eq!(
        fake.calls.load(Ordering::SeqCst),
        calls_before_excess,
        "the excess of a client over its share does not reach the backend"
    );
    assert_eq!(
        excess.status.as_u16(),
        excess_expected,
        "the excess follows on_rate_limit"
    );
    let excess_line = wait_for_access_line(&log, "flood-excess").await?;
    assert_eq!(excess_line["decision_error"], "client_busy");

    // Another client is judged by the model while the flooder holds its share.
    let calls_before_other = fake.calls.load(Ordering::SeqCst);
    let other = get_as(&base, "/articles/normal", "203.0.113.2", "other-client").await?;
    assert_eq!(other.status.as_u16(), 200);
    assert_eq!(
        fake.calls.load(Ordering::SeqCst),
        calls_before_other + 1,
        "the other client reached the model"
    );
    let other_line = wait_for_access_line(&log, "other-client").await?;
    assert_eq!(other_line["decision_error"], "");
    assert_eq!(other_line["reason"], "below_threshold");

    holder.await??;
    proxy.stop().await
}
