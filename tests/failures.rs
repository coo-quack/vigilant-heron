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
        }
    }

    fn config(&self) -> Result<Config, BoxError> {
        let action = if self.redirect {
            "action redirect https://example.com/blocked;"
        } else {
            "action block;"
        };
        let text = format!(
            r#"
listen 127.0.0.1:0;

decision {{
    backend jev;
    model jev-latest;
    url "{url}";
    api_token_env "{TOKEN_ENV}";
    timeout {timeout}ms;
    max_concurrency {concurrency};
    queue_timeout {queue}ms;
    inspect_body 512;
    max_body 1024;
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
    on_rate_limit {rate};
    on_decision_error {error};
}}
"#,
            url = self.decide_url,
            timeout = self.timeout_ms,
            concurrency = self.max_concurrency,
            queue = self.queue_timeout_ms,
            upstream = self.upstream_url,
            rate = self.on_rate_limit,
            error = self.on_decision_error,
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
    let (first, second) = tokio::join!(
        get(&base, "/articles/ratelimited"),
        get(&base, "/articles/normal"),
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
