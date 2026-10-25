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
            timeout_ms: 2000,
        }
    }

    fn config(&self) -> Result<Config, BoxError> {
        let action = if self.redirect {
            "action = \"redirect\"\nredirect_to = \"https://example.com/blocked\""
        } else {
            "action = \"block\""
        };
        let text = format!(
            r#"
listen = "127.0.0.1:0"

[decision]
backend = "jev"
model = "jev-latest"
url = "{url}"
api_token_env = "{TOKEN_ENV}"
timeout_ms = {timeout}
max_concurrency = {concurrency}
inspect_body_bytes = 512
max_body_bytes = 1024

[default]
status = 421

[[sites]]
hosts = ["example.com"]
upstream = "{upstream}"
mode = "enforce"
{action}
block_threshold = 0.9
instruction_threshold = 0.5
deny_paths = ["/.env"]
fail_closed_paths = ["/wp-login.php"]
on_rate_limit = "{rate}"
on_decision_error = "{error}"
"#,
            url = self.decide_url,
            timeout = self.timeout_ms,
            concurrency = self.max_concurrency,
            upstream = self.upstream_url,
            rate = self.on_rate_limit,
            error = self.on_decision_error,
        );
        let token = GOOD_TOKEN;
        Ok(Config::from_toml_str_with_lookup(&text, move |name| {
            (name == TOKEN_ENV).then(|| token.to_owned())
        })?)
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

#[rstest]
#[case::allow(true, 200)]
#[case::block(false, 403)]
#[tokio::test]
async fn queued_request_with_one_slot_fails_over_within_the_timeout(
    #[case] allow: bool,
    #[case] expected: u16,
) -> TestResult {
    let fake = start_jev_fake().await?;
    let upstream = Upstream::start().await?;
    let setting = if allow { "allow" } else { "block" };
    let mut setup = Setup::new(fake.url.clone(), upstream.url());
    setup.max_concurrency = 1;
    setup.timeout_ms = 300;
    setup.on_rate_limit = setting;
    setup.on_decision_error = setting;
    let proxy = start_proxy_config(setup.config()?).await?;
    let base = proxy.base();

    let started = Instant::now();
    let (holder, queued) = tokio::join!(
        get(&base, "/articles/slowanswer"),
        get(&base, "/articles/queued"),
    );
    let elapsed = started.elapsed();

    assert_eq!(holder?.status.as_u16(), expected);
    assert_eq!(queued?.status.as_u16(), expected);
    assert!(
        elapsed < Duration::from_millis(1500),
        "both requests must finish within the budget plus slack, took {elapsed:?}"
    );
    proxy.stop().await
}
