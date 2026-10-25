//! Live tests that call Cloudflare Workers AI. They are ignored by default and
//! never run in CI.
//!
//! Set `VH_CLEF_LIVE_URL` to the full `clef-flash` endpoint URL and
//! `CLOUDFLARE_AI_TOKEN` to a token with Workers AI access, then run
//! `cargo test --test clef_live -- --ignored`.
//!
//! The thresholds are 0.5, so a request is blocked when its attack or
//! AI-instruction score reaches 0.5. Clear attacks must be blocked, and plain
//! page loads must pass.

mod common;

use bytes::Bytes;
use common::{BoxError, TestResult, Upstream, send, start_proxy_config};
use http::{Method, StatusCode};
use vigilant_heron::Config;

const URL_ENV: &str = "VH_CLEF_LIVE_URL";
const TOKEN_ENV: &str = "CLOUDFLARE_AI_TOKEN";

/// Returns the live settings, or the reason the test is skipped.
fn live_settings() -> Result<(String, String), &'static str> {
    let url = std::env::var(URL_ENV)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or("VH_CLEF_LIVE_URL is not set")?;
    let token = std::env::var(TOKEN_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or("CLOUDFLARE_AI_TOKEN is not set")?;
    Ok((url, token))
}

async fn live_proxy(
    url: &str,
    token: String,
    upstream_url: &str,
) -> Result<common::Proxy, BoxError> {
    let text = format!(
        r#"
listen 127.0.0.1:0;

client_max_body_size 10485760;
decision {{
    backend clef;
    model clef-flash;
    url "{url}";
    api_token_env "{TOKEN_ENV}";
    timeout 10000ms;
    inspect_body 8192;
}}

default_status 421;

site example.com {{
    upstream "{upstream_url}";
    mode enforce;
    action block;
    block_threshold 0.5;
    instruction_threshold 0.5;
}}
"#
    );
    let config = Config::parse_str_with_lookup(&text, "test.conf", move |name| {
        (name == TOKEN_ENV).then(|| token.clone())
    })?;
    start_proxy_config(config).await
}

async fn status_for(base: &str, path: &str) -> Result<StatusCode, BoxError> {
    Ok(
        send(base, Method::GET, path, "example.com", &[], Bytes::new())
            .await?
            .status,
    )
}

#[tokio::test]
#[ignore = "calls Cloudflare Workers AI; needs VH_CLEF_LIVE_URL and CLOUDFLARE_AI_TOKEN"]
async fn clear_attacks_are_blocked_by_live_clef() -> TestResult {
    let Ok((url, token)) = live_settings() else {
        eprintln!("skipping: set {URL_ENV} and {TOKEN_ENV} to run the live Clef tests");
        return Ok(());
    };
    let upstream = Upstream::start().await?;
    let proxy = live_proxy(&url, token, &upstream.url()).await?;
    let attacks = [
        "/?id=1%27%20or%20%271%27%3D%271",
        "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "/?file=..%2F..%2F..%2Fetc%2Fpasswd",
    ];
    for path in attacks {
        assert_eq!(
            status_for(&proxy.base(), path).await?,
            StatusCode::FORBIDDEN,
            "{path}"
        );
    }
    proxy.stop().await
}

#[tokio::test]
#[ignore = "calls Cloudflare Workers AI; needs VH_CLEF_LIVE_URL and CLOUDFLARE_AI_TOKEN"]
async fn plain_page_loads_pass_live_clef() -> TestResult {
    let Ok((url, token)) = live_settings() else {
        eprintln!("skipping: set {URL_ENV} and {TOKEN_ENV} to run the live Clef tests");
        return Ok(());
    };
    let upstream = Upstream::start().await?;
    let proxy = live_proxy(&url, token, &upstream.url()).await?;
    for path in ["/", "/articles/hello-world", "/about"] {
        assert_eq!(
            status_for(&proxy.base(), path).await?,
            StatusCode::OK,
            "{path}"
        );
    }
    proxy.stop().await
}
