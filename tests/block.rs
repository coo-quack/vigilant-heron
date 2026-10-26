//! Block responses in-process: `block_status`, `block_page`, 444, locations and access denials.

mod common;

use bytes::Bytes;
use common::{BoxError, StubBehavior, StubDecider, TestResult, Upstream, send, start_proxy};
use http::{Method, StatusCode};

/// A configuration for one site `example.com` with `site_lines` in its block and `top_lines` at the top level.
fn config(decide_url: &str, upstream_url: &str, top_lines: &str, site_lines: &str) -> String {
    format!(
        r#"
listen 127.0.0.1:0;

decision {{
    backend http;
    url "{decide_url}";
    timeout 2000ms;
    inspect_body 512;
}}

default_status 421;
{top_lines}

site example.com {{
    upstream {upstream_url};
    mode enforce;
    action block;
    block_threshold 0.9;
    instruction_threshold 0.5;
    {site_lines}
}}
"#
    )
}

/// A decision stub that judges every request an attack.
async fn attacking_stub() -> Result<StubDecider, BoxError> {
    let stub = StubDecider::start().await?;
    stub.set_behavior(StubBehavior {
        attack: 0.95,
        ..StubBehavior::default()
    });
    Ok(stub)
}

#[tokio::test]
async fn block_status_replaces_the_403_of_an_attack() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = attacking_stub().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream.url(),
        "",
        "block_status 404;",
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/?q=x",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(reply.text(), "");
    proxy.stop().await
}

#[tokio::test]
async fn block_page_is_served_as_html_with_the_block_status() -> TestResult {
    let dir = std::env::temp_dir().join("vh-block-it-page");
    std::fs::create_dir_all(&dir)?;
    let page = dir.join("blocked.html");
    std::fs::write(&page, "<!doctype html><h1>Blocked</h1>")?;
    let upstream = Upstream::start().await?;
    let stub = attacking_stub().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream.url(),
        "",
        &format!("block_status 403;\n    block_page {};", page.display()),
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/?q=x",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(
        reply
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(reply.text(), "<!doctype html><h1>Blocked</h1>");
    proxy.stop().await
}

#[tokio::test]
async fn top_level_block_settings_are_inherited_by_a_site() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = attacking_stub().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream.url(),
        "block_status 410;",
        "",
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/?q=x",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::GONE);
    proxy.stop().await
}

#[tokio::test]
async fn status_444_closes_the_connection_without_a_response() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = attacking_stub().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream.url(),
        "",
        "block_status 444;",
    ))
    .await?;

    // The client gets no HTTP response: the request fails with the connection closed.
    let result = send(
        &proxy.base(),
        Method::GET,
        "/?q=x",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await;
    assert!(result.is_err(), "expected no response, got a reply");
    // The proxy keeps serving: a benign request on a new connection still succeeds.
    stub.set_behavior(StubBehavior::default());
    let reply = send(
        &proxy.base(),
        Method::GET,
        "/ok",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;
    assert_eq!(reply.status, StatusCode::OK);
    proxy.stop().await
}

#[tokio::test]
async fn location_block_settings_override_the_site_for_its_paths() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = attacking_stub().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream.url(),
        "",
        "block_status 403;\n    location /api/ {\n        block_status 404;\n    }",
    ))
    .await?;

    let api = send(
        &proxy.base(),
        Method::GET,
        "/api/x?q=1",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;
    let other = send(
        &proxy.base(),
        Method::GET,
        "/web?q=1",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;

    assert_eq!(api.status, StatusCode::NOT_FOUND);
    assert_eq!(other.status, StatusCode::FORBIDDEN);
    proxy.stop().await
}

#[tokio::test]
async fn access_list_denial_stays_403_whatever_block_status_says() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream.url(),
        "",
        "block_status 404;\n    deny all;",
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.text(), "Forbidden\n");
    proxy.stop().await
}

#[test]
fn an_invalid_block_status_fails_to_load() {
    let text = config(
        "http://127.0.0.1:9/decide",
        "http://127.0.0.1:9",
        "",
        "block_status 302;",
    );
    let result = vigilant_heron::Config::parse_str(&text, "block.conf");
    assert!(
        matches!(&result, Err(error) if error.to_string().contains("block.conf:")),
        "{result:?}"
    );
}
