//! `proxy_set_header` in-process: values with variables, removal, inheritance and replacement.

mod common;

use bytes::Bytes;
use common::{BoxError, StubDecider, TestResult, Upstream, send, start_proxy};
use http::{Method, StatusCode};
use serde_json::Value;

/// A configuration for one site `example.com` with `top_lines` at the top level and `site_lines` in the site.
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

/// Reads one header of the echo, as the upstream received it.
fn received(echo: &Value, name: &str) -> Option<String> {
    echo.get("headers")
        .and_then(|headers| headers.get(name))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

#[tokio::test]
async fn set_header_adds_the_client_address_and_copies_a_client_header() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream.url(),
        "",
        "proxy_set_header X-Real-IP $client_ip;\n    proxy_set_header X-Forwarded-Proto \"$http_x_forwarded_proto\";",
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/hello",
        "example.com",
        &[("x-forwarded-proto", "https")],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::OK);
    let echo = reply.json();
    assert_eq!(received(&echo, "x-real-ip").as_deref(), Some("127.0.0.1"));
    assert_eq!(
        received(&echo, "x-forwarded-proto").as_deref(),
        Some("https")
    );
    proxy.stop().await
}

#[tokio::test]
async fn an_empty_value_removes_a_header_the_client_sent() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream.url(),
        "",
        "proxy_set_header X-Internal \"\";",
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/",
        "example.com",
        &[("x-internal", "secret")],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(received(&reply.json(), "x-internal"), None);
    proxy.stop().await
}

#[tokio::test]
async fn host_can_be_set_to_the_upstream_name() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream.url(),
        "",
        "proxy_set_header Host \"app.internal\";",
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

    assert_eq!(reply.json()["host"], "app.internal");
    proxy.stop().await
}

#[tokio::test]
async fn top_level_operations_are_inherited_by_a_site_without_its_own() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream.url(),
        "proxy_set_header X-Top \"from-top\";",
        "",
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

    assert_eq!(
        received(&reply.json(), "x-top").as_deref(),
        Some("from-top")
    );
    proxy.stop().await
}

#[tokio::test]
async fn a_location_with_operations_replaces_the_site_list() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(
        &stub.decide_url(),
        &upstream.url(),
        "",
        "proxy_set_header X-Site \"site\";\n    location /shop/ {\n        proxy_set_header X-Loc \"location\";\n    }",
    ))
    .await?;

    let shop = send(
        &proxy.base(),
        Method::GET,
        "/shop/item",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;
    let other = send(
        &proxy.base(),
        Method::GET,
        "/other",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;

    let shop = shop.json();
    assert_eq!(received(&shop, "x-loc").as_deref(), Some("location"));
    assert_eq!(received(&shop, "x-site"), None);
    assert_eq!(received(&other.json(), "x-site").as_deref(), Some("site"));
    proxy.stop().await
}

#[tokio::test]
async fn a_bad_operation_fails_to_load_with_its_line() -> Result<(), BoxError> {
    let text = config(
        "http://127.0.0.1:9/decide",
        "http://127.0.0.1:9",
        "",
        "proxy_set_header Connection close;",
    );
    let result = vigilant_heron::Config::parse_str(&text, "headers.conf");
    assert!(
        matches!(&result, Err(error) if error.to_string().contains("headers.conf:") && error.to_string().contains("hop-by-hop")),
        "{result:?}"
    );
    Ok(())
}

#[tokio::test]
async fn a_request_without_a_body_is_forwarded_without_a_content_length() -> TestResult {
    let upstream = Upstream::start().await?;
    let stub = StubDecider::start().await?;
    let proxy = start_proxy(&config(&stub.decide_url(), &upstream.url(), "", "")).await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/forwarded",
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;
    assert_eq!(reply.status, StatusCode::OK);
    // Forwarding keeps the request as the client sent it: no length header is added.
    let echo = reply.json();
    assert_eq!(received(&echo, "content-length"), None);
    assert_eq!(received(&echo, "transfer-encoding"), None);
    proxy.stop().await
}
