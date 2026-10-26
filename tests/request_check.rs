//! `test-request` agrees with the running router: each sample request gets the same
//! outcome, reason and rule from `check_request` as from the in-process proxy, as the
//! access log records it. A request that no check decides reaches the stub backend from
//! the proxy and never from the check.

mod common;

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use bytes::Bytes;
use common::{BoxError, StubDecider, TestResult, Upstream, send, start_proxy};
use http::Method;
use serde_json::Value;
use vigilant_heron::{Outcome, check_request};

/// The client address the proxy sees: the test connects from loopback, and no `real_ip` is set.
const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// One sample request and what the router should decide for it.
struct Case {
    label: &'static str,
    method: Method,
    target: &'static str,
    host: &'static str,
    /// Extra headers, besides `Host` and the request id.
    headers: &'static [(&'static str, &'static str)],
    /// Length of the body, filled with `a`.
    body_len: usize,
    /// The outcome the check must report.
    expect: Outcome,
    /// The reason the check must report, `None` when the backend decides.
    reason: Option<&'static str>,
    /// The rule id the check must report, empty for none.
    rule: &'static str,
}

/// Writes the request in the form `test-request` reads, with the same Host, headers and body.
fn raw_request(case: &Case, request_id: &str) -> Vec<u8> {
    let mut text = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nx-request-id: {request_id}\r\n",
        case.method, case.target, case.host
    );
    for (name, value) in case.headers {
        let _ = write!(text, "{name}: {value}\r\n");
    }
    if case.body_len > 0 {
        let _ = write!(text, "content-length: {}\r\n", case.body_len);
    }
    text.push_str("\r\n");
    let mut raw = text.into_bytes();
    raw.extend(std::iter::repeat_n(b'a', case.body_len));
    raw
}

/// Waits until the access log has a line for `request_id`, and returns it.
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

fn cases() -> Vec<Case> {
    vec![
        Case {
            label: "enforce site, built-in rule blocks",
            method: Method::GET,
            target: "/items?id=1%20UNION%20SELECT%20password%20FROM%20users",
            host: "enforce.test",
            headers: &[],
            body_len: 0,
            expect: Outcome::Blocked(403),
            reason: Some("rule"),
            rule: "vh-sqli-001",
        },
        Case {
            label: "enforce site, deny_path blocks without a rule id",
            method: Method::GET,
            target: "/xmlrpc.php",
            host: "enforce.test",
            headers: &[],
            body_len: 0,
            expect: Outcome::Blocked(403),
            reason: Some("rule"),
            rule: "",
        },
        Case {
            label: "enforce site, skip rule forwards",
            method: Method::GET,
            target: "/healthz",
            host: "enforce.test",
            headers: &[],
            body_len: 0,
            expect: Outcome::Forwarded,
            reason: Some("skip_rule"),
            rule: "local-health",
        },
        Case {
            label: "enforce site, no rule decides, the backend is asked",
            method: Method::GET,
            target: "/search?q=hello",
            host: "enforce.test",
            headers: &[],
            body_len: 0,
            expect: Outcome::BackendDecides,
            reason: None,
            rule: "",
        },
        Case {
            label: "shadow site, rule would block and the request is forwarded",
            method: Method::GET,
            target: "/items?id=1%20UNION%20SELECT%20password%20FROM%20users",
            host: "shadow.test",
            headers: &[],
            body_len: 0,
            expect: Outcome::Forwarded,
            reason: Some("rule"),
            rule: "vh-sqli-001",
        },
        Case {
            label: "access list denies the client",
            method: Method::GET,
            target: "/",
            host: "denied.test",
            headers: &[],
            body_len: 0,
            expect: Outcome::Blocked(403),
            reason: Some("access_denied"),
            rule: "",
        },
        Case {
            label: "unknown Host gets the default status",
            method: Method::GET,
            target: "/",
            host: "nowhere.test",
            headers: &[],
            body_len: 0,
            expect: Outcome::Rejected(421),
            reason: Some("unknown_host"),
            rule: "",
        },
        Case {
            label: "body over client_max_body_size is refused",
            method: Method::POST,
            target: "/upload",
            host: "enforce.test",
            headers: &[("content-type", "application/octet-stream")],
            body_len: 1500,
            expect: Outcome::Rejected(413),
            reason: Some("body_too_large"),
            rule: "",
        },
    ]
}

/// The configuration of both the check and the proxy: four sites and one top-level skip rule.
fn config_text(log: &str, decide_url: &str, upstream_url: &str) -> String {
    format!(
        r#"
listen 127.0.0.1:0;
request_id_header x-request-id;
access_log "{log}" json;
client_max_body_size 1024;
decision {{
    backend http;
    url "{decide_url}";
    timeout 2000ms;
    inspect_body 512;
}}
default_status 421;

rule local-health {{
    description "health probe";
    action skip;
    path = /healthz;
}}

site enforce.test {{
    upstream "{upstream_url}";
    mode enforce;
    action block;
    block_threshold 0.9;
    instruction_threshold 0.5;
    deny_path /xmlrpc.php;
}}

site shadow.test {{
    upstream "{upstream_url}";
    mode shadow;
    action block;
    block_threshold 0.9;
    instruction_threshold 0.5;
}}

site denied.test {{
    upstream "{upstream_url}";
    mode enforce;
    action block;
    block_threshold 0.9;
    instruction_threshold 0.5;
    deny 127.0.0.1;
}}
"#
    )
}

#[tokio::test]
async fn test_request_agrees_with_the_running_router() -> TestResult {
    let dir = std::env::temp_dir().join(format!("vh-check-agree-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let log = dir.join("access.log");
    let _ = std::fs::remove_file(&log);

    let stub = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let text = config_text(
        &log.display().to_string(),
        &stub.decide_url(),
        &upstream.url(),
    );
    let conf: PathBuf = dir.join("router.conf");
    std::fs::write(&conf, &text)?;
    let proxy = start_proxy(&text).await?;

    for (index, case) in cases().iter().enumerate() {
        let label = case.label;
        let raw = raw_request(case, &format!("agree-{index}"));

        // The check: its outcome, and no call to the backend.
        let before_check = stub.calls();
        let check = check_request(&conf, &raw, CLIENT)?;
        assert_eq!(
            stub.calls(),
            before_check,
            "{label}: the check called the backend"
        );
        assert_eq!(check.outcome, case.expect, "{label}: check outcome");
        assert_eq!(check.reason, case.reason, "{label}: check reason");
        assert_eq!(
            check.rule_id.as_deref().unwrap_or(""),
            case.rule,
            "{label}: check rule"
        );

        // The proxy: the same request, answered through the real pipeline.
        let request_id = format!("agree-{index}");
        let mut header_list: Vec<(&str, &str)> = case.headers.to_vec();
        header_list.push(("x-request-id", request_id.as_str()));
        let body = Bytes::from(vec![b'a'; case.body_len]);
        let before_proxy = stub.calls();
        let reply = send(
            &proxy.base(),
            case.method.clone(),
            case.target,
            case.host,
            &header_list,
            body,
        )
        .await?;
        let line = wait_for_line(&log, &request_id).await?;
        let logged_action = line["action"].as_str().unwrap_or_default();

        match &check.outcome {
            Outcome::Forwarded => assert_eq!(logged_action, "allow", "{label}: proxy action"),
            Outcome::Blocked(status) => {
                assert_eq!(reply.status.as_u16(), *status, "{label}: proxy status");
                assert_eq!(logged_action, "block", "{label}: proxy action");
            }
            Outcome::Redirected => {
                assert_eq!(logged_action, "redirect", "{label}: proxy action");
            }
            Outcome::Rejected(status) => {
                assert_eq!(reply.status.as_u16(), *status, "{label}: proxy status");
                assert_eq!(logged_action, "reject", "{label}: proxy action");
            }
            Outcome::BackendDecides => {
                assert_eq!(
                    stub.calls(),
                    before_proxy + 1,
                    "{label}: proxy backend calls"
                );
                let reason = line["reason"].as_str().unwrap_or_default();
                assert!(
                    reason == "model" || reason == "below_threshold",
                    "{label}: proxy reason {reason}"
                );
            }
        }
        if let Some(reason) = check.reason {
            assert_eq!(
                line["reason"].as_str(),
                Some(reason),
                "{label}: proxy reason"
            );
        }
        assert_eq!(
            line["rule_id"].as_str().unwrap_or_default(),
            case.rule,
            "{label}: proxy rule"
        );
        if let Some(site) = &check.site {
            assert_eq!(line["site"].as_str(), Some(site.as_str()), "{label}: site");
        }
    }

    proxy.stop().await?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
