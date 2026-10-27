//! `suggest-skip-rules` and the configuration agree: the rule the command writes for a
//! learned shape skips exactly that shape when it is loaded and checked with `test-request`.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use serde_json::json;
use vigilant_heron::{Outcome, SuggestOptions, check_request, suggest_skip_rules};

/// The client address of the sample requests.
const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Log lines for 60 judged `GET /` requests with shape `p=<num>`, from 12 clients on 4 days,
/// with low scores and no block.
fn learned_log() -> String {
    (0..60)
        .map(|i| {
            json!({
                "time": format!("2026-01-{:02}T12:00:00Z", 1 + i % 4),
                "client_ip": format!("192.0.2.{}", 1 + i % 12),
                "site": "example.test",
                "method": "GET",
                "path": "/",
                "query_shape": "p=<num>",
                "action": "allow",
                "reason": "model",
                "would_have": "",
                "attack": "0.05",
                "ai_instruction": "0.02",
            })
            .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// A configuration with the learned rule text at the top level.
fn config_with(rule: &str) -> String {
    format!(
        "listen 127.0.0.1:8080;\ndecision {{\n    backend http;\n    url http://127.0.0.1:9/decide;\n}}\n{rule}\nsite example.test {{\n    upstream http://127.0.0.1:9;\n}}\n"
    )
}

/// Writes `text` into a fresh temporary directory named after the test.
fn write_config(name: &str, text: &str) -> Result<PathBuf, std::io::Error> {
    let dir = std::env::temp_dir().join(format!("vh-skip-suggest-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("router.conf");
    std::fs::write(&path, text)?;
    Ok(path)
}

#[test]
fn a_learned_rule_skips_the_learned_shape_and_nothing_else()
-> Result<(), Box<dyn std::error::Error>> {
    let report = suggest_skip_rules(learned_log().as_bytes(), &SuggestOptions::default())?;
    let candidate = report
        .candidates
        .first()
        .ok_or("the learned shape should be a candidate")?;
    let rule = candidate
        .rule
        .as_deref()
        .ok_or("the candidate should have rule text")?;
    assert_eq!(report.candidates.len(), 1);
    assert!(rule.starts_with("rule learned-1 {"), "{rule}");

    let conf = write_config("learned-rule", &config_with(rule))?;

    let learned = check_request(
        &conf,
        b"GET /?p=123 HTTP/1.1\r\nHost: example.test\r\n\r\n",
        CLIENT,
    )?;
    assert_eq!(learned.outcome, Outcome::Forwarded);
    assert_eq!(learned.reason, Some("skip_rule"));
    assert_eq!(learned.rule_id.as_deref(), Some("learned-1"));

    let not_numeric = check_request(
        &conf,
        b"GET /?p=abc HTTP/1.1\r\nHost: example.test\r\n\r\n",
        CLIENT,
    )?;
    assert_ne!(not_numeric.rule_id.as_deref(), Some("learned-1"));
    assert_ne!(not_numeric.reason, Some("skip_rule"));

    let extra_parameter = check_request(
        &conf,
        b"GET /?p=1&x=2 HTTP/1.1\r\nHost: example.test\r\n\r\n",
        CLIENT,
    )?;
    assert_ne!(extra_parameter.rule_id.as_deref(), Some("learned-1"));
    assert_ne!(extra_parameter.reason, Some("skip_rule"));

    let post = check_request(
        &conf,
        b"POST /?p=1 HTTP/1.1\r\nHost: example.test\r\n\r\n",
        CLIENT,
    )?;
    assert_ne!(post.rule_id.as_deref(), Some("learned-1"));
    assert_ne!(post.reason, Some("skip_rule"));
    Ok(())
}
