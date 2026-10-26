//! Benchmarks of the request hot path, through the public API only.
//!
//! Three groups are measured:
//!
//! - `check_request`: the `test-request` check of one raw request against a
//!   small configuration with the HTTP decision backend and one skip rule,
//!   loaded once. Four requests cover the paths through the screening: a plain
//!   page that no rule decides, a page that a skip rule forwards, a long request
//!   that goes through every built-in rule without a match, and a request that a
//!   built-in rule blocks.
//! - `suggest_skip_rules`: learning skip-rule candidates from 10,000 json access
//!   log lines held in memory.
//! - `config_load`: parsing and validating `examples/vigilant-heron.conf` with a
//!   fixed token lookup, so no environment variable is needed.
//!
//! Run with `cargo bench --bench hot_path`. The CI job runs `-- --test`, which
//! runs each benchmark once and does not measure time.

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use vigilant_heron::{Config, Outcome, SuggestOptions, check_request_with, suggest_skip_rules};

/// The sample configuration: one site, the HTTP decision backend (never called by
/// `check_request`, so no key or server is needed), and a skip rule for `/?p=123`.
/// The built-in rules are on by default.
const SAMPLE_CONFIG: &str = r#"
listen 127.0.0.1:8080;
decision {
    backend http;
    url http://127.0.0.1:9/decide;
}
rule bench-page-skip {
    description "bench: forward the numbered page without the model";
    action skip;
    path = /;
    query ~* "^p=[0-9]+$";
}
site example.com {
    upstream http://127.0.0.1:9;
}
"#;

/// The client address of the sample requests.
const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// The number of synthetic json access log lines.
const LOG_LINES: usize = 10_000;

/// Writes the sample configuration into the bench temp directory.
///
/// Cargo sets `CARGO_TARGET_TMPDIR` for benchmarks, so no system temp path is used.
fn write_sample_config() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let path = dir.join("hot_path-router.conf");
    assert!(
        std::fs::create_dir_all(&dir).is_ok() && std::fs::write(&path, SAMPLE_CONFIG).is_ok(),
        "cannot write the sample configuration to {}",
        path.display()
    );
    path
}

/// A raw HTTP/1.1 request with the given request line and headers, and no body.
fn raw_request(target: &str, headers: &[(String, String)]) -> Vec<u8> {
    let mut text = format!("GET {target} HTTP/1.1\r\nHost: example.com\r\n");
    for (name, value) in headers {
        let _ = write!(text, "{name}: {value}\r\n");
    }
    text.push_str("\r\n");
    text.into_bytes()
}

/// A request with a long query and many headers, which no built-in rule matches.
fn long_request() -> Vec<u8> {
    let query: Vec<String> = (0..40)
        .map(|i| format!("field{i}=value-{i}-lorem-ipsum-dolor-sit-amet"))
        .collect();
    let target = format!("/search?{}", query.join("&"));
    let mut headers = vec![
        ("User-Agent".to_owned(), "Mozilla/5.0 (bench)".to_owned()),
        (
            "Accept".to_owned(),
            "text/html,application/xhtml+xml".to_owned(),
        ),
        ("Accept-Language".to_owned(), "ja,en;q=0.8".to_owned()),
        ("Referer".to_owned(), "https://example.com/".to_owned()),
    ];
    for i in 0..40 {
        headers.push((format!("X-Bench-{i}"), format!("header value number {i}")));
    }
    raw_request(&target, &headers)
}

/// Checks the sample request once and asserts the outcome, so a broken fixture
/// fails the run before any timing starts.
fn assert_outcome(config: &Config, raw: &[u8], expected: &Outcome) {
    let outcome = check_request_with(config, raw, CLIENT).map(|check| check.outcome);
    assert_eq!(
        outcome.ok().as_ref(),
        Some(expected),
        "sample request outcome"
    );
}

fn bench_check_request(c: &mut Criterion) {
    let loaded = Config::load(&write_sample_config());
    assert!(
        loaded.is_ok(),
        "the sample configuration does not load: {:?}",
        loaded.as_ref().err()
    );
    let Ok(config) = loaded else {
        return;
    };

    let plain = raw_request("/", &[]);
    let skipped = raw_request("/?p=123", &[]);
    let long = long_request();
    let blocked = raw_request("/?q=1%20union%20select%201", &[]);

    assert_outcome(&config, &plain, &Outcome::BackendDecides);
    assert_outcome(&config, &skipped, &Outcome::Forwarded);
    assert_outcome(&config, &long, &Outcome::BackendDecides);
    assert_outcome(&config, &blocked, &Outcome::Blocked(403));

    let mut group = c.benchmark_group("check_request");
    group.bench_function("plain_page", |b| {
        b.iter(|| black_box(check_request_with(&config, black_box(&plain), CLIENT)));
    });
    group.bench_function("skip_rule_page", |b| {
        b.iter(|| black_box(check_request_with(&config, black_box(&skipped), CLIENT)));
    });
    group.bench_function("long_request_all_builtin_rules", |b| {
        b.iter(|| black_box(check_request_with(&config, black_box(&long), CLIENT)));
    });
    group.bench_function("builtin_rule_block", |b| {
        b.iter(|| black_box(check_request_with(&config, black_box(&blocked), CLIENT)));
    });
    group.finish();
}

/// Builds `LOG_LINES` json access log lines in the format the access log writes.
fn synthetic_log() -> String {
    let mut text = String::new();
    for i in 0..LOG_LINES {
        let line = format!(
            "{{\"time\":\"2026-01-{:02}T12:00:00Z\",\"client_ip\":\"192.0.2.{}\",\"site\":\"example.com\",\"method\":\"GET\",\"path\":\"/{}\",\"query_shape\":\"p=<num>\",\"action\":\"allow\",\"reason\":\"model\",\"would_have\":\"\",\"attack\":\"0.0{}\",\"ai_instruction\":\"0.0{}\"}}\n",
            1 + i % 28,
            1 + i % 200,
            ["", "news", "item"].get(i % 3).copied().unwrap_or_default(),
            i % 9,
            i % 7,
        );
        text.push_str(&line);
    }
    text
}

fn bench_suggest_skip_rules(c: &mut Criterion) {
    let log = synthetic_log();
    let options = SuggestOptions::default();
    c.bench_function("suggest_skip_rules/10k_lines", |b| {
        b.iter(|| black_box(suggest_skip_rules(black_box(log.as_bytes()), &options)));
    });
}

/// The shipped sample configuration, embedded so the bench does not depend on the
/// working directory. Its `api_token_env` reads a variable that is not set in CI, so
/// the token lookup is a fixed value and the bench measures parsing and validation.
const EXAMPLE_CONFIG: &str = include_str!("../examples/vigilant-heron.conf");

fn bench_config_load(c: &mut Criterion) {
    const ORIGIN: &str = "examples/vigilant-heron.conf";
    let token = |_: &str| Some("bench-token".to_owned());
    assert!(
        Config::parse_str_with_lookup(EXAMPLE_CONFIG, ORIGIN, token).is_ok(),
        "the sample configuration must load"
    );
    c.bench_function("config_load/example", |b| {
        b.iter(|| {
            black_box(Config::parse_str_with_lookup(
                black_box(EXAMPLE_CONFIG),
                ORIGIN,
                token,
            ))
        });
    });
}

criterion_group!(
    benches,
    bench_check_request,
    bench_suggest_skip_rules,
    bench_config_load
);
criterion_main!(benches);
