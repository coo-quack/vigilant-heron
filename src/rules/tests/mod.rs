//! Unit tests for the rule parser, the access and rule settings, the built-in
//! signatures, normalization and matching.

mod builtin;
mod matching;
mod opt_in;
mod parser;

use std::sync::Arc;

use proptest::prelude::*;

use super::Rule;
use crate::config::Config;
use crate::error::ConfigError;

/// A configuration with `top` at the top level and `site_lines` inside `example.com`.
fn config(top: &str, site_lines: &str) -> Result<Config, ConfigError> {
    let text = format!(
        "listen 127.0.0.1:8080;\n{top}\n\
         decision {{\n    backend http;\n    url http://stub-decider:9000/decide;\n}}\n\
         default_status 421;\n\
         site example.com {{\n    upstream http://upstream:80;\n{site_lines}}}\n"
    );
    Config::parse_str(&text, "test.conf")
}

fn message(result: Result<Config, ConfigError>) -> String {
    match result {
        Ok(_) => String::new(),
        Err(error) => error.to_string(),
    }
}

fn ids(rules: &[Arc<Rule>]) -> Vec<String> {
    rules.iter().map(|rule| rule.id.to_string()).collect()
}

fn first_site(cfg: &Config) -> Result<&crate::config::SiteConfig, ConfigError> {
    cfg.sites.first().ok_or_else(|| ConfigError::Invalid {
        file: "test.conf".to_owned(),
        line: 1,
        message: "no site".to_owned(),
    })
}

const UA: &[(&str, &str)] = &[("user-agent", "Mozilla/5.0 (Macintosh)")];

fn site_with(rules: &str, site_lines: &str) -> Result<crate::config::SiteConfig, ConfigError> {
    let cfg = config(rules, site_lines)?;
    cfg.sites
        .into_iter()
        .next()
        .ok_or_else(|| ConfigError::Invalid {
            file: "test.conf".to_owned(),
            line: 1,
            message: "no site".to_owned(),
        })
}

const FRAGMENTS: &[&str] = &[
    "%2e",
    "%252e",
    "%2525",
    "+",
    "%00",
    "\0",
    "../",
    "%2f",
    "<script>",
    "javascript:",
    "' or 1=1--",
    "${jndi:",
    "union",
    " select ",
    "%27",
    "%3C",
    "{{7*7}}",
    "php://",
    "169.254.169.254",
    "/etc/passwd",
    "sqlmap",
    "\u{3042}",
    "=",
    "&",
    "?",
    "/",
    "%",
    "a",
    "Z",
    "1",
];

/// Text built from attack-relevant fragments and arbitrary characters.
fn attack_text() -> impl Strategy<Value = String> {
    prop_oneof![
        proptest::collection::vec(proptest::sample::select(FRAGMENTS), 0..16)
            .prop_map(|parts| parts.concat()),
        ".{0,64}",
    ]
}
