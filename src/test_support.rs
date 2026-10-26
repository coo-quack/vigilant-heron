//! Helpers shared by the unit tests.

use crate::config::{Config, SiteConfig};
use crate::error::ConfigError;

/// Builds one site from `site_fields`, written as configuration directives.
///
/// The defaults are `mode enforce;` and `action block;`, and each one is left
/// out when `site_fields` already sets that directive.
pub(crate) fn site(site_fields: &str) -> Result<SiteConfig, ConfigError> {
    let sets = |name: &str| {
        site_fields
            .lines()
            .any(|line| line.trim_start().starts_with(name))
    };
    let mode = if sets("mode ") { "" } else { "mode enforce;" };
    let action = if sets("action ") { "" } else { "action block;" };
    let input = format!(
        r"
listen 127.0.0.1:8080;

client_max_body_size 10m;
decision {{
    backend http;
    url http://stub-decider:9000/decide;
    timeout 150ms;
    inspect_body 8k;
}}

default_status 421;

site example.com {{
    upstream http://upstream:80;
    {mode}
    {action}
    block_threshold 0.9;
    instruction_threshold 0.5;
    {site_fields}
}}
"
    );
    let config = Config::parse_str(&input, "test.conf")?;
    config
        .sites
        .into_iter()
        .next()
        .ok_or_else(|| ConfigError::Invalid {
            file: "test.conf".to_owned(),
            line: 1,
            message: "no site in the test fixture".to_owned(),
        })
}
