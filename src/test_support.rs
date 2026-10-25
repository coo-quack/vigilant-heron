//! Helpers shared by the unit tests.

use crate::config::{Config, SiteConfig};
use crate::error::ConfigError;

/// Builds one site whose table is `site_fields` plus defaults.
///
/// The defaults are `mode = "enforce"` and `action = "block"`, and each one is
/// left out when `site_fields` already sets that key.
pub(crate) fn site(site_fields: &str) -> Result<SiteConfig, ConfigError> {
    let mode = if site_fields.contains("mode =") {
        ""
    } else {
        "mode = \"enforce\""
    };
    let action = if site_fields.contains("action =") {
        ""
    } else {
        "action = \"block\""
    };
    let input = format!(
        r#"
listen = "127.0.0.1:8080"

[decision]
backend = "http"
url = "http://stub-decider:9000/decide"
timeout_ms = 150
inspect_body_bytes = 8192
max_body_bytes = 10485760

[default]
status = 421

[[sites]]
hosts = ["example.com"]
upstream = "http://upstream:80"
{mode}
{action}
block_threshold = 0.9
instruction_threshold = 0.5
{site_fields}
"#
    );
    let config = Config::from_toml_str(&input)?;
    config.sites.into_iter().next().ok_or(ConfigError::NoSites)
}
