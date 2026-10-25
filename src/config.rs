//! Loading and validating the TOML configuration.

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use http::{HeaderName, HeaderValue, StatusCode, Uri};
use serde::Deserialize;

use crate::clef::{ApiToken, ClefModel};
use crate::error::ConfigError;
use crate::router::normalize_host;

/// Validated configuration for the whole proxy.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    /// Socket address the binary binds, such as `0.0.0.0:8080`.
    pub listen: String,
    /// Format of the tracing output.
    pub log_format: LogFormat,
    /// Header that carries the real client address behind a trusted proxy.
    pub client_ip_header: Option<HeaderName>,
    /// Settings for the decision backend.
    pub decision: DecisionConfig,
    /// Status returned for hosts that match no site.
    pub default_status: StatusCode,
    /// Sites, in the order they were declared.
    pub sites: Vec<SiteConfig>,
}

/// Settings for the HTTP decision backend and the body it receives.
#[derive(Debug, Clone, PartialEq)]
pub struct DecisionConfig {
    /// Absolute `http://` or `https://` URI the decision request is posted to.
    pub url: Uri,
    /// Protocol spoken to the decision backend.
    pub backend: BackendConfig,
    /// Time allowed for the whole decision exchange.
    pub timeout: Duration,
    /// Bytes of the request body that are sent to the backend.
    pub inspect_body_bytes: usize,
    /// Largest request body the proxy reads at all.
    pub max_body_bytes: usize,
    /// Extra header names to drop before sending, lowercased.
    pub redact_headers: Vec<String>,
}

/// The protocol used to reach the decision backend.
#[derive(Debug, Clone, PartialEq)]
pub enum BackendConfig {
    /// The JSON protocol described in the README.
    Http,
    /// Cloudflare Clef, or a server that speaks its protocol.
    Clef {
        /// Model that answers the questions.
        model: ClefModel,
        /// Bearer token, read from the environment variable named in the config.
        token: ApiToken,
    },
}

/// Configuration for one site, selected by the request `Host`.
#[derive(Debug, Clone, PartialEq)]
pub struct SiteConfig {
    /// Normalized host names that select this site.
    pub hosts: Vec<String>,
    /// Absolute `http://` URI requests are forwarded to.
    pub upstream: Uri,
    /// Whether verdicts are enforced or only recorded.
    pub mode: Mode,
    /// What happens to a request that is judged to be an attack.
    pub action: SiteAction,
    /// Attack score at or above which the request is judged an attack.
    pub block_threshold: f64,
    /// AI instruction score at or above which the request is judged an attack.
    pub instruction_threshold: f64,
    /// Path prefixes that are always blocked without calling the backend.
    pub deny_paths: Vec<String>,
    /// Path prefixes that are blocked when the backend fails.
    pub fail_closed_paths: Vec<String>,
    /// File extensions that may skip the backend, lowercased.
    pub static_extensions: Vec<String>,
    /// Whether responses carry the `x-vigilant-heron` header.
    pub debug_headers: bool,
}

/// Whether a site enforces its verdicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Blocks or redirects attacks.
    Enforce,
    /// Forwards everything and records what would have happened.
    Shadow,
}

/// The response given to a request that is judged to be an attack.
#[derive(Debug, Clone, PartialEq)]
pub enum SiteAction {
    /// Respond with 403.
    Block,
    /// Respond with 302 and this `Location` value.
    Redirect(HeaderValue),
}

/// Format of the tracing output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// One JSON object per line.
    #[default]
    Json,
    /// Human-readable multi-line output.
    Pretty,
}

impl Config {
    /// Parses and validates a configuration from TOML text.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Parse`] when the text is not valid TOML for this
    /// schema, and the other [`ConfigError`] variants when a value is invalid.
    pub fn from_toml_str(input: &str) -> Result<Self, ConfigError> {
        Self::from_toml_str_with_lookup(input, |name| std::env::var(name).ok())
    }

    /// Parses and validates a configuration, reading the Clef token through `lookup`.
    ///
    /// `lookup` receives the environment variable name from `api_token_env` and
    /// returns its value. [`Config::from_toml_str`] passes the process environment.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Config::from_toml_str`], and
    /// [`ConfigError::MissingApiToken`] or [`ConfigError::EmptyApiToken`] when
    /// `lookup` gives no usable token.
    pub fn from_toml_str_with_lookup<F>(input: &str, lookup: F) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let raw: RawConfig = toml::from_str(input)?;
        raw.validate(&lookup)
    }

    /// Reads, parses and validates the configuration file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Read`] when the file cannot be read, and the same
    /// errors as [`Config::from_toml_str`] otherwise.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_toml_str(&text)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    listen: String,
    #[serde(default)]
    log_format: LogFormat,
    client_ip_header: Option<String>,
    decision: RawDecision,
    #[serde(rename = "default")]
    default_section: RawDefault,
    #[serde(default)]
    sites: Vec<RawSite>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDecision {
    url: String,
    #[serde(default)]
    backend: RawBackend,
    model: Option<ClefModel>,
    api_token_env: Option<String>,
    timeout_ms: u64,
    inspect_body_bytes: usize,
    max_body_bytes: usize,
    #[serde(default)]
    redact_headers: Vec<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "lowercase")]
enum RawBackend {
    #[default]
    Http,
    Clef,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDefault {
    status: u16,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum RawAction {
    Block,
    Redirect,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSite {
    hosts: Vec<String>,
    upstream: String,
    mode: Mode,
    action: RawAction,
    redirect_to: Option<String>,
    block_threshold: f64,
    instruction_threshold: f64,
    #[serde(default)]
    deny_paths: Vec<String>,
    #[serde(default)]
    fail_closed_paths: Vec<String>,
    #[serde(default = "default_static_extensions")]
    static_extensions: Vec<String>,
    #[serde(default)]
    debug_headers: bool,
}

fn default_static_extensions() -> Vec<String> {
    [
        "css", "js", "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "woff", "woff2", "ttf",
        "map",
    ]
    .iter()
    .map(|ext| (*ext).to_owned())
    .collect()
}

impl RawConfig {
    fn validate<F>(self, lookup: &F) -> Result<Config, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        if self.sites.is_empty() {
            return Err(ConfigError::NoSites);
        }
        let decision = self.decision.validate(lookup)?;
        let default_status = validate_default_status(self.default_section.status)?;
        let client_ip_header = self
            .client_ip_header
            .map(|value| {
                HeaderName::from_str(&value)
                    .map_err(|_| ConfigError::InvalidClientIpHeader { value })
            })
            .transpose()?;
        let mut sites = Vec::with_capacity(self.sites.len());
        let mut seen_hosts = HashSet::new();
        for (index, site) in self.sites.into_iter().enumerate() {
            let site = site.validate(index)?;
            for host in &site.hosts {
                if !seen_hosts.insert(host.clone()) {
                    return Err(ConfigError::DuplicateHost { host: host.clone() });
                }
            }
            sites.push(site);
        }
        Ok(Config {
            listen: self.listen,
            log_format: self.log_format,
            client_ip_header,
            decision,
            default_status,
            sites,
        })
    }
}

impl RawDecision {
    fn validate<F>(self, lookup: &F) -> Result<DecisionConfig, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let url = parse_absolute_uri(&self.url, &["http", "https"]).ok_or_else(|| {
            ConfigError::InvalidDecisionUrl {
                value: self.url.clone(),
            }
        })?;
        let backend = self.backend_config(lookup)?;
        if self.timeout_ms == 0 {
            return Err(ConfigError::ZeroTimeout);
        }
        if self.inspect_body_bytes > self.max_body_bytes {
            return Err(ConfigError::InspectExceedsMax {
                inspect: self.inspect_body_bytes,
                max: self.max_body_bytes,
            });
        }
        Ok(DecisionConfig {
            url,
            backend,
            timeout: Duration::from_millis(self.timeout_ms),
            inspect_body_bytes: self.inspect_body_bytes,
            max_body_bytes: self.max_body_bytes,
            redact_headers: self
                .redact_headers
                .iter()
                .map(|name| name.to_ascii_lowercase())
                .collect(),
        })
    }

    fn backend_config<F>(&self, lookup: &F) -> Result<BackendConfig, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        match self.backend {
            RawBackend::Http => {
                if self.model.is_some() {
                    return Err(ConfigError::UnexpectedClefField { field: "model" });
                }
                if self.api_token_env.is_some() {
                    return Err(ConfigError::UnexpectedClefField {
                        field: "api_token_env",
                    });
                }
                Ok(BackendConfig::Http)
            }
            RawBackend::Clef => {
                let model = self
                    .model
                    .ok_or(ConfigError::MissingClefField { field: "model" })?;
                let name = self
                    .api_token_env
                    .as_deref()
                    .ok_or(ConfigError::MissingClefField {
                        field: "api_token_env",
                    })?;
                let value = lookup(name).ok_or_else(|| ConfigError::MissingApiToken {
                    name: name.to_owned(),
                })?;
                let token = value.trim();
                if token.is_empty() {
                    return Err(ConfigError::EmptyApiToken {
                        name: name.to_owned(),
                    });
                }
                Ok(BackendConfig::Clef {
                    model,
                    token: ApiToken::new(token.to_owned()),
                })
            }
        }
    }
}

impl RawSite {
    fn validate(self, site: usize) -> Result<SiteConfig, ConfigError> {
        if self.hosts.is_empty() {
            return Err(ConfigError::EmptyHosts { site });
        }
        let mut hosts = Vec::with_capacity(self.hosts.len());
        for host in &self.hosts {
            let normalized = normalize_host(host);
            if normalized.is_empty() {
                return Err(ConfigError::InvalidHost {
                    site,
                    value: host.clone(),
                });
            }
            hosts.push(normalized);
        }
        let upstream = parse_absolute_uri(&self.upstream, &["http"]).ok_or_else(|| {
            ConfigError::InvalidUpstream {
                site,
                value: self.upstream.clone(),
            }
        })?;
        check_threshold(site, "block_threshold", self.block_threshold)?;
        check_threshold(site, "instruction_threshold", self.instruction_threshold)?;
        let action = match (self.action, self.redirect_to) {
            (RawAction::Block, None) => SiteAction::Block,
            (RawAction::Block, Some(_)) => return Err(ConfigError::UnexpectedRedirectTo { site }),
            (RawAction::Redirect, None) => return Err(ConfigError::MissingRedirectTo { site }),
            (RawAction::Redirect, Some(to)) => {
                let location =
                    HeaderValue::from_str(&to).map_err(|_| ConfigError::InvalidRedirectTo {
                        site,
                        value: to.clone(),
                    })?;
                SiteAction::Redirect(location)
            }
        };
        Ok(SiteConfig {
            hosts,
            upstream,
            mode: self.mode,
            action,
            block_threshold: self.block_threshold,
            instruction_threshold: self.instruction_threshold,
            deny_paths: self.deny_paths,
            fail_closed_paths: self.fail_closed_paths,
            static_extensions: self
                .static_extensions
                .iter()
                .map(|ext| ext.to_ascii_lowercase())
                .collect(),
            debug_headers: self.debug_headers,
        })
    }
}

fn check_threshold(site: usize, name: &'static str, value: f64) -> Result<(), ConfigError> {
    if (0.0..=1.0).contains(&value) {
        Ok(())
    } else {
        Err(ConfigError::ThresholdOutOfRange { site, name, value })
    }
}

fn validate_default_status(status: u16) -> Result<StatusCode, ConfigError> {
    match StatusCode::from_u16(status) {
        Ok(code) if code.is_client_error() || code.is_server_error() => Ok(code),
        _ => Err(ConfigError::InvalidDefaultStatus { status }),
    }
}

/// Parses `value` as an absolute URI with one of `schemes` and an authority.
fn parse_absolute_uri(value: &str, schemes: &[&str]) -> Option<Uri> {
    let uri = value.parse::<Uri>().ok()?;
    let scheme_ok = uri
        .scheme_str()
        .is_some_and(|scheme| schemes.contains(&scheme));
    (scheme_ok && uri.authority().is_some()).then_some(uri)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    const DECISION: &str = r#"
listen = "127.0.0.1:8080"

[decision]
url = "http://stub-decider:9000/decide"
timeout_ms = 150
inspect_body_bytes = 8192
max_body_bytes = 10485760

[default]
status = 421
"#;

    const SITE: &str = r#"
[[sites]]
hosts = ["example.com", "www.example.com"]
upstream = "http://upstream:80"
mode = "enforce"
action = "block"
block_threshold = 0.9
instruction_threshold = 0.5
"#;

    fn config_with(extra_site: &str) -> String {
        format!("{DECISION}{SITE}{extra_site}")
    }

    #[test]
    fn valid_config_parses_every_key() -> Result<(), ConfigError> {
        let input = r#"
listen = "127.0.0.1:8080"
client_ip_header = "X-Real-IP"

[decision]
url = "http://stub-decider:9000/decide"
timeout_ms = 150
inspect_body_bytes = 8192
max_body_bytes = 10485760
redact_headers = ["X-Session"]

[default]
status = 421

[[sites]]
hosts = ["Example.COM:443."]
upstream = "http://upstream:80"
mode = "shadow"
action = "redirect"
redirect_to = "https://example.com/blocked"
block_threshold = 0.9
instruction_threshold = 0.5
deny_paths = ["/xmlrpc.php"]
fail_closed_paths = ["/wp-login.php"]
static_extensions = ["CSS"]
debug_headers = true
"#;
        let config = Config::from_toml_str(input)?;
        assert_eq!(config.listen, "127.0.0.1:8080");
        assert_eq!(config.log_format, LogFormat::Json);
        assert_eq!(config.default_status, StatusCode::MISDIRECTED_REQUEST);
        assert_eq!(
            config.client_ip_header,
            Some(HeaderName::from_static("x-real-ip"))
        );
        assert_eq!(config.decision.redact_headers, vec!["x-session".to_owned()]);
        assert_eq!(config.decision.timeout, Duration::from_millis(150));
        let site = config.sites.first().ok_or(ConfigError::NoSites)?;
        assert_eq!(site.hosts, vec!["example.com".to_owned()]);
        assert_eq!(site.mode, Mode::Shadow);
        assert_eq!(
            site.action,
            SiteAction::Redirect(HeaderValue::from_static("https://example.com/blocked"))
        );
        assert_eq!(site.static_extensions, vec!["css".to_owned()]);
        assert!(site.debug_headers);
        Ok(())
    }

    #[test]
    fn default_static_extensions_apply_when_key_is_absent() -> Result<(), ConfigError> {
        let config = Config::from_toml_str(&config_with(""))?;
        let site = config.sites.first().ok_or(ConfigError::NoSites)?;
        assert!(site.static_extensions.contains(&"woff2".to_owned()));
        assert!(site.static_extensions.contains(&"map".to_owned()));
        assert_eq!(site.static_extensions.len(), 13);
        Ok(())
    }

    #[test]
    fn log_format_pretty_is_accepted() -> Result<(), ConfigError> {
        let input = format!("log_format = \"pretty\"\n{}", config_with(""));
        assert_eq!(Config::from_toml_str(&input)?.log_format, LogFormat::Pretty);
        Ok(())
    }

    #[test]
    fn unknown_key_is_a_parse_error() {
        let input = config_with("surprise = true\n");
        assert!(matches!(
            Config::from_toml_str(&input),
            Err(ConfigError::Parse(_))
        ));
    }

    #[test]
    fn missing_file_is_a_read_error() {
        let result = Config::load(Path::new("/nonexistent/vigilant-heron/config.toml"));
        assert!(matches!(result, Err(ConfigError::Read { .. })));
    }

    #[test]
    fn config_without_sites_is_rejected() {
        assert!(matches!(
            Config::from_toml_str(DECISION),
            Err(ConfigError::NoSites)
        ));
    }

    #[test]
    fn site_with_empty_hosts_is_rejected() {
        let site = SITE.replace(
            "hosts = [\"example.com\", \"www.example.com\"]",
            "hosts = []",
        );
        assert!(matches!(
            Config::from_toml_str(&format!("{DECISION}{site}")),
            Err(ConfigError::EmptyHosts { site: 0 })
        ));
    }

    #[test]
    fn host_that_normalizes_to_nothing_is_rejected() {
        let input = config_with("").replace("\"example.com\", \"www.example.com\"", "\":80\"");
        assert!(matches!(
            Config::from_toml_str(&input),
            Err(ConfigError::InvalidHost { site: 0, .. })
        ));
    }

    #[test]
    fn same_host_in_two_sites_is_rejected_after_normalization() {
        let second = r#"
[[sites]]
hosts = ["EXAMPLE.com."]
upstream = "http://other:80"
mode = "enforce"
action = "block"
block_threshold = 0.9
instruction_threshold = 0.5
"#;
        assert!(matches!(
            Config::from_toml_str(&config_with(second)),
            Err(ConfigError::DuplicateHost { host }) if host == "example.com"
        ));
    }

    #[rstest]
    #[case::attack_negative("block_threshold = -0.1", "block_threshold")]
    #[case::attack_above_one("block_threshold = 1.1", "block_threshold")]
    #[case::attack_nan("block_threshold = nan", "block_threshold")]
    #[case::instruction_above_one("instruction_threshold = 2.0", "instruction_threshold")]
    #[case::instruction_nan("instruction_threshold = nan", "instruction_threshold")]
    fn threshold_outside_unit_interval_is_rejected(#[case] line: &str, #[case] name: &str) {
        let site = SITE
            .replace(
                "block_threshold = 0.9",
                if name == "block_threshold" {
                    line
                } else {
                    "block_threshold = 0.9"
                },
            )
            .replace(
                "instruction_threshold = 0.5",
                if name == "instruction_threshold" {
                    line
                } else {
                    "instruction_threshold = 0.5"
                },
            );
        let result = Config::from_toml_str(&format!("{DECISION}{site}"));
        assert!(matches!(
            result,
            Err(ConfigError::ThresholdOutOfRange { site: 0, name: found, .. }) if found == name
        ));
    }

    #[test]
    fn thresholds_at_both_ends_are_accepted() -> Result<(), ConfigError> {
        let site = SITE
            .replace("block_threshold = 0.9", "block_threshold = 0.0")
            .replace("instruction_threshold = 0.5", "instruction_threshold = 1.0");
        Config::from_toml_str(&format!("{DECISION}{site}"))?;
        Ok(())
    }

    #[test]
    fn redirect_without_redirect_to_is_rejected() {
        let site = SITE.replace("action = \"block\"", "action = \"redirect\"");
        assert!(matches!(
            Config::from_toml_str(&format!("{DECISION}{site}")),
            Err(ConfigError::MissingRedirectTo { site: 0 })
        ));
    }

    #[test]
    fn block_with_redirect_to_is_rejected() {
        let site = SITE.replace(
            "action = \"block\"",
            "action = \"block\"\nredirect_to = \"https://example.com/blocked\"",
        );
        assert!(matches!(
            Config::from_toml_str(&format!("{DECISION}{site}")),
            Err(ConfigError::UnexpectedRedirectTo { site: 0 })
        ));
    }

    #[test]
    fn redirect_target_with_control_character_is_rejected() {
        let site = SITE.replace(
            "action = \"block\"",
            "action = \"redirect\"\nredirect_to = \"https://a.test/\\u0001\"",
        );
        assert!(matches!(
            Config::from_toml_str(&format!("{DECISION}{site}")),
            Err(ConfigError::InvalidRedirectTo { site: 0, .. })
        ));
    }

    #[rstest]
    #[case::https("https://upstream:443")]
    #[case::relative("upstream:80")]
    #[case::bare_path("/only/path")]
    #[case::unparseable("http://[::1")]
    fn upstream_must_be_absolute_http(#[case] upstream: &str) {
        let site = SITE.replace("http://upstream:80", upstream);
        assert!(matches!(
            Config::from_toml_str(&format!("{DECISION}{site}")),
            Err(ConfigError::InvalidUpstream { site: 0, .. })
        ));
    }

    #[test]
    fn decision_url_must_be_absolute_http() {
        let input = DECISION.replace("http://stub-decider:9000/decide", "decide.local");
        assert!(matches!(
            Config::from_toml_str(&format!("{input}{SITE}")),
            Err(ConfigError::InvalidDecisionUrl { .. })
        ));
    }

    #[test]
    fn client_ip_header_must_be_a_header_name() {
        let input = format!("client_ip_header = \"bad header\"\n{}", config_with(""));
        assert!(matches!(
            Config::from_toml_str(&input),
            Err(ConfigError::InvalidClientIpHeader { .. })
        ));
    }

    #[test]
    fn zero_timeout_is_rejected() {
        let input = DECISION.replace("timeout_ms = 150", "timeout_ms = 0");
        assert!(matches!(
            Config::from_toml_str(&format!("{input}{SITE}")),
            Err(ConfigError::ZeroTimeout)
        ));
    }

    #[test]
    fn inspect_larger_than_max_is_rejected() {
        let input = DECISION.replace("inspect_body_bytes = 8192", "inspect_body_bytes = 20000000");
        assert!(matches!(
            Config::from_toml_str(&format!("{input}{SITE}")),
            Err(ConfigError::InspectExceedsMax {
                inspect: 20_000_000,
                max: 10_485_760
            })
        ));
    }

    #[rstest]
    #[case::ok_status(200)]
    #[case::redirect(302)]
    #[case::informational(199)]
    #[case::too_large(600)]
    #[case::not_http(0)]
    fn default_status_must_be_client_or_server_error(#[case] status: u16) {
        let input = DECISION.replace("status = 421", &format!("status = {status}"));
        assert!(matches!(
            Config::from_toml_str(&format!("{input}{SITE}")),
            Err(ConfigError::InvalidDefaultStatus { status: found }) if found == status
        ));
    }

    #[test]
    fn shipped_example_and_e2e_configs_are_valid() -> Result<(), ConfigError> {
        Config::from_toml_str(include_str!("../examples/config.toml"))?;
        Config::from_toml_str(include_str!("../e2e/config.toml"))?;
        Ok(())
    }

    const CLEF_URL: &str =
        "https://api.cloudflare.com/client/v4/accounts/acc/ai/run/@cf/cloudflare/clef-flash";

    fn clef_toml(backend_lines: &str) -> String {
        format!(
            r#"
listen = "127.0.0.1:8080"

[decision]
url = "{CLEF_URL}"
timeout_ms = 300
inspect_body_bytes = 8192
max_body_bytes = 10485760
{backend_lines}

[default]
status = 421
{SITE}"#
        )
    }

    fn lookup(name: &str) -> Option<String> {
        match name {
            "CLEF_TOKEN" => Some("  tok-123-secret \n".to_owned()),
            "BLANK_TOKEN" => Some("   ".to_owned()),
            _ => None,
        }
    }

    #[test]
    fn default_backend_is_http_and_needs_no_token() -> Result<(), ConfigError> {
        let config = Config::from_toml_str_with_lookup(&config_with(""), |_| None)?;
        assert_eq!(config.decision.backend, BackendConfig::Http);
        Ok(())
    }

    #[test]
    fn clef_backend_reads_the_model_and_a_trimmed_token() -> Result<(), ConfigError> {
        let input =
            clef_toml("backend = \"clef\"\nmodel = \"clef-flash\"\napi_token_env = \"CLEF_TOKEN\"");
        let config = Config::from_toml_str_with_lookup(&input, lookup)?;
        match &config.decision.backend {
            BackendConfig::Clef { model, token } => {
                assert_eq!(*model, ClefModel::Flash);
                assert_eq!(token.expose(), "tok-123-secret");
            }
            BackendConfig::Http => return Err(ConfigError::NoSites),
        }
        Ok(())
    }

    #[test]
    fn token_never_appears_in_the_debug_output_of_the_config() -> Result<(), ConfigError> {
        let input =
            clef_toml("backend = \"clef\"\nmodel = \"clef\"\napi_token_env = \"CLEF_TOKEN\"");
        let config = Config::from_toml_str_with_lookup(&input, lookup)?;
        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("tok-123-secret"));
        Ok(())
    }

    #[test]
    fn clef_backend_accepts_an_https_url_and_http_for_self_hosted_servers()
    -> Result<(), ConfigError> {
        let input =
            clef_toml("backend = \"clef\"\nmodel = \"clef\"\napi_token_env = \"CLEF_TOKEN\"")
                .replace(CLEF_URL, "http://stub-decider:9000/decide");
        Config::from_toml_str_with_lookup(&input, lookup)?;
        Ok(())
    }

    #[test]
    fn clef_backend_without_a_model_is_rejected() {
        let input = clef_toml("backend = \"clef\"\napi_token_env = \"CLEF_TOKEN\"");
        assert!(matches!(
            Config::from_toml_str_with_lookup(&input, lookup),
            Err(ConfigError::MissingClefField { field: "model" })
        ));
    }

    #[test]
    fn clef_backend_without_a_token_variable_name_is_rejected() {
        let input = clef_toml("backend = \"clef\"\nmodel = \"clef-flash\"");
        assert!(matches!(
            Config::from_toml_str_with_lookup(&input, lookup),
            Err(ConfigError::MissingClefField {
                field: "api_token_env"
            })
        ));
    }

    #[test]
    fn unset_token_variable_is_rejected_by_name() {
        let input =
            clef_toml("backend = \"clef\"\nmodel = \"clef-flash\"\napi_token_env = \"ABSENT\"");
        assert!(matches!(
            Config::from_toml_str_with_lookup(&input, lookup),
            Err(ConfigError::MissingApiToken { name }) if name == "ABSENT"
        ));
    }

    #[test]
    fn blank_token_variable_is_rejected() {
        let input = clef_toml(
            "backend = \"clef\"\nmodel = \"clef-flash\"\napi_token_env = \"BLANK_TOKEN\"",
        );
        assert!(matches!(
            Config::from_toml_str_with_lookup(&input, lookup),
            Err(ConfigError::EmptyApiToken { name }) if name == "BLANK_TOKEN"
        ));
    }

    #[test]
    fn http_backend_rejects_a_clef_model() {
        let input = clef_toml("model = \"clef\"");
        assert!(matches!(
            Config::from_toml_str_with_lookup(&input, lookup),
            Err(ConfigError::UnexpectedClefField { field: "model" })
        ));
    }

    #[test]
    fn http_backend_rejects_a_token_variable_name() {
        let input = clef_toml("api_token_env = \"CLEF_TOKEN\"");
        assert!(matches!(
            Config::from_toml_str_with_lookup(&input, lookup),
            Err(ConfigError::UnexpectedClefField {
                field: "api_token_env"
            })
        ));
    }

    #[test]
    fn unknown_backend_name_is_a_parse_error() {
        let input = clef_toml("backend = \"gpt\"");
        assert!(matches!(
            Config::from_toml_str_with_lookup(&input, lookup),
            Err(ConfigError::Parse(_))
        ));
    }

    #[test]
    fn unknown_clef_model_is_a_parse_error() {
        let input =
            clef_toml("backend = \"clef\"\nmodel = \"clef-mini\"\napi_token_env = \"CLEF_TOKEN\"");
        assert!(matches!(
            Config::from_toml_str_with_lookup(&input, lookup),
            Err(ConfigError::Parse(_))
        ));
    }

    #[rstest]
    #[case::ftp("ftp://decide.local/x")]
    #[case::no_authority("http:/decide")]
    fn decision_url_must_be_http_or_https(#[case] url: &str) {
        let input = DECISION.replace("http://stub-decider:9000/decide", url);
        assert!(matches!(
            Config::from_toml_str(&format!("{input}{SITE}")),
            Err(ConfigError::InvalidDecisionUrl { .. })
        ));
    }

    #[test]
    fn default_status_accepts_4xx_and_5xx() -> Result<(), ConfigError> {
        for status in [400_u16, 421, 503, 599] {
            let input = DECISION.replace("status = 421", &format!("status = {status}"));
            Config::from_toml_str(&format!("{input}{SITE}"))?;
        }
        Ok(())
    }
}
