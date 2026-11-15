//! Fixtures that the tests of the submodules share.

use crate::config::{Config, ConfigError, SiteConfig};

/// A configuration that is valid as written.
pub(crate) const BASE: &str = "listen 127.0.0.1:8080;\n\
    decision {\n    backend http;\n    url http://stub-decider:9000/decide;\n}\n\
    site example.com {\n    upstream http://upstream:80;\n}\n";

fn lookup(name: &str) -> Option<String> {
    (name == "TEST_TOKEN").then(|| " tok-123 ".to_owned())
}

pub(crate) fn parse(text: &str) -> Result<Config, ConfigError> {
    Config::parse_str_with_lookup(text, "test.conf", lookup)
}

/// The message of an error, which always starts with `file:line:` for file errors.
pub(crate) fn message<T>(result: Result<T, ConfigError>) -> String {
    match result {
        Ok(_) => String::new(),
        Err(error) => error.to_string(),
    }
}

pub(crate) fn with_decision(lines: &str) -> String {
    format!(
        "listen 127.0.0.1:8080;\ndecision {{\n    url http://stub-decider:9000/decide;\n{lines}}}\n\
         site example.com {{\n    upstream http://upstream:80;\n}}\n"
    )
}

pub(crate) fn with_site(lines: &str) -> String {
    format!(
        "listen 127.0.0.1:8080;\ndecision {{\n    backend http;\n    url http://stub-decider:9000/decide;\n}}\n\
         site example.com {{\n    upstream http://upstream:80;\n{lines}}}\n"
    )
}

pub(crate) fn first_site(config: &Config) -> Result<&SiteConfig, ConfigError> {
    config.sites.first().ok_or_else(|| ConfigError::Invalid {
        file: "test.conf".to_owned(),
        line: 1,
        message: "no site".to_owned(),
    })
}

/// A configuration with the given site blocks after the decision block.
pub(crate) fn with_sites(sites: &str) -> String {
    format!(
        "listen 127.0.0.1:8080;\ndecision {{\n    backend http;\n    url http://stub-decider:9000/decide;\n}}\n{sites}"
    )
}

/// Fixtures of the connection and timer tests: no token variable is set, and `parse` takes the
/// top-level lines and the site lines apart.
pub(crate) mod connection_limit {
    use crate::config::{Config, ConfigError};

    pub(crate) const DECISION: &str =
        "decision {\n    backend http;\n    url http://stub-decider:9000/decide;\n}\n";
    pub(crate) const SITE: &str = "site example.com {\n    upstream http://upstream:80;\n}\n";

    pub(crate) fn parse(top: &str, site: &str) -> Result<Config, ConfigError> {
        let text = format!(
            "listen 127.0.0.1:8080;\n{top}{DECISION}site example.com {{\n    upstream http://upstream:80;\n{site}}}\n"
        );
        Config::parse_str_with_lookup(&text, "test.conf", |_| None)
    }

    pub(crate) fn message(result: Result<Config, ConfigError>) -> String {
        match result {
            Ok(_) => String::new(),
            Err(error) => error.to_string(),
        }
    }

    /// A configuration that is valid as written, for the tests of this module.
    pub(crate) const PLAIN_BASE: &str = "listen 127.0.0.1:8080;\n\
        decision {\n    backend http;\n    url http://stub-decider:9000/decide;\n}\n\
        site example.com {\n    upstream http://upstream:80;\n}\n";

    pub(crate) fn parse_plain(text: &str) -> Result<Config, ConfigError> {
        Config::parse_str_with_lookup(text, "test.conf", |_| None)
    }
}
