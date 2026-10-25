//! Selecting a site from the request `Host` header.

use std::collections::HashMap;

use http::HeaderValue;

use crate::config::SiteConfig;

/// Maps normalized host names to site indexes.
#[derive(Debug)]
pub(crate) struct Router {
    hosts: HashMap<String, usize>,
}

impl Router {
    /// Builds the host table from the configured sites.
    pub(crate) fn new(sites: &[SiteConfig]) -> Self {
        let hosts = sites
            .iter()
            .enumerate()
            .flat_map(|(index, site)| site.hosts.iter().map(move |host| (host.clone(), index)))
            .collect();
        Self { hosts }
    }

    /// Returns the index of the site that serves `host`, if any.
    pub(crate) fn lookup(&self, host: Option<&HeaderValue>) -> Option<usize> {
        let raw = host?.to_str().ok()?;
        self.hosts.get(&normalize_host(raw)).copied()
    }
}

/// Normalizes a host name: lowercase, without port and without trailing dots.
///
/// The result is idempotent, so normalizing it again returns the same string.
pub(crate) fn normalize_host(raw: &str) -> String {
    let host = if raw.starts_with('[') {
        // An IPv6 literal keeps its brackets; a port follows the closing bracket.
        raw.find(']').and_then(|end| raw.get(..=end)).unwrap_or(raw)
    } else {
        raw.split_once(':').map_or(raw, |(name, _port)| name)
    };
    host.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;
    use proptest::prelude::*;
    use rstest::rstest;

    use super::*;
    use crate::test_support::site;

    #[rstest]
    #[case::plain("example.com", "example.com")]
    #[case::uppercase("Example.COM", "example.com")]
    #[case::port("example.com:8080", "example.com")]
    #[case::trailing_dot("example.com.", "example.com")]
    #[case::trailing_dot_and_port("example.com.:443", "example.com")]
    #[case::many_trailing_dots("example.com..", "example.com")]
    #[case::ipv6_with_port("[::1]:8080", "[::1]")]
    #[case::ipv6_without_port("[2001:DB8::1]", "[2001:db8::1]")]
    fn normalize_host_strips_case_port_and_trailing_dot(#[case] raw: &str, #[case] expected: &str) {
        assert_eq!(normalize_host(raw), expected);
    }

    proptest! {
        #[test]
        fn normalize_host_is_idempotent(raw in "[ -~]{0,40}") {
            let once = normalize_host(&raw);
            prop_assert_eq!(normalize_host(&once), once.clone());
        }
    }

    #[test]
    fn lookup_finds_a_site_regardless_of_case_and_port() -> Result<(), crate::error::ConfigError> {
        let sites = vec![site("")?];
        let router = Router::new(&sites);
        let header = HeaderValue::from_static("EXAMPLE.com:8080");
        assert_eq!(router.lookup(Some(&header)), Some(0));
        Ok(())
    }

    #[test]
    fn lookup_returns_none_for_an_unknown_host() -> Result<(), crate::error::ConfigError> {
        let sites = vec![site("")?];
        let router = Router::new(&sites);
        let header = HeaderValue::from_static("other.example");
        assert_eq!(router.lookup(Some(&header)), None);
        Ok(())
    }

    #[test]
    fn lookup_returns_none_when_the_host_header_is_missing() -> Result<(), crate::error::ConfigError>
    {
        let sites = vec![site("")?];
        assert_eq!(Router::new(&sites).lookup(None), None);
        Ok(())
    }
}
