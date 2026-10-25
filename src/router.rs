//! Selecting a site from the request `Host` header, with nginx `server_name` matching.
//!
//! A site lists its names in one of these forms: an exact name, a leading
//! wildcard `*.example.com`, a trailing wildcard `example.*`, the form
//! `.example.com` (which is `example.com` and `*.example.com`), or a regular
//! expression `~pattern`. A host is looked up in that order of precedence:
//! exact name, then the longest leading wildcard, then the longest trailing
//! wildcard, then the first matching regular expression in configuration order.
//! A host that matches nothing goes to the site marked `default_server`, when
//! there is one.

use std::collections::HashMap;

use http::HeaderValue;
use regex::Regex;

use crate::config::SiteConfig;

/// One name from a site's `site` list, after normalization.
#[derive(Debug, Clone)]
pub(crate) enum HostPattern {
    /// An exact name such as `example.com`.
    Exact(String),
    /// `*.example.com`, stored as the suffix `.example.com`.
    Leading(String),
    /// `example.*`, stored as the prefix `example.`.
    Trailing(String),
    /// `.example.com`, which matches `example.com` and `*.example.com`. Stored without the leading dot.
    Domain(String),
    /// `~pattern`, with the pattern text as written after the `~`.
    Regex {
        /// The pattern text, without the `~`.
        source: String,
        /// The compiled pattern.
        pattern: Regex,
    },
}

impl HostPattern {
    /// Parses one `site` argument. A plain name is lowercased and loses its
    /// trailing dots; a regular expression is kept as written.
    ///
    /// # Errors
    ///
    /// Returns the reason when the name is empty, has a `*` anywhere but in a
    /// leading or trailing wildcard, or the regular expression does not compile.
    pub(crate) fn parse(raw: &str) -> Result<Self, String> {
        if let Some(source) = raw.strip_prefix('~') {
            if source.is_empty() {
                return Err("the regular expression is empty".to_owned());
            }
            let pattern = Regex::new(source)
                .map_err(|error| format!("the regular expression does not compile: {error}"))?;
            return Ok(Self::Regex {
                source: source.to_owned(),
                pattern,
            });
        }
        let name = normalize_host(raw);
        if name.is_empty() {
            return Err("the name is empty".to_owned());
        }
        if let Some(rest) = name.strip_prefix("*.") {
            require_plain(rest)?;
            return Ok(Self::Leading(format!(".{rest}")));
        }
        if let Some(rest) = name.strip_prefix('.') {
            require_plain(rest)?;
            return Ok(Self::Domain(rest.to_owned()));
        }
        if let Some(rest) = name.strip_suffix(".*") {
            require_plain(rest)?;
            return Ok(Self::Trailing(format!("{rest}.")));
        }
        require_plain(&name)?;
        Ok(Self::Exact(name))
    }

    /// The name as written in the configuration, normalized. Used in messages and as `SiteConfig::hosts`.
    pub(crate) fn display(&self) -> String {
        match self {
            Self::Exact(name) => name.clone(),
            Self::Leading(suffix) => format!("*{suffix}"),
            Self::Trailing(prefix) => format!("{prefix}*"),
            Self::Domain(name) => format!(".{name}"),
            Self::Regex { source, .. } => format!("~{source}"),
        }
    }

    /// The table keys this name takes up. Two sites that claim the same key are a duplicate.
    pub(crate) fn claims(&self) -> Vec<String> {
        match self {
            Self::Exact(name) => vec![format!("exact {name}")],
            Self::Leading(suffix) => vec![format!("leading {suffix}")],
            Self::Trailing(prefix) => vec![format!("trailing {prefix}")],
            Self::Domain(name) => vec![format!("exact {name}"), format!("leading .{name}")],
            Self::Regex { source, .. } => vec![format!("regex {source}")],
        }
    }
}

impl PartialEq for HostPattern {
    /// Two patterns are equal when they are written the same way.
    fn eq(&self, other: &Self) -> bool {
        self.display() == other.display()
    }
}

/// Rejects a `*` in a name that is not a wildcard, and an empty name.
fn require_plain(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("the name is empty".to_owned());
    }
    if name.contains('*') {
        return Err("\"*\" is only allowed as a whole leading or trailing label".to_owned());
    }
    Ok(())
}

/// Maps normalized host names to site indexes.
#[derive(Debug)]
pub(crate) struct Router {
    exact: HashMap<String, usize>,
    /// Leading wildcards, keyed by suffix with its leading dot.
    leading: HashMap<String, usize>,
    /// Trailing wildcards, keyed by prefix with its trailing dot.
    trailing: HashMap<String, usize>,
    /// Regular expressions, in configuration order.
    regexes: Vec<(Regex, usize)>,
    /// The site that takes hosts matching nothing.
    default: Option<usize>,
}

impl Router {
    /// Builds the host tables from the configured sites. Duplicate names are
    /// rejected while the configuration is built, so the first site wins only defensively.
    pub(crate) fn new(sites: &[SiteConfig]) -> Self {
        let mut router = Self {
            exact: HashMap::new(),
            leading: HashMap::new(),
            trailing: HashMap::new(),
            regexes: Vec::new(),
            default: None,
        };
        for (index, site) in sites.iter().enumerate() {
            for pattern in &site.host_patterns {
                match pattern {
                    HostPattern::Exact(name) => {
                        router.exact.entry(name.clone()).or_insert(index);
                    }
                    HostPattern::Leading(suffix) => {
                        router.leading.entry(suffix.clone()).or_insert(index);
                    }
                    HostPattern::Trailing(prefix) => {
                        router.trailing.entry(prefix.clone()).or_insert(index);
                    }
                    HostPattern::Domain(name) => {
                        router.exact.entry(name.clone()).or_insert(index);
                        router.leading.entry(format!(".{name}")).or_insert(index);
                    }
                    HostPattern::Regex { pattern, .. } => {
                        router.regexes.push((pattern.clone(), index));
                    }
                }
            }
            if site.default_server {
                router.default.get_or_insert(index);
            }
        }
        router
    }

    /// Returns the index of the site that serves `host`: the matching site, or
    /// the default site when none matches. `None` when no site matches and there
    /// is no default site.
    pub(crate) fn lookup(&self, host: Option<&HeaderValue>) -> Option<usize> {
        let raw = host.and_then(|value| value.to_str().ok());
        raw.and_then(|raw| self.find(&normalize_host(raw)))
            .or(self.default)
    }

    /// Finds the site for a normalized host, by the precedence of the module documentation.
    fn find(&self, host: &str) -> Option<usize> {
        if let Some(index) = self.exact.get(host) {
            return Some(*index);
        }
        // The leftmost dot gives the longest suffix, so the first hit is the longest wildcard.
        for (position, _) in host.match_indices('.') {
            if position == 0 {
                continue;
            }
            let hit = host
                .get(position..)
                .and_then(|suffix| self.leading.get(suffix));
            if let Some(index) = hit {
                return Some(*index);
            }
        }
        // The rightmost dot gives the longest prefix, so the first hit is the longest wildcard.
        for (position, _) in host.rmatch_indices('.') {
            let hit = host
                .get(..position + 1)
                .and_then(|prefix| self.trailing.get(prefix));
            if let Some(index) = hit {
                return Some(*index);
            }
        }
        self.regexes
            .iter()
            .find(|(pattern, _)| pattern.is_match(host))
            .map(|(_, index)| *index)
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

/// Returns true when a `Host` value has the shape of a hostname or a literal, with an optional port.
///
/// Accepted: letters, digits, `.` and `-` in the name (a trailing dot is allowed), or a
/// bracketed IPv6 literal of hex digits, `:` and `.`, then an optional `:port` of digits.
/// Anything else, including an empty value, is refused before routing.
pub(crate) fn is_valid_host(raw: &str) -> bool {
    let port_ok = |port: &str| !port.is_empty() && port.chars().all(|c| c.is_ascii_digit());
    if let Some(rest) = raw.strip_prefix('[') {
        let Some((literal, after)) = rest.split_once(']') else {
            return false;
        };
        let literal_ok = !literal.is_empty()
            && literal
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.');
        return literal_ok && (after.is_empty() || after.strip_prefix(':').is_some_and(port_ok));
    }
    let (name, port) = match raw.split_once(':') {
        Some((name, port)) => (name, Some(port)),
        None => (raw, None),
    };
    let name_ok = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    name_ok && port.is_none_or(port_ok)
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;
    use proptest::prelude::*;
    use rstest::rstest;

    use super::*;
    use crate::config::Config;
    use crate::error::ConfigError;
    use crate::test_support::site;

    #[rstest]
    #[case::name("example.com")]
    #[case::name_with_port("example.com:8080")]
    #[case::trailing_dot("example.com.")]
    #[case::hyphen_and_digits("a-1.example.co")]
    #[case::ipv4("192.0.2.1:80")]
    #[case::ipv6("[2001:db8::1]")]
    #[case::ipv6_with_port("[::1]:8443")]
    fn valid_hosts_are_accepted(#[case] raw: &str) {
        assert!(is_valid_host(raw), "{raw}");
    }

    #[rstest]
    #[case::empty("")]
    #[case::space("exa mple.com")]
    #[case::slash("example.com/x")]
    #[case::underscore("my_host.example.com")]
    #[case::semicolon("example.com;x")]
    #[case::empty_port("example.com:")]
    #[case::letter_port("example.com:80a")]
    #[case::unclosed_ipv6("[::1")]
    #[case::ipv6_with_bad_char("[::g]")]
    #[case::empty_ipv6("[]")]
    #[case::ipv6_junk_after("[::1]x")]
    #[case::leading_colon("::1")]
    fn invalid_hosts_are_refused(#[case] raw: &str) {
        assert!(!is_valid_host(raw), "{raw}");
    }

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

    #[rstest]
    #[case::exact("Example.COM.", "example.com")]
    #[case::leading("*.Example.com", "*.example.com")]
    #[case::leading_multi_label("*.a.example.com", "*.a.example.com")]
    #[case::trailing("example.*", "example.*")]
    #[case::domain(".example.com", ".example.com")]
    #[case::regex("~^(www\\.)?example\\.(com|jp)$", "~^(www\\.)?example\\.(com|jp)$")]
    fn host_names_are_parsed_and_written_back(#[case] raw: &str, #[case] written: &str) {
        let pattern = HostPattern::parse(raw);
        assert_eq!(pattern.map(|p| p.display()).as_deref(), Ok(written));
    }

    #[rstest]
    #[case::empty("")]
    #[case::bare_star("*")]
    #[case::star_in_the_middle("a*.example.com")]
    #[case::leading_wildcard_without_name("*.")]
    #[case::domain_without_name(".")]
    #[case::trailing_wildcard_without_name(".*")]
    #[case::empty_regex("~")]
    #[case::regex_that_does_not_compile("~(unclosed")]
    fn invalid_host_names_are_rejected(#[case] raw: &str) {
        assert!(HostPattern::parse(raw).is_err());
    }

    /// Builds a router from one site per name, in order. Site `i` has the index `i`.
    fn router_for(names: &[&str]) -> Result<Router, ConfigError> {
        let sites = names
            .iter()
            .map(|name| format!("site {name} {{\n    upstream http://127.0.0.1:9;\n}}\n"))
            .collect::<Vec<_>>()
            .concat();
        let text = format!(
            "listen 127.0.0.1:0;\ndecision {{\n    backend http;\n    url http://127.0.0.1:9/decide;\n}}\n{sites}"
        );
        let config = Config::parse_str(&text, "router-test.conf")?;
        Ok(Router::new(&config.sites))
    }

    fn lookup_host(router: &Router, host: &str) -> Option<usize> {
        let value = HeaderValue::from_str(host);
        value.ok().and_then(|value| router.lookup(Some(&value)))
    }

    #[rstest]
    // Exact names beat every wildcard and regular expression.
    #[case::exact_beats_leading("example.com", 0)]
    #[case::leading_wildcard("a.example.com", 1)]
    // *.b.example.com (site 2) is longer than *.example.com (site 1), so it wins.
    #[case::longest_leading_wildcard("x.b.example.com", 2)]
    #[case::leading_wildcard_matches_several_labels("a.b.c.example.com", 1)]
    // A leading wildcard beats a regular expression that also matches.
    #[case::leading_beats_regex("api.example.com", 1)]
    // A domain name (.example.org, site 3) matches its bare name as an exact name.
    #[case::domain_name_matches_bare_name("example.org", 3)]
    #[case::domain_name_matches_subdomain("a.example.org", 3)]
    // A trailing wildcard, when no leading wildcard matches.
    #[case::trailing_wildcard("example.net", 4)]
    // The longest trailing wildcard wins: a.b.* (site 5) over a.* (site 6).
    #[case::longest_trailing_wildcard("a.b.c", 5)]
    #[case::shorter_trailing_wildcard("a.c", 6)]
    // A regular expression is used when no name matches; the first one in order wins.
    #[case::regex_in_order("www.example.jp", 7)]
    #[case::first_regex_wins("xa.test", 9)]
    #[case::later_regex_when_earlier_one_matches_first("ya.test", 10)]
    #[case::second_regex_when_first_fails("y.test", 11)]
    fn precedence_is_exact_then_leading_then_trailing_then_regex(
        #[case] host: &str,
        #[case] expected: usize,
    ) -> Result<(), ConfigError> {
        let router = router_for(&[
            "example.com",
            "*.example.com",
            "*.b.example.com",
            ".example.org",
            "example.*",
            "a.b.*",
            "a.*",
            "~^(www\\.)?example\\.(com|jp)$",
            "~^api\\.",
            "~^x",
            "~a\\.test$",
            "~^y",
        ])?;
        assert_eq!(lookup_host(&router, host), Some(expected));
        Ok(())
    }

    #[test]
    fn domain_names_match_the_name_and_its_subdomains() -> Result<(), ConfigError> {
        let router = router_for(&[".example.com"])?;
        assert_eq!(lookup_host(&router, "example.com"), Some(0));
        assert_eq!(lookup_host(&router, "a.example.com"), Some(0));
        assert_eq!(lookup_host(&router, "notexample.com"), None);
        Ok(())
    }

    #[test]
    fn a_leading_wildcard_does_not_match_a_host_that_starts_with_a_dot() -> Result<(), ConfigError>
    {
        let router = router_for(&["*.example.com"])?;
        assert_eq!(lookup_host(&router, ".example.com"), None);
        assert_eq!(lookup_host(&router, "example.com"), None);
        Ok(())
    }

    #[test]
    fn a_trailing_wildcard_does_not_match_a_longer_label() -> Result<(), ConfigError> {
        let router = router_for(&["example.*"])?;
        assert_eq!(lookup_host(&router, "example.com"), Some(0));
        assert_eq!(lookup_host(&router, "myexample.com"), None);
        Ok(())
    }

    #[test]
    fn a_host_that_matches_nothing_goes_to_the_default_server() -> Result<(), ConfigError> {
        let text = "listen 127.0.0.1:0;\ndecision {\n    backend http;\n    url http://127.0.0.1:9/decide;\n}\nsite a.test {\n    upstream http://127.0.0.1:9;\n}\nsite b.test {\n    upstream http://127.0.0.1:9;\n    default_server;\n}\n";
        let config = Config::parse_str(text, "default.conf")?;
        let router = Router::new(&config.sites);
        assert_eq!(lookup_host(&router, "a.test"), Some(0));
        assert_eq!(lookup_host(&router, "unknown.test"), Some(1));
        assert_eq!(router.lookup(None), Some(1));
        Ok(())
    }

    #[test]
    fn without_a_default_server_unmatched_hosts_have_no_site() -> Result<(), ConfigError> {
        let router = router_for(&["example.com"])?;
        assert_eq!(lookup_host(&router, "other.example"), None);
        assert_eq!(router.lookup(None), None);
        Ok(())
    }

    #[test]
    fn lookup_finds_a_site_regardless_of_case_and_port() -> Result<(), ConfigError> {
        let sites = vec![site("")?];
        let router = Router::new(&sites);
        let header = HeaderValue::from_static("EXAMPLE.com:8080");
        assert_eq!(router.lookup(Some(&header)), Some(0));
        Ok(())
    }

    #[test]
    fn lookup_returns_none_for_an_unknown_host() -> Result<(), ConfigError> {
        let sites = vec![site("")?];
        let router = Router::new(&sites);
        let header = HeaderValue::from_static("other.example");
        assert_eq!(router.lookup(Some(&header)), None);
        Ok(())
    }

    #[test]
    fn lookup_returns_none_when_the_host_header_is_missing() -> Result<(), ConfigError> {
        let sites = vec![site("")?];
        assert_eq!(Router::new(&sites).lookup(None), None);
        Ok(())
    }
}
