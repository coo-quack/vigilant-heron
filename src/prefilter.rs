//! Checks that need no model, in the order they run: `deny_path`, block rules,
//! skip rules and the static asset skip.
//!
//! The access list is checked before this module, and the decision model after it.

use std::sync::Arc;

use http::Method;

use crate::config::SiteConfig;
use crate::rules::{RuleInput, first_match};

/// Result of the checks that run before the decision backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Screening {
    /// A block rule matched, or a `deny_path` entry did (`None`). The backend is never called.
    Rule(Option<Arc<str>>),
    /// A skip rule matched; forwarded without calling the backend.
    SkipRule(Arc<str>),
    /// A static asset request; forwarded without calling the backend.
    Skip,
    /// Nothing matched; the backend decides.
    Inspect,
}

/// Percent-decodes a raw request path once and removes dot segments. Case is kept.
///
/// The result is used only for matching. The request is forwarded with its raw path.
pub(crate) fn decoded_path(raw: &str) -> String {
    let decoded = percent_encoding::percent_decode_str(raw).decode_utf8_lossy();
    remove_dot_segments(&decoded)
}

/// Normalizes a raw request path for `deny_path` and static matching: [`decoded_path`], then lowercasing.
pub(crate) fn normalized_path(raw: &str) -> String {
    decoded_path(raw).to_lowercase()
}

/// Applies RFC 3986 `remove_dot_segments` with empty segments collapsed.
///
/// Runs of `/` become one, `.` segments disappear, and `..` removes the previous
/// segment without climbing above the root. A trailing `/` is kept.
fn remove_dot_segments(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            kept => segments.push(kept),
        }
    }
    let mut normalized = format!("/{}", segments.join("/"));
    if path.ends_with('/') && !segments.is_empty() {
        normalized.push('/');
    }
    normalized
}

/// Screens a request against the site's deny paths, rules and static assets.
///
/// Block rules are checked before skip rules, so a skip rule never lets through
/// a request that a block rule matches.
pub(crate) fn screen(site: &SiteConfig, input: &RuleInput<'_>, body_is_empty: bool) -> Screening {
    let path = input.path.to_lowercase();
    if denied(site, &path) {
        return Screening::Rule(None);
    }
    if let Some(rule) = first_match(&site.rules.block, input) {
        tracing::debug!(rule = %rule.id, description = %rule.description, "rule matched");
        return Screening::Rule(Some(Arc::clone(&rule.id)));
    }
    if let Some(rule) = first_match(&site.rules.skip, input) {
        tracing::debug!(rule = %rule.id, description = %rule.description, "skip rule matched");
        return Screening::SkipRule(Arc::clone(&rule.id));
    }
    if static_skip(site, input.method, &path, input.has_query(), body_is_empty) {
        return Screening::Skip;
    }
    Screening::Inspect
}

/// Returns true when a `deny_path` entry is a prefix of `path`, which must come from [`normalized_path`].
pub(crate) fn denied(site: &SiteConfig, path: &str) -> bool {
    site.deny_paths
        .iter()
        .any(|denied| path.starts_with(denied.to_lowercase().as_str()))
}

/// Returns true when a plain read of a static asset may skip the backend.
///
/// `path` must come from [`normalized_path`].
pub(crate) fn static_skip(
    site: &SiteConfig,
    method: &Method,
    path: &str,
    has_query: bool,
    body_is_empty: bool,
) -> bool {
    let plain_read = *method == Method::GET || *method == Method::HEAD;
    plain_read && !has_query && body_is_empty && is_static_path(site, path)
}

fn is_static_path(site: &SiteConfig, path: &str) -> bool {
    let segment = path.rsplit('/').next().unwrap_or(path);
    segment.rsplit_once('.').is_some_and(|(_, extension)| {
        site.static_extensions
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(extension))
    })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use http::{HeaderMap, Method};
    use proptest::prelude::*;
    use rstest::rstest;

    use super::*;
    use crate::error::ConfigError;
    use crate::test_support::site;

    /// Screens a request with no headers and no body prefix, given its raw path.
    fn screen_path(
        site: &SiteConfig,
        method: &Method,
        raw_path: &str,
        has_query: bool,
        body_is_empty: bool,
    ) -> Screening {
        let headers = HeaderMap::new();
        let query = has_query.then_some("x=1");
        let client = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let input = RuleInput::new(method, raw_path, query, &headers, &[], client);
        screen(site, &input, body_is_empty)
    }

    #[rstest]
    #[case::plain("/xmlrpc.php", "/xmlrpc.php")]
    #[case::percent_encoded_letter("/%78mlrpc.php", "/xmlrpc.php")]
    #[case::uppercase_path("/XMLRPC.PHP", "/xmlrpc.php")]
    #[case::uppercase_escape("/%78MLRPC.php", "/xmlrpc.php")]
    #[case::longer_path("/xmlrpc.php/extra", "/xmlrpc.php/extra")]
    fn deny_rule_matches_after_one_decode_and_lowercase(
        #[case] raw: &str,
        #[case] expected_path: &str,
    ) -> Result<(), ConfigError> {
        let config = site("deny_path /xmlrpc.php;")?;
        let path = normalized_path(raw);
        assert_eq!(path, expected_path);
        assert_eq!(
            screen_path(&config, &Method::GET, &path, false, true),
            Screening::Rule(None)
        );
        Ok(())
    }

    #[test]
    fn deny_rule_is_not_applied_to_other_paths() -> Result<(), ConfigError> {
        let config = site("deny_path /xmlrpc.php;")?;
        assert_eq!(
            screen_path(&config, &Method::POST, "/index.php", false, false),
            Screening::Inspect
        );
        Ok(())
    }

    #[test]
    fn percent_decoding_happens_only_once() {
        assert_eq!(normalized_path("/%2578"), "/%78");
    }

    #[rstest]
    #[case::double_slash("//xmlrpc.php", "/xmlrpc.php")]
    #[case::dot_segment("/./xmlrpc.php", "/xmlrpc.php")]
    #[case::parent_segment("/foo/../xmlrpc.php", "/xmlrpc.php")]
    #[case::encoded_dot_segment("/%2e/xmlrpc.php", "/xmlrpc.php")]
    #[case::trailing_dot("/xmlrpc.php/.", "/xmlrpc.php")]
    #[case::parent_cannot_climb_above_root("/../../xmlrpc.php", "/xmlrpc.php")]
    #[case::encoded_slash_and_dots("/a%2F..%2Fxmlrpc.php", "/xmlrpc.php")]
    #[case::trailing_slash_is_kept("/style.css/", "/style.css/")]
    #[case::root_stays_root("/./", "/")]
    fn normalized_path_resolves_dot_segments_and_empty_segments(
        #[case] raw: &str,
        #[case] expected: &str,
    ) {
        assert_eq!(normalized_path(raw), expected);
    }

    #[rstest]
    #[case::double_slash("//xmlrpc.php")]
    #[case::dot_segment("/./xmlrpc.php")]
    #[case::parent_segment("/foo/../xmlrpc.php")]
    #[case::encoded_dot_segment("/%2e/xmlrpc.php")]
    #[case::trailing_dot("/xmlrpc.php/.")]
    #[case::encoded_slash_and_dots("/a%2F..%2Fxmlrpc.php")]
    fn deny_rule_cannot_be_bypassed_with_path_tricks(#[case] raw: &str) -> Result<(), ConfigError> {
        let config = site("deny_path /xmlrpc.php;")?;
        let path = normalized_path(raw);
        assert_eq!(
            screen_path(&config, &Method::POST, &path, false, true),
            Screening::Rule(None)
        );
        Ok(())
    }

    proptest! {
        #[test]
        fn remove_dot_segments_is_idempotent(path in "[a-z./]{0,30}") {
            let once = remove_dot_segments(&path);
            prop_assert_eq!(remove_dot_segments(&once), once.clone());
        }

        #[test]
        fn normalized_path_is_idempotent_without_escapes(raw in "[a-zA-Z0-9./-]{0,40}") {
            let once = normalized_path(&raw);
            prop_assert_eq!(normalized_path(&once), once.clone());
        }

        #[test]
        fn normalized_path_has_no_empty_or_dot_segments(raw in "[a-zA-Z0-9./%-]{0,40}") {
            let normalized = normalized_path(&raw);
            prop_assert!(normalized.starts_with('/'));
            prop_assert!(!normalized.contains("//"));
            prop_assert!(!normalized.contains("/./"));
            prop_assert!(!normalized.contains("/../"));
        }
    }

    #[rstest]
    #[case::css(Method::GET, "/style.css", false, true, Screening::Skip)]
    #[case::head(Method::HEAD, "/app.js", false, true, Screening::Skip)]
    #[case::uppercase_extension(Method::GET, "/image.png", false, true, Screening::Skip)]
    #[case::encoded_dot(Method::GET, "/style%2ecss", false, true, Screening::Skip)]
    #[case::woff2(Method::GET, "/font.woff2", false, true, Screening::Skip)]
    #[case::query_string_blocks_skip(Method::GET, "/style.css", true, true, Screening::Inspect)]
    #[case::post_blocks_skip(Method::POST, "/style.css", false, true, Screening::Inspect)]
    #[case::body_blocks_skip(Method::GET, "/app.js", false, false, Screening::Inspect)]
    #[case::html_is_inspected(Method::GET, "/page.html", false, true, Screening::Inspect)]
    #[case::trailing_slash_is_inspected(
        Method::GET,
        "/style.css/",
        false,
        true,
        Screening::Inspect
    )]
    #[case::no_extension(Method::GET, "/readme", false, true, Screening::Inspect)]
    fn static_skip_requires_a_plain_read_of_a_static_path(
        #[case] method: Method,
        #[case] raw_path: &str,
        #[case] has_query: bool,
        #[case] body_is_empty: bool,
        #[case] expected: Screening,
    ) -> Result<(), ConfigError> {
        let config = site("")?;
        let path = normalized_path(raw_path);
        assert_eq!(
            screen_path(&config, &method, &path, has_query, body_is_empty),
            expected
        );
        Ok(())
    }

    #[test]
    fn deny_rule_takes_precedence_over_static_skip() -> Result<(), ConfigError> {
        let config = site("deny_path /assets/;")?;
        assert_eq!(
            screen_path(&config, &Method::GET, "/assets/app.js", false, true),
            Screening::Rule(None)
        );
        Ok(())
    }
}
