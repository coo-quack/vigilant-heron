//! Checks that need no model: rule blocks and static asset skips.

use http::Method;

use crate::config::SiteConfig;

/// Result of the checks that run before the decision backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Screening {
    /// A `deny_paths` entry matched; the backend is never called.
    Rule,
    /// A static asset request; forwarded without calling the backend.
    Skip,
    /// Nothing matched; the backend decides.
    Inspect,
}

/// Normalizes a raw request path for matching: one percent-decode, dot-segment
/// removal, then lowercasing.
///
/// The result is used only for matching. The request is forwarded with its raw path.
pub(crate) fn normalized_path(raw: &str) -> String {
    let decoded = percent_encoding::percent_decode_str(raw).decode_utf8_lossy();
    remove_dot_segments(&decoded).to_lowercase()
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

/// Screens a request against the site's rules.
///
/// `path` must come from [`normalized_path`].
pub(crate) fn screen(
    site: &SiteConfig,
    method: &Method,
    path: &str,
    has_query: bool,
    body_is_empty: bool,
) -> Screening {
    if site
        .deny_paths
        .iter()
        .any(|denied| path.starts_with(denied.to_lowercase().as_str()))
    {
        return Screening::Rule;
    }
    let plain_read = *method == Method::GET || *method == Method::HEAD;
    if plain_read && !has_query && body_is_empty && is_static_path(site, path) {
        return Screening::Skip;
    }
    Screening::Inspect
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
    use http::Method;
    use proptest::prelude::*;
    use rstest::rstest;

    use super::*;
    use crate::error::ConfigError;
    use crate::test_support::site;

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
        let config = site("deny_paths = [\"/xmlrpc.php\"]")?;
        let path = normalized_path(raw);
        assert_eq!(path, expected_path);
        assert_eq!(
            screen(&config, &Method::GET, &path, false, true),
            Screening::Rule
        );
        Ok(())
    }

    #[test]
    fn deny_rule_is_not_applied_to_other_paths() -> Result<(), ConfigError> {
        let config = site("deny_paths = [\"/xmlrpc.php\"]")?;
        assert_eq!(
            screen(&config, &Method::POST, "/index.php", false, false),
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
        let config = site("deny_paths = [\"/xmlrpc.php\"]")?;
        let path = normalized_path(raw);
        assert_eq!(
            screen(&config, &Method::POST, &path, false, true),
            Screening::Rule
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
            screen(&config, &method, &path, has_query, body_is_empty),
            expected
        );
        Ok(())
    }

    #[test]
    fn deny_rule_takes_precedence_over_static_skip() -> Result<(), ConfigError> {
        let config = site("deny_paths = [\"/assets/\"]")?;
        assert_eq!(
            screen(&config, &Method::GET, "/assets/app.js", false, true),
            Screening::Rule
        );
        Ok(())
    }
}
