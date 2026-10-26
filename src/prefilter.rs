//! Checks that need no model, in the order they run: `deny_path`, block rules,
//! skip rules and the static asset skip.
//!
//! The access list is checked before this module, and the decision model after it.
//!
//! Security checks read the request path in several ways, see [`path_views`]. The
//! request is forwarded with its raw path, so only the matching is affected.

use std::borrow::Cow;
use std::sync::Arc;

use http::Method;
use percent_encoding::percent_decode_str;

use crate::config::SiteConfig;
use crate::rules::{RuleInput, first_match, first_skip_match};

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

/// Extensions of scripts that run for a path. A static skip never applies when one
/// of them is in an earlier segment, as in `/index.php/x.css`.
const DYNAMIC_EXTENSIONS: [&str; 10] = [
    "php", "phtml", "jsp", "jspx", "asp", "aspx", "cgi", "pl", "py", "rb",
];

/// Raw path text that makes a path unsafe for a static skip: a parameter separator,
/// a backslash, or an encoded `/`, `\` or `;`. Compared in lowercase.
const UNSAFE_RAW_MARKERS: [&str; 5] = [";", "\\", "%2f", "%5c", "%3b"];

/// The ways the request path is read by the security checks.
///
/// Upstreams differ: a servlet container drops `;params` from each segment, IIS
/// takes `\` as a separator, and Express matches the raw path, where `%2F` is not a
/// separator. Each reading is one of these, and a security decision takes the
/// strictest outcome over all of them. The list, in order:
///
/// 1. The path percent-decoded once, dot segments resolved on `/`.
/// 2. As 1, with each segment cut at its first `;`.
/// 3. As 1, with `\` read as `/`.
/// 4. As 2 and 3 together.
/// 5. The raw path, dot segments resolved on `/` only (`%2F` and `%5C` are not
///    separators), then percent-decoded once.
/// 6. As 5, with `;` params cut and `\` read as `/`.
///
/// Duplicates are removed, so a path with no tricks has one view. The returned
/// views keep their case; NUL bytes are removed from each.
pub(crate) fn path_views(raw: &str) -> Vec<String> {
    let mut views: Vec<String> = Vec::with_capacity(6);
    let decoded = [(false, false), (true, false), (false, true), (true, true)];
    let raw_forms = [(false, false), (true, true)];
    let all = decoded
        .into_iter()
        .map(|(strip, backslash)| decoded_view(raw, strip, backslash))
        .chain(
            raw_forms
                .into_iter()
                .map(|(strip, backslash)| raw_view(raw, strip, backslash)),
        );
    for view in all {
        let view = view.replace('\0', "");
        if !views.contains(&view) {
            views.push(view);
        }
    }
    views
}

/// Percent-decodes a raw request path once and removes dot segments. Case is kept.
///
/// This is view 1 of [`path_views`]. The result is used only for matching. The
/// request is forwarded with its raw path.
pub(crate) fn decoded_path(raw: &str) -> String {
    decoded_view(raw, false, false)
}

/// Views 1 to 4: decode once, read `\` as `/` when `backslash`, resolve dot segments, cut
/// segments at `;` when `strip`.
fn decoded_view(raw: &str, strip: bool, backslash: bool) -> String {
    let decoded = percent_decode_lossy(raw);
    let text = if backslash {
        decoded.replace('\\', "/")
    } else {
        decoded.into_owned()
    };
    remove_dot_segments(&text, strip)
}

/// Views 5 and 6: resolve dot segments on the raw text, then decode once. Only `/`
/// (and `\` when `backslash`) separates segments, so an encoded separator stays inside
/// its segment.
fn raw_view(raw: &str, strip: bool, backslash: bool) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for segment in raw.split(|c: char| c == '/' || (backslash && c == '\\')) {
        let segment = if strip {
            segment.split(';').next().unwrap_or_default()
        } else {
            segment
        };
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            kept => segments.push(kept),
        }
    }
    let joined = format!("/{}", segments.join("/"));
    percent_decode_lossy(&joined).into_owned()
}

/// Decodes the percent escapes of `raw` once; bytes that are not valid UTF-8 become U+FFFD.
pub(crate) fn percent_decode_lossy(raw: &str) -> Cow<'_, str> {
    percent_decode_str(raw).decode_utf8_lossy()
}

/// Applies RFC 3986 `remove_dot_segments` with empty segments collapsed.
///
/// Runs of `/` become one, `.` segments disappear, and `..` removes the previous
/// segment without climbing above the root. A trailing `/` is kept. With `strip`,
/// each segment is cut at its first `;` before it is judged, so `..;` is `..`.
fn remove_dot_segments(path: &str, strip: bool) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        let segment = if strip {
            segment.split(';').next().unwrap_or_default()
        } else {
            segment
        };
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
    let lowered: Vec<String> = input.paths.iter().map(|path| path.to_lowercase()).collect();
    if denied(site, &lowered) {
        return Screening::Rule(None);
    }
    if let Some(rule) = first_match(&site.rules.block, input) {
        tracing::debug!(rule = %rule.id, description = %rule.description, "rule matched");
        return Screening::Rule(Some(Arc::clone(&rule.id)));
    }
    if let Some(rule) = first_skip_match(&site.rules.skip, input) {
        tracing::debug!(rule = %rule.id, description = %rule.description, "skip rule matched");
        return Screening::SkipRule(Arc::clone(&rule.id));
    }
    if static_skip(site, input, &lowered, body_is_empty) {
        return Screening::Skip;
    }
    Screening::Inspect
}

/// Returns true when a `deny_path` entry is a prefix of any view. Views must be lowercase.
///
/// Any view matching is a denial, so an interpretation the upstream may use cannot escape it.
pub(crate) fn denied(site: &SiteConfig, views: &[String]) -> bool {
    denied_by(site, views).is_some()
}

/// Returns the first `deny_path` entry, as configured, that is a prefix of any view. Views must be lowercase.
pub(crate) fn denied_by<'a>(site: &'a SiteConfig, views: &[String]) -> Option<&'a str> {
    site.deny_paths
        .iter()
        .zip(&site.deny_paths_lowered)
        .find(|(_, prefix)| views.iter().any(|view| view.starts_with(prefix.as_str())))
        .map(|(denied, _)| denied.as_str())
}

/// Returns true when a `fail_closed_path` entry is a prefix of any view. Views must be lowercase.
pub(crate) fn fails_closed(site: &SiteConfig, views: &[String]) -> bool {
    site.fail_closed_paths.iter().any(|prefix| {
        let prefix = prefix.to_lowercase();
        views.iter().any(|view| view.starts_with(prefix.as_str()))
    })
}

/// Returns true when a plain read of a static asset may skip the backend.
///
/// Every condition must hold:
///
/// - a GET or HEAD with no query, no body and the raw path free of `;`, `\`, `%2F`,
///   `%5C` and `%3B` (case-insensitive);
/// - under a `static_location` prefix, when the site sets any: every view starts with one;
/// - in every view, the last segment has a static extension and no earlier segment
///   has a script extension;
/// - no `fail_closed_path` matches any view.
///
/// `views` must be the lowercase views of the request path.
pub(crate) fn static_skip(
    site: &SiteConfig,
    input: &RuleInput<'_>,
    views: &[String],
    body_is_empty: bool,
) -> bool {
    let plain_read = *input.method == Method::GET || *input.method == Method::HEAD;
    if !(plain_read && !input.has_query() && body_is_empty) {
        return false;
    }
    let raw = input.raw_path.to_ascii_lowercase();
    if UNSAFE_RAW_MARKERS.iter().any(|marker| raw.contains(marker)) {
        return false;
    }
    if !site.static_locations.is_empty()
        && !views.iter().all(|view| {
            site.static_locations
                .iter()
                .any(|prefix| view.starts_with(prefix.as_str()))
        })
    {
        return false;
    }
    views.iter().all(|view| is_static_view(site, view)) && !fails_closed(site, views)
}

/// Returns true when a lowercase view ends in a static extension and no earlier segment
/// ends in a script extension.
fn is_static_view(site: &SiteConfig, path: &str) -> bool {
    let mut segments = path.split('/').rev();
    let last = segments.next().unwrap_or_default();
    let static_last = extension(last).is_some_and(|extension| {
        site.static_extensions
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(extension))
    });
    let dynamic_earlier = segments.any(|segment| {
        extension(segment).is_some_and(|extension| DYNAMIC_EXTENSIONS.contains(&extension))
    });
    static_last && !dynamic_earlier
}

/// The text after the last `.` of a segment.
fn extension(segment: &str) -> Option<&str> {
    segment.rsplit_once('.').map(|(_, extension)| extension)
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

    /// The lowercase views of a raw path, as the pipeline passes them to the checks.
    fn lower_views(raw: &str) -> Vec<String> {
        path_views(raw)
            .iter()
            .map(|view| view.to_lowercase())
            .collect()
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
        assert_eq!(decoded_path(raw).to_lowercase(), expected_path);
        assert_eq!(
            screen_path(&config, &Method::GET, raw, false, true),
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
        assert_eq!(decoded_path("/%2578"), "/%78");
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
    fn decoded_path_resolves_dot_segments_and_empty_segments(
        #[case] raw: &str,
        #[case] expected: &str,
    ) {
        assert_eq!(decoded_path(raw), expected);
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
        assert_eq!(
            screen_path(&config, &Method::POST, raw, false, true),
            Screening::Rule(None)
        );
        Ok(())
    }

    /// The exploit paths of the security review: each must be denied by `deny_path`.
    #[rstest]
    #[case::semicolon_segment("deny_path /actuator;", "/;/actuator/env")]
    #[case::dot_dot_semicolon("deny_path /actuator;", "/static/..;/actuator/env")]
    #[case::dot_dot_semicolon_manager("deny_path /manager;", "/x/..;/manager/html")]
    #[case::encoded_semicolon("deny_path /actuator;", "/%3Bjunk/actuator/env")]
    #[case::backslash_parent("deny_path /admin;", "/x\\..\\admin")]
    #[case::encoded_slash_parent("deny_path /admin;", "/admin/1%2F..%2F..%2Fy")]
    #[case::encoded_slash_lower_case("deny_path /admin;", "/ADMIN%2F..%2Fx")]
    fn deny_path_holds_for_every_reading_of_the_path(
        #[case] fields: &str,
        #[case] raw: &str,
    ) -> Result<(), ConfigError> {
        let config = site(fields)?;
        assert_eq!(
            screen_path(&config, &Method::GET, raw, false, true),
            Screening::Rule(None),
            "{raw}"
        );
        Ok(())
    }

    #[test]
    fn path_views_hold_each_reading_of_the_path() {
        assert_eq!(path_views("/plain"), ["/plain"]);
        assert!(path_views("/login;x").contains(&"/login".to_owned()));
        assert!(path_views("/x\\..\\admin").contains(&"/admin".to_owned()));
        assert!(path_views("/admin/1%2F..%2F..%2Fy").contains(&"/admin/1/../../y".to_owned()));
    }

    proptest! {
        #[test]
        fn remove_dot_segments_is_idempotent(path in "[a-z./]{0,30}") {
            let once = remove_dot_segments(&path, false);
            prop_assert_eq!(remove_dot_segments(&once, false), once.clone());
        }

        #[test]
        fn decoded_path_is_idempotent_without_escapes(raw in "[a-zA-Z0-9./-]{0,40}") {
            let once = decoded_path(&raw);
            prop_assert_eq!(decoded_path(&once), once.clone());
        }

        #[test]
        fn decoded_path_has_no_empty_or_dot_segments(raw in "[a-zA-Z0-9./%-]{0,40}") {
            let normalized = decoded_path(&raw);
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
    // Parameters, backslashes and encoded separators make the static skip unsafe.
    #[case::number_with_parameter_and_css(
        Method::GET,
        "/api/items/1%20or%201=1;.css",
        false,
        true,
        Screening::Inspect
    )]
    #[case::semicolon_before_extension(Method::GET, "/x;.css", false, true, Screening::Inspect)]
    #[case::backslash(Method::GET, "/a\\b.css", false, true, Screening::Inspect)]
    #[case::encoded_slash(Method::GET, "/a%2Fb.css", false, true, Screening::Inspect)]
    #[case::encoded_backslash(Method::GET, "/a%5cb.css", false, true, Screening::Inspect)]
    #[case::encoded_semicolon(Method::GET, "/a%3Bb.css", false, true, Screening::Inspect)]
    // A script earlier in the path serves the request as PATH_INFO.
    #[case::path_info_of_a_script(Method::GET, "/index.php/x.css", false, true, Screening::Inspect)]
    #[case::path_info_of_an_aspx_page(
        Method::GET,
        "/app.aspx/x.woff2",
        false,
        true,
        Screening::Inspect
    )]
    fn static_skip_requires_a_plain_read_of_a_static_path(
        #[case] method: Method,
        #[case] raw_path: &str,
        #[case] has_query: bool,
        #[case] body_is_empty: bool,
        #[case] expected: Screening,
    ) -> Result<(), ConfigError> {
        let config = site("")?;
        assert_eq!(
            screen_path(&config, &method, raw_path, has_query, body_is_empty),
            expected,
            "{raw_path}"
        );
        Ok(())
    }

    #[test]
    fn a_fail_closed_path_ending_in_a_static_extension_is_inspected() -> Result<(), ConfigError> {
        let config = site("fail_closed_path /api/x.css;")?;
        assert_eq!(
            screen_path(&config, &Method::GET, "/api/x.css", false, true),
            Screening::Inspect
        );
        assert_eq!(
            screen_path(&config, &Method::GET, "/other/x.css", false, true),
            Screening::Skip
        );
        Ok(())
    }

    #[rstest]
    #[case::inside_the_prefix("/static/a.css", Screening::Skip)]
    #[case::outside_the_prefix("/img/a.css", Screening::Inspect)]
    #[case::dot_dot_leaves_the_prefix("/static/..;/img/a.css", Screening::Inspect)]
    fn static_location_limits_the_static_skip(
        #[case] raw: &str,
        #[case] expected: Screening,
    ) -> Result<(), ConfigError> {
        let config = site("static_location /static/;")?;
        assert_eq!(
            screen_path(&config, &Method::GET, raw, false, true),
            expected
        );
        Ok(())
    }

    #[test]
    fn a_skip_rule_path_must_hold_for_every_reading() -> Result<(), ConfigError> {
        let config = site(
            "rule skip-static {\n    description \"static\";\n    action skip;\n    path /static/;\n}\n",
        )?;
        assert_eq!(
            screen_path(&config, &Method::POST, "/static/x", false, true),
            Screening::SkipRule(Arc::from("skip-static"))
        );
        assert_eq!(
            screen_path(&config, &Method::POST, "/static/..;/admin/x", false, true),
            Screening::Inspect
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

    proptest! {
        /// A segment of a generated path: plain, dot, parameter, backslash or encoded separator.
        #[test]
        fn adding_a_deny_prefix_never_turns_a_block_into_an_allow(
            segments in proptest::collection::vec(
                prop_oneof![
                    Just("a"), Just(".."), Just("."), Just(";x"), Just("..;"), Just("\\"),
                    Just("%2F"), Just("%5C"), Just("admin"), Just("login.css"), Just("x.php"),
                ],
                1..6,
            ),
            extra in prop_oneof![Just("/a"), Just("/admin/1"), Just("/x"), Just("/login")],
        ) {
            let raw = format!("/{}", segments.join("/"));
            let narrow = site("deny_path /admin;").map_err(|error| TestCaseError::fail(error.to_string()))?;
            let wide = site(&format!("deny_path /admin;\ndeny_path {extra};"))
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
            let before = screen_path(&narrow, &Method::GET, &raw, false, true);
            let after = screen_path(&wide, &Method::GET, &raw, false, true);
            if before == Screening::Rule(None) {
                prop_assert_eq!(after, Screening::Rule(None));
            }
        }

        /// The static skip never applies unless every reading of the path is static.
        #[test]
        fn static_skip_needs_every_reading_to_be_static(
            segments in proptest::collection::vec(
                prop_oneof![
                    Just("a"), Just(".."), Just("."), Just(";x"), Just("..;"), Just("\\"),
                    Just("%2F"), Just("%5C"), Just("%3B"), Just("index.php"), Just("x.css"), Just("y.js"),
                ],
                1..6,
            ),
        ) {
            let raw = format!("/{}", segments.join("/"));
            let config = site("").map_err(|error| TestCaseError::fail(error.to_string()))?;
            if screen_path(&config, &Method::GET, &raw, false, true) == Screening::Skip {
                for view in lower_views(&raw) {
                    prop_assert!(is_static_view(&config, &view), "{raw} as {view}");
                }
            }
        }
    }
}
