//! The readings of a request path that the security checks use, and the percent-decoding that
//! the path views and the rule inputs share.

use std::borrow::Cow;

use percent_encoding::percent_decode_str;

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

/// Percent-decodes a raw request path once, removes dot segments and NUL bytes. Case is kept.
///
/// This is the first view of [`path_views`], so `decoded_path(raw)` is always
/// `path_views(raw)[0]`. The result is used only for matching. The request is
/// forwarded with its raw path.
pub(crate) fn decoded_path(raw: &str) -> String {
    decoded_view(raw, false, false).replace('\0', "")
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
fn percent_decode_lossy(raw: &str) -> Cow<'_, str> {
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

/// Decodes percent escapes at most twice, so double encoding is undone too, and drops NUL bytes.
pub(crate) fn decode_twice(raw: &str) -> String {
    let once = percent_decode_lossy(raw);
    let twice = percent_decode_lossy(&once);
    twice.replace('\0', "")
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rstest::rstest;

    use super::*;

    #[test]
    fn percent_decoding_happens_only_once() {
        assert_eq!(decoded_path("/%2578"), "/%78");
    }

    #[test]
    fn nul_bytes_are_removed_from_the_decoded_path() {
        assert_eq!(decoded_path("/%00admin"), "/admin");
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

        #[test]
        fn decoded_path_is_the_first_path_view(raw in any::<String>()) {
            let views = path_views(&raw);
            let decoded = decoded_path(&raw);
            prop_assert_eq!(views.first(), Some(&decoded));
        }

        #[test]
        fn decoded_path_is_the_first_path_view_for_escape_heavy_input(
            raw in r"[a-zA-Z0-9/.%;\\]{0,40}|(%00|%2e|%2f|%3b|%5c|/|\.|;|\\){0,12}"
        ) {
            let views = path_views(&raw);
            let decoded = decoded_path(&raw);
            prop_assert_eq!(views.first(), Some(&decoded));
        }
    }
}
