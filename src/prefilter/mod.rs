//! Checks that need no model, in the order they run: `deny_path`, block rules,
//! skip rules and the static asset skip.
//!
//! The access list is checked before this module, and the decision model after it.
//!
//! Security checks read the request path in several ways, see [`path_views`]. The
//! request is forwarded with its raw path, so only the matching is affected.

mod paths;
mod static_skip;
#[cfg(test)]
mod test_helpers;

use std::sync::Arc;

use crate::config::SiteConfig;
use crate::rules::{RuleInput, first_match, first_skip_match};

pub(crate) use paths::{decode_twice, decoded_path, path_views};
use static_skip::static_skip;

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

/// Screens a request against the site's deny paths, rules and static assets.
///
/// `lowered` are the lowercase path views of the request, see [`path_views`]. The caller
/// computes them once and passes the same ones to the policy.
///
/// Block rules are checked before skip rules, so a skip rule never lets through
/// a request that a block rule matches.
pub(crate) fn screen(
    site: &SiteConfig,
    input: &RuleInput<'_>,
    lowered: &[String],
    body_is_empty: bool,
) -> Screening {
    if denied(site, lowered) {
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
    if static_skip(site, input, lowered, body_is_empty) {
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
    site.fail_closed_lowered
        .iter()
        .any(|prefix| views.iter().any(|view| view.starts_with(prefix.as_str())))
}

#[cfg(test)]
mod tests {
    use http::Method;
    use proptest::prelude::*;
    use rstest::rstest;

    use super::*;
    use crate::error::ConfigError;
    use crate::prefilter::test_helpers::{screen_path, screen_query};
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
    fn a_block_rule_still_runs_before_a_static_skip_with_a_bare_token() -> Result<(), ConfigError> {
        let config = site(
            "static_query_token on;\n    rule block-tinymce {\n        description \"blocked\";\n        action block;\n        path /wp-tinymce.js;\n    }",
        )?;
        assert_eq!(
            screen_query(&config, "/wp-tinymce.js", "wp-mce-1"),
            Screening::Rule(Some(Arc::from("block-tinymce")))
        );
        assert_eq!(
            screen_query(&config, "/app.js", "wp-mce-1"),
            Screening::Skip
        );
        Ok(())
    }

    #[test]
    fn a_block_rule_still_runs_before_a_static_skip_with_a_cache_buster() -> Result<(), ConfigError>
    {
        let config = site(
            "static_query_params ver;\n    rule no-old-jquery {\n        description \"old jquery\";\n        action block;\n        query ~ \"^ver=1\\.\";\n    }",
        )?;
        assert_eq!(
            screen_query(&config, "/jquery.js", "ver=1.12.4"),
            Screening::Rule(Some(Arc::from("no-old-jquery")))
        );
        assert_eq!(
            screen_query(&config, "/jquery.js", "ver=3.7.1"),
            Screening::Skip
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
    }
}
