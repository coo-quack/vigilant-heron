//! The pure decision table that turns screening and verdicts into an action.

use http::HeaderValue;

use crate::config::{Mode, SiteAction, SiteConfig};
use crate::decision::Verdict;

/// What the proxy does with a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Action {
    /// Forward the request to the upstream.
    Allow,
    /// Respond with 403.
    Block,
    /// Respond with 302 and this `Location` value.
    Redirect(HeaderValue),
}

impl Action {
    /// Returns the name used in logs and the debug header.
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
            Self::Redirect(_) => "redirect",
        }
    }
}

/// Why the action was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reason {
    /// A deny rule matched.
    Rule,
    /// The verdict reached a threshold.
    Model,
    /// The backend failed on a path that must fail closed.
    FailClosed,
    /// The backend failed on an ordinary path.
    FailOpen,
    /// A static asset skipped the backend.
    Skip,
    /// The verdict stayed below both thresholds.
    BelowThreshold,
}

impl Reason {
    /// Returns the name used in logs and the debug header.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Rule => "rule",
            Self::Model => "model",
            Self::FailClosed => "fail_closed",
            Self::FailOpen => "fail_open",
            Self::Skip => "skip",
            Self::BelowThreshold => "below_threshold",
        }
    }
}

/// Input to the decision table.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Assessment {
    /// A deny rule matched; the backend was not called.
    Rule,
    /// A static asset skipped the backend.
    Skip,
    /// The backend returned a verdict.
    Model(Verdict),
    /// The backend failed or timed out.
    ModelFailed,
}

/// The result of applying the decision table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Decision {
    /// The action taken, after shadow mode is applied.
    pub(crate) action: Action,
    /// Why the action was chosen.
    pub(crate) reason: Reason,
    /// In shadow mode, the non-allow action that would have been taken.
    pub(crate) would_have: Option<Action>,
}

/// Applies the decision table to one request.
///
/// `path` must come from [`crate::prefilter::normalized_path`].
pub(crate) fn decide(site: &SiteConfig, path: &str, assessment: &Assessment) -> Decision {
    let (intended, reason) = match assessment {
        Assessment::Rule => (site_action(site), Reason::Rule),
        Assessment::Skip => (Action::Allow, Reason::Skip),
        Assessment::Model(verdict) if exceeds_thresholds(site, verdict) => {
            (site_action(site), Reason::Model)
        }
        Assessment::Model(_) => (Action::Allow, Reason::BelowThreshold),
        Assessment::ModelFailed if fails_closed(site, path) => {
            (site_action(site), Reason::FailClosed)
        }
        Assessment::ModelFailed => (Action::Allow, Reason::FailOpen),
    };
    match site.mode {
        Mode::Enforce => Decision {
            action: intended,
            reason,
            would_have: None,
        },
        Mode::Shadow => {
            let would_have = (intended != Action::Allow).then_some(intended);
            Decision {
                action: Action::Allow,
                reason,
                would_have,
            }
        }
    }
}

fn site_action(site: &SiteConfig) -> Action {
    match &site.action {
        SiteAction::Block => Action::Block,
        SiteAction::Redirect(location) => Action::Redirect(location.clone()),
    }
}

fn exceeds_thresholds(site: &SiteConfig, verdict: &Verdict) -> bool {
    verdict.attack.value() >= site.block_threshold
        || verdict.ai_instruction.value() >= site.instruction_threshold
}

fn fails_closed(site: &SiteConfig, path: &str) -> bool {
    site.fail_closed_paths
        .iter()
        .any(|prefix| path.starts_with(prefix.to_lowercase().as_str()))
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::decision::verdict;
    use crate::error::ConfigError;
    use crate::prefilter::normalized_path;
    use crate::test_support::site;

    const REDIRECT: &str = "action = \"redirect\"\nredirect_to = \"https://example.com/blocked\"";
    const FAIL_CLOSED: &str = "fail_closed_paths = [\"/WP-LOGIN.php\"]";
    const SHADOW: &str = "mode = \"shadow\"";

    fn fields(parts: &[&str]) -> String {
        parts.join("\n")
    }

    #[rstest]
    #[case::rule_blocks(fields(&[]), Assessment::Rule, "/x", "block", Reason::Rule, None)]
    #[case::rule_redirects(fields(&[REDIRECT]), Assessment::Rule, "/x", "redirect", Reason::Rule, None)]
    #[case::rule_in_shadow_is_allowed(fields(&[SHADOW]), Assessment::Rule, "/x", "allow", Reason::Rule, Some("block"))]
    #[case::skip_is_allowed(fields(&[]), Assessment::Skip, "/x.css", "allow", Reason::Skip, None)]
    #[case::attack_at_threshold_blocks(fields(&[]), Assessment::Model(verdict(0.9, 0.0)), "/x", "block", Reason::Model, None)]
    #[case::attack_just_below_threshold_allows(fields(&[]), Assessment::Model(verdict(0.8999, 0.0)), "/x", "allow", Reason::BelowThreshold, None)]
    #[case::instruction_at_threshold_blocks(fields(&[]), Assessment::Model(verdict(0.0, 0.5)), "/x", "block", Reason::Model, None)]
    #[case::instruction_just_below_threshold_allows(fields(&[]), Assessment::Model(verdict(0.0, 0.4999)), "/x", "allow", Reason::BelowThreshold, None)]
    #[case::attack_above_threshold_redirects(fields(&[REDIRECT]), Assessment::Model(verdict(1.0, 0.0)), "/x", "redirect", Reason::Model, None)]
    #[case::low_scores_redirect_site_allows(fields(&[REDIRECT]), Assessment::Model(verdict(0.1, 0.1)), "/x", "allow", Reason::BelowThreshold, None)]
    #[case::attack_in_shadow_records_block(fields(&[SHADOW]), Assessment::Model(verdict(0.95, 0.0)), "/x", "allow", Reason::Model, Some("block"))]
    #[case::attack_in_shadow_records_redirect(fields(&[SHADOW, REDIRECT]), Assessment::Model(verdict(0.95, 0.0)), "/x", "allow", Reason::Model, Some("redirect"))]
    #[case::low_scores_in_shadow_record_nothing(fields(&[SHADOW]), Assessment::Model(verdict(0.1, 0.1)), "/x", "allow", Reason::BelowThreshold, None)]
    #[case::failure_on_fail_closed_path_blocks(fields(&[FAIL_CLOSED]), Assessment::ModelFailed, "/wp-login.php/slow", "block", Reason::FailClosed, None)]
    #[case::failure_on_fail_closed_path_is_case_insensitive(fields(&[FAIL_CLOSED]), Assessment::ModelFailed, "/wp-login.php", "block", Reason::FailClosed, None)]
    #[case::failure_on_fail_closed_path_redirects(fields(&[FAIL_CLOSED, REDIRECT]), Assessment::ModelFailed, "/wp-login.php", "redirect", Reason::FailClosed, None)]
    #[case::failure_on_ordinary_path_allows(fields(&[FAIL_CLOSED]), Assessment::ModelFailed, "/index.php", "allow", Reason::FailOpen, None)]
    #[case::failure_on_fail_closed_path_in_shadow(fields(&[FAIL_CLOSED, SHADOW]), Assessment::ModelFailed, "/wp-login.php", "allow", Reason::FailClosed, Some("block"))]
    #[case::failure_on_ordinary_path_in_shadow(fields(&[FAIL_CLOSED, SHADOW]), Assessment::ModelFailed, "/index.php", "allow", Reason::FailOpen, None)]
    fn decision_table(
        #[case] site_fields: String,
        #[case] assessment: Assessment,
        #[case] path: &str,
        #[case] expected_action: &str,
        #[case] expected_reason: Reason,
        #[case] expected_would_have: Option<&str>,
    ) -> Result<(), ConfigError> {
        let config = site(&site_fields)?;
        let decision = decide(&config, path, &assessment);
        assert_eq!(decision.action.name(), expected_action);
        assert_eq!(decision.reason, expected_reason);
        assert_eq!(
            decision.would_have.as_ref().map(Action::name),
            expected_would_have
        );
        Ok(())
    }

    #[rstest]
    #[case::double_slash("//wp-login.php")]
    #[case::dot_segment("/./wp-login.php/slow")]
    #[case::parent_segment("/x/../wp-login.php")]
    #[case::encoded_dot_segment("/%2e/wp-login.php")]
    fn fail_closed_applies_after_path_normalization(#[case] raw: &str) -> Result<(), ConfigError> {
        let config = site(&fields(&[FAIL_CLOSED]))?;
        let decision = decide(&config, &normalized_path(raw), &Assessment::ModelFailed);
        assert_eq!(decision.reason, Reason::FailClosed);
        assert_eq!(decision.action, Action::Block);
        Ok(())
    }

    #[test]
    fn redirect_action_carries_the_location() -> Result<(), ConfigError> {
        let config = site(&fields(&[REDIRECT]))?;
        let decision = decide(&config, "/x", &Assessment::Rule);
        assert_eq!(
            decision.action,
            Action::Redirect(http::HeaderValue::from_static(
                "https://example.com/blocked"
            ))
        );
        Ok(())
    }

    #[test]
    fn shadow_mode_never_leaves_an_attack_unforwarded() -> Result<(), ConfigError> {
        let config = site(&fields(&[SHADOW, REDIRECT]))?;
        for assessment in [
            Assessment::Rule,
            Assessment::Model(verdict(1.0, 1.0)),
            Assessment::ModelFailed,
        ] {
            let decision = decide(&config, "/wp-login.php", &assessment);
            assert_eq!(decision.action, Action::Allow);
        }
        Ok(())
    }
}
