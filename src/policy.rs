//! The pure decision table that turns screening and verdicts into an action.
//!
//! Deterministic rules are decided before the backend is called, so the
//! `Rule` assessment never depends on how a backend failure is configured.

use http::{HeaderValue, StatusCode};

use crate::config::{FailureAction, Mode, SiteAction, SiteConfig};
use crate::decision::Verdict;
use crate::prefilter::fails_closed;

/// What the proxy does with a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Action {
    /// Forward the request to the upstream.
    Allow,
    /// Respond with 403.
    Block,
    /// Respond with 302 and this `Location` value.
    Redirect(HeaderValue),
    /// Respond with this status, because a limit refused the request, such as a client
    /// over its share of decision calls (429). Shadow mode records it as a would-have action.
    Reject(StatusCode),
}

impl Action {
    /// Returns the name used in logs and the debug header.
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
            Self::Redirect(_) => "redirect",
            Self::Reject(_) => "reject",
        }
    }
}

/// Why the action was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reason {
    /// A deny rule matched; the backend was not called.
    Rule,
    /// The verdict reached a threshold.
    Model,
    /// A static asset or a skip rule skipped the backend.
    Skip,
    /// A skip rule matched and the backend was not called.
    SkipRule,
    /// The client is refused by the access list. The site action does not apply.
    AccessDenied,
    /// The verdict stayed below both thresholds.
    BelowThreshold,
    /// The decision failed on a `fail_closed_paths` entry, whatever the failure.
    FailClosedPath,
    /// The backend rate-limited the request and the site allows it.
    RateLimitedAllowed,
    /// The backend rate-limited the request and the site blocks it.
    RateLimitedBlocked,
    /// The client held its share of decision calls and the site allows the excess.
    ClientBusyAllowed,
    /// The client held its share of decision calls and the site refuses the excess with 429.
    ClientBusyBlocked,
    /// The decision failed for another reason and the site allows it.
    DecisionErrorAllowed,
    /// The decision failed for another reason and the site blocks it.
    DecisionErrorBlocked,
}

impl Reason {
    /// Returns the name used in logs and the debug header.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Rule => "rule",
            Self::Model => "model",
            Self::Skip => "skip",
            Self::SkipRule => "skip_rule",
            Self::AccessDenied => "access_denied",
            Self::BelowThreshold => "below_threshold",
            Self::FailClosedPath => "fail_closed_path",
            Self::RateLimitedAllowed => "rate_limited_allowed",
            Self::RateLimitedBlocked => "rate_limited_blocked",
            Self::ClientBusyAllowed => "client_busy_allowed",
            Self::ClientBusyBlocked => "client_busy_blocked",
            Self::DecisionErrorAllowed => "decision_error_allowed",
            Self::DecisionErrorBlocked => "decision_error_blocked",
        }
    }
}

/// Input to the decision table.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Assessment {
    /// A deny rule matched; the backend was not called.
    Rule,
    /// A static asset skipped the backend.
    Skip,
    /// A skip rule matched and the backend was not called.
    SkipRule,
    /// The access list refused the client before any other check.
    AccessDenied,
    /// The backend returned a verdict.
    Model(Verdict),
    /// The client already holds its `max_concurrency_per_client` share of decision calls.
    /// The backend was not called. Logged as `client_busy`, and governed by `on_client_busy`.
    ClientBusy,
    /// The backend rate-limited the request, or no local slot was free in time.
    RateLimited {
        /// Specific cause for the log, such as `rate_limited` or `backend_busy`.
        cause: &'static str,
        /// Raw `Retry-After` value, for the log only.
        retry_after: Option<String>,
    },
    /// The backend failed for any other reason.
    DecisionFailed {
        /// Specific cause for the log, such as `timeout` or `http_status`.
        cause: &'static str,
    },
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
/// `views` are the lowercase path views of the request, see [`crate::prefilter::path_views`].
pub(crate) fn decide(site: &SiteConfig, views: &[String], assessment: &Assessment) -> Decision {
    let (intended, reason) = match assessment {
        Assessment::Rule => (site_action(site), Reason::Rule),
        Assessment::Skip => (Action::Allow, Reason::Skip),
        Assessment::SkipRule => (Action::Allow, Reason::SkipRule),
        Assessment::AccessDenied => (Action::Block, Reason::AccessDenied),
        Assessment::Model(verdict) if exceeds_thresholds(site, verdict) => {
            (site_action(site), Reason::Model)
        }
        Assessment::Model(_) => (Action::Allow, Reason::BelowThreshold),
        Assessment::RateLimited { .. }
        | Assessment::ClientBusy
        | Assessment::DecisionFailed { .. } => failure_outcome(site, views, assessment),
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

/// Decides a request whose backend failed: `fail_closed_paths` always blocks, and
/// otherwise the setting for the failure group decides.
///
/// A client over its share is refused with 429 rather than the site action, whatever
/// `on_rate_limit` says, so that the two settings can differ.
fn failure_outcome(
    site: &SiteConfig,
    views: &[String],
    assessment: &Assessment,
) -> (Action, Reason) {
    if fails_closed(site, views) {
        return (site_action(site), Reason::FailClosedPath);
    }
    let (rate_limited, setting) = match assessment {
        Assessment::ClientBusy => {
            return match site.on_client_busy {
                FailureAction::Allow => (Action::Allow, Reason::ClientBusyAllowed),
                FailureAction::Block => (
                    Action::Reject(StatusCode::TOO_MANY_REQUESTS),
                    Reason::ClientBusyBlocked,
                ),
            };
        }
        Assessment::RateLimited { .. } => (true, site.on_rate_limit),
        _ => (false, site.on_decision_error),
    };
    match (rate_limited, setting) {
        (true, FailureAction::Allow) => (Action::Allow, Reason::RateLimitedAllowed),
        (true, FailureAction::Block) => (site_action(site), Reason::RateLimitedBlocked),
        (false, FailureAction::Allow) => (Action::Allow, Reason::DecisionErrorAllowed),
        (false, FailureAction::Block) => (site_action(site), Reason::DecisionErrorBlocked),
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

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::decision::verdict;
    use crate::error::ConfigError;
    use crate::prefilter::path_views;
    use crate::test_support::site;

    const REDIRECT: &str = "action redirect https://example.com/blocked;";
    const FAIL_CLOSED: &str = "fail_closed_path /WP-LOGIN.php;";
    const SHADOW: &str = "mode shadow;";

    /// The lowercase path views of a raw path, as the pipeline passes them to `decide`.
    fn views_of(raw: &str) -> Vec<String> {
        path_views(raw)
            .iter()
            .map(|view| view.to_lowercase())
            .collect()
    }

    fn fields(parts: &[&str]) -> String {
        parts.join("\n")
    }

    fn rate_limited() -> Assessment {
        Assessment::RateLimited {
            cause: "rate_limited",
            retry_after: None,
        }
    }

    fn decision_failed() -> Assessment {
        Assessment::DecisionFailed { cause: "timeout" }
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
    fn verdict_and_rule_table(
        #[case] site_fields: String,
        #[case] assessment: Assessment,
        #[case] path: &str,
        #[case] expected_action: &str,
        #[case] expected_reason: Reason,
        #[case] expected_would_have: Option<&str>,
    ) -> Result<(), ConfigError> {
        let config = site(&site_fields)?;
        let decision = decide(&config, &views_of(path), &assessment);
        assert_eq!(decision.action.name(), expected_action);
        assert_eq!(decision.reason, expected_reason);
        assert_eq!(
            decision.would_have.as_ref().map(Action::name),
            expected_would_have
        );
        Ok(())
    }

    /// Every combination of failure group, setting, fail-closed match and mode.
    #[rstest]
    // group, setting, fail_closed path matched, mode, expected action, reason, would_have
    #[case::rate_allow_open_enforce(
        "rate",
        "allow",
        false,
        "enforce",
        "allow",
        Reason::RateLimitedAllowed,
        None
    )]
    #[case::rate_allow_closed_enforce(
        "rate",
        "allow",
        true,
        "enforce",
        "block",
        Reason::FailClosedPath,
        None
    )]
    #[case::rate_block_open_enforce(
        "rate",
        "block",
        false,
        "enforce",
        "block",
        Reason::RateLimitedBlocked,
        None
    )]
    #[case::rate_block_closed_enforce(
        "rate",
        "block",
        true,
        "enforce",
        "block",
        Reason::FailClosedPath,
        None
    )]
    #[case::rate_allow_open_shadow(
        "rate",
        "allow",
        false,
        "shadow",
        "allow",
        Reason::RateLimitedAllowed,
        None
    )]
    #[case::rate_allow_closed_shadow(
        "rate",
        "allow",
        true,
        "shadow",
        "allow",
        Reason::FailClosedPath,
        Some("block")
    )]
    #[case::rate_block_open_shadow(
        "rate",
        "block",
        false,
        "shadow",
        "allow",
        Reason::RateLimitedBlocked,
        Some("block")
    )]
    #[case::rate_block_closed_shadow(
        "rate",
        "block",
        true,
        "shadow",
        "allow",
        Reason::FailClosedPath,
        Some("block")
    )]
    #[case::error_allow_open_enforce(
        "error",
        "allow",
        false,
        "enforce",
        "allow",
        Reason::DecisionErrorAllowed,
        None
    )]
    #[case::error_allow_closed_enforce(
        "error",
        "allow",
        true,
        "enforce",
        "block",
        Reason::FailClosedPath,
        None
    )]
    #[case::error_block_open_enforce(
        "error",
        "block",
        false,
        "enforce",
        "block",
        Reason::DecisionErrorBlocked,
        None
    )]
    #[case::error_block_closed_enforce(
        "error",
        "block",
        true,
        "enforce",
        "block",
        Reason::FailClosedPath,
        None
    )]
    #[case::error_allow_open_shadow(
        "error",
        "allow",
        false,
        "shadow",
        "allow",
        Reason::DecisionErrorAllowed,
        None
    )]
    #[case::error_allow_closed_shadow(
        "error",
        "allow",
        true,
        "shadow",
        "allow",
        Reason::FailClosedPath,
        Some("block")
    )]
    #[case::error_block_open_shadow(
        "error",
        "block",
        false,
        "shadow",
        "allow",
        Reason::DecisionErrorBlocked,
        Some("block")
    )]
    #[case::error_block_closed_shadow(
        "error",
        "block",
        true,
        "shadow",
        "allow",
        Reason::FailClosedPath,
        Some("block")
    )]
    fn failure_table(
        #[case] group: &str,
        #[case] setting: &str,
        #[case] fail_closed: bool,
        #[case] mode: &str,
        #[case] expected_action: &str,
        #[case] expected_reason: Reason,
        #[case] expected_would_have: Option<&str>,
    ) -> Result<(), ConfigError> {
        let key = if group == "rate" {
            "on_rate_limit"
        } else {
            "on_decision_error"
        };
        let setting_line = format!("{key} {setting};");
        let mode_line = format!("mode {mode};");
        let config_fields = [FAIL_CLOSED.to_owned(), setting_line, mode_line];
        let config = site(&config_fields.join("\n"))?;
        let path = if fail_closed {
            "/wp-login.php"
        } else {
            "/index.php"
        };
        let assessment = if group == "rate" {
            rate_limited()
        } else {
            decision_failed()
        };
        let decision = decide(&config, &views_of(path), &assessment);
        assert_eq!(decision.action.name(), expected_action);
        assert_eq!(decision.reason, expected_reason);
        assert_eq!(
            decision.would_have.as_ref().map(Action::name),
            expected_would_have
        );
        Ok(())
    }

    /// A client over its share: `on_client_busy` decides, and `on_rate_limit` does not.
    #[rstest]
    // on_client_busy, on_rate_limit, fail_closed path matched, mode, expected action, reason, would_have
    #[case::busy_block_enforce(
        "block",
        "allow",
        false,
        "enforce",
        "reject",
        Reason::ClientBusyBlocked,
        None
    )]
    #[case::busy_allow_enforce(
        "allow",
        "block",
        false,
        "enforce",
        "allow",
        Reason::ClientBusyAllowed,
        None
    )]
    #[case::busy_block_closed_enforce(
        "block",
        "allow",
        true,
        "enforce",
        "block",
        Reason::FailClosedPath,
        None
    )]
    #[case::busy_block_shadow(
        "block",
        "allow",
        false,
        "shadow",
        "allow",
        Reason::ClientBusyBlocked,
        Some("reject")
    )]
    #[case::busy_allow_shadow(
        "allow",
        "block",
        false,
        "shadow",
        "allow",
        Reason::ClientBusyAllowed,
        None
    )]
    #[case::busy_block_closed_shadow(
        "block",
        "allow",
        true,
        "shadow",
        "allow",
        Reason::FailClosedPath,
        Some("block")
    )]
    fn client_busy_table(
        #[case] on_client_busy: &str,
        #[case] on_rate_limit: &str,
        #[case] fail_closed: bool,
        #[case] mode: &str,
        #[case] expected_action: &str,
        #[case] expected_reason: Reason,
        #[case] expected_would_have: Option<&str>,
    ) -> Result<(), ConfigError> {
        let config = site(&fields(&[
            FAIL_CLOSED,
            &format!("on_client_busy {on_client_busy};"),
            &format!("on_rate_limit {on_rate_limit};"),
            &format!("mode {mode};"),
        ]))?;
        let path = if fail_closed {
            "/wp-login.php"
        } else {
            "/index.php"
        };
        let decision = decide(&config, &views_of(path), &Assessment::ClientBusy);
        assert_eq!(decision.action.name(), expected_action);
        assert_eq!(decision.reason, expected_reason);
        assert_eq!(
            decision.would_have.as_ref().map(Action::name),
            expected_would_have
        );
        Ok(())
    }

    #[test]
    fn client_busy_block_answers_429_by_default() -> Result<(), ConfigError> {
        let config = site(&fields(&[]))?;
        let decision = decide(&config, &views_of("/index.php"), &Assessment::ClientBusy);
        assert_eq!(
            decision.action,
            Action::Reject(StatusCode::TOO_MANY_REQUESTS)
        );
        assert_eq!(decision.reason, Reason::ClientBusyBlocked);
        Ok(())
    }

    #[test]
    fn rule_is_decided_regardless_of_failure_settings() -> Result<(), ConfigError> {
        for setting in ["allow", "block"] {
            let config = site(&fields(&[
                "deny_path /.env;",
                &format!("on_rate_limit {setting};"),
                &format!("on_decision_error {setting};"),
            ]))?;
            let decision = decide(&config, &views_of("/.env"), &Assessment::Rule);
            assert_eq!(decision.action, Action::Block);
            assert_eq!(decision.reason, Reason::Rule);
        }
        Ok(())
    }

    #[test]
    fn redirect_action_carries_the_location() -> Result<(), ConfigError> {
        let config = site(&fields(&[REDIRECT]))?;
        let decision = decide(&config, &views_of("/x"), &Assessment::Rule);
        assert_eq!(
            decision.action,
            Action::Redirect(http::HeaderValue::from_static(
                "https://example.com/blocked"
            ))
        );
        Ok(())
    }

    #[test]
    fn access_denial_is_a_block_whatever_the_site_action_and_is_forwarded_in_shadow()
    -> Result<(), ConfigError> {
        let redirect = site(&fields(&[REDIRECT]))?;
        let enforced = decide(&redirect, &views_of("/x"), &Assessment::AccessDenied);
        assert_eq!(enforced.action, Action::Block);
        assert_eq!(enforced.reason, Reason::AccessDenied);
        let shadow = site(&fields(&[SHADOW]))?;
        let recorded = decide(&shadow, &views_of("/x"), &Assessment::AccessDenied);
        assert_eq!(recorded.action, Action::Allow);
        assert_eq!(recorded.reason, Reason::AccessDenied);
        assert_eq!(recorded.would_have, Some(Action::Block));
        Ok(())
    }

    #[test]
    fn shadow_mode_never_leaves_an_attack_unforwarded() -> Result<(), ConfigError> {
        let config = site(&fields(&[SHADOW, REDIRECT]))?;
        for assessment in [
            Assessment::Rule,
            Assessment::Model(verdict(1.0, 1.0)),
            decision_failed(),
        ] {
            let decision = decide(&config, &views_of("/wp-login.php"), &assessment);
            assert_eq!(decision.action, Action::Allow);
        }
        Ok(())
    }

    #[rstest]
    #[case::double_slash("//wp-login.php")]
    #[case::dot_segment("/./wp-login.php/slow")]
    #[case::parent_segment("/x/../wp-login.php")]
    #[case::encoded_dot_segment("/%2e/wp-login.php")]
    fn fail_closed_applies_after_path_normalization(#[case] raw: &str) -> Result<(), ConfigError> {
        let config = site(&fields(&[FAIL_CLOSED]))?;
        let decision = decide(&config, &views_of(raw), &decision_failed());
        assert_eq!(decision.reason, Reason::FailClosedPath);
        assert_eq!(decision.action, Action::Block);
        Ok(())
    }
}
