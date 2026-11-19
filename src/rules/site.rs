//! The rules one site runs, and the switches that turn built-in rules on and off.

use std::sync::Arc;

use super::{ParsedRule, Rule, RuleAction, RuleSwitches, SiteRules};
use crate::conf::{Directive, invalid};
use crate::error::ConfigError;

/// Builds the rule lists of one site.
///
/// Built-in rules come first, when they are active for the site (see
/// [`builtin_active`]). Then the top-level rules that apply to the site, then the
/// rules inside the site's own block. Block and skip rules go into separate
/// lists, and the list of block rules is always checked first.
pub(crate) fn site_rules(
    hosts: &[String],
    builtin: &[Arc<Rule>],
    builtin_enabled: bool,
    top_switches: &RuleSwitches,
    own_switches: &RuleSwitches,
    top: &[ParsedRule],
    own: &[ParsedRule],
) -> SiteRules {
    let mut rules = SiteRules::default();
    rules.block.extend(
        builtin
            .iter()
            .filter(|rule| {
                builtin_active(
                    &rule.id,
                    rule.default_on,
                    builtin_enabled,
                    top_switches,
                    own_switches,
                )
            })
            .cloned(),
    );
    let applies = |parsed: &&ParsedRule| {
        parsed
            .sites
            .as_ref()
            .is_none_or(|names| names.iter().any(|name| hosts.contains(name)))
    };
    for parsed in top.iter().filter(applies).chain(own) {
        match parsed.rule.action {
            RuleAction::Block => rules.block.push(Arc::clone(&parsed.rule)),
            RuleAction::Skip => rules.skip.push(Arc::clone(&parsed.rule)),
        }
    }
    rules
}

/// Decides whether a built-in rule runs at a site.
///
/// The nearest level that names the id decides, and the site's own lists are
/// nearer than the top level's. Inside one level, `disable_rule` wins over
/// `enable_rule`. A rule that no list names runs when the built-in set is on
/// and the rule is on by default.
pub(crate) fn builtin_active(
    id: &str,
    default_on: bool,
    builtin_enabled: bool,
    top: &RuleSwitches,
    own: &RuleSwitches,
) -> bool {
    if own.disabled.iter().any(|name| name == id) {
        return false;
    }
    if own.enabled.iter().any(|name| name == id) {
        return true;
    }
    if top.disabled.iter().any(|name| name == id) {
        return false;
    }
    if top.enabled.iter().any(|name| name == id) {
        return true;
    }
    builtin_enabled && default_on
}

/// Checks that the ids of `disable_rule` or `enable_rule` name only built-in rules, and returns them.
pub(crate) fn builtin_ids(
    directive: &Directive,
    builtin: &[Arc<Rule>],
) -> Result<Vec<String>, ConfigError> {
    if directive.args.is_empty() {
        return Err(invalid(
            directive,
            format!("\"{}\" needs at least one rule id", directive.name),
        ));
    }
    let mut ids = Vec::new();
    for id in &directive.args {
        if !builtin.iter().any(|rule| &*rule.id == id.as_str()) {
            return Err(invalid(
                directive,
                format!("\"{}\" names no built-in rule: {id}", directive.name),
            ));
        }
        ids.push(id.clone());
    }
    Ok(ids)
}
