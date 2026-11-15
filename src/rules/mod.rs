//! Rules: nginx-style `rule <id> { ... }` blocks that decide a request without the decision model.
//!
//! A block rule blocks a matching request before the backend is called. A skip
//! rule forwards a matching request without calling the backend. The built-in
//! rules in `builtin.conf` are parsed with the same parser as user rules.
//!
//! The directives of a rule are described in the README.

mod builtin;
mod matching;
mod parse;
mod site;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use http::{HeaderName, Method};

pub(crate) use builtin::builtin_rules;
pub(crate) use matching::{PathMatch, Pattern};
pub(crate) use matching::{RuleInput, first_match, first_skip_match};
pub(crate) use parse::{claim_id, parse_rule};
pub(crate) use site::{builtin_ids, site_rules};

use crate::realip::IpNet;

/// What a matching rule does with the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuleAction {
    /// Block the request before the backend is called.
    Block,
    /// Forward the request without calling the backend.
    Skip,
}

/// A rule: every condition it lists must match.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Rule {
    /// The id, unique across the configuration. Logged as `$rule_id`.
    pub(crate) id: Arc<str>,
    /// The text from `description`, shown in the error log when the rule matches.
    pub(crate) description: String,
    /// Whether a match blocks the request or lets it skip the backend.
    pub(crate) action: RuleAction,
    /// `method`: the request method must be one of these.
    pub(crate) methods: Option<Vec<Method>>,
    /// `path`: the request path must match.
    pub(crate) path: Option<PathMatch>,
    /// `client`: the client address must be inside one of these networks.
    pub(crate) clients: Option<Vec<IpNet>>,
    /// `query`: each pattern must match the normalized query.
    pub(crate) query: Vec<Pattern>,
    /// `header`: each named header must have a value that matches.
    pub(crate) headers: Vec<(HeaderName, Pattern)>,
    /// `body`: each pattern must match the normalized body prefix.
    pub(crate) body: Vec<Pattern>,
    /// `any`: each pattern must match one of the path, query, header values or body prefix.
    pub(crate) any: Vec<Pattern>,
    /// Whether a built-in rule runs without `enable_rule`. Always true for user rules.
    pub(crate) default_on: bool,
}

/// The `disable_rule` and `enable_rule` ids written at one level of the configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RuleSwitches {
    /// Ids from `disable_rule`.
    pub(crate) disabled: Vec<String>,
    /// Ids from `enable_rule`.
    pub(crate) enabled: Vec<String>,
}

/// Where a rule block was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    /// The built-in rules, which may use the `vh-` prefix.
    Builtin,
    /// A top-level rule. It may name sites with `site`.
    Top,
    /// A rule inside a `site` block. It applies to that site only.
    Site,
}

/// A parsed rule with the place it was written, for errors found later.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ParsedRule {
    /// The rule itself.
    pub(crate) rule: Arc<Rule>,
    /// The normalized host names from a top-level `site` directive. `None` applies to all sites.
    pub(crate) sites: Option<Vec<String>>,
    /// The file the rule was written in, as the user named it.
    pub(crate) file: Arc<str>,
    /// The line of the rule's `rule` directive.
    pub(crate) line: usize,
}

/// The rules one site runs, in evaluation order.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct SiteRules {
    /// Built-in rules, then top-level and site block rules. Checked before `skip`.
    pub(crate) block: Vec<Arc<Rule>>,
    /// Top-level and site block skip rules, checked after every block rule.
    pub(crate) skip: Vec<Arc<Rule>>,
}
