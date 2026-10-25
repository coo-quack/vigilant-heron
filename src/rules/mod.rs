//! Rules: nginx-style `rule <id> { ... }` blocks that decide a request without the decision model.
//!
//! A block rule blocks a matching request before the backend is called. A skip
//! rule forwards a matching request without calling the backend. The built-in
//! rules in `builtin.conf` are parsed with the same parser as user rules.
//!
//! The directives of a rule are described in the README.

mod matching;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use http::{HeaderName, Method};

pub(crate) use matching::{PathMatch, Pattern};
pub(crate) use matching::{RuleInput, first_match};

use crate::conf::{self, Directive};
use crate::config::{block, invalid, one_arg};
use crate::error::ConfigError;
use crate::realip::IpNet;
use crate::router::normalize_host;

/// The built-in rules, shipped with the binary.
const BUILTIN_CONF: &str = include_str!("builtin.conf");

/// Most rules in one configuration, built-in rules included.
pub(crate) const MAX_RULES: usize = 1000;

/// Longest rule id, in bytes.
const MAX_ID_BYTES: usize = 64;

/// Prefix of the ids of built-in rules. User rules may not use it.
pub(crate) const BUILTIN_PREFIX: &str = "vh-";

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

/// Parses one `rule <id> { ... }` directive.
///
/// # Errors
///
/// Returns [`ConfigError::Invalid`] naming the directive's file and line for a
/// bad id, a missing or repeated directive, an unknown directive, an invalid
/// pattern or a rule without a condition.
#[expect(
    clippy::too_many_lines,
    reason = "one arm per directive keeps each name and its check together"
)]
pub(crate) fn parse_rule(directive: &Directive, scope: Scope) -> Result<ParsedRule, ConfigError> {
    let id = rule_id(directive, scope)?;
    let children = block(directive).map_err(|_| {
        invalid(
            directive,
            format!("rule \"{id}\" needs a block with its directives"),
        )
    })?;

    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut description: Option<String> = None;
    let mut action: Option<RuleAction> = None;
    let mut sites: Option<Vec<String>> = None;
    let mut methods: Option<Vec<Method>> = None;
    let mut path: Option<PathMatch> = None;
    let mut clients: Option<Vec<IpNet>> = None;
    let mut query = Vec::new();
    let mut headers = Vec::new();
    let mut body = Vec::new();
    let mut any = Vec::new();

    for child in children {
        let name = child.name.as_str();
        let single = matches!(
            name,
            "description" | "action" | "site" | "method" | "path" | "client"
        );
        if single && !seen.insert(name) {
            return Err(invalid(child, format!("duplicate directive \"{name}\"")));
        }
        match name {
            "description" => {
                let text = one_arg(child)?;
                if text.trim().is_empty() {
                    return Err(invalid(child, "\"description\" must not be empty"));
                }
                description = Some(text.to_owned());
            }
            "action" => {
                action = Some(match child.args.as_slice() {
                    [word] if word == "block" => RuleAction::Block,
                    [word] if word == "skip" => RuleAction::Skip,
                    _ => {
                        return Err(invalid(child, "\"action\" must be \"block\" or \"skip\""));
                    }
                });
            }
            "site" => {
                if scope != Scope::Top {
                    return Err(invalid(
                        child,
                        "\"site\" is only valid in a top-level rule; a rule inside a site applies to that site",
                    ));
                }
                if child.args.is_empty() {
                    return Err(invalid(child, "\"site\" needs at least one host name"));
                }
                let mut names = Vec::new();
                for host in &child.args {
                    let normalized = normalize_host(host);
                    if normalized.is_empty() {
                        return Err(invalid(
                            child,
                            format!("\"site\" has an invalid host name: {host}"),
                        ));
                    }
                    names.push(normalized);
                }
                sites = Some(names);
            }
            "method" => {
                if child.args.is_empty() {
                    return Err(invalid(child, "\"method\" needs at least one method"));
                }
                let mut list = Vec::new();
                for text in &child.args {
                    let method = Method::from_bytes(text.as_bytes()).map_err(|_| {
                        invalid(child, format!("\"method\" is not a valid method: {text}"))
                    })?;
                    list.push(method);
                }
                methods = Some(list);
            }
            "path" => path = Some(path_match(child)?),
            "client" => {
                if child.args.is_empty() {
                    return Err(invalid(
                        child,
                        "\"client\" needs at least one address or network",
                    ));
                }
                let mut nets = Vec::new();
                for text in &child.args {
                    let net = IpNet::parse(text).ok_or_else(|| {
                        invalid(
                            child,
                            format!("\"client\" is not an address or network: {text}"),
                        )
                    })?;
                    nets.push(net);
                }
                clients = Some(nets);
            }
            "query" => query.push(pattern_directive(child)?),
            "body" => body.push(pattern_directive(child)?),
            "any" => any.push(pattern_directive(child)?),
            "header" => headers.push(header_directive(child)?),
            other => {
                return Err(invalid(
                    child,
                    format!("unknown directive \"{other}\" in rule \"{id}\""),
                ));
            }
        }
    }

    let description = description
        .ok_or_else(|| invalid(directive, format!("rule \"{id}\" needs a \"description\"")))?;
    let action =
        action.ok_or_else(|| invalid(directive, format!("rule \"{id}\" needs an \"action\"")))?;
    let has_condition = methods.is_some()
        || path.is_some()
        || clients.is_some()
        || !query.is_empty()
        || !headers.is_empty()
        || !body.is_empty()
        || !any.is_empty();
    if !has_condition {
        return Err(invalid(
            directive,
            format!("rule \"{id}\" needs at least one condition"),
        ));
    }

    Ok(ParsedRule {
        rule: Arc::new(Rule {
            id: Arc::from(id.as_str()),
            description,
            action,
            methods,
            path,
            clients,
            query,
            headers,
            body,
            any,
        }),
        sites,
        file: Arc::clone(&directive.file),
        line: directive.line,
    })
}

/// Checks the id after `rule` against the rules it may have.
fn rule_id(directive: &Directive, scope: Scope) -> Result<String, ConfigError> {
    let [id] = directive.args.as_slice() else {
        return Err(invalid(
            directive,
            "\"rule\" takes exactly one id before its block",
        ));
    };
    let well_formed = !id.is_empty()
        && id.len() <= MAX_ID_BYTES
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if !well_formed {
        return Err(invalid(
            directive,
            format!(
                "rule id \"{id}\" must be 1 to {MAX_ID_BYTES} letters, digits, \"-\", \"_\" or \".\""
            ),
        ));
    }
    let reserved = id.starts_with(BUILTIN_PREFIX);
    match (scope, reserved) {
        (Scope::Builtin, true) | (Scope::Top | Scope::Site, false) => Ok(id.clone()),
        (Scope::Builtin, false) => Err(invalid(directive, "built-in rule ids start with \"vh-\"")),
        (Scope::Top | Scope::Site, true) => Err(invalid(
            directive,
            format!(
                "rule id \"{id}\" uses the prefix \"vh-\", which is reserved for built-in rules"
            ),
        )),
    }
}

/// Reads `~` or `~*`. Returns true for the case-insensitive operator.
fn operator(directive: &Directive, text: &str) -> Result<bool, ConfigError> {
    match text {
        "~" => Ok(false),
        "~*" => Ok(true),
        _ => Err(invalid(
            directive,
            format!(
                "\"{}\" takes ~ or ~* before the regex, got \"{text}\"",
                directive.name
            ),
        )),
    }
}

fn compile(
    directive: &Directive,
    case_insensitive: bool,
    source: &str,
) -> Result<Pattern, ConfigError> {
    Pattern::new(source, case_insensitive).map_err(|message| invalid(directive, message))
}

/// `query`, `body` and `any`: an operator and a regex.
fn pattern_directive(directive: &Directive) -> Result<Pattern, ConfigError> {
    match directive.args.as_slice() {
        [op, source] => {
            let case_insensitive = operator(directive, op)?;
            compile(directive, case_insensitive, source)
        }
        _ => Err(invalid(
            directive,
            format!(
                "\"{}\" takes an operator and a regex: {} ~ <regex>;",
                directive.name, directive.name
            ),
        )),
    }
}

/// `header <name> <operator> <regex>`.
fn header_directive(directive: &Directive) -> Result<(HeaderName, Pattern), ConfigError> {
    match directive.args.as_slice() {
        [name, op, source] => {
            let header = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                invalid(
                    directive,
                    format!("\"header\" is not a header name: {name}"),
                )
            })?;
            let case_insensitive = operator(directive, op)?;
            Ok((header, compile(directive, case_insensitive, source)?))
        }
        _ => Err(invalid(
            directive,
            "\"header\" takes a name, an operator and a regex: header <name> ~* <regex>;",
        )),
    }
}

/// `path <value>` (prefix), `path <modifier> <value>` with `=`, `^~`, `~` or `~*`.
fn path_match(directive: &Directive) -> Result<PathMatch, ConfigError> {
    let prefix = |value: &String| {
        if value.starts_with('/') {
            Ok(PathMatch::Prefix(value.clone()))
        } else {
            Err(invalid(
                directive,
                format!("\"path\" value must start with \"/\": {value}"),
            ))
        }
    };
    match directive.args.as_slice() {
        [value] => prefix(value),
        [modifier, value] => match modifier.as_str() {
            "^~" => prefix(value),
            "=" => {
                if value.starts_with('/') {
                    Ok(PathMatch::Exact(value.clone()))
                } else {
                    Err(invalid(
                        directive,
                        format!("\"path\" value must start with \"/\": {value}"),
                    ))
                }
            }
            "~" => Ok(PathMatch::Regex(compile(directive, false, value)?)),
            "~*" => Ok(PathMatch::Regex(compile(directive, true, value)?)),
            _ => Err(invalid(
                directive,
                format!("\"path\" modifier must be =, ^~, ~ or ~*, got \"{modifier}\""),
            )),
        },
        _ => Err(invalid(
            directive,
            "\"path\" takes a value, optionally after a modifier",
        )),
    }
}

/// Records a rule id, and fails when the id or the total count of rules is already used.
///
/// `claimed` maps each id to the place it was written, built-in rules included.
pub(crate) fn claim_id(
    claimed: &mut HashMap<String, String>,
    parsed: &ParsedRule,
) -> Result<(), ConfigError> {
    let id = parsed.rule.id.to_string();
    if let Some(first) = claimed.get(&id) {
        return Err(ConfigError::Invalid {
            file: parsed.file.to_string(),
            line: parsed.line,
            message: format!("rule id \"{id}\" is already defined at {first}"),
        });
    }
    if claimed.len() >= MAX_RULES {
        return Err(ConfigError::Invalid {
            file: parsed.file.to_string(),
            line: parsed.line,
            message: format!("too many rules: at most {MAX_RULES} rules, built-in ones included"),
        });
    }
    claimed.insert(id, format!("{}:{}", parsed.file, parsed.line));
    Ok(())
}

/// The parsed built-in rules, or the line and message of the first error.
type BuiltinCache = Result<Vec<Arc<Rule>>, (usize, String)>;

/// Returns the built-in rules, parsed once from `builtin.conf`.
///
/// # Errors
///
/// Returns [`ConfigError::Invalid`] naming `builtin.conf` and the line if the
/// shipped file does not parse. A test keeps that from happening in a release.
pub(crate) fn builtin_rules() -> Result<&'static [Arc<Rule>], ConfigError> {
    static BUILTIN: OnceLock<BuiltinCache> = OnceLock::new();
    match BUILTIN.get_or_init(load_builtin) {
        Ok(rules) => Ok(rules),
        Err((line, message)) => Err(ConfigError::Invalid {
            file: "builtin.conf".to_owned(),
            line: *line,
            message: message.clone(),
        }),
    }
}

fn load_builtin() -> Result<Vec<Arc<Rule>>, (usize, String)> {
    let directives = conf::parse_source(BUILTIN_CONF, "builtin.conf").map_err(position)?;
    let mut rules = Vec::new();
    for directive in &directives {
        if directive.name != "rule" {
            return Err((
                directive.line,
                "only rule blocks are allowed in builtin.conf".to_owned(),
            ));
        }
        let parsed = parse_rule(directive, Scope::Builtin).map_err(position)?;
        rules.push(parsed.rule);
    }
    Ok(rules)
}

/// The line and message of an error, for the built-in rules.
fn position(error: ConfigError) -> (usize, String) {
    match error {
        ConfigError::Syntax { line, message, .. } | ConfigError::Invalid { line, message, .. } => {
            (line, message)
        }
        other => (1, other.to_string()),
    }
}

/// Builds the rule lists of one site.
///
/// Built-in rules come first, when enabled and not disabled. Then the top-level
/// rules that apply to the site, then the rules inside the site's own block.
/// Block and skip rules go into separate lists, and the list of block rules is
/// always checked first.
pub(crate) fn site_rules(
    hosts: &[String],
    builtin: &[Arc<Rule>],
    builtin_enabled: bool,
    disabled: &[String],
    top: &[ParsedRule],
    own: &[ParsedRule],
) -> SiteRules {
    let mut rules = SiteRules::default();
    if builtin_enabled {
        rules.block.extend(
            builtin
                .iter()
                .filter(|rule| !disabled.iter().any(|id| id.as_str() == &*rule.id))
                .cloned(),
        );
    }
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

/// Checks that `disable_rule` names only built-in rules, and returns the ids.
pub(crate) fn disabled_ids(
    directive: &Directive,
    builtin: &[Arc<Rule>],
) -> Result<Vec<String>, ConfigError> {
    if directive.args.is_empty() {
        return Err(invalid(
            directive,
            "\"disable_rule\" needs at least one rule id",
        ));
    }
    let mut ids = Vec::new();
    for id in &directive.args {
        if !builtin.iter().any(|rule| &*rule.id == id.as_str()) {
            return Err(invalid(
                directive,
                format!("\"disable_rule\" names no built-in rule: {id}"),
            ));
        }
        ids.push(id.clone());
    }
    Ok(ids)
}
