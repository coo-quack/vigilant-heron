//! Parsing of `rule <id> { ... }` blocks and the id registry.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use http::{HeaderName, Method};

use super::matching::{PathMatch, Pattern};
use super::{ParsedRule, Rule, RuleAction, Scope};
use crate::conf::{Directive, block, invalid, one_arg};
use crate::error::ConfigError;
use crate::realip::IpNet;
use crate::router::normalize_host;

/// Most rules in one configuration, built-in rules included.
pub(crate) const MAX_RULES: usize = 1000;

/// Longest rule id, in bytes.
const MAX_ID_BYTES: usize = 64;

/// Prefix of the ids of built-in rules. User rules may not use it.
pub(crate) const BUILTIN_PREFIX: &str = "vh-";

/// Parses one `rule <id> { ... }` directive.
///
/// # Errors
///
/// Returns [`ConfigError::Invalid`] naming the directive's file and line for a
/// bad id, a missing or repeated directive, an unknown directive, an invalid
/// pattern or a rule without a condition.
pub(crate) fn parse_rule(directive: &Directive, scope: Scope) -> Result<ParsedRule, ConfigError> {
    let id = rule_id(directive, scope)?;
    let children = block(directive).map_err(|_| {
        invalid(
            directive,
            format!("rule \"{id}\" needs a block with its directives"),
        )
    })?;

    let mut draft = RuleDraft::new(id, scope);
    for child in children {
        draft.apply(child)?;
    }
    draft.finish(directive)
}

/// A `rule` block while it is read: its id and scope, and the settings read so far, which
/// become the fields of [`Rule`] and [`ParsedRule`] of the same names.
struct RuleDraft<'a> {
    /// The rule id, already checked by [`rule_id`].
    id: String,
    /// Where the block was written.
    scope: Scope,
    /// The names of the single-use directives seen so far.
    seen: HashSet<&'a str>,
    /// Whether the rule runs without `enable_rule`. Only `default off` in a built-in rule clears it.
    default_on: bool,
    description: Option<String>,
    action: Option<RuleAction>,
    sites: Option<Vec<String>>,
    methods: Option<Vec<Method>>,
    path: Option<PathMatch>,
    clients: Option<Vec<IpNet>>,
    query: Vec<Pattern>,
    headers: Vec<(HeaderName, Pattern)>,
    body: Vec<Pattern>,
    any: Vec<Pattern>,
}

impl<'a> RuleDraft<'a> {
    /// An empty draft for the rule `id`.
    fn new(id: String, scope: Scope) -> Self {
        Self {
            id,
            scope,
            seen: HashSet::new(),
            default_on: true,
            description: None,
            action: None,
            sites: None,
            methods: None,
            path: None,
            clients: None,
            query: Vec::new(),
            headers: Vec::new(),
            body: Vec::new(),
            any: Vec::new(),
        }
    }

    /// Applies one directive of the block. A repeated single-use directive fails
    /// before its value is read.
    fn apply(&mut self, child: &'a Directive) -> Result<(), ConfigError> {
        let name = child.name.as_str();
        let single = matches!(
            name,
            "description" | "action" | "default" | "site" | "method" | "path" | "client"
        );
        if single && !self.seen.insert(name) {
            return Err(invalid(child, format!("duplicate directive \"{name}\"")));
        }
        match name {
            "description" => self.description = Some(description_text(child)?),
            "action" => self.action = Some(rule_action(child)?),
            "default" => {
                default_off(child, self.scope)?;
                self.default_on = false;
            }
            "site" => self.sites = Some(site_hosts(child, self.scope)?),
            "method" => self.methods = Some(method_list(child)?),
            "path" => self.path = Some(path_match(child)?),
            "client" => self.clients = Some(client_nets(child)?),
            "query" => self.query.push(pattern_directive(child)?),
            "body" => self.body.push(pattern_directive(child)?),
            "any" => self.any.push(pattern_directive(child)?),
            "header" => self.headers.push(header_directive(child)?),
            other => {
                return Err(invalid(
                    child,
                    format!("unknown directive \"{other}\" in rule \"{}\"", self.id),
                ));
            }
        }
        Ok(())
    }

    /// Checks what the block as a whole needs (a description, an action and a
    /// condition) and builds the rule. `directive` is the `rule` directive, which
    /// the errors and the result point at.
    fn finish(self, directive: &Directive) -> Result<ParsedRule, ConfigError> {
        let id = self.id;
        let description = self
            .description
            .ok_or_else(|| invalid(directive, format!("rule \"{id}\" needs a \"description\"")))?;
        let action = self
            .action
            .ok_or_else(|| invalid(directive, format!("rule \"{id}\" needs an \"action\"")))?;
        let has_condition = self.methods.is_some()
            || self.path.is_some()
            || self.clients.is_some()
            || !self.query.is_empty()
            || !self.headers.is_empty()
            || !self.body.is_empty()
            || !self.any.is_empty();
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
                methods: self.methods,
                path: self.path,
                clients: self.clients,
                query: self.query,
                headers: self.headers,
                body: self.body,
                any: self.any,
                default_on: self.default_on,
            }),
            sites: self.sites,
            file: Arc::clone(&directive.file),
            line: directive.line,
        })
    }
}

/// `description <text>`: one argument that is not blank.
fn description_text(directive: &Directive) -> Result<String, ConfigError> {
    let text = one_arg(directive)?;
    if text.trim().is_empty() {
        return Err(invalid(directive, "\"description\" must not be empty"));
    }
    Ok(text.to_owned())
}

/// `action block` or `action skip`.
fn rule_action(directive: &Directive) -> Result<RuleAction, ConfigError> {
    match directive.args.as_slice() {
        [word] if word == "block" => Ok(RuleAction::Block),
        [word] if word == "skip" => Ok(RuleAction::Skip),
        _ => Err(invalid(
            directive,
            "\"action\" must be \"block\" or \"skip\"",
        )),
    }
}

/// `default off`, valid in a built-in rule only.
fn default_off(directive: &Directive, scope: Scope) -> Result<(), ConfigError> {
    if scope != Scope::Builtin {
        return Err(invalid(
            directive,
            "\"default\" is only valid in a built-in rule; a user rule is on as soon as it is written",
        ));
    }
    match directive.args.as_slice() {
        [word] if word == "off" => Ok(()),
        _ => Err(invalid(directive, "\"default\" must be \"off\"")),
    }
}

/// `site <host>...`, valid in a top-level rule only. Returns the normalized host names.
fn site_hosts(directive: &Directive, scope: Scope) -> Result<Vec<String>, ConfigError> {
    if scope != Scope::Top {
        return Err(invalid(
            directive,
            "\"site\" is only valid in a top-level rule; a rule inside a site applies to that site",
        ));
    }
    if directive.args.is_empty() {
        return Err(invalid(directive, "\"site\" needs at least one host name"));
    }
    let mut names = Vec::new();
    for host in &directive.args {
        let normalized = normalize_host(host);
        if normalized.is_empty() {
            return Err(invalid(
                directive,
                format!("\"site\" has an invalid host name: {host}"),
            ));
        }
        names.push(normalized);
    }
    Ok(names)
}

/// `method <name>...`.
fn method_list(directive: &Directive) -> Result<Vec<Method>, ConfigError> {
    if directive.args.is_empty() {
        return Err(invalid(directive, "\"method\" needs at least one method"));
    }
    let mut list = Vec::new();
    for text in &directive.args {
        let method = Method::from_bytes(text.as_bytes()).map_err(|_| {
            invalid(
                directive,
                format!("\"method\" is not a valid method: {text}"),
            )
        })?;
        list.push(method);
    }
    Ok(list)
}

/// `client <address or network>...`.
fn client_nets(directive: &Directive) -> Result<Vec<IpNet>, ConfigError> {
    if directive.args.is_empty() {
        return Err(invalid(
            directive,
            "\"client\" needs at least one address or network",
        ));
    }
    let mut nets = Vec::new();
    for text in &directive.args {
        let net = IpNet::parse(text).ok_or_else(|| {
            invalid(
                directive,
                format!("\"client\" is not an address or network: {text}"),
            )
        })?;
        nets.push(net);
    }
    Ok(nets)
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
