//! The built-in rules, parsed once from `builtin.conf`.

use std::sync::{Arc, OnceLock};

use super::parse::parse_rule;
use super::{Rule, Scope};
use crate::conf;
use crate::error::ConfigError;

/// The built-in rules, shipped with the binary.
const BUILTIN_CONF: &str = include_str!("builtin.conf");

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
pub(crate) fn position(error: ConfigError) -> (usize, String) {
    match error {
        ConfigError::Syntax { line, message, .. } | ConfigError::Invalid { line, message, .. } => {
            (line, message)
        }
        other => (1, other.to_string()),
    }
}
