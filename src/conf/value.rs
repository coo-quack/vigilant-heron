//! The helpers that the directive parsers share: the error that names a directive's file and line,
//! access to its arguments and block, the single-use check, and the parsers of times, sizes,
//! numbers and on/off.

use std::collections::HashSet;
use std::str::FromStr;
use std::time::Duration;

use super::Directive;
use crate::error::ConfigError;

/// Where a directive came from, for error messages.
fn at(directive: &Directive) -> (String, usize) {
    (directive.file.to_string(), directive.line)
}

pub(crate) fn invalid(directive: &Directive, message: impl Into<String>) -> ConfigError {
    let (file, line) = at(directive);
    ConfigError::Invalid {
        file,
        line,
        message: message.into(),
    }
}

/// An error at the top of the file, for something that has no directive to point at.
pub(crate) fn invalid_at_top(directives: &[Directive], message: &str) -> ConfigError {
    let (file, line) = directives
        .first()
        .map_or(("configuration".to_owned(), 1), at);
    ConfigError::Invalid {
        file,
        line,
        message: message.to_owned(),
    }
}

pub(crate) fn one_arg(directive: &Directive) -> Result<&str, ConfigError> {
    match directive.args.as_slice() {
        [value] => Ok(value.as_str()),
        _ => Err(invalid(
            directive,
            format!("\"{}\" takes exactly one argument", directive.name),
        )),
    }
}

pub(crate) fn block(directive: &Directive) -> Result<&[Directive], ConfigError> {
    directive.children.as_deref().ok_or_else(|| {
        invalid(
            directive,
            format!("\"{}\" must be followed by a block", directive.name),
        )
    })
}

/// Parses a whole number of type `T`. The message is the same for every type.
pub(crate) fn parse_number<T: FromStr>(
    directive: &Directive,
    text: &str,
) -> Result<T, ConfigError> {
    text.parse::<T>().map_err(|_| {
        invalid(
            directive,
            format!(
                "\"{}\" must be a whole number, got \"{text}\"",
                directive.name
            ),
        )
    })
}

/// Parses a time: a number with `ms`, `s`, `m` or `h`. A bare number is seconds, as in nginx.
pub(crate) fn parse_time(directive: &Directive, text: &str) -> Result<Duration, ConfigError> {
    let (digits, unit) = split_unit(text);
    let value: u64 = digits.parse().map_err(|_| {
        invalid(
            directive,
            format!("\"{}\" is not a time: \"{text}\"", directive.name),
        )
    })?;
    let duration = match unit.to_ascii_lowercase().as_str() {
        "ms" => Duration::from_millis(value),
        "" | "s" => Duration::from_secs(value),
        "m" => Duration::from_secs(value.saturating_mul(60)),
        "h" => Duration::from_secs(value.saturating_mul(3600)),
        _ => {
            return Err(invalid(
                directive,
                format!(
                    "\"{}\" has an unknown time unit in \"{text}\"",
                    directive.name
                ),
            ));
        }
    };
    Ok(duration)
}

/// Parses a size: a number with `k`, `m` or `g` (any case). A bare number is bytes.
pub(crate) fn parse_size(directive: &Directive, text: &str) -> Result<usize, ConfigError> {
    let (digits, unit) = split_unit(text);
    let value: usize = digits.parse().map_err(|_| {
        invalid(
            directive,
            format!("\"{}\" is not a size: \"{text}\"", directive.name),
        )
    })?;
    let multiplier: usize = match unit.to_ascii_lowercase().as_str() {
        "" => 1,
        "k" => 1024,
        "m" => 1024 * 1024,
        "g" => 1024 * 1024 * 1024,
        _ => {
            return Err(invalid(
                directive,
                format!(
                    "\"{}\" has an unknown size unit in \"{text}\"",
                    directive.name
                ),
            ));
        }
    };
    value.checked_mul(multiplier).ok_or_else(|| {
        invalid(
            directive,
            format!("\"{}\" is too large: \"{text}\"", directive.name),
        )
    })
}

/// Splits `12ms` into `12` and `ms`.
fn split_unit(text: &str) -> (&str, &str) {
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    text.split_at(split)
}

pub(crate) fn parse_bool(directive: &Directive, text: &str) -> Result<bool, ConfigError> {
    match text {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => Err(invalid(
            directive,
            format!("\"{}\" must be \"on\" or \"off\"", directive.name),
        )),
    }
}

/// Parses a time that must be greater than zero.
pub(crate) fn parse_positive_time(
    directive: &Directive,
    text: &str,
) -> Result<Duration, ConfigError> {
    let duration = parse_time(directive, text)?;
    if duration.is_zero() {
        return Err(invalid(
            directive,
            format!("\"{}\" must be greater than 0", directive.name),
        ));
    }
    Ok(duration)
}

/// Records a directive that may appear only once.
pub(crate) fn once(seen: &mut HashSet<String>, directive: &Directive) -> Result<(), ConfigError> {
    if seen.insert(directive.name.clone()) {
        Ok(())
    } else {
        Err(invalid(
            directive,
            format!("duplicate directive \"{}\"", directive.name),
        ))
    }
}
