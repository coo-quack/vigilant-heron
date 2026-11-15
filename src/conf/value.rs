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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rstest::rstest;

    use super::*;

    /// A directive on line 7 of `test.conf` with no block.
    fn directive(name: &str, args: &[&str]) -> Directive {
        Directive {
            name: name.to_owned(),
            args: args.iter().map(|arg| (*arg).to_owned()).collect(),
            children: None,
            file: Arc::from("test.conf"),
            line: 7,
        }
    }

    fn message<T>(result: Result<T, ConfigError>) -> String {
        match result {
            Ok(_) => String::new(),
            Err(error) => error.to_string(),
        }
    }

    #[rstest]
    #[case::none(&[])]
    #[case::two(&["enforce", "shadow"])]
    fn a_directive_that_does_not_have_one_argument_is_rejected(#[case] args: &[&str]) {
        let mode = directive("mode", args);
        assert_eq!(
            message(one_arg(&mode)),
            "test.conf:7: \"mode\" takes exactly one argument"
        );
    }

    #[test]
    fn a_directive_without_a_block_is_rejected_where_one_is_needed() {
        let site = directive("site", &["example.com"]);
        assert_eq!(
            message(block(&site)),
            "test.conf:7: \"site\" must be followed by a block"
        );
    }

    #[test]
    fn an_error_with_no_directive_to_point_at_names_the_configuration() {
        assert_eq!(
            invalid_at_top(&[], "\"listen\" is required").to_string(),
            "configuration:1: \"listen\" is required"
        );
    }

    #[rstest]
    #[case::a_word("ten")]
    #[case::negative("-1")]
    #[case::a_fraction("1.5")]
    fn a_value_that_is_not_a_whole_number_is_rejected(#[case] text: &str) {
        let count = directive("max_connections", &[text]);
        assert_eq!(
            message(parse_number::<usize>(&count, text)),
            format!("test.conf:7: \"max_connections\" must be a whole number, got \"{text}\"")
        );
    }

    #[rstest]
    #[case::unit_only("ms")]
    #[case::a_word("soon")]
    fn a_time_without_a_number_is_rejected(#[case] text: &str) {
        let timeout = directive("timeout", &[text]);
        assert_eq!(
            message(parse_time(&timeout, text)),
            format!("test.conf:7: \"timeout\" is not a time: \"{text}\"")
        );
    }

    #[rstest]
    #[case::minutes("m")]
    #[case::hours("h")]
    fn a_time_too_long_to_count_in_seconds_is_the_longest_time(
        #[case] unit: &str,
    ) -> Result<(), ConfigError> {
        let text = format!("{}{unit}", u64::MAX);
        let timeout = directive("timeout", &[&text]);
        assert_eq!(parse_time(&timeout, &text)?, Duration::from_secs(u64::MAX));
        Ok(())
    }

    #[rstest]
    #[case::unit_only("k")]
    #[case::a_word("big")]
    fn a_size_without_a_number_is_rejected(#[case] text: &str) {
        let size = directive("inspect_body", &[text]);
        assert_eq!(
            message(parse_size(&size, text)),
            format!("test.conf:7: \"inspect_body\" is not a size: \"{text}\"")
        );
    }

    #[test]
    fn a_size_with_an_unknown_unit_is_rejected() {
        let size = directive("inspect_body", &["5x"]);
        assert_eq!(
            message(parse_size(&size, "5x")),
            "test.conf:7: \"inspect_body\" has an unknown size unit in \"5x\""
        );
    }

    #[rstest]
    #[case::kilobytes("k")]
    #[case::megabytes("m")]
    #[case::gigabytes("g")]
    fn a_size_that_does_not_fit_is_rejected(#[case] unit: &str) {
        let text = format!("{}{unit}", usize::MAX);
        let size = directive("inspect_body", &[&text]);
        assert_eq!(
            message(parse_size(&size, &text)),
            format!("test.conf:7: \"inspect_body\" is too large: \"{text}\"")
        );
    }
}
