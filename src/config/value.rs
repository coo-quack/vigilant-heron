//! Helpers shared by the directive parsers: arguments, blocks, numbers, times, sizes and flags.

use std::collections::HashSet;
use std::str::FromStr;
use std::time::Duration;

use super::{FailureAction, HeaderBuffers, LingeringClose};
use crate::conf::Directive;
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

/// Parses `lingering_close`: `on`, `always` or `off`.
pub(crate) fn parse_lingering_close(
    directive: &Directive,
    text: &str,
) -> Result<LingeringClose, ConfigError> {
    match text {
        "on" => Ok(LingeringClose::On),
        "always" => Ok(LingeringClose::Always),
        "off" => Ok(LingeringClose::Off),
        _ => Err(invalid(
            directive,
            format!(
                "\"{}\" must be \"on\", \"always\" or \"off\"",
                directive.name
            ),
        )),
    }
}

pub(crate) fn parse_failure(
    directive: &Directive,
    text: &str,
) -> Result<FailureAction, ConfigError> {
    match text {
        "allow" => Ok(FailureAction::Allow),
        "block" => Ok(FailureAction::Block),
        _ => Err(invalid(
            directive,
            format!("\"{}\" must be \"allow\" or \"block\"", directive.name),
        )),
    }
}

pub(crate) fn parse_threshold(directive: &Directive, text: &str) -> Result<f64, ConfigError> {
    let value: f64 = text.parse().map_err(|_| {
        invalid(
            directive,
            format!("\"{}\" must be a number between 0 and 1", directive.name),
        )
    })?;
    if (0.0..=1.0).contains(&value) {
        Ok(value)
    } else {
        Err(invalid(
            directive,
            format!("\"{}\" must be between 0 and 1, got {text}", directive.name),
        ))
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

/// Parses `client_max_body_size`: `0` means unlimited and gives `None`.
pub(crate) fn parse_body_limit(
    directive: &Directive,
    text: &str,
) -> Result<Option<usize>, ConfigError> {
    let size = parse_size(directive, text)?;
    Ok((size > 0).then_some(size))
}

/// Parses `large_client_header_buffers <number> <size>`.
pub(crate) fn parse_header_buffers(directive: &Directive) -> Result<HeaderBuffers, ConfigError> {
    let [count, size] = directive.args.as_slice() else {
        return Err(invalid(
            directive,
            "\"large_client_header_buffers\" takes two arguments: a number and a size",
        ));
    };
    let count = parse_number::<usize>(directive, count)?;
    let size = parse_size(directive, size)?;
    if count == 0 || size == 0 {
        return Err(invalid(
            directive,
            "\"large_client_header_buffers\" needs a number and a size of at least 1",
        ));
    }
    Ok(HeaderBuffers { count, size })
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
    use std::time::Duration;

    use rstest::rstest;

    use super::*;
    use crate::config::test_helpers::{message, parse, with_decision};

    #[rstest]
    #[case::bare_is_seconds("2", Duration::from_secs(2))]
    #[case::milliseconds("250ms", Duration::from_millis(250))]
    #[case::minutes("2m", Duration::from_secs(120))]
    #[case::hours("1h", Duration::from_secs(3600))]
    #[case::uppercase_unit("3S", Duration::from_secs(3))]
    fn time_units_follow_nginx(
        #[case] text: &str,
        #[case] expected: Duration,
    ) -> Result<(), ConfigError> {
        let config = parse(&with_decision(&format!(
            "    backend http;\n    timeout {text};\n"
        )))?;
        assert_eq!(config.decision.timeout, expected);
        Ok(())
    }

    #[test]
    fn an_unknown_time_unit_is_rejected() {
        let text = with_decision("    backend http;\n    timeout 5x;\n");
        assert!(message(parse(&text)).contains("unknown time unit"));
    }

    #[rstest]
    #[case::bytes("100", 100)]
    #[case::kilobytes("8k", 8 * 1024)]
    #[case::uppercase_megabytes("1M", 1024 * 1024)]
    #[case::gigabytes("1g", 1024 * 1024 * 1024)]
    fn size_units_follow_nginx(
        #[case] text: &str,
        #[case] expected: usize,
    ) -> Result<(), ConfigError> {
        let config = parse(&with_decision(&format!(
            "    backend http;\n    inspect_body {text};\n"
        )))?;
        assert_eq!(config.decision.inspect_body_bytes, expected);
        Ok(())
    }
}
