//! Parsers of the values of single directives: `lingering_close`, the failure actions, the
//! thresholds, `client_max_body_size` and `large_client_header_buffers`.

use super::{FailureAction, HeaderBuffers, LingeringClose};
use crate::conf::{Directive, invalid, parse_number, parse_size};
use crate::error::ConfigError;

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
