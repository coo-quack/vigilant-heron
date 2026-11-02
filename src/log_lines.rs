//! Reading the `json` access log: the line loop and the field helpers that
//! `suggest-skip-rules` and `shadow-report` share.
//!
//! Each line is read on its own, so a large log is never held in memory whole. Every
//! field of the `json` format is a string, so the numbers are read from strings too.

use std::io::{self, BufRead};

use serde_json::Value;

/// Calls `visit` with each line of `input`, without its line break. A line that is not
/// valid UTF-8 is passed with the invalid bytes replaced.
///
/// # Errors
///
/// Returns the error of a failed read from `input`.
pub(crate) fn for_each_line<R: BufRead>(
    mut input: R,
    mut visit: impl FnMut(&str),
) -> io::Result<()> {
    let mut buffer = Vec::new();
    loop {
        buffer.clear();
        if input.read_until(b'\n', &mut buffer)? == 0 {
            return Ok(());
        }
        let line = String::from_utf8_lossy(&buffer);
        visit(line.trim_end_matches(['\n', '\r']));
    }
}

/// The line as a JSON object, or `None` when it is not one.
pub(crate) fn object_line(line: &str) -> Option<Value> {
    let value: Value = serde_json::from_str(line).ok()?;
    value.is_object().then_some(value)
}

/// A string field, or the empty string when it is missing or not a string.
pub(crate) fn text_field<'a>(value: &'a Value, name: &str) -> &'a str {
    value.get(name).and_then(Value::as_str).unwrap_or("")
}

/// A number field. The `json` format writes scores as strings, so a string is parsed
/// too. An empty or non-numeric value gives `None`.
pub(crate) fn number_field(value: &Value, name: &str) -> Option<f64> {
    let number = match value.get(name)? {
        Value::String(text) => text.parse::<f64>().ok()?,
        Value::Number(number) => number.as_f64()?,
        _ => return None,
    };
    number.is_finite().then_some(number)
}

/// A whole-number field, such as `input_tokens` or `latency_ms`. An empty or
/// non-numeric value gives `None`.
pub(crate) fn whole_field(value: &Value, name: &str) -> Option<u64> {
    text_field(value, name).parse().ok()
}

/// Whether an action or `would_have` value blocks the request. A redirect counts as a block.
pub(crate) fn is_block(text: &str) -> bool {
    matches!(text, "block" | "redirect")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use serde_json::json;

    /// A reader whose every read fails, to check that the error is returned.
    struct FailingReader;

    impl io::Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("the disk went away"))
        }
    }

    /// The lines that `for_each_line` passes on, for the given input.
    fn lines_of(input: &[u8]) -> Vec<String> {
        let mut lines = Vec::new();
        for_each_line(input, |line| lines.push(line.to_owned()))
            .unwrap_or_else(|error| panic!("reading from memory failed: {error}"));
        lines
    }

    #[test]
    fn each_line_is_passed_without_its_line_break() {
        assert_eq!(lines_of(b"one\ntwo\r\n"), ["one", "two"]);
    }

    #[test]
    fn a_last_line_without_a_line_break_is_still_passed() {
        assert_eq!(lines_of(b"one\ntwo"), ["one", "two"]);
    }

    #[test]
    fn an_empty_input_passes_no_line() {
        assert_eq!(lines_of(b""), Vec::<String>::new());
    }

    #[test]
    fn invalid_utf8_is_replaced_and_the_line_is_still_passed() {
        assert_eq!(lines_of(b"a\xffb\n"), ["a\u{fffd}b"]);
    }

    #[test]
    fn a_failed_read_is_returned_as_the_error() {
        let result = for_each_line(io::BufReader::new(FailingReader), |_| {});
        assert_eq!(
            result.map_err(|error| error.to_string()),
            Err("the disk went away".to_owned())
        );
    }

    #[rstest]
    #[case::json_object(r#"{"time":"t"}"#, true)]
    #[case::json_array("[1,2]", false)]
    #[case::json_number("42", false)]
    #[case::not_json("time=2026 client=x", false)]
    #[case::empty_line("", false)]
    fn only_a_json_object_is_an_object_line(#[case] line: &str, #[case] expected: bool) {
        assert_eq!(object_line(line).is_some(), expected);
    }

    #[test]
    fn a_missing_or_non_string_text_field_is_empty() {
        let value = json!({"count": 3});
        assert_eq!(text_field(&value, "count"), "");
        assert_eq!(text_field(&value, "missing"), "");
    }

    #[rstest]
    #[case::string_score(json!({"attack": "0.25"}), Some(0.25))]
    #[case::json_number_score(json!({"attack": 0.5}), Some(0.5))]
    #[case::empty_string(json!({"attack": ""}), None)]
    #[case::not_a_number(json!({"attack": "high"}), None)]
    #[case::infinite(json!({"attack": "inf"}), None)]
    #[case::missing(json!({}), None)]
    #[case::boolean(json!({"attack": true}), None)]
    fn number_field_reads_string_and_json_numbers(
        #[case] value: Value,
        #[case] expected: Option<f64>,
    ) {
        assert_eq!(number_field(&value, "attack"), expected);
    }

    #[rstest]
    #[case::whole("1234", Some(1234))]
    #[case::empty("", None)]
    #[case::fraction("1.5", None)]
    #[case::negative("-1", None)]
    fn whole_field_reads_only_whole_numbers(#[case] text: &str, #[case] expected: Option<u64>) {
        assert_eq!(
            whole_field(&json!({"input_tokens": text}), "input_tokens"),
            expected
        );
    }

    #[rstest]
    #[case::block("block", true)]
    #[case::redirect("redirect", true)]
    #[case::allow("allow", false)]
    #[case::reject("reject", false)]
    #[case::empty("", false)]
    #[case::other_case("Block", false)]
    fn block_and_redirect_are_the_blocking_actions(#[case] text: &str, #[case] expected: bool) {
        assert_eq!(is_block(text), expected);
    }
}
