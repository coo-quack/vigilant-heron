//! Reading the `json` access log: the line loop and the field helpers that
//! `suggest-skip-rules` and `shadow-report` share.
//!
//! Each line is read on its own, and a line longer than [`MAX_LINE_BYTES`] is never
//! held in memory: it is passed on as [`Line::TooLong`] and the rest of it is skipped.
//! So the memory used for one line is bounded, whatever the log holds. Every field of
//! the `json` format is a string, so the numbers are read from strings too.

use std::io::{self, BufRead, Read};

use serde_json::Value;

/// The longest line that is kept, in bytes, without its line break. A longer line is
/// passed on as [`Line::TooLong`].
pub(crate) const MAX_LINE_BYTES: usize = 1024 * 1024;

/// One line of a log, as [`for_each_line`] passes it on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Line<'a> {
    /// A line within the length limit, without its line break. Invalid UTF-8 is replaced.
    Text(&'a str),
    /// A line over the length limit. Its text was skipped, and the next line follows it.
    TooLong,
}

/// Calls `visit` with each line of `input`, without its line break.
///
/// A line longer than [`MAX_LINE_BYTES`] is passed as [`Line::TooLong`], and the input
/// is then read on to the end of that line without keeping it.
///
/// # Errors
///
/// Returns the error of a failed read from `input`.
pub(crate) fn for_each_line<R: BufRead>(
    mut input: R,
    mut visit: impl FnMut(Line<'_>),
) -> io::Result<()> {
    // One byte more than the limit, so that a line of exactly the limit and its line break fit.
    let limit = u64::try_from(MAX_LINE_BYTES + 1).unwrap_or(u64::MAX);
    let mut buffer = Vec::new();
    loop {
        buffer.clear();
        if Read::take(&mut input, limit).read_until(b'\n', &mut buffer)? == 0 {
            return Ok(());
        }
        if buffer.len() > MAX_LINE_BYTES && buffer.last() != Some(&b'\n') {
            visit(Line::TooLong);
            discard_through_newline(&mut input)?;
            continue;
        }
        let content = buffer.strip_suffix(b"\n").unwrap_or(&buffer);
        let text = String::from_utf8_lossy(content);
        visit(Line::Text(text.trim_end_matches('\r')));
    }
}

/// Reads and drops the input up to and including the next line break, or to the end of
/// the input. Nothing is kept.
fn discard_through_newline<R: BufRead>(input: &mut R) -> io::Result<()> {
    loop {
        let available = input.fill_buf()?;
        if available.is_empty() {
            return Ok(());
        }
        if let Some(index) = available.iter().position(|&byte| byte == b'\n') {
            input.consume(index + 1);
            return Ok(());
        }
        let length = available.len();
        input.consume(length);
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
    use crate::test_support::FailingReader;
    use rstest::rstest;
    use serde_json::json;

    /// The lines that `for_each_line` passes on: the text of each line, or `None` for a
    /// line that was too long.
    fn lines_of(input: &[u8]) -> Vec<Option<String>> {
        let mut lines = Vec::new();
        for_each_line(input, |line| match line {
            Line::Text(text) => lines.push(Some(text.to_owned())),
            Line::TooLong => lines.push(None),
        })
        .unwrap_or_else(|error| panic!("reading from memory failed: {error}"));
        lines
    }

    /// The text of each line, for inputs whose lines all fit.
    fn texts_of(input: &[u8]) -> Vec<String> {
        lines_of(input).into_iter().flatten().collect()
    }

    #[test]
    fn each_line_is_passed_without_its_line_break() {
        assert_eq!(texts_of(b"one\ntwo\r\n"), ["one", "two"]);
    }

    #[test]
    fn a_last_line_without_a_line_break_is_still_passed() {
        assert_eq!(texts_of(b"one\ntwo"), ["one", "two"]);
    }

    #[test]
    fn an_empty_input_passes_no_line() {
        assert_eq!(texts_of(b""), Vec::<String>::new());
    }

    #[test]
    fn invalid_utf8_is_replaced_and_the_line_is_still_passed() {
        assert_eq!(texts_of(b"a\xffb\n"), ["a\u{fffd}b"]);
    }

    #[test]
    fn a_failed_read_is_returned_as_the_error() {
        let result = for_each_line(io::BufReader::new(FailingReader), |_| {});
        assert_eq!(
            result.map_err(|error| error.to_string()),
            Err("the disk went away".to_owned())
        );
    }

    #[test]
    fn a_line_of_exactly_the_length_limit_is_read_whole() {
        let mut input = vec![b'a'; MAX_LINE_BYTES];
        input.push(b'\n');
        let lines = lines_of(&input);
        assert_eq!(lines.len(), 1);
        assert_eq!(
            lines.first().and_then(Option::as_ref).map(String::len),
            Some(MAX_LINE_BYTES)
        );
    }

    #[test]
    fn a_line_one_byte_over_the_limit_is_too_long_and_the_next_line_is_read() {
        let mut input = vec![b'a'; MAX_LINE_BYTES + 1];
        input.extend_from_slice(b"\nok\n");
        assert_eq!(lines_of(&input), [None, Some("ok".to_owned())]);
    }

    #[test]
    fn the_rest_of_an_overlong_line_is_discarded_up_to_its_line_break() {
        // The part after the limit is ten bytes and a line break, then the real next line.
        // The ten bytes must not come out as a line of their own.
        let mut input = vec![b'x'; MAX_LINE_BYTES];
        input.extend_from_slice(b"yyyyyyyyyy\nok\n");
        assert_eq!(lines_of(&input), [None, Some("ok".to_owned())]);
    }

    #[test]
    fn an_overlong_last_line_without_a_line_break_ends_the_input() {
        let mut input = vec![b'a'; MAX_LINE_BYTES + 5];
        input.extend_from_slice(b"\xff");
        assert_eq!(lines_of(&input), [None]);
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
