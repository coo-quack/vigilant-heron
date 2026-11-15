//! Redaction of `multipart/form-data` bodies, part by part.

use super::lexical::redact_lexical;
use crate::sanitize::REDACTED;
use crate::sanitize::keys::is_redacted_key;

/// Returns the boundary of a `multipart/form-data` content type, without its quotes.
///
/// Parameters are read one by one, so a quoted value may hold `;`, as in
/// `boundary="a;b"`. A parameter without `=` is skipped. An empty boundary is `None`.
pub(crate) fn multipart_boundary(content_type: Option<&str>) -> Option<String> {
    let content_type = content_type?;
    let (media_type, mut rest) = content_type.split_once(';').unwrap_or((content_type, ""));
    if !media_type
        .trim()
        .eq_ignore_ascii_case("multipart/form-data")
    {
        return None;
    }
    while !rest.is_empty() {
        let (key, after) = rest.split_once(['=', ';'])?;
        rest = if rest.strip_prefix(key)?.starts_with('=') {
            let (value, remaining) = parameter_value(after);
            if key.trim().eq_ignore_ascii_case("boundary") {
                return Some(value.to_owned()).filter(|boundary| !boundary.is_empty());
            }
            remaining
        } else {
            // A parameter without `=`: skip it.
            after
        };
    }
    None
}

/// Splits one parameter value from the parameters after it. A quoted value runs to the
/// closing quote, and whatever follows the quote up to the next `;` is dropped. An
/// unquoted value runs to the next `;` and is trimmed.
fn parameter_value(after_equals: &str) -> (&str, &str) {
    let text = after_equals.trim_start();
    if let Some(quoted) = text.strip_prefix('"') {
        let (value, tail) = quoted.split_once('"').unwrap_or((quoted, ""));
        let remaining = tail.split_once(';').map_or("", |(_, remaining)| remaining);
        return (value, remaining);
    }
    match text.split_once(';') {
        Some((value, remaining)) => (value.trim(), remaining),
        None => (text.trim(), ""),
    }
}

/// A delimiter line of a multipart body. See [`find_delimiter`].
#[derive(Debug, PartialEq, Eq)]
struct Delimiter {
    /// Offset of the `--` that starts the line.
    start: usize,
    /// What follows `--boundary` on the line.
    end: DelimiterEnd,
}

/// What follows `--boundary` on a delimiter line.
#[derive(Debug, PartialEq, Eq)]
enum DelimiterEnd {
    /// `--`: the closing delimiter. `close_end` is the offset just past the `--`, where
    /// the epilogue starts.
    Closing { close_end: usize },
    /// Spaces or tabs, then a newline. A part follows.
    Line,
    /// Spaces or tabs, then the end of the text: the line was cut.
    Cut,
}

/// Finds the first delimiter line at or after `from`.
///
/// A delimiter line is `open` (`--boundary`) at the start of the text (only when `from` is
/// 0) or right after a `\n`, followed by `--`, or by spaces and tabs and then a newline or
/// the end of the text. `--boundaryx` and `--boundary x` are content. `sep` is `open` with a
/// leading `\n`. A candidate that is not a delimiter is skipped and the search goes on after
/// it, so each byte is read a bounded number of times.
fn find_delimiter(text: &str, open: &str, sep: &str, from: usize) -> Option<Delimiter> {
    let mut search = from;
    if from == 0 && text.starts_with(open) {
        if let Some(end) = delimiter_end(text, open.len()) {
            return Some(Delimiter { start: 0, end });
        }
        search = open.len();
    }
    loop {
        // Checked sums: the search position can neither wrap nor stall.
        let found = text.get(search..)?.find(sep)?;
        let start = search.checked_add(found)?.checked_add(1)?;
        let after = start.checked_add(open.len())?;
        if let Some(end) = delimiter_end(text, after) {
            return Some(Delimiter { start, end });
        }
        search = after;
    }
}

/// Reads what follows `--boundary` at `after` in `text`. Returns `None` when the line is
/// not a delimiter line, so its text is content.
fn delimiter_end(text: &str, after: usize) -> Option<DelimiterEnd> {
    let rest = text.get(after..)?;
    if rest.starts_with("--") {
        return Some(DelimiterEnd::Closing {
            close_end: after + 2,
        });
    }
    let line = rest.trim_start_matches([' ', '\t']);
    if line.is_empty() {
        Some(DelimiterEnd::Cut)
    } else if line.starts_with("\r\n") || line.starts_with('\n') {
        Some(DelimiterEnd::Line)
    } else {
        None
    }
}

/// Redacts the value of each `multipart/form-data` part that is sensitive: a part whose
/// `Content-Disposition` name is sensitive, or a file part when `redact_file_parts` is set.
/// Boundaries and part headers are copied as they were sent.
///
/// Delimiters count only at the start of a line (see [`find_delimiter`]). The text before the
/// first delimiter (the preamble) and the text after a closing delimiter (the epilogue) are
/// scanned as text, and parts that follow a closing delimiter are still read as parts.
///
/// When `truncated` is set, `text` is only the start of a longer body. Its last part has no
/// closing delimiter, and it is judged by its headers: they are copied, and its content is
/// replaced when the part is redacted. Otherwise its content is scanned as text. The text
/// from a cut delimiter line, or from a cut part whose headers are not complete, is scanned
/// as text too (see [`scan_cut_rest`]).
///
/// Returns `None` when the framing is not as expected: no delimiter at all, a complete part
/// with no blank line after its headers, no closing delimiter in a body that was not
/// truncated, or a delimiter line that ends early in a body that was not truncated. The
/// caller then uses lexical redaction. Each part is searched only inside its own bytes, so
/// the work is linear.
pub(crate) fn redact_multipart(
    text: &str,
    boundary: &str,
    truncated: bool,
    redact_fields: &[String],
    redact_file_parts: bool,
) -> Option<String> {
    let open = format!("--{boundary}");
    let sep = format!("\n{open}");
    let mut out = String::with_capacity(text.len());
    let mut delim = find_delimiter(text, &open, &sep, 0)?;
    // The preamble, before the first delimiter, is not a part: it is scanned as text.
    out.push_str(&redact_lexical(text.get(..delim.start)?, redact_fields));
    loop {
        let after = delim.start + open.len();
        match delim.end {
            DelimiterEnd::Cut => {
                return scan_cut_rest(out, text, delim.start, truncated, redact_fields);
            }
            DelimiterEnd::Closing { close_end } => {
                out.push_str(text.get(delim.start..close_end)?);
                // The epilogue runs to the next delimiter line, when the sender put one
                // there, or to the end. Parts after it are still read as parts.
                let next = find_delimiter(text, &open, &sep, close_end);
                let epilogue_end = next.as_ref().map_or(text.len(), |next| next.start);
                out.push_str(&redact_lexical(
                    text.get(close_end..epilogue_end)?,
                    redact_fields,
                ));
                match next {
                    Some(next) => delim = next,
                    None => return Some(out),
                }
            }
            DelimiterEnd::Line => {
                let next = find_delimiter(text, &open, &sep, after);
                if next.is_none() && !truncated {
                    return None;
                }
                // The part ends at the newline before the next delimiter, or at the cut.
                let part_end = match &next {
                    Some(next) => next.start.checked_sub(1)?,
                    None => text.len(),
                };
                let part = text.get(after..part_end)?;
                let Some((blank_at, blank_len)) = blank_line(part) else {
                    return scan_cut_rest(out, text, delim.start, next.is_none(), redact_fields);
                };
                let body_start = after + blank_at + blank_len;
                let redacted = part_is_redacted(
                    text.get(after..body_start)?,
                    redact_fields,
                    redact_file_parts,
                );
                out.push_str(text.get(delim.start..body_start)?);
                let content = text.get(body_start..part_end)?;
                let Some(next) = next else {
                    // The last part of a cut body: its headers are complete, so its content
                    // is judged by them. Its end is not known, so unredacted content is
                    // scanned as text.
                    if redacted {
                        out.push_str(REDACTED);
                    } else {
                        out.push_str(&redact_lexical(content, redact_fields));
                    }
                    return Some(out);
                };
                let value = content.strip_suffix('\r').unwrap_or(content);
                if redacted {
                    // Keep the line ending before the next delimiter, so the framing stays intact.
                    out.push_str(REDACTED);
                    out.push_str(text.get(body_start + value.len()..=part_end)?);
                } else {
                    out.push_str(text.get(body_start..=part_end)?);
                }
                delim = next;
            }
        }
    }
}

/// Finds the blank line that ends the part headers in `part`. Returns its offset and its
/// length, which is 2 for `\n\n` and 3 for `\n\r\n`.
fn blank_line(part: &str) -> Option<(usize, usize)> {
    // The two cannot start at the same offset, so the smaller offset decides.
    let lf = part.find("\n\n").map(|at| (at, 2));
    let crlf = part.find("\n\r\n").map(|at| (at, 3));
    [lf, crlf].into_iter().flatten().min()
}

/// Appends the rest of a cut body from `pos`, scanned as text. This is for text that could
/// not be read as a part: a delimiter line that ends with the text, or a cut part with no
/// blank line after its headers. When `cut` is false the framing is broken, and the result
/// is `None` so that the caller scans the whole body as text.
fn scan_cut_rest(
    mut out: String,
    text: &str,
    pos: usize,
    cut: bool,
    redact_fields: &[String],
) -> Option<String> {
    if !cut {
        return None;
    }
    out.push_str(&redact_lexical(text.get(pos..)?, redact_fields));
    Some(out)
}

/// Joins folded header lines: a line that starts with a space or a tab continues the line
/// before it. Each other line is written after a `\n`, so the first line of the result is
/// empty. One pass over the headers.
fn unfold_headers(headers: &str) -> String {
    let mut out = String::with_capacity(headers.len());
    for line in headers.lines() {
        if !line.starts_with([' ', '\t']) {
            out.push('\n');
        }
        out.push_str(line);
    }
    out
}

/// Returns true when a part must be redacted: its `Content-Disposition` `name` is a redacted
/// field, or `redact_file_parts` is set and the part is a file part (see [`is_file_part_key`]).
/// The headers are unfolded first, so a parameter on a continuation line is read.
fn part_is_redacted(headers: &str, redact_fields: &[String], redact_file_parts: bool) -> bool {
    let headers = unfold_headers(headers);
    content_disposition_params(&headers).any(|(key, value)| {
        (key.eq_ignore_ascii_case("name")
            && is_redacted_key(value.trim_matches('"'), redact_fields))
            || (redact_file_parts && is_file_part_key(key))
    })
}

/// Returns the `(key, value)` pairs of the `Content-Disposition` header lines in a part's
/// headers, with the spaces around each key and value removed. A `;` separates the pairs.
fn content_disposition_params(headers: &str) -> impl Iterator<Item = (&str, &str)> {
    headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(field, _)| field.trim().eq_ignore_ascii_case("content-disposition"))
        .flat_map(|(_, value)| value.split(';'))
        .filter_map(|param| param.split_once('='))
        .map(|(key, value)| (key.trim(), value.trim()))
}

/// Returns true when a `Content-Disposition` parameter name marks a file part: `filename`,
/// `filename*`, or an RFC 2231 continuation such as `filename*0` and `filename*0*`, in any
/// letter case. The value is not decoded.
fn is_file_part_key(key: &str) -> bool {
    key.get(..8)
        .is_some_and(|head| head.eq_ignore_ascii_case("filename"))
        && key
            .get(8..)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('*'))
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::sanitize::body::redact_body;
    use crate::sanitize::test_helpers::redact;

    /// Redacts the start of a body that was cut, as `build_event` does.
    fn redact_cut(
        content_type: Option<&str>,
        body: &[u8],
        fields: &[String],
        redact_file_parts: bool,
    ) -> String {
        redact_body(content_type, body, true, fields, redact_file_parts)
    }

    #[rstest]
    #[case::password_part(
        "multipart/form-data; boundary=BB",
        "--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--BB--\r\n",
        "--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n[REDACTED]\r\n--BB--\r\n"
    )]
    #[case::quoted_boundary(
        "multipart/form-data; boundary=\"BB\"",
        "--BB\r\nContent-Disposition: form-data; name=\"token\"\r\n\r\nabc\r\n--BB--",
        "--BB\r\nContent-Disposition: form-data; name=\"token\"\r\n\r\n[REDACTED]\r\n--BB--"
    )]
    #[case::lf_line_endings(
        "multipart/form-data; boundary=BB",
        "--BB\nContent-Disposition: form-data; name=\"secret\"\n\nabc\n--BB--\n",
        "--BB\nContent-Disposition: form-data; name=\"secret\"\n\n[REDACTED]\n--BB--\n"
    )]
    #[case::lf_blank_line_before_crlf_in_value(
        "multipart/form-data; boundary=BB",
        "--BB\nContent-Disposition: form-data; name=\"password\"\n\na\r\n\r\nb\n--BB--\n",
        "--BB\nContent-Disposition: form-data; name=\"password\"\n\n[REDACTED]\n--BB--\n"
    )]
    #[case::crlf_blank_line_before_lf_in_value(
        "multipart/form-data; boundary=BB",
        "--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\n\nmore\r\n--BB--\r\n",
        "--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n[REDACTED]\r\n--BB--\r\n"
    )]
    #[case::lf_framing_redacts_a_second_part(
        "multipart/form-data; boundary=BB",
        "--BB\nContent-Disposition: form-data; name=\"name\"\n\nalice\n--BB\nContent-Disposition: form-data; name=\"password\"\n\nhunter2\n--BB--\n",
        "--BB\nContent-Disposition: form-data; name=\"name\"\n\nalice\n--BB\nContent-Disposition: form-data; name=\"password\"\n\n[REDACTED]\n--BB--\n"
    )]
    #[case::padding_after_the_opening_delimiter_keeps_the_framing(
        "multipart/form-data; boundary=BB",
        "--BB      \r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nalice\r\n--BB      \r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--BB--\r\n",
        "--BB      \r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nalice\r\n--BB      \r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n[REDACTED]\r\n--BB--\r\n"
    )]
    fn sensitive_multipart_part_values_are_redacted(
        #[case] content_type: &str,
        #[case] body: &str,
        #[case] expected: &str,
    ) {
        assert_eq!(redact(Some(content_type), body.as_bytes()), expected);
    }

    #[test]
    fn multipart_ordinary_part_is_kept_and_sensitive_and_file_parts_are_redacted() {
        let body = "--BB\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nalice\r\n\
                    --BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n\
                    --BB\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"pw.png\"\r\n\
                    Content-Type: image/png\r\n\r\nbinary\r\n--BB--\r\n";
        let redacted = redact(Some("multipart/form-data; boundary=BB"), body.as_bytes());
        assert_eq!(
            redacted,
            "--BB\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nalice\r\n\
             --BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n[REDACTED]\r\n\
             --BB\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"pw.png\"\r\n\
             Content-Type: image/png\r\n\r\n[REDACTED]\r\n--BB--\r\n"
        );
    }

    #[test]
    fn multipart_redact_field_names_are_redacted() {
        let fields = vec!["ticket_ref".to_owned()];
        let body =
            "--BB\r\nContent-Disposition: form-data; name=\"ticket_ref\"\r\n\r\nT1\r\n--BB--\r\n";
        assert_eq!(
            redact_body(
                Some("multipart/form-data; boundary=BB"),
                body.as_bytes(),
                false,
                &fields,
                true
            ),
            "--BB\r\nContent-Disposition: form-data; name=\"ticket_ref\"\r\n\r\n[REDACTED]\r\n--BB--\r\n"
        );
    }

    #[rstest]
    #[case::missing_closing_delimiter(
        "multipart/form-data; boundary=BB",
        "--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2"
    )]
    #[case::missing_blank_line(
        "multipart/form-data; boundary=BB",
        "--BB\r\nContent-Disposition: form-data; name=\"password\"\r\nhunter2\r\n--BB--"
    )]
    #[case::wrong_boundary(
        "multipart/form-data; boundary=XX",
        "--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--BB--"
    )]
    #[case::no_boundary_parameter(
        "multipart/form-data",
        "--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--BB--"
    )]
    #[case::opening_delimiter_not_at_a_line_start(
        "multipart/form-data; boundary=BB",
        "x--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--BB--"
    )]
    #[case::delimiter_line_cut_in_a_complete_body(
        "multipart/form-data; boundary=BB",
        "--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--BB"
    )]
    #[case::part_without_blank_line_after_a_good_part(
        "multipart/form-data; boundary=BB",
        "--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--BB\r\nContent-Disposition: form-data; name=\"x\"\r\nab\r\n--BB--"
    )]
    fn broken_multipart_falls_back_to_lexical_redaction(
        #[case] content_type: &str,
        #[case] body: &str,
    ) {
        assert_eq!(
            redact(Some(content_type), body.as_bytes()),
            redact_lexical(body, &[])
        );
    }

    #[test]
    fn multipart_content_with_no_sensitive_names_is_unchanged() {
        let body =
            "--BB\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\nhello\r\n--BB--\r\n";
        assert_eq!(
            redact(Some("multipart/form-data; boundary=BB"), body.as_bytes()),
            body
        );
    }

    #[rstest]
    #[case::sensitive_part_before_the_cut(
        "--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--BB\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\nhel",
        "--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n[REDACTED]\r\n--BB\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\nhel"
    )]
    #[case::ordinary_part_before_the_cut_is_kept(
        "--BB\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nalice\r\n--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhun",
        "--BB\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nalice\r\n--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n[REDACTED]"
    )]
    #[case::cut_inside_part_headers_keeps_the_headers(
        "--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--BB\r\nContent-Disposition: form-data; na",
        "--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n[REDACTED]\r\n--BB\r\nContent-Disposition: form-data; na"
    )]
    #[case::cut_right_after_the_delimiter_line(
        "--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--BB",
        "--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n[REDACTED]\r\n--BB"
    )]
    #[case::partial_delimiter_stays_inside_the_cut_part(
        "--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--B",
        "--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n[REDACTED]"
    )]
    #[case::file_part_cut_mid_content(
        "--BB\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"pic.jpg\"\r\nContent-Type: image/jpeg\r\n\r\nJFIF-data",
        "--BB\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"pic.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n[REDACTED]"
    )]
    #[case::cut_part_without_a_blank_line_is_scanned_as_text(
        "--BB\r\nContent-Disposition: form-data; name=\"comment\"\r\npassword=hunter2&x=1",
        "--BB\r\nContent-Disposition: form-data; name=\"comment\"\r\npassword=[REDACTED]&x=1"
    )]
    #[case::ordinary_cut_part_content_is_scanned_as_text(
        "--BB\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\nnote=1&password=hunter2",
        "--BB\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\nnote=1&password=[REDACTED]"
    )]
    #[case::lf_line_endings_cut_mid_content(
        "--BB\nContent-Disposition: form-data; name=\"password\"\n\nhunter2\n--BB\nContent-Disposition: form-data; name=\"comment\"\n\nhel",
        "--BB\nContent-Disposition: form-data; name=\"password\"\n\n[REDACTED]\n--BB\nContent-Disposition: form-data; name=\"comment\"\n\nhel"
    )]
    #[case::lf_line_endings_cut_inside_headers(
        "--BB\nContent-Disposition: form-data; name=\"password\"\n\nhunter2\n--BB\nContent-Disposition: form-data; na",
        "--BB\nContent-Disposition: form-data; name=\"password\"\n\n[REDACTED]\n--BB\nContent-Disposition: form-data; na"
    )]
    #[case::cut_after_the_headers_before_the_blank_line_at_cr(
        "--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r",
        "--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r"
    )]
    #[case::cut_after_the_headers_before_the_blank_line_at_crlf(
        "--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n",
        "--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n"
    )]
    #[case::cut_between_cr_and_lf_of_the_delimiter_line(
        "--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--BB\r",
        "--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n[REDACTED]"
    )]
    fn truncated_multipart_redacts_the_parts_before_and_at_the_cut(
        #[case] body: &str,
        #[case] expected: &str,
    ) {
        assert_eq!(
            redact_cut(
                Some("multipart/form-data; boundary=BB"),
                body.as_bytes(),
                &[],
                true
            ),
            expected
        );
    }

    #[test]
    fn truncated_multipart_redact_field_part_cut_mid_content_is_redacted() {
        let fields = vec!["async-upload".to_owned()];
        let body = "--BB\r\nContent-Disposition: form-data; name=\"async-upload\"; filename=\"a.jpg\"\r\n\r\nJFIF";
        assert_eq!(
            redact_cut(
                Some("multipart/form-data; boundary=BB"),
                body.as_bytes(),
                &fields,
                false
            ),
            "--BB\r\nContent-Disposition: form-data; name=\"async-upload\"; filename=\"a.jpg\"\r\n\r\n[REDACTED]"
        );
    }

    #[rstest]
    #[case::no_opening_delimiter("password=hunter2")]
    #[case::complete_part_without_blank_line(
        "--BB\r\nContent-Disposition: form-data; name=\"password\"\r\nhunter2\r\n--BB\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nab"
    )]
    fn truncated_multipart_with_framing_broken_before_the_cut_is_lexical(#[case] body: &str) {
        assert_eq!(
            redact_cut(
                Some("multipart/form-data; boundary=BB"),
                body.as_bytes(),
                &[],
                true
            ),
            redact_lexical(body, &[])
        );
    }

    #[rstest]
    #[case::filename("name=\"upload\"; filename=\"pic.jpg\"")]
    #[case::filename_star("name=\"upload\"; filename*=UTF-8''%E5%86%99%E7%9C%9F.jpg")]
    #[case::filename_continuation("name=\"upload\"; filename*0=\"a\"; filename*1=\".jpg\"")]
    #[case::filename_encoded_continuation(
        "name=\"upload\"; filename*0*=UTF-8''a; filename*1=\".jpg\""
    )]
    #[case::filename_in_upper_case("name=\"upload\"; FILENAME=\"a.txt\"")]
    fn file_parts_are_redacted_with_their_headers_kept(#[case] disposition: &str) {
        let body = format!(
            "--BB\r\nContent-Disposition: form-data; {disposition}\r\nContent-Type: image/jpeg\r\n\r\nJFIF\r\n--BB--\r\n"
        );
        let expected = format!(
            "--BB\r\nContent-Disposition: form-data; {disposition}\r\nContent-Type: image/jpeg\r\n\r\n[REDACTED]\r\n--BB--\r\n"
        );
        assert_eq!(
            redact(Some("multipart/form-data; boundary=BB"), body.as_bytes()),
            expected
        );
    }

    #[rstest]
    #[case::boundary_text_in_the_middle_of_a_preamble_line(
        "note --BB here\r\n--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--BB--\r\n",
        "note --BB here\r\n--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n[REDACTED]\r\n--BB--\r\n"
    )]
    #[case::content_line_that_starts_with_the_boundary_and_more(
        "--BB\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\nline\r\n--BBx\r\nmore\r\n--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--BB--\r\n",
        "--BB\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\nline\r\n--BBx\r\nmore\r\n--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n[REDACTED]\r\n--BB--\r\n"
    )]
    #[case::content_line_with_the_boundary_then_a_space_and_text(
        "--BB\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\nline\r\n--BB x\r\nmore\r\n--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--BB--\r\n",
        "--BB\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\nline\r\n--BB x\r\nmore\r\n--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n[REDACTED]\r\n--BB--\r\n"
    )]
    #[case::tab_padding_after_the_delimiter(
        "--BB\t\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--BB--\r\n",
        "--BB\t\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n[REDACTED]\r\n--BB--\r\n"
    )]
    fn multipart_delimiters_count_only_at_the_start_of_a_line(
        #[case] body: &str,
        #[case] expected: &str,
    ) {
        assert_eq!(
            redact(Some("multipart/form-data; boundary=BB"), body.as_bytes()),
            expected
        );
    }

    #[test]
    fn multipart_parts_after_a_closing_delimiter_line_are_still_redacted() {
        let body = "--BB\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\nbefore\r\n--BB--\r\ntoken=t1\r\n--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--BB--\r\n";
        assert_eq!(
            redact(Some("multipart/form-data; boundary=BB"), body.as_bytes()),
            "--BB\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\nbefore\r\n--BB--\r\ntoken=[REDACTED]\r\n--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n[REDACTED]\r\n--BB--\r\n"
        );
    }

    #[test]
    fn multipart_preamble_and_epilogue_are_scanned_as_text() {
        let body = "pre password=p1\r\n--BB\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\nhello\r\n--BB--\r\ntoken=t2\r\n";
        assert_eq!(
            redact(Some("multipart/form-data; boundary=BB"), body.as_bytes()),
            "pre password=[REDACTED]\r\n--BB\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\nhello\r\n--BB--\r\ntoken=[REDACTED]\r\n"
        );
    }

    #[rstest]
    #[case::name_on_a_continuation_line(
        "--BB\r\nContent-Disposition: form-data;\r\n name=\"password\"\r\n\r\nhunter2\r\n--BB--\r\n",
        "--BB\r\nContent-Disposition: form-data;\r\n name=\"password\"\r\n\r\n[REDACTED]\r\n--BB--\r\n"
    )]
    #[case::filename_on_a_tab_continuation_line(
        "--BB\r\nContent-Disposition: form-data; name=\"upload\";\r\n\tfilename=\"a.jpg\"\r\nContent-Type: image/jpeg\r\n\r\nJFIF\r\n--BB--\r\n",
        "--BB\r\nContent-Disposition: form-data; name=\"upload\";\r\n\tfilename=\"a.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n[REDACTED]\r\n--BB--\r\n"
    )]
    fn folded_content_disposition_lines_are_read_as_one(
        #[case] body: &str,
        #[case] expected: &str,
    ) {
        assert_eq!(
            redact(Some("multipart/form-data; boundary=BB"), body.as_bytes()),
            expected
        );
    }

    #[test]
    fn unfold_headers_joins_continuation_lines_and_keeps_the_others() {
        assert_eq!(
            unfold_headers("\nA: 1;\r\n x\r\nB: 2\r\n\r\n"),
            "\n\nA: 1; x\nB: 2\n"
        );
    }

    #[rstest]
    #[case::bare("multipart/form-data; boundary=BB", Some("BB"))]
    #[case::quoted("multipart/form-data; boundary=\"BB\"", Some("BB"))]
    #[case::quoted_with_a_semicolon("multipart/form-data; boundary=\"a;b\"", Some("a;b"))]
    #[case::quoted_after_other_parameters(
        "multipart/form-data; charset=utf-8; boundary=\"a;b\"; x=y",
        Some("a;b")
    )]
    #[case::semicolon_inside_an_earlier_quoted_parameter(
        "multipart/form-data; charset=\"x;y\"; boundary=BB",
        Some("BB")
    )]
    #[case::spaces_around_the_equals_sign("multipart/form-data; boundary = \"a;b\"", Some("a;b"))]
    #[case::spaces_inside_an_unquoted_value("multipart/form-data; boundary= BB ; x=1", Some("BB"))]
    #[case::key_in_upper_case("multipart/form-data; BOUNDARY=BB", Some("BB"))]
    #[case::parameter_without_equals_is_skipped(
        "multipart/form-data; foo; boundary=BB",
        Some("BB")
    )]
    #[case::media_type_in_upper_case("MULTIPART/FORM-DATA ; boundary=BB", Some("BB"))]
    #[case::empty_unquoted_value("multipart/form-data; boundary=", None)]
    #[case::empty_quoted_value("multipart/form-data; boundary=\"\"", None)]
    #[case::no_parameters("multipart/form-data", None)]
    #[case::other_multipart_type("multipart/mixed; boundary=BB", None)]
    #[case::other_media_type("text/plain; boundary=BB", None)]
    fn multipart_boundary_reads_the_parameters(
        #[case] content_type: &str,
        #[case] expected: Option<&str>,
    ) {
        assert_eq!(multipart_boundary(Some(content_type)).as_deref(), expected);
    }

    #[test]
    fn multipart_boundary_with_a_semicolon_redacts_the_parts() {
        let body = "--a;b\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--a;b--\r\n";
        assert_eq!(
            redact(
                Some("multipart/form-data; boundary=\"a;b\""),
                body.as_bytes()
            ),
            "--a;b\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n[REDACTED]\r\n--a;b--\r\n"
        );
    }

    #[test]
    fn scan_cut_rest_scans_the_rest_only_for_a_cut_body() {
        assert_eq!(
            scan_cut_rest("x".to_owned(), "head\npassword=hunter2", 5, true, &[]),
            Some("xpassword=[REDACTED]".to_owned())
        );
        assert_eq!(
            scan_cut_rest("x".to_owned(), "head\npassword=hunter2", 5, false, &[]),
            None
        );
    }

    #[rstest]
    #[rstest]
    #[case::closing("--x", 0, Some(DelimiterEnd::Closing { close_end: 2 }))]
    #[case::closing_at_an_offset("x--", 1, Some(DelimiterEnd::Closing { close_end: 3 }))]
    #[case::cut_at_the_end("", 0, Some(DelimiterEnd::Cut))]
    #[case::cut_after_spaces_and_tabs("  \t", 0, Some(DelimiterEnd::Cut))]
    #[case::crlf_line("\r\nx", 0, Some(DelimiterEnd::Line))]
    #[case::lf_line_after_spaces("  \t\nx", 0, Some(DelimiterEnd::Line))]
    #[case::text_is_content("x", 0, None)]
    #[case::space_then_text_is_content(" x", 0, None)]
    #[case::single_dash_is_content("-", 0, None)]
    #[case::cr_alone_is_content("\r", 0, None)]
    fn delimiter_end_reads_what_follows_the_boundary(
        #[case] text: &str,
        #[case] after: usize,
        #[case] expected: Option<DelimiterEnd>,
    ) {
        assert_eq!(delimiter_end(text, after), expected);
    }

    #[rstest]
    #[case::delimiter_at_the_start("--BB\r\nx", 0, Some(Delimiter { start: 0, end: DelimiterEnd::Line }))]
    #[case::boundary_not_after_a_newline("x--BB\r\n", 0, None)]
    #[case::boundary_followed_by_text_is_skipped("--BBx\n--BB--", 0, Some(Delimiter { start: 6, end: DelimiterEnd::Closing { close_end: 12 } }))]
    #[case::search_starts_after_the_given_offset("--BB\r\n--BB\r\n", 4, Some(Delimiter { start: 6, end: DelimiterEnd::Line }))]
    #[case::start_of_text_is_not_a_delimiter_after_the_start("--BB\r\n", 1, None)]
    #[case::cut_after_spaces("\n--BB \t", 0, Some(Delimiter { start: 1, end: DelimiterEnd::Cut }))]
    fn find_delimiter_accepts_only_lines_that_are_delimiters(
        #[case] text: &str,
        #[case] from: usize,
        #[case] expected: Option<Delimiter>,
    ) {
        assert_eq!(find_delimiter(text, "--BB", "\n--BB", from), expected);
    }

    #[rstest]
    #[case::lf("a\n\nb", Some((1, 2)))]
    #[case::crlf("a\n\r\nb", Some((1, 3)))]
    #[case::lf_before_crlf("a\n\nb\n\r\n", Some((1, 2)))]
    #[case::crlf_before_lf("a\n\r\nb\n\n", Some((1, 3)))]
    #[case::no_blank_line("a\nb\r\n", None)]
    fn blank_line_finds_the_first_blank_line_of_either_kind(
        #[case] part: &str,
        #[case] expected: Option<(usize, usize)>,
    ) {
        assert_eq!(blank_line(part), expected);
    }

    #[rstest]
    #[case::filename("filename", true)]
    #[case::upper_case("FILENAME", true)]
    #[case::filename_star("filename*", true)]
    #[case::continuation("filename*0", true)]
    #[case::encoded_continuation("filename*0*", true)]
    #[case::filenames("filenames", false)]
    #[case::filename_underscore("filename_", false)]
    #[case::name("name", false)]
    #[case::file("file", false)]
    #[case::other_eight_letters_then_a_star("abcdefgh*", false)]
    #[case::prefixed_filename("xfilename", false)]
    fn is_file_part_key_accepts_filename_and_its_continuations(
        #[case] key: &str,
        #[case] expected: bool,
    ) {
        assert_eq!(is_file_part_key(key), expected);
    }

    #[test]
    fn a_part_named_filename_without_a_filename_parameter_is_not_a_file_part() {
        let body = "--BB\r\nContent-Disposition: form-data; name=\"filename\"\r\n\r\nreport.pdf\r\n--BB--\r\n";
        assert_eq!(
            redact(Some("multipart/form-data; boundary=BB"), body.as_bytes()),
            body
        );
    }

    #[test]
    fn redact_file_parts_off_keeps_file_content() {
        let body = "--BB\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"pic.jpg\"\r\nContent-Type: image/jpeg\r\n\r\nJFIF\r\n--BB--\r\n";
        assert_eq!(
            redact_body(
                Some("multipart/form-data; boundary=BB"),
                body.as_bytes(),
                false,
                &[],
                false
            ),
            body
        );
    }

    #[test]
    fn redact_file_parts_off_still_redacts_a_file_part_with_a_sensitive_name() {
        let body = "--BB\r\nContent-Disposition: form-data; name=\"password\"; filename=\"x.txt\"\r\n\r\nhunter2\r\n--BB--\r\n";
        assert_eq!(
            redact_body(
                Some("multipart/form-data; boundary=BB"),
                body.as_bytes(),
                false,
                &[],
                false
            ),
            "--BB\r\nContent-Disposition: form-data; name=\"password\"; filename=\"x.txt\"\r\n\r\n[REDACTED]\r\n--BB--\r\n"
        );
    }

    #[test]
    fn redact_file_parts_off_still_redacts_a_file_part_named_in_redact_field() {
        let fields = vec!["async-upload".to_owned()];
        let body = "--BB\r\nContent-Disposition: form-data; name=\"async-upload\"; filename=\"a.jpg\"\r\n\r\nJFIF\r\n--BB--\r\n";
        assert_eq!(
            redact_body(
                Some("multipart/form-data; boundary=BB"),
                body.as_bytes(),
                false,
                &fields,
                false
            ),
            "--BB\r\nContent-Disposition: form-data; name=\"async-upload\"; filename=\"a.jpg\"\r\n\r\n[REDACTED]\r\n--BB--\r\n"
        );
    }
}
