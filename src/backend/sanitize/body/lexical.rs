//! Redaction of text that is not valid form data or JSON: `key=value` tokens, XML elements
//! and JSON-like text.

use crate::backend::sanitize::REDACTED;
use crate::backend::sanitize::keys::is_redacted_key;

/// Redacts sensitive fields in text that is not valid form data or JSON.
///
/// Two passes run. The first redacts `key=value` tokens separated by `&`, `;` or
/// whitespace. The second redacts `"key": value` pairs, where the value is a JSON
/// string, a bracketed value or a bare token.
pub(crate) fn redact_lexical(text: &str, redact_fields: &[String]) -> String {
    let elements = redact_xml_elements(text, redact_fields);
    redact_json_like(
        &redact_key_value_tokens(&elements, redact_fields),
        redact_fields,
    )
}

/// Redacts the text of XML elements whose local name is sensitive, as in
/// `<password>x</password>` and `<wsse:Password Type="...">x</wsse:Password>`. Attributes
/// and element names are kept.
///
/// Each tag is read once, and the text up to the next `<` is read at most twice, so the
/// work is linear in the length of the text.
fn redact_xml_elements(text: &str, redact_fields: &[String]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut search = 0;
    while let Some(lt) = text
        .get(search..)
        .and_then(|rest| rest.find('<'))
        .map(|k| search + k)
    {
        let Some(gt) = text
            .get(lt..)
            .and_then(|rest| rest.find('>'))
            .map(|k| lt + k)
        else {
            break;
        };
        search = gt + 1;
        let Some(tag) = text.get(lt + 1..gt) else {
            break;
        };
        if tag.starts_with(['/', '!', '?']) || tag.ends_with('/') {
            continue;
        }
        let name = tag
            .split(|c: char| c.is_whitespace() || c == '/')
            .next()
            .unwrap_or("");
        let local = name.rsplit(':').next().unwrap_or("");
        if !is_redacted_key(local, redact_fields) {
            continue;
        }
        let Some(close) = text
            .get(gt + 1..)
            .and_then(|rest| rest.find('<'))
            .map(|k| gt + 1 + k)
        else {
            break;
        };
        // Only text that is followed by a closing tag is an element value.
        if close == gt + 1 || !text.get(close..).is_some_and(|rest| rest.starts_with("</")) {
            continue;
        }
        let Some(kept) = text.get(copied..=gt) else {
            break;
        };
        out.push_str(kept);
        out.push_str(REDACTED);
        copied = close;
        search = close;
    }
    out.push_str(text.get(copied..).unwrap_or(""));
    out
}

fn redact_key_value_tokens(text: &str, redact_fields: &[String]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut token = String::new();
    for c in text.chars() {
        if c == '&' || c == ';' || c.is_whitespace() {
            push_token(&mut out, &token, redact_fields);
            token.clear();
            out.push(c);
        } else {
            token.push(c);
        }
    }
    push_token(&mut out, &token, redact_fields);
    out
}

fn push_token(out: &mut String, token: &str, redact_fields: &[String]) {
    match token.split_once('=') {
        Some((key, _))
            if is_redacted_key(key.trim_matches(|c| c == '"' || c == '\''), redact_fields) =>
        {
            out.push_str(key);
            out.push('=');
            out.push_str(REDACTED);
        }
        _ => out.push_str(token),
    }
}

/// Redacts `"key": value` pairs in text that is not valid JSON.
///
/// Single pass: every key is read once, and a value is scanned only when it is
/// replaced or copied, so the work is linear in the length of the text.
fn redact_json_like(text: &str, redact_fields: &[String]) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while let Some(&c) = chars.get(i) {
        if c != '"' {
            out.push(c);
            i += 1;
            continue;
        }
        let Some(key_end) = string_end(&chars, i) else {
            copy_range(&chars, i, chars.len(), &mut out);
            break;
        };
        let colon = skip_whitespace(&chars, key_end);
        if chars.get(colon) != Some(&':') {
            copy_range(&chars, i, key_end, &mut out);
            i = key_end;
            continue;
        }
        let value_start = skip_whitespace(&chars, colon + 1);
        let key = collect_range(&chars, i + 1, key_end - 1);
        copy_range(&chars, i, value_start, &mut out);
        let sensitive = is_redacted_key(&key, redact_fields);
        if !sensitive && matches!(chars.get(value_start), Some('{' | '[')) {
            // Keep scanning inside the container, where nested keys are checked. The
            // container's end is not needed, so it is not searched for: each character
            // is then visited a bounded number of times.
            i = value_start;
            continue;
        }
        // Only a value that is copied or replaced needs its end, and the scan resumes after it.
        let value_stop = value_end(&chars, value_start);
        if sensitive {
            let value_is_string = chars.get(value_start) == Some(&'"');
            let quote = if value_is_string { "\"" } else { "" };
            out.push_str(quote);
            out.push_str(REDACTED);
            out.push_str(quote);
        } else {
            copy_range(&chars, value_start, value_stop, &mut out);
        }
        i = value_stop;
    }
    out
}

/// Returns the index just past the closing quote of the string opened at `open`.
fn string_end(chars: &[char], open: usize) -> Option<usize> {
    let mut j = open + 1;
    while let Some(&c) = chars.get(j) {
        match c {
            '\\' => j += 2,
            '"' => return Some(j + 1),
            _ => j += 1,
        }
    }
    None
}

fn skip_whitespace(chars: &[char], from: usize) -> usize {
    let mut j = from;
    while chars.get(j).is_some_and(|c| c.is_whitespace()) {
        j += 1;
    }
    j
}

/// Returns the index just past the value that starts at `start`.
fn value_end(chars: &[char], start: usize) -> usize {
    match chars.get(start) {
        Some('"') => string_end(chars, start).unwrap_or(chars.len()),
        Some('{' | '[') => container_end(chars, start),
        _ => {
            let mut j = start;
            while let Some(&c) = chars.get(j) {
                if matches!(c, ',' | '}' | ']') || c.is_whitespace() {
                    break;
                }
                j += 1;
            }
            j
        }
    }
}

fn container_end(chars: &[char], start: usize) -> usize {
    let mut depth = 0_usize;
    let mut j = start;
    while let Some(&c) = chars.get(j) {
        match c {
            '"' => {
                j = string_end(chars, j).unwrap_or(chars.len());
                continue;
            }
            '{' | '[' => depth += 1,
            '}' | ']' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return j + 1;
                }
            }
            _ => {}
        }
        j += 1;
    }
    chars.len()
}

fn copy_range(chars: &[char], from: usize, to: usize, out: &mut String) {
    for c in (from..to).filter_map(|j| chars.get(j)) {
        out.push(*c);
    }
}

fn collect_range(chars: &[char], from: usize, to: usize) -> String {
    (from..to).filter_map(|j| chars.get(j).copied()).collect()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use proptest::prelude::*;
    use rstest::rstest;
    use serde_json::Value;

    use super::*;
    use crate::backend::sanitize::keys::is_sensitive_key;
    use crate::backend::sanitize::test_helpers::{finishes_within, redact};

    #[test]
    fn malformed_json_string_value_is_redacted() {
        assert_eq!(
            redact(Some("application/json"), br#"{"password": "hunter2""#),
            r#"{"password": "[REDACTED]""#
        );
    }

    #[test]
    fn malformed_json_bare_values_are_redacted_up_to_a_delimiter() {
        assert_eq!(
            redact(
                Some("application/json"),
                br#"{"token":12345,"name":"alice""#
            ),
            r#"{"token":[REDACTED],"name":"alice""#
        );
    }

    #[test]
    fn malformed_json_redacts_nested_keys_and_escaped_quotes() {
        assert_eq!(
            redact(
                Some("application/json"),
                br#"{"outer":{"password":"a\"b", "x":1"#
            ),
            r#"{"outer":{"password":"[REDACTED]", "x":1"#
        );
    }

    #[test]
    fn malformed_json_redacts_a_sensitive_container_whole() {
        assert_eq!(
            redact(
                Some("application/json"),
                br#"{"secret":{"a":"hunter 2"}, "ok":true"#
            ),
            r#"{"secret":[REDACTED], "ok":true"#
        );
    }

    #[test]
    fn plain_text_key_value_pairs_are_redacted() {
        assert_eq!(
            redact(Some("text/plain"), b"session=1; password=hunter2 next"),
            "session=[REDACTED]; password=[REDACTED] next"
        );
        assert_eq!(
            redact(None, b"a=1&card=4111&b=2"),
            "a=1&card=[REDACTED]&b=2"
        );
    }

    #[test]
    fn plain_text_without_sensitive_keys_is_unchanged() {
        assert_eq!(redact(Some("text/plain"), b"hello world"), "hello world");
    }

    /// Random JSON values whose keys include sensitive and ordinary names.
    fn arbitrary_json() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            "[a-z0-9 ]{0,8}".prop_map(Value::String),
            any::<i32>().prop_map(Value::from),
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
        ];
        leaf.prop_recursive(4, 32, 4, |inner| {
            prop_oneof![
                proptest::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
                proptest::collection::vec(
                    (prop_oneof!["password", "name", "token", "note"], inner),
                    0..4,
                )
                .prop_map(|pairs| { Value::Object(pairs.into_iter().collect()) }),
            ]
        })
    }

    /// The JSON-like redaction as it was before the value end was computed lazily.
    /// The value end was computed for every key, so a nested container was scanned
    /// to its end once per key. Kept as the reference for the output.
    fn redact_json_like_eager(text: &str) -> String {
        let chars: Vec<char> = text.chars().collect();
        let mut out = String::with_capacity(text.len());
        let mut i = 0;
        while let Some(&c) = chars.get(i) {
            if c != '"' {
                out.push(c);
                i += 1;
                continue;
            }
            let Some(key_end) = string_end(&chars, i) else {
                copy_range(&chars, i, chars.len(), &mut out);
                break;
            };
            let colon = skip_whitespace(&chars, key_end);
            if chars.get(colon) != Some(&':') {
                copy_range(&chars, i, key_end, &mut out);
                i = key_end;
                continue;
            }
            let value_start = skip_whitespace(&chars, colon + 1);
            let value_stop = value_end(&chars, value_start);
            let key = collect_range(&chars, i + 1, key_end - 1);
            copy_range(&chars, i, value_start, &mut out);
            let value_is_string = chars.get(value_start) == Some(&'"');
            let value_is_container = matches!(chars.get(value_start), Some('{' | '['));
            if is_sensitive_key(&key) {
                out.push_str(if value_is_string {
                    "\"[REDACTED]\""
                } else {
                    "[REDACTED]"
                });
                i = value_stop;
            } else if value_is_container {
                i = value_start;
            } else {
                copy_range(&chars, value_start, value_stop, &mut out);
                i = value_stop;
            }
        }
        out
    }

    #[test]
    fn nested_unclosed_containers_are_redacted_in_linear_time() {
        // Every key opens a container that never closes: the old code scanned the rest of the body for each key.
        let body = "\"\":{".repeat(1024 * 1024 / 5);
        let started = std::time::Instant::now();
        // The bound is generous so that a loaded machine does not fail it; the quadratic code took minutes.
        let redacted = finishes_within(Duration::from_secs(10), move || {
            redact(None, body.as_bytes())
        });
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(redacted.starts_with("\"\":{\"\":{"));
    }

    #[test]
    fn quoted_redact_field_names_are_redacted_in_lexical_text() {
        let redact_fields = ["nickname".to_owned()];
        assert_eq!(
            redact_lexical("'nickname'=alice \"nickname\"=bob", &redact_fields),
            "'nickname'=[REDACTED] \"nickname\"=[REDACTED]"
        );
    }

    #[test]
    fn a_malformed_json_string_with_spaces_is_redacted_whole() {
        let redacted = redact(
            Some("application/json"),
            br#"{"password": "correct horse battery", "user": "alice""#,
        );
        assert_eq!(redacted, r#"{"password": "[REDACTED]", "user": "alice""#);
    }

    #[test]
    fn a_closing_bracket_inside_a_string_does_not_end_a_sensitive_container() {
        let redacted = redact(None, br#"{"password": {"x": "}", "y": "leakme"}, "#);
        assert_eq!(redacted, r#"{"password": [REDACTED], "#);
    }

    #[rstest]
    #[case::object(r#"{"password": {"a": {"b": 1}, "note": "TOPSECRET"}, "#)]
    #[case::array(r#"{"password": [[1], "TOPSECRET"], "#)]
    fn nested_containers_under_a_sensitive_key_are_redacted_whole(#[case] body: &str) {
        assert_eq!(
            redact(None, body.as_bytes()),
            r#"{"password": [REDACTED], "#
        );
    }

    #[test]
    fn a_field_after_a_sensitive_container_in_malformed_json_is_kept() {
        let redacted = redact(None, br#"{"password": {"a": 1}, "user": "alice""#);
        assert_eq!(redacted, r#"{"password": [REDACTED], "user": "alice""#);
    }

    /// Malformed bodies that drive every scanning loop of the redaction. Each loop must
    /// finish, and must redact the secret. A mutant that stops a loop from advancing is
    /// reported here in seconds rather than at the mutation timeout.
    #[test]
    fn scanning_loops_finish_and_redact_on_malformed_bodies() {
        let secret = "zq-leak-7";
        let bodies = [
            format!(r#"{{"note": "a\"b", "password": "{secret}", "#),
            format!(r#"{{"password" : "{secret}", "#),
            format!(r#"{{"password": {secret}, "#),
            format!(r#"{{"password": {{"a": {{"b": 1}}, "note": "{secret}"}}, "#),
            format!("<a><password>{secret}</password><b>x</b>"),
            format!("<>x<password>{secret}</password>"),
        ];
        let outputs = finishes_within(Duration::from_secs(10), move || {
            bodies
                .iter()
                .map(|body| redact(None, body.as_bytes()))
                .collect::<Vec<_>>()
        });
        for output in outputs {
            assert!(!output.contains(secret), "{output}");
        }
    }

    proptest! {
        #[test]
        fn lazy_value_end_redacts_exactly_what_the_eager_version_did(
            tokens in proptest::collection::vec(
                prop_oneof![
                    Just("\"".to_owned()),
                    Just(":".to_owned()),
                    Just("{".to_owned()),
                    Just("}".to_owned()),
                    Just("[".to_owned()),
                    Just("]".to_owned()),
                    Just(",".to_owned()),
                    Just(" ".to_owned()),
                    Just("\\".to_owned()),
                    Just("password".to_owned()),
                    Just("name".to_owned()),
                    Just("1".to_owned()),
                ],
                0..80,
            ),
        ) {
            let text: String = tokens.concat();
            prop_assert_eq!(redact_json_like(&text, &[]), redact_json_like_eager(&text));
        }

        #[test]
        fn well_formed_json_is_redacted_the_same_as_before(
            value in arbitrary_json(),
        ) {
            let text = value.to_string();
            prop_assert_eq!(redact_json_like(&text, &[]), redact_json_like_eager(&text));
        }

        #[test]
        fn lexical_key_value_redaction_never_keeps_the_secret(value in "zq[a-z0-9]{8,16}") {
            let redacted = redact_lexical(&format!("name=alice&password={value}"), &[]);
            prop_assert!(!redacted.contains(&value));
            prop_assert!(redacted.contains("name=alice"));
        }

        #[test]
        fn malformed_json_never_keeps_the_secret(value in "zq[a-z0-9]{8,16}") {
            let quoted = redact(Some("application/json"), format!("{{\"password\": \"{value}\"").as_bytes());
            let bare = redact(Some("application/json"), format!("{{\"token\":{value}").as_bytes());
            prop_assert!(!quoted.contains(&value));
            prop_assert!(!bare.contains(&value));
        }
    }

    #[rstest]
    #[case::password_element(
        "application/xml",
        "<auth><username>bob</username><password>hunter2</password></auth>",
        "<auth><username>bob</username><password>[REDACTED]</password></auth>"
    )]
    #[case::soap_namespaced_password_with_attribute(
        "application/soap+xml",
        "<wsse:Security><wsse:Password Type=\"PasswordText\">hunter2</wsse:Password></wsse:Security>",
        "<wsse:Security><wsse:Password Type=\"PasswordText\">[REDACTED]</wsse:Password></wsse:Security>"
    )]
    #[case::text_xml_token_element(
        "text/xml",
        "<req><api:token>abc</api:token></req>",
        "<req><api:token>[REDACTED]</api:token></req>"
    )]
    #[case::mislabelled_as_json(
        "application/json",
        "<auth><password>hunter2</password></auth>",
        "<auth><password>[REDACTED]</password></auth>"
    )]
    fn sensitive_xml_elements_are_redacted(
        #[case] content_type: &str,
        #[case] body: &str,
        #[case] expected: &str,
    ) {
        assert_eq!(redact(Some(content_type), body.as_bytes()), expected);
    }

    #[test]
    fn xml_ordinary_elements_are_kept() {
        let body = "<auth><username>bob</username><name>Bob</name></auth>";
        assert_eq!(redact(Some("application/xml"), body.as_bytes()), body);
    }

    #[test]
    fn xml_self_closing_and_empty_sensitive_elements_are_kept() {
        let body = "<req><password/><token></token></req>";
        assert_eq!(redact(Some("application/xml"), body.as_bytes()), body);
    }

    #[test]
    fn text_after_a_self_closing_sensitive_element_is_kept() {
        let body = "<req><password/>ok</req>";
        assert_eq!(redact(Some("application/xml"), body.as_bytes()), body);
    }

    #[test]
    fn only_the_element_name_decides_not_its_attributes() {
        let body = "<note kind=\"password\">hello</note>";
        assert_eq!(redact(Some("application/xml"), body.as_bytes()), body);
    }

    #[test]
    fn xml_comment_is_not_an_element() {
        let body = "<!--password-->hello</x>";
        assert_eq!(redact(Some("application/xml"), body.as_bytes()), body);
    }

    #[test]
    fn empty_tag_is_copied_and_the_scan_goes_on() {
        assert_eq!(
            redact(Some("application/xml"), b"a<>b<token>x</token>"),
            "a<>b<token>[REDACTED]</token>"
        );
    }
}
