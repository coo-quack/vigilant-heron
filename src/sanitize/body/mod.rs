//! Redaction of a request body, by its format.

mod lexical;
mod multipart;

use serde_json::Value;

use super::REDACTED;
use super::keys::is_redacted_key;
use super::query::redact_query;
use lexical::redact_lexical;
use multipart::{multipart_boundary, redact_multipart};

/// Redacts sensitive fields of a body.
///
/// Form bodies are split into fields on `&` and `;`, as query strings are. Multipart
/// bodies are split into parts, and a part is redacted by its `Content-Disposition`
/// name, or by its file name when `redact_file_parts` is set. Other bodies are parsed as
/// JSON when possible. Anything else, including malformed JSON and XML, gets lexical
/// redaction. A multipart body that does not have the expected framing also gets lexical
/// redaction, and the text of a multipart body outside its parts is scanned as text.
///
/// `truncated` says that `body` is only the start of a longer body. See [`redact_multipart`].
pub(crate) fn redact_body(
    content_type: Option<&str>,
    body: &[u8],
    truncated: bool,
    redact_fields: &[String],
    redact_file_parts: bool,
) -> String {
    let text = String::from_utf8_lossy(body);
    if is_form_content_type(content_type) {
        return redact_query(&text, redact_fields);
    }
    if let Some(multipart) = multipart_boundary(content_type).and_then(|boundary| {
        redact_multipart(
            &text,
            &boundary,
            truncated,
            redact_fields,
            redact_file_parts,
        )
    }) {
        return multipart;
    }
    if let Some(json) = redact_json(body, redact_fields) {
        return json;
    }
    redact_lexical(&text, redact_fields)
}

fn is_form_content_type(content_type: Option<&str>) -> bool {
    content_type
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| {
            media_type
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
}

fn redact_json(body: &[u8], redact_fields: &[String]) -> Option<String> {
    let mut value: Value = serde_json::from_slice(body).ok()?;
    redact_value(&mut value, redact_fields);
    serde_json::to_string(&value).ok()
}

fn redact_value(value: &mut Value, redact_fields: &[String]) {
    match value {
        Value::Object(map) => {
            for (key, entry) in map.iter_mut() {
                if is_redacted_key(key, redact_fields) {
                    *entry = Value::String(REDACTED.to_owned());
                } else {
                    redact_value(entry, redact_fields);
                }
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                redact_value(item, redact_fields);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rstest::rstest;

    use super::*;
    use crate::sanitize::keys::is_sensitive_key;
    use crate::sanitize::test_helpers::redact;

    fn form_pairs(encoded: &str) -> Vec<(String, String)> {
        form_urlencoded::parse(encoded.as_bytes())
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect()
    }

    fn json_value(encoded: &str) -> Option<Value> {
        serde_json::from_str(encoded).ok()
    }

    #[test]
    fn body_fields_named_key_or_ticket_are_not_redacted_by_the_header_rules() {
        assert!(!is_sensitive_key("key"));
        assert!(!is_sensitive_key("ticket"));
        assert_eq!(
            redact(
                Some("application/x-www-form-urlencoded"),
                b"key=k1&ticket=T9&authentication_method=sms"
            ),
            "key=k1&ticket=T9&authentication_method=sms"
        );
    }

    #[test]
    fn drupal_login_password_is_redacted_in_a_form_body() {
        let redacted = redact(
            Some("application/x-www-form-urlencoded"),
            b"name=alice&pass=hunter2&form_id=user_login_form",
        );
        let pairs = form_pairs(&redacted);
        assert!(pairs.contains(&("name".to_owned(), "alice".to_owned())));
        assert!(pairs.contains(&("pass".to_owned(), REDACTED.to_owned())));
        assert!(!redacted.contains("hunter2"));
    }

    #[test]
    fn ordinary_fields_with_short_sensitive_looking_parts_are_kept() {
        let body = b"author=ann&shipping=tokyo&passenger=kim";
        assert_eq!(
            redact(Some("application/x-www-form-urlencoded"), body),
            "author=ann&shipping=tokyo&passenger=kim"
        );
        assert_eq!(
            redact(None, b"author=ann&shipping=tokyo&passenger=kim"),
            "author=ann&shipping=tokyo&passenger=kim"
        );
    }

    #[test]
    fn json_and_lexical_bodies_redact_the_pass_field() {
        let json = redact(
            Some("application/json"),
            br#"{"name":"alice","pass":"hunter2"}"#,
        );
        let value = json_value(&json).unwrap_or(Value::Null);
        assert_eq!(value["pass"], REDACTED);
        assert_eq!(value["name"], "alice");
        assert_eq!(
            redact(
                Some("application/json"),
                br#"{"name":"alice","pass":"hunter2""#
            ),
            r#"{"name":"alice","pass":"[REDACTED]""#
        );
        assert_eq!(
            redact(Some("text/plain"), b"name=alice&pass=hunter2"),
            "name=alice&pass=[REDACTED]"
        );
    }

    #[test]
    fn form_body_redacts_sensitive_values_and_keeps_others() {
        let redacted = redact(
            Some("application/x-www-form-urlencoded"),
            b"user=alice&password=hunter2&comment=hello+world",
        );
        let pairs = form_pairs(&redacted);
        assert!(pairs.contains(&("user".to_owned(), "alice".to_owned())));
        assert!(pairs.contains(&("password".to_owned(), REDACTED.to_owned())));
        assert!(pairs.contains(&("comment".to_owned(), "hello world".to_owned())));
        assert!(!redacted.contains("hunter2"));
    }

    #[test]
    fn json_body_redacts_nested_and_array_values() {
        let body = br#"{"user":{"name":"alice","password":"hunter2"},"items":[{"token":"t1"},{"name":"n"}],"count":3}"#;
        let redacted = redact(Some("application/json"), body);
        let value = json_value(&redacted).unwrap_or(Value::Null);
        assert_eq!(value["user"]["name"], "alice");
        assert_eq!(value["user"]["password"], REDACTED);
        assert_eq!(value["items"][0]["token"], REDACTED);
        assert_eq!(value["items"][1]["name"], "n");
        assert_eq!(value["count"], 3);
        assert!(!redacted.contains("hunter2"));
    }

    #[test]
    fn json_value_under_a_sensitive_key_is_replaced_whole() {
        let redacted = redact(Some("application/json"), br#"{"secret":{"a":1,"b":[2]}}"#);
        let value = json_value(&redacted).unwrap_or(Value::Null);
        assert_eq!(value["secret"], REDACTED);
    }

    #[test]
    fn json_content_type_with_parameters_is_recognized() {
        let redacted = redact(Some("Application/JSON; charset=utf-8"), br#"{"pwd":"x"}"#);
        let value = json_value(&redacted).unwrap_or(Value::Null);
        assert_eq!(value["pwd"], REDACTED);
    }

    #[test]
    fn redact_field_names_are_redacted_in_every_body_format() {
        let fields = vec!["ticket_ref".to_owned()];
        let form = redact_body(
            Some("application/x-www-form-urlencoded"),
            b"Ticket_Ref=T1&ticket=x",
            false,
            &fields,
            true,
        );
        let pairs = form_pairs(&form);
        assert!(pairs.contains(&("Ticket_Ref".to_owned(), REDACTED.to_owned())));
        assert!(pairs.contains(&("ticket".to_owned(), "x".to_owned())));

        let json = redact_body(
            Some("application/json"),
            br#"{"outer":{"ticket_ref":"T1"},"ticket":"x"}"#,
            false,
            &fields,
            true,
        );
        let value = json_value(&json).unwrap_or(Value::Null);
        assert_eq!(value["outer"]["ticket_ref"], REDACTED);
        assert_eq!(value["ticket"], "x");

        assert_eq!(
            redact_body(None, b"ticket_ref=T1 ticket=x", false, &fields, true),
            "ticket_ref=[REDACTED] ticket=x"
        );
        assert_eq!(
            redact_body(
                Some("application/json"),
                br#"{"ticket_ref": "T1", "n": 1"#,
                false,
                &fields,
                true
            ),
            r#"{"ticket_ref": "[REDACTED]", "n": 1"#
        );
    }

    #[test]
    fn redact_field_names_match_the_whole_name_only() {
        let fields = vec!["ticket_ref".to_owned()];
        assert_eq!(
            redact_body(
                None,
                b"my_ticket_ref=T1&ticket_refs=2",
                false,
                &fields,
                true
            ),
            "my_ticket_ref=T1&ticket_refs=2"
        );
    }

    #[test]
    fn form_field_value_runs_to_the_next_separator_even_with_a_space() {
        assert_eq!(
            redact(
                Some("application/x-www-form-urlencoded"),
                b"password=hunter 2&q=y"
            ),
            "password=[REDACTED]&q=y"
        );
    }

    #[test]
    fn form_body_redacts_a_percent_encoded_sensitive_name() {
        assert_eq!(
            redact(
                Some("application/x-www-form-urlencoded"),
                b"pass%77ord=x&q=y"
            ),
            "pass%77ord=[REDACTED]&q=y"
        );
    }

    #[rstest]
    #[case::semicolon_hides_password("a=1;password=hunter2", "a=1;password=[REDACTED]")]
    #[case::semicolon_before_ordinary("a=1;b=2", "a=1;b=2")]
    #[case::ampersand_still_works("a=1&password=x", "a=1&password=[REDACTED]")]
    fn form_body_semicolons_separate_fields(#[case] body: &str, #[case] expected: &str) {
        assert_eq!(
            redact(Some("application/x-www-form-urlencoded"), body.as_bytes()),
            expected
        );
    }

    proptest! {
        #[test]
        fn redacted_form_never_contains_a_sensitive_value(value in "[ -~]{1,24}") {
            prop_assume!(value != REDACTED);
            let encoded = form_urlencoded::Serializer::new(String::new())
                .append_pair("password", &value)
                .append_pair("name", "alice")
                .finish();
            let redacted = redact(Some("application/x-www-form-urlencoded"), encoded.as_bytes());
            let pairs = form_pairs(&redacted);
            prop_assert!(pairs.iter().all(|(_, found)| *found != value));
        }

        #[test]
        fn redacted_json_never_contains_a_sensitive_value(value in "[ -~]{1,24}") {
            prop_assume!(value != REDACTED);
            let body = serde_json::json!({"outer": [{"token": value.clone()}], "name": "alice"});
            let redacted = redact(Some("application/json"), body.to_string().as_bytes());
            let parsed = json_value(&redacted).unwrap_or(Value::Null);
            prop_assert_ne!(&parsed["outer"][0]["token"], &Value::String(value.clone()));
        }
    }
}
