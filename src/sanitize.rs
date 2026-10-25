//! Building the event that is sent to the decision backend.
//!
//! Everything taken from the client is placed under `untrusted` so the backend
//! can treat it as data, never as instructions.

use http::{HeaderMap, Method};
use serde::Serialize;
use serde_json::Value;

/// Replacement for the value of a sensitive field.
pub(crate) const REDACTED: &str = "[REDACTED]";

const DROPPED_HEADERS: [&str; 5] = [
    "cookie",
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
];

const SENSITIVE_KEY_PARTS: [&str; 10] = [
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "card", "cvv", "ssn",
];

/// The JSON body posted to the decision backend.
#[derive(Debug, Serialize)]
pub(crate) struct DecisionEvent {
    event: Event,
}

#[derive(Debug, Serialize)]
struct Event {
    untrusted: Untrusted,
    meta: Meta,
}

#[derive(Debug, Serialize)]
struct Untrusted {
    method: String,
    path: String,
    query: Option<String>,
    headers: Vec<(String, String)>,
    body: String,
}

#[derive(Debug, Serialize)]
struct Meta {
    host: String,
    client_ip: String,
    body_truncated: bool,
}

/// Request data that is sanitized into a [`DecisionEvent`].
pub(crate) struct EventInput<'a> {
    /// Request method.
    pub(crate) method: &'a Method,
    /// Raw request path without the query.
    pub(crate) path: &'a str,
    /// Raw query string, when present.
    pub(crate) query: Option<&'a str>,
    /// Request headers.
    pub(crate) headers: &'a HeaderMap,
    /// Request body, already read in full.
    pub(crate) body: &'a [u8],
    /// Normalized host of the matched site.
    pub(crate) host: &'a str,
    /// Client address for logs and the backend.
    pub(crate) client_ip: &'a str,
    /// Extra header names to drop, lowercased.
    pub(crate) redact_headers: &'a [String],
    /// Maximum number of body bytes sent to the backend.
    pub(crate) inspect_body_bytes: usize,
}

/// Builds the backend event, redacting credentials and truncating the body.
pub(crate) fn build_event(input: &EventInput<'_>) -> DecisionEvent {
    let content_type = input
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    let redacted = redact_body(content_type, input.body);
    let (body, body_truncated) = truncate_utf8(redacted, input.inspect_body_bytes);
    DecisionEvent {
        event: Event {
            untrusted: Untrusted {
                method: input.method.as_str().to_owned(),
                path: input.path.to_owned(),
                query: input.query.map(str::to_owned),
                headers: sanitize_headers(input.headers, input.redact_headers),
                body,
            },
            meta: Meta {
                host: input.host.to_owned(),
                client_ip: input.client_ip.to_owned(),
                body_truncated,
            },
        },
    }
}

/// Copies the headers that may be sent, dropping credentials and redacted names.
pub(crate) fn sanitize_headers(headers: &HeaderMap, extra: &[String]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(name, _)| {
            let name = name.as_str();
            !DROPPED_HEADERS.contains(&name)
                && !extra
                    .iter()
                    .any(|dropped| dropped.eq_ignore_ascii_case(name))
        })
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}

/// Returns true when a field name suggests a credential or payment secret.
pub(crate) fn is_sensitive_key(key: &str) -> bool {
    let lowered = key.to_lowercase();
    SENSITIVE_KEY_PARTS
        .iter()
        .any(|part| lowered.contains(part))
}

/// Redacts sensitive fields of a body.
///
/// Form bodies are parsed as form data. Other bodies are parsed as JSON when
/// possible. Anything else, including malformed JSON, gets lexical redaction.
pub(crate) fn redact_body(content_type: Option<&str>, body: &[u8]) -> String {
    if is_form_content_type(content_type) {
        return redact_form(body);
    }
    if let Some(json) = redact_json(body) {
        return json;
    }
    redact_lexical(&String::from_utf8_lossy(body))
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

/// Redacts sensitive fields in text that is not valid form data or JSON.
///
/// Two passes run. The first redacts `key=value` tokens separated by `&`, `;` or
/// whitespace. The second redacts `"key": value` pairs, where the value is a JSON
/// string, a bracketed value or a bare token.
pub(crate) fn redact_lexical(text: &str) -> String {
    redact_json_like(&redact_key_value_tokens(text))
}

fn redact_key_value_tokens(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut token = String::new();
    for c in text.chars() {
        if c == '&' || c == ';' || c.is_whitespace() {
            push_token(&mut out, &token);
            token.clear();
            out.push(c);
        } else {
            token.push(c);
        }
    }
    push_token(&mut out, &token);
    out
}

fn push_token(out: &mut String, token: &str) {
    match token.split_once('=') {
        Some((key, _)) if is_sensitive_key(key.trim_matches(|c| c == '"' || c == '\'')) => {
            out.push_str(key);
            out.push('=');
            out.push_str(REDACTED);
        }
        _ => out.push_str(token),
    }
}

fn redact_json_like(text: &str) -> String {
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
            // Keep scanning inside the container, where nested keys are checked.
            i = value_start;
        } else {
            copy_range(&chars, value_start, value_stop, &mut out);
            i = value_stop;
        }
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

fn redact_form(body: &[u8]) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (key, value) in form_urlencoded::parse(body) {
        let value: &str = if is_sensitive_key(&key) {
            REDACTED
        } else {
            &value
        };
        serializer.append_pair(&key, value);
    }
    serializer.finish()
}

fn redact_json(body: &[u8]) -> Option<String> {
    let mut value: Value = serde_json::from_slice(body).ok()?;
    redact_value(&mut value);
    serde_json::to_string(&value).ok()
}

fn redact_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, entry) in map.iter_mut() {
                if is_sensitive_key(key) {
                    *entry = Value::String(REDACTED.to_owned());
                } else {
                    redact_value(entry);
                }
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                redact_value(item);
            }
        }
        _ => {}
    }
}

/// Shortens `text` to at most `limit` bytes on a character boundary.
///
/// Returns the text and whether it was cut.
pub(crate) fn truncate_utf8(mut text: String, limit: usize) -> (String, bool) {
    if text.len() <= limit {
        return (text, false);
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    (text, true)
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;
    use http::header::{AUTHORIZATION, COOKIE, HeaderMap, HeaderName};

    type BoxError = Box<dyn std::error::Error>;
    use proptest::prelude::*;
    use rstest::rstest;

    use super::*;

    fn form_pairs(encoded: &str) -> Vec<(String, String)> {
        form_urlencoded::parse(encoded.as_bytes())
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect()
    }

    fn json_value(encoded: &str) -> Option<Value> {
        serde_json::from_str(encoded).ok()
    }

    #[rstest]
    #[case::cookie(COOKIE.as_str())]
    #[case::authorization(AUTHORIZATION.as_str())]
    #[case::proxy_authorization("proxy-authorization")]
    #[case::api_key("x-api-key")]
    #[case::auth_token("x-auth-token")]
    fn credential_headers_are_dropped(#[case] name: &str) -> Result<(), BoxError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_bytes(name.as_bytes())?,
            HeaderValue::from_str("secret")?,
        );
        headers.insert(http::header::USER_AGENT, HeaderValue::from_static("curl"));
        let kept = sanitize_headers(&headers, &[]);
        assert!(kept.iter().all(|(kept_name, _)| kept_name != name));
        assert!(kept.iter().any(|(kept_name, _)| kept_name == "user-agent"));
        Ok(())
    }

    #[test]
    fn extra_redact_headers_are_dropped_case_insensitively()
    -> Result<(), http::header::InvalidHeaderValue> {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-session"),
            HeaderValue::from_str("abc")?,
        );
        headers.insert(
            HeaderName::from_static("x-trace"),
            HeaderValue::from_static("1"),
        );
        let kept = sanitize_headers(&headers, &["X-Session".to_owned()]);
        assert_eq!(kept, vec![("x-trace".to_owned(), "1".to_owned())]);
        Ok(())
    }

    #[test]
    fn headers_with_non_utf8_values_are_kept_lossily()
    -> Result<(), http::header::InvalidHeaderValue> {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-raw"),
            HeaderValue::from_bytes(b"a\xffb")?,
        );
        let kept = sanitize_headers(&headers, &[]);
        assert_eq!(kept, vec![("x-raw".to_owned(), "a\u{fffd}b".to_owned())]);
        Ok(())
    }

    #[rstest]
    #[case::password("password")]
    #[case::passwd("passwd")]
    #[case::pwd("pwd")]
    #[case::secret("client_secret")]
    #[case::token("csrf_token")]
    #[case::api_key("api_key")]
    #[case::apikey("APIKEY")]
    #[case::card("card_number")]
    #[case::cvv("CVV")]
    #[case::ssn("ssn")]
    fn sensitive_key_names_are_detected(#[case] key: &str) {
        assert!(is_sensitive_key(key));
    }

    #[rstest]
    #[case::name("name")]
    #[case::email("email")]
    #[case::comment("comment")]
    fn ordinary_key_names_are_not_sensitive(#[case] key: &str) {
        assert!(!is_sensitive_key(key));
    }

    #[test]
    fn form_body_redacts_sensitive_values_and_keeps_others() {
        let redacted = redact_body(
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
        let redacted = redact_body(Some("application/json"), body);
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
        let redacted = redact_body(Some("application/json"), br#"{"secret":{"a":1,"b":[2]}}"#);
        let value = json_value(&redacted).unwrap_or(Value::Null);
        assert_eq!(value["secret"], REDACTED);
    }

    #[test]
    fn json_content_type_with_parameters_is_recognized() {
        let redacted = redact_body(Some("Application/JSON; charset=utf-8"), br#"{"pwd":"x"}"#);
        let value = json_value(&redacted).unwrap_or(Value::Null);
        assert_eq!(value["pwd"], REDACTED);
    }

    #[test]
    fn malformed_json_string_value_is_redacted() {
        assert_eq!(
            redact_body(Some("application/json"), br#"{"password": "hunter2""#),
            r#"{"password": "[REDACTED]""#
        );
    }

    #[test]
    fn malformed_json_bare_values_are_redacted_up_to_a_delimiter() {
        assert_eq!(
            redact_body(
                Some("application/json"),
                br#"{"token":12345,"name":"alice""#
            ),
            r#"{"token":[REDACTED],"name":"alice""#
        );
    }

    #[test]
    fn malformed_json_redacts_nested_keys_and_escaped_quotes() {
        assert_eq!(
            redact_body(
                Some("application/json"),
                br#"{"outer":{"password":"a\"b", "x":1"#
            ),
            r#"{"outer":{"password":"[REDACTED]", "x":1"#
        );
    }

    #[test]
    fn malformed_json_redacts_a_sensitive_container_whole() {
        assert_eq!(
            redact_body(
                Some("application/json"),
                br#"{"secret":{"a":"hunter 2"}, "ok":true"#
            ),
            r#"{"secret":[REDACTED], "ok":true"#
        );
    }

    #[test]
    fn plain_text_key_value_pairs_are_redacted() {
        assert_eq!(
            redact_body(Some("text/plain"), b"session=1; password=hunter2 next"),
            "session=1; password=[REDACTED] next"
        );
        assert_eq!(
            redact_body(None, b"a=1&card=4111&b=2"),
            "a=1&card=[REDACTED]&b=2"
        );
    }

    #[test]
    fn plain_text_without_sensitive_keys_is_unchanged() {
        assert_eq!(
            redact_body(Some("text/plain"), b"hello world"),
            "hello world"
        );
    }

    proptest! {
        #[test]
        fn lexical_key_value_redaction_never_keeps_the_secret(value in "zq[a-z0-9]{8,16}") {
            let redacted = redact_lexical(&format!("name=alice&password={value}"));
            prop_assert!(!redacted.contains(&value));
            prop_assert!(redacted.contains("name=alice"));
        }

        #[test]
        fn malformed_json_never_keeps_the_secret(value in "zq[a-z0-9]{8,16}") {
            let quoted = redact_body(Some("application/json"), format!("{{\"password\": \"{value}\"").as_bytes());
            let bare = redact_body(Some("application/json"), format!("{{\"token\":{value}").as_bytes());
            prop_assert!(!quoted.contains(&value));
            prop_assert!(!bare.contains(&value));
        }
    }

    #[test]
    fn truncation_keeps_whole_characters() {
        assert_eq!(
            truncate_utf8("あいう".to_owned(), 4),
            ("あ".to_owned(), true)
        );
        assert_eq!(
            truncate_utf8("あいう".to_owned(), 3),
            ("あ".to_owned(), true)
        );
        assert_eq!(
            truncate_utf8("あいう".to_owned(), 9),
            ("あいう".to_owned(), false)
        );
        assert_eq!(truncate_utf8(String::new(), 0), (String::new(), false));
    }

    #[test]
    fn build_event_marks_a_truncated_body() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain"),
        );
        let event = build_event(&EventInput {
            method: &Method::POST,
            path: "/post",
            query: Some("a=1"),
            headers: &headers,
            body: b"0123456789",
            host: "example.com",
            client_ip: "203.0.113.7",
            redact_headers: &[],
            inspect_body_bytes: 4,
        });
        let json = serde_json::to_value(&event).unwrap_or(Value::Null);
        assert_eq!(json["event"]["untrusted"]["body"], "0123");
        assert_eq!(json["event"]["untrusted"]["query"], "a=1");
        assert_eq!(json["event"]["meta"]["body_truncated"], true);
        assert_eq!(json["event"]["meta"]["host"], "example.com");
    }

    #[test]
    fn build_event_places_client_data_only_under_untrusted() {
        let headers = HeaderMap::new();
        let event = build_event(&EventInput {
            method: &Method::GET,
            path: "/",
            query: None,
            headers: &headers,
            body: b"",
            host: "example.com",
            client_ip: "203.0.113.7",
            redact_headers: &[],
            inspect_body_bytes: 10,
        });
        let json = serde_json::to_value(&event).unwrap_or(Value::Null);
        let top_keys: Vec<&str> = json["event"]
            .as_object()
            .map(|map| map.keys().map(String::as_str).collect())
            .unwrap_or_default();
        assert_eq!(top_keys.len(), 2);
        assert!(top_keys.contains(&"untrusted"));
        assert!(top_keys.contains(&"meta"));
        assert_eq!(json["event"]["untrusted"]["query"], Value::Null);
        assert_eq!(json["event"]["meta"]["body_truncated"], false);
    }

    proptest! {
        #[test]
        fn redacted_form_never_contains_a_sensitive_value(value in "[ -~]{1,24}") {
            prop_assume!(value != REDACTED);
            let encoded = form_urlencoded::Serializer::new(String::new())
                .append_pair("password", &value)
                .append_pair("name", "alice")
                .finish();
            let redacted = redact_body(Some("application/x-www-form-urlencoded"), encoded.as_bytes());
            let pairs = form_pairs(&redacted);
            prop_assert!(pairs.iter().all(|(_, found)| *found != value));
        }

        #[test]
        fn redacted_json_never_contains_a_sensitive_value(value in "[ -~]{1,24}") {
            prop_assume!(value != REDACTED);
            let body = serde_json::json!({"outer": [{"token": value.clone()}], "name": "alice"});
            let redacted = redact_body(Some("application/json"), body.to_string().as_bytes());
            let parsed = json_value(&redacted).unwrap_or(Value::Null);
            prop_assert_ne!(&parsed["outer"][0]["token"], &Value::String(value.clone()));
        }

        #[test]
        fn truncation_respects_the_limit_and_keeps_a_prefix(text in "\\PC{0,64}", limit in 0_usize..80) {
            let original = text.clone();
            let (truncated, was_cut) = truncate_utf8(text, limit);
            prop_assert!(truncated.len() <= limit);
            prop_assert!(original.starts_with(&truncated));
            if was_cut {
                prop_assert!(truncated.len() < original.len());
            } else {
                prop_assert_eq!(truncated, original);
            }
        }
    }
}
