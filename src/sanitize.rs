//! Building the event that is sent to the decision backend.
//!
//! Everything taken from the client is placed under `untrusted` so the backend
//! can treat it as data, never as instructions.

use http::{HeaderMap, Method};
use serde::Serialize;
use serde_json::Value;

/// Replacement for the value of a sensitive field.
pub(crate) const REDACTED: &str = "[REDACTED]";

/// Credential headers dropped by name. Other headers are dropped when their name is
/// sensitive under [`is_sensitive_key`], so `x-csrf-token` and `x-session-id` are dropped too.
const DROPPED_HEADERS: [&str; 5] = [
    "cookie",
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
];

/// Parts that mark a field as sensitive when they occur anywhere in its name.
///
/// The name is compared without its non-alphanumeric characters and in lowercase,
/// so `api_key`, `API-KEY` and `apikey` all match `apikey`.
const SENSITIVE_KEY_PARTS: [&str; 14] = [
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "apikey",
    "card",
    "cvv",
    "ssn",
    "passphrase",
    "passcode",
    "credential",
    "privatekey",
    "accesskey",
];

/// Short words that mark a field as sensitive only when a whole word of its name
/// is one of them. A substring match would redact `shipping` (`pin`), `author`
/// (`auth`) and `passenger` (`pass`).
const SENSITIVE_WORDS: [&str; 7] = ["pass", "pin", "otp", "auth", "session", "cookie", "jwt"];

/// The JSON body posted to the decision backend.
#[derive(Debug, Serialize)]
pub(crate) struct DecisionEvent {
    pub(crate) event: Event,
}

#[derive(Debug, Serialize)]
pub(crate) struct Event {
    pub(crate) untrusted: Untrusted,
    pub(crate) meta: Meta,
}

#[derive(Debug, Serialize)]
pub(crate) struct Untrusted {
    method: String,
    path: String,
    query: Option<String>,
    headers: Vec<(String, String)>,
    body: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct Meta {
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
    /// The start of the request body. Shorter than the whole body when `body_continues` is set.
    pub(crate) body: &'a [u8],
    /// Whether the request body continues past `body`.
    pub(crate) body_continues: bool,
    /// Normalized host of the matched site.
    pub(crate) host: &'a str,
    /// Client address for logs and the backend.
    pub(crate) client_ip: &'a str,
    /// Extra header names to drop, lowercased.
    pub(crate) redact_headers: &'a [String],
    /// Extra body field names to redact, lowercased (`redact_field`).
    pub(crate) redact_fields: &'a [String],
    /// Maximum number of body bytes sent to the backend.
    pub(crate) inspect_body_bytes: usize,
}

/// Builds the backend event, redacting credentials and truncating the body.
pub(crate) fn build_event(input: &EventInput<'_>) -> DecisionEvent {
    let content_type = input
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    let redacted = redact_body(content_type, input.body, input.redact_fields);
    let (body, cut) = truncate_utf8(redacted, input.inspect_body_bytes);
    let body_truncated = cut || input.body_continues;
    DecisionEvent {
        event: Event {
            untrusted: Untrusted {
                method: input.method.as_str().to_owned(),
                path: input.path.to_owned(),
                query: input
                    .query
                    .map(|query| redact_query(query, input.redact_fields)),
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

/// Redacts the values of sensitive parameters in a query string.
///
/// A parameter is redacted by the same rule as a body field, applied to its decoded
/// name. The other parameters are copied as they were sent, so their order and
/// encoding are kept. A parameter without `=` has no value and is copied as it is.
fn redact_query(query: &str, redact_fields: &[String]) -> String {
    query
        .split('&')
        .map(|parameter| match parameter.split_once('=') {
            Some((name, _)) if is_redacted_key(&decode_name(name), redact_fields) => {
                format!("{name}={REDACTED}")
            }
            _ => parameter.to_owned(),
        })
        .collect::<Vec<String>>()
        .join("&")
}

/// Decodes a parameter name the way form data does (`+` is a space, `%XX` is a byte).
fn decode_name(raw: &str) -> String {
    form_urlencoded::parse(raw.as_bytes())
        .map(|(name, _)| name.into_owned())
        .collect()
}

/// Copies the headers that may be sent, dropping credentials and redacted names.
pub(crate) fn sanitize_headers(headers: &HeaderMap, extra: &[String]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(name, _)| {
            let name = name.as_str();
            !DROPPED_HEADERS.contains(&name)
                && !is_sensitive_key(name)
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
///
/// The name is sensitive when one of [`SENSITIVE_KEY_PARTS`] occurs in it, or when
/// one of its words is one of [`SENSITIVE_WORDS`]. Words are split at every
/// non-alphanumeric character and at a lowercase-to-uppercase change.
pub(crate) fn is_sensitive_key(key: &str) -> bool {
    let compact: String = key
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>()
        .to_ascii_lowercase();
    SENSITIVE_KEY_PARTS
        .iter()
        .any(|part| compact.contains(part))
        || key_words(key)
            .iter()
            .any(|word| SENSITIVE_WORDS.contains(&word.as_str()))
}

/// Splits a field name into lowercase words, at non-alphanumeric characters and at a
/// lowercase-to-uppercase change, as in `userPin` (`user`, `pin`).
fn key_words(key: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut after_lower = false;
    for c in key.chars() {
        if !c.is_ascii_alphanumeric() {
            words.push(std::mem::take(&mut word));
            after_lower = false;
            continue;
        }
        if c.is_ascii_uppercase() && after_lower {
            words.push(std::mem::take(&mut word));
        }
        after_lower = c.is_ascii_lowercase();
        word.push(c.to_ascii_lowercase());
    }
    words.push(word);
    words.retain(|word| !word.is_empty());
    words
}

/// Returns true when a field must be redacted: a sensitive name, or one of the
/// `redact_field` names. Those are compared case-insensitively with the whole name.
fn is_redacted_key(key: &str, redact_fields: &[String]) -> bool {
    is_sensitive_key(key)
        || redact_fields
            .iter()
            .any(|field| field.eq_ignore_ascii_case(key))
}

/// Redacts sensitive fields of a body.
///
/// Form bodies are parsed as form data. Other bodies are parsed as JSON when
/// possible. Anything else, including malformed JSON, gets lexical redaction.
pub(crate) fn redact_body(
    content_type: Option<&str>,
    body: &[u8],
    redact_fields: &[String],
) -> String {
    if is_form_content_type(content_type) {
        return redact_form(body, redact_fields);
    }
    if let Some(json) = redact_json(body, redact_fields) {
        return json;
    }
    redact_lexical(&String::from_utf8_lossy(body), redact_fields)
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
pub(crate) fn redact_lexical(text: &str, redact_fields: &[String]) -> String {
    redact_json_like(&redact_key_value_tokens(text, redact_fields), redact_fields)
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
            out.push_str(if value_is_string {
                "\"[REDACTED]\""
            } else {
                "[REDACTED]"
            });
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

fn redact_form(body: &[u8], redact_fields: &[String]) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (key, value) in form_urlencoded::parse(body) {
        let value: &str = if is_redacted_key(&key, redact_fields) {
            REDACTED
        } else {
            &value
        };
        serializer.append_pair(&key, value);
    }
    serializer.finish()
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
    use std::time::Duration;

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

    /// Redacts a body with no extra field names.
    fn redact(content_type: Option<&str>, body: &[u8]) -> String {
        redact_body(content_type, body, &[])
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

    #[rstest]
    #[case::csrf_token("x-csrf-token")]
    #[case::xsrf_token("x-xsrf-token")]
    #[case::amz_security_token("x-amz-security-token")]
    #[case::access_token("x-access-token")]
    #[case::session_id("x-session-id")]
    #[case::secret("x-client-secret")]
    #[case::jwt("cf-access-jwt-assertion")]
    fn sensitive_named_headers_are_dropped(#[case] name: &str) -> Result<(), BoxError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_bytes(name.as_bytes())?,
            HeaderValue::from_static("secret"),
        );
        headers.insert(http::header::ACCEPT, HeaderValue::from_static("*/*"));
        let kept = sanitize_headers(&headers, &[]);
        assert_eq!(kept, vec![("accept".to_owned(), "*/*".to_owned())]);
        Ok(())
    }

    #[rstest]
    #[case::host("host")]
    #[case::user_agent("user-agent")]
    #[case::content_type("content-type")]
    #[case::content_length("content-length")]
    #[case::accept("accept")]
    #[case::accept_language("accept-language")]
    #[case::accept_encoding("accept-encoding")]
    #[case::referer("referer")]
    #[case::origin("origin")]
    #[case::sec_websocket_key("sec-websocket-key")]
    #[case::sec_websocket_version("sec-websocket-version")]
    #[case::sec_websocket_extensions("sec-websocket-extensions")]
    #[case::sec_websocket_protocol("sec-websocket-protocol")]
    #[case::sec_fetch_site("sec-fetch-site")]
    #[case::x_forwarded_for("x-forwarded-for")]
    #[case::x_forwarded_proto("x-forwarded-proto")]
    #[case::x_real_ip("x-real-ip")]
    #[case::cf_connecting_ip("cf-connecting-ip")]
    #[case::x_request_id("x-request-id")]
    fn headers_the_model_needs_are_kept(#[case] name: &str) -> Result<(), BoxError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_bytes(name.as_bytes())?,
            HeaderValue::from_static("value"),
        );
        let kept = sanitize_headers(&headers, &[]);
        assert_eq!(kept, vec![(name.to_owned(), "value".to_owned())]);
        Ok(())
    }

    #[rstest]
    #[case::plain("a=1&b=two", "a=1&b=two")]
    #[case::sensitive_value("token=abc&c=3", "token=[REDACTED]&c=3")]
    #[case::keeps_order_and_encoding(
        "z=1&password=%26x+y&a=b%20c",
        "z=1&password=[REDACTED]&a=b%20c"
    )]
    #[case::encoded_name("pass%77ord=x&q=y", "pass%77ord=[REDACTED]&q=y")]
    #[case::name_without_value("token&flag", "token&flag")]
    #[case::empty_value_is_redacted("api_key=", "api_key=[REDACTED]")]
    #[case::ordinary_names_are_kept("pinned_note=1&shipping=2", "pinned_note=1&shipping=2")]
    fn sensitive_query_parameters_are_redacted(#[case] query: &str, #[case] expected: &str) {
        assert_eq!(redact_query(query, &[]), expected);
    }

    #[test]
    fn redact_field_names_also_redact_query_parameters() {
        let fields = ["lang".to_owned()];
        assert_eq!(redact_query("lang=ja&q=x", &fields), "lang=[REDACTED]&q=x");
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
    #[case::pass("pass")]
    #[case::drupal_pass_confirm("pass_confirm")]
    #[case::passphrase("passphrase")]
    #[case::passcode("passcode")]
    #[case::pin("pin")]
    #[case::pin_camel("userPin")]
    #[case::otp("otp")]
    #[case::credential("credential")]
    #[case::auth("auth")]
    #[case::session("session_id")]
    #[case::private_key("private_key")]
    #[case::private_key_camel("PrivateKey")]
    #[case::access_key("AWS-ACCESS_KEY")]
    #[case::secret_key("secret_key")]
    #[case::jwt("jwt")]
    #[case::cookie("cookie")]
    fn sensitive_key_names_are_detected(#[case] key: &str) {
        assert!(is_sensitive_key(key));
    }

    #[rstest]
    #[case::name("name")]
    #[case::email("email")]
    #[case::comment("comment")]
    #[case::author("author")]
    #[case::shipping("shipping")]
    #[case::passenger("passenger")]
    #[case::pinned("pinned_note")]
    #[case::footprint("footprint")]
    fn ordinary_key_names_are_not_sensitive(#[case] key: &str) {
        assert!(!is_sensitive_key(key));
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
    fn redact_field_names_are_redacted_in_every_body_format() {
        let fields = vec!["ticket_ref".to_owned()];
        let form = redact_body(
            Some("application/x-www-form-urlencoded"),
            b"Ticket_Ref=T1&ticket=x",
            &fields,
        );
        let pairs = form_pairs(&form);
        assert!(pairs.contains(&("Ticket_Ref".to_owned(), REDACTED.to_owned())));
        assert!(pairs.contains(&("ticket".to_owned(), "x".to_owned())));

        let json = redact_body(
            Some("application/json"),
            br#"{"outer":{"ticket_ref":"T1"},"ticket":"x"}"#,
            &fields,
        );
        let value = json_value(&json).unwrap_or(Value::Null);
        assert_eq!(value["outer"]["ticket_ref"], REDACTED);
        assert_eq!(value["ticket"], "x");

        assert_eq!(
            redact_body(None, b"ticket_ref=T1 ticket=x", &fields),
            "ticket_ref=[REDACTED] ticket=x"
        );
        assert_eq!(
            redact_body(
                Some("application/json"),
                br#"{"ticket_ref": "T1", "n": 1"#,
                &fields
            ),
            r#"{"ticket_ref": "[REDACTED]", "n": 1"#
        );
    }

    #[test]
    fn redact_field_names_match_the_whole_name_only() {
        let fields = vec!["ticket_ref".to_owned()];
        assert_eq!(
            redact_body(None, b"my_ticket_ref=T1&ticket_refs=2", &fields),
            "my_ticket_ref=T1&ticket_refs=2"
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

    /// Runs `work` on another thread and fails when it does not finish within `limit`.
    fn finishes_within<T: Send + 'static>(
        limit: Duration,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(work());
        });
        match receiver.recv_timeout(limit) {
            Ok(value) => value,
            Err(error) => panic!("the work did not finish within {limit:?}: {error}"),
        }
    }

    #[test]
    fn nested_unclosed_containers_are_redacted_in_linear_time() {
        // Every key opens a container that never closes: the old code scanned the rest of the body for each key.
        let body = "\"\":{".repeat(1024 * 1024 / 5);
        let started = std::time::Instant::now();
        let redacted = finishes_within(Duration::from_secs(2), move || {
            redact(None, body.as_bytes())
        });
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(redacted.starts_with("\"\":{\"\":{"));
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
            body_continues: false,
            host: "example.com",
            client_ip: "203.0.113.7",
            redact_headers: &[],
            redact_fields: &[],
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
            body_continues: false,
            host: "example.com",
            client_ip: "203.0.113.7",
            redact_headers: &[],
            redact_fields: &[],
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
