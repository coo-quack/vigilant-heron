//! Building the event that is sent to the decision backend.
//!
//! Everything taken from the client is placed under `untrusted` so the backend
//! can treat it as data, never as instructions.

mod body;
mod keys;
mod query;

use http::{HeaderMap, Method};
use serde::Serialize;

use body::redact_body;
use keys::sanitize_headers;
use query::redact_query;

pub(crate) use query::{block_query, query_shape};

/// Replacement for the value of a sensitive field.
pub(crate) const REDACTED: &str = "[REDACTED]";

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
    /// Whether the content of a multipart file part is replaced (`redact_file_parts`).
    pub(crate) redact_file_parts: bool,
    /// Maximum number of body bytes sent to the backend.
    pub(crate) inspect_body_bytes: usize,
}

/// Builds the backend event, redacting credentials and truncating the body.
pub(crate) fn build_event(input: &EventInput<'_>) -> DecisionEvent {
    let content_type = input
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    let redacted = redact_body(
        content_type,
        input.body,
        input.body_continues,
        input.redact_fields,
        input.redact_file_parts,
    );
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
mod test_helpers {
    use std::time::Duration;

    use super::body::redact_body;

    /// Redacts a body with no extra field names, as a body that was not cut.
    pub(crate) fn redact(content_type: Option<&str>, body: &[u8]) -> String {
        redact_body(content_type, body, false, &[], true)
    }

    /// Runs `work` on another thread and fails when it does not finish within `limit`.
    pub(crate) fn finishes_within<T: Send + 'static>(
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
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use http::HeaderValue;
    use proptest::prelude::*;
    use rstest::rstest;
    use serde_json::Value;

    use super::test_helpers::finishes_within;
    use super::*;

    #[test]
    fn block_query_redacts_sensitive_parameters_as_the_backend_event_does() {
        let query = "password=hunter2&token=abc&q=x";
        assert_eq!(
            block_query(Some(query), &[]).as_deref(),
            Some("password=[REDACTED]&token=[REDACTED]&q=x")
        );
        let event = build_event(&EventInput {
            method: &Method::GET,
            path: "/search",
            query: Some(query),
            headers: &HeaderMap::new(),
            body: b"",
            body_continues: false,
            host: "example.com",
            client_ip: "203.0.113.7",
            redact_headers: &[],
            redact_fields: &[],
            redact_file_parts: true,
            inspect_body_bytes: 0,
        });
        assert_eq!(
            event.event.untrusted.query,
            block_query(Some(query), &[]),
            "the log and the backend must see the same query"
        );
    }

    #[rstest]
    #[case::continues(true, false)]
    #[case::complete(false, true)]
    fn build_event_passes_body_continues_to_the_multipart_redaction(
        #[case] body_continues: bool,
        #[case] hunter2_is_sent: bool,
    ) {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("multipart/form-data; boundary=BB"),
        );
        let event = build_event(&EventInput {
            method: &Method::POST,
            path: "/post",
            query: None,
            headers: &headers,
            body: b"--BB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2",
            body_continues,
            host: "example.com",
            client_ip: "203.0.113.7",
            redact_headers: &[],
            redact_fields: &[],
            redact_file_parts: true,
            inspect_body_bytes: 1024,
        });
        let json = serde_json::to_value(&event).unwrap_or(Value::Null);
        let body = json["event"]["untrusted"]["body"]
            .as_str()
            .unwrap_or_default();
        assert_eq!(body.contains("hunter2"), hunter2_is_sent);
        assert_eq!(json["event"]["meta"]["body_truncated"], body_continues);
    }

    #[rstest]
    #[case::redacted(true, false)]
    #[case::kept(false, true)]
    fn build_event_passes_redact_file_parts_to_the_body(
        #[case] redact_file_parts: bool,
        #[case] jfif_is_sent: bool,
    ) {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("multipart/form-data; boundary=BB"),
        );
        let event = build_event(&EventInput {
            method: &Method::POST,
            path: "/post",
            query: None,
            headers: &headers,
            body: b"--BB\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"a.jpg\"\r\n\r\nJFIF\r\n--BB--\r\n",
            body_continues: false,
            host: "example.com",
            client_ip: "203.0.113.7",
            redact_headers: &[],
            redact_fields: &[],
            redact_file_parts,
            inspect_body_bytes: 1024,
        });
        let json = serde_json::to_value(&event).unwrap_or(Value::Null);
        let body = json["event"]["untrusted"]["body"]
            .as_str()
            .unwrap_or_default();
        assert_eq!(body.contains("JFIF"), jfif_is_sent);
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
            redact_file_parts: true,
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
            redact_file_parts: true,
            inspect_body_bytes: 10,
        });
        let json = serde_json::to_value(&event).unwrap_or(Value::Null);
        let top_keys: Vec<&str> = json["event"]
            .as_object()
            .map_or_default(|map| map.keys().map(String::as_str).collect());
        assert_eq!(top_keys.len(), 2);
        assert!(top_keys.contains(&"untrusted"));
        assert!(top_keys.contains(&"meta"));
        assert_eq!(json["event"]["untrusted"]["query"], Value::Null);
        assert_eq!(json["event"]["meta"]["body_truncated"], false);
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
    fn truncation_at_a_multibyte_boundary_finishes_and_keeps_whole_characters() {
        let (text, cut) = finishes_within(Duration::from_secs(10), || {
            truncate_utf8("日本語".to_owned(), 4)
        });
        assert_eq!((text.as_str(), cut), ("日", true));
    }

    proptest! {
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
