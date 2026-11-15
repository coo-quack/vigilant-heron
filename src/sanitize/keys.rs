//! Sensitive names: the lists, the checks of a header name and of a field name, and the
//! headers that are sent to the backend.

use http::HeaderMap;

/// Credential headers dropped by name. Other headers are dropped when their name is
/// sensitive under [`is_sensitive_header`], so `x-csrf-token` and `x-session-id` are dropped too.
const DROPPED_HEADERS: [&str; 5] = [
    "cookie",
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
];

/// Parts that mark a field as sensitive when they occur anywhere in its name. These are
/// long enough that an ordinary name rarely contains one.
///
/// The name is compared without its non-alphanumeric characters and in lowercase,
/// so `api_key`, `API-KEY` and `apikey` all match `apikey`.
const SENSITIVE_KEY_PARTS: [&str; 13] = [
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "passphrase",
    "passcode",
    "credential",
    "privatekey",
    "accesskey",
    "creditcard",
    "cardnumber",
    // Covers request signatures such as `x-hub-signature-256`, `svix-signature`
    // and `x-slack-signature`, which carry an HMAC of the request.
    "signature",
];

/// Last words that mark a header as sensitive, as in `x-functions-key`, `x-master-key`,
/// `x-authkey` and `x-sessionkey`. Only header names are checked against these: a body
/// or query field named `key` is common and ordinary, so [`is_sensitive_key`] does not
/// use them.
const SENSITIVE_HEADER_KEY_WORDS: [&str; 3] = ["key", "authkey", "sessionkey"];

/// Short words that mark a field as sensitive only when a whole word of its name
/// is one of them. A substring match would redact `shipping` (`pin`), `author`
/// (`auth`), `passenger` (`pass`), `class_name` and `business_name` (`ssn`) and
/// `discard` (`card`).
///
/// Words are split as described in [`key_words`]: `card_id`, `userSSN` and `new_pwd`
/// are sensitive, `postcard` is not.
///
const SENSITIVE_WORDS: [&str; 12] = [
    "pass", "pin", "otp", "auth", "session", "cookie", "jwt", "pwd", "card", "cvv", "cvc", "ssn",
];

/// Whole words that mark a header name as sensitive, as in `x-cas-ticket` and
/// `x-authentication`. `ticket` is a common body field (support tickets, `ticket_ref`),
/// so body and query fields keep it visible. Whole-word matching keeps `authenticated`
/// and `authenticator-id` visible.
const SENSITIVE_HEADER_WORDS: [&str; 2] = ["ticket", "authentication"];

/// Header names that end in `key` but are not credentials. `Sec-WebSocket-Key` is the
/// random nonce of the WebSocket handshake, and its value is not secret.
const KEY_HEADER_EXEMPTIONS: [&str; 1] = ["sec-websocket-key"];

/// Copies the headers that may be sent, dropping credentials and redacted names.
pub(crate) fn sanitize_headers(headers: &HeaderMap, extra: &[String]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(name, _)| {
            let name = name.as_str();
            !DROPPED_HEADERS.contains(&name)
                && !is_sensitive_header(name)
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
/// non-alphanumeric character and at a lowercase-to-uppercase change. The parts are
/// matched anywhere in the name, the words only as whole words.
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

/// Returns true when a header name is sensitive: by [`is_sensitive_key`], by one of
/// [`SENSITIVE_HEADER_WORDS`] as a word, or by a last word in [`SENSITIVE_HEADER_KEY_WORDS`]
/// (except the [`KEY_HEADER_EXEMPTIONS`]). A header such as `x-limit-key` is dropped by the
/// last rule.
pub(crate) fn is_sensitive_header(name: &str) -> bool {
    if is_sensitive_key(name) {
        return true;
    }
    let words = key_words(name);
    if words
        .iter()
        .any(|word| SENSITIVE_HEADER_WORDS.contains(&word.as_str()))
    {
        return true;
    }
    !KEY_HEADER_EXEMPTIONS.contains(&name.to_ascii_lowercase().as_str())
        && words
            .last()
            .is_some_and(|word| SENSITIVE_HEADER_KEY_WORDS.contains(&word.as_str()))
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
pub(crate) fn is_redacted_key(key: &str, redact_fields: &[String]) -> bool {
    is_sensitive_key(key)
        || redact_fields
            .iter()
            .any(|field| field.eq_ignore_ascii_case(key))
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;
    use http::header::{AUTHORIZATION, COOKIE, HeaderMap, HeaderName};
    use rstest::rstest;

    use super::*;

    type BoxError = Box<dyn std::error::Error>;

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
    #[case::card_id_word("card_id")]
    #[case::ssn_word("user_ssn")]
    #[case::ssn_camel("userSSN")]
    #[case::ssn_after_underscore("user_SSN")]
    #[case::new_pwd("new_pwd")]
    #[case::cvc("cvc")]
    #[case::credit_card_part("credit_card")]
    #[case::card_number_part("card_number_full")]
    #[case::cvv_part("cvvCode")]
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
    #[case::class_name("class_name")]
    #[case::business_name("business_name")]
    #[case::process_name("process_name")]
    #[case::address_number("address_number")]
    #[case::classname("classname")]
    #[case::discard("discard")]
    #[case::postcard_size("postcard_size")]
    #[case::postcard_camel("postcardSize")]
    fn ordinary_key_names_are_not_sensitive(#[case] key: &str) {
        assert!(!is_sensitive_key(key));
    }

    #[rstest]
    #[case::signature_hub_sha256("x-hub-signature-256")]
    #[case::signature_hub("x-hub-signature")]
    #[case::signature_svix("svix-signature")]
    #[case::signature_slack("x-slack-signature")]
    #[case::signature_bare("signature")]
    #[case::functions_key("x-functions-key")]
    #[case::azure_functions_key("x-azure-functions-key")]
    #[case::master_key("x-master-key")]
    #[case::admin_key("x-admin-key")]
    #[case::app_key("x-app-key")]
    #[case::limit_key("x-limit-key")]
    #[case::bare_key("x-key")]
    #[case::authkey("x-authkey")]
    #[case::sessionkey("x-sessionkey")]
    #[case::ticket("x-cas-ticket")]
    #[case::authentication("authentication")]
    #[case::x_authentication("x-authentication")]
    fn credential_header_names_added_for_the_signature_key_and_ticket_families_are_dropped(
        #[case] name: &str,
    ) -> Result<(), BoxError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_bytes(name.as_bytes())?,
            HeaderValue::from_static("secret"),
        );
        headers.insert(http::header::ACCEPT, HeaderValue::from_static("*/*"));
        let kept = sanitize_headers(&headers, &[]);
        assert!(kept.iter().all(|(kept_name, _)| kept_name != name));
        assert!(kept.iter().any(|(kept_name, _)| kept_name == "accept"));
        Ok(())
    }

    #[rstest]
    #[case::keyboard("keyboard")]
    #[case::cache_control("cache-control")]
    #[case::request_id("x-request-id")]
    #[case::key_in_the_middle("x-key-version")]
    #[case::websocket_key("sec-websocket-key")]
    #[case::authenticated("x-authenticated")]
    #[case::authenticator_id("x-authenticator-id")]
    fn ordinary_header_names_are_kept_by_the_key_and_ticket_rules(
        #[case] name: &str,
    ) -> Result<(), BoxError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_bytes(name.as_bytes())?,
            HeaderValue::from_static("visible"),
        );
        let kept = sanitize_headers(&headers, &[]);
        assert!(kept.iter().any(|(kept_name, _)| kept_name == name));
        Ok(())
    }
}
