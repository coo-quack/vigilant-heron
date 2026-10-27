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
/// `x-authentication`. They are checked only for header names: `ticket` is a common
/// body field (support tickets, `ticket_ref`), so body and query fields keep it visible.
/// Whole-word matching keeps `authenticated` and `authenticator-id` visible.
const SENSITIVE_HEADER_WORDS: [&str; 2] = ["ticket", "authentication"];

/// Header names that end in `key` but are not credentials. `Sec-WebSocket-Key` is the
/// random nonce of the WebSocket handshake, and its value is not secret.
const KEY_HEADER_EXEMPTIONS: [&str; 1] = ["sec-websocket-key"];

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
/// Both `&` and `;` separate parameters, because some upstreams split on `;` too. A
/// parameter is redacted by the same rule as a body field, applied to its decoded
/// name. The other parameters and the separators are copied as they were sent, so
/// their order and encoding are kept. A parameter without `=` has no value and is
/// copied as it is.
fn redact_query(query: &str, redact_fields: &[String]) -> String {
    let mut redacted = String::with_capacity(query.len());
    let mut parameter = String::new();
    for c in query.chars() {
        if is_parameter_separator(c) {
            redacted.push_str(&redact_parameter(&parameter, redact_fields));
            redacted.push(c);
            parameter.clear();
        } else {
            parameter.push(c);
        }
    }
    redacted.push_str(&redact_parameter(&parameter, redact_fields));
    redacted
}

/// Whether a character separates two query parameters.
fn is_parameter_separator(c: char) -> bool {
    c == '&' || c == ';'
}

/// Redacts the value of one query parameter when its name is sensitive.
fn redact_parameter(parameter: &str, redact_fields: &[String]) -> String {
    match parameter.split_once('=') {
        Some((name, _)) if is_redacted_key(&decode_name(name), redact_fields) => {
            format!("{name}={REDACTED}")
        }
        _ => parameter.to_owned(),
    }
}

/// Decodes a parameter name the way form data does (`+` is a space, `%XX` is a byte).
fn decode_name(raw: &str) -> String {
    form_urlencoded::parse(raw.as_bytes())
        .map(|(name, _)| name.into_owned())
        .collect()
}

/// Describes the shape of a query string for the `$query_shape` log variable.
///
/// The output keeps the parameter names and the class of each value, and never
/// the value text: `p=42&s=secret+words` becomes `p=<num>&s=<text>`. Parameters
/// are separated by `&` or `;` as in [`redact_query`], and empty pieces are
/// skipped. At most 16 parameters are shown, then `<more>`. Returns `None` when
/// the query has no parameter at all.
pub(crate) fn query_shape(query: &str) -> Option<String> {
    const MAX_PARAMETERS: usize = 16;
    let mut parameters = query
        .split(is_parameter_separator)
        .filter(|piece| !piece.is_empty());
    let mut shapes: Vec<String> = parameters
        .by_ref()
        .take(MAX_PARAMETERS)
        .map(parameter_shape)
        .collect();
    if parameters.next().is_some() {
        shapes.push("<more>".to_owned());
    }
    (!shapes.is_empty()).then(|| shapes.join("&"))
}

/// Describes one non-empty query parameter as `name=<class>`, or `<bare>` when it has no `=`.
fn parameter_shape(parameter: &str) -> String {
    match parameter.split_once('=') {
        None => "<bare>".to_owned(),
        Some((raw_name, raw_value)) => {
            let name = decode_name(raw_name);
            let name = if is_plain_name(&name) {
                name
            } else {
                "<name>".to_owned()
            };
            format!("{name}={}", value_class(raw_value))
        }
    }
}

/// Whether a decoded parameter name is a plain identifier: an ASCII letter or `_`
/// first, then up to 31 ASCII letters, digits, `_`, `.`, `-`, `[` or `]`.
fn is_plain_name(name: &str) -> bool {
    let mut chars = name.chars();
    let starts_well = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    starts_well
        && name.len() <= 32
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | '[' | ']'))
}

/// The class of a raw parameter value, taken after form decoding: `<empty>`,
/// `<num>` (1 to 20 digits), `<word>` (1 to 64 letters, digits, `_` or `-`) or `<text>`.
fn value_class(raw_value: &str) -> &'static str {
    let value = decode_value(raw_value);
    if value.is_empty() {
        "<empty>"
    } else if value.len() <= 20 && value.bytes().all(|b| b.is_ascii_digit()) {
        "<num>"
    } else if value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        "<word>"
    } else {
        "<text>"
    }
}

/// Decodes a parameter value the way form data does. The value is placed after a
/// dummy name so that the form parser decodes it; the raw value holds no `&` or `;`.
fn decode_value(raw: &str) -> String {
    form_urlencoded::parse(format!("v={raw}").as_bytes())
        .map(|(_, value)| value.into_owned())
        .collect()
}

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
/// last rule. Body and query fields are not checked against these two header rules.
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
fn is_redacted_key(key: &str, redact_fields: &[String]) -> bool {
    is_sensitive_key(key)
        || redact_fields
            .iter()
            .any(|field| field.eq_ignore_ascii_case(key))
}

/// Redacts sensitive fields of a body.
///
/// Form bodies are split into fields on `&` and `;`, as query strings are. Multipart
/// bodies are split into parts, and a part is redacted by its `Content-Disposition`
/// name. Other bodies are parsed as JSON when possible. Anything else, including
/// malformed JSON and XML, gets lexical redaction. A multipart body that does not have
/// the expected framing also gets lexical redaction.
pub(crate) fn redact_body(
    content_type: Option<&str>,
    body: &[u8],
    redact_fields: &[String],
) -> String {
    let text = String::from_utf8_lossy(body);
    if is_form_content_type(content_type) {
        return redact_query(&text, redact_fields);
    }
    if let Some(multipart) = multipart_boundary(content_type)
        .and_then(|boundary| redact_multipart(&text, &boundary, redact_fields))
    {
        return multipart;
    }
    if let Some(json) = redact_json(body, redact_fields) {
        return json;
    }
    redact_lexical(&text, redact_fields)
}

/// Returns the boundary of a `multipart/form-data` content type, without its quotes.
fn multipart_boundary(content_type: Option<&str>) -> Option<String> {
    let mut params = content_type?.split(';');
    if !params
        .next()?
        .trim()
        .eq_ignore_ascii_case("multipart/form-data")
    {
        return None;
    }
    params.find_map(|param| {
        let (key, value) = param.split_once('=')?;
        (key.trim().eq_ignore_ascii_case("boundary"))
            .then(|| value.trim().trim_matches('"').to_owned())
            .filter(|boundary| !boundary.is_empty())
    })
}

/// Redacts the value of each `multipart/form-data` part whose `Content-Disposition` name is
/// sensitive. Boundaries and part headers are copied as they were sent.
///
/// Returns `None` when the framing is not as expected (no opening delimiter, a part without a
/// blank line after its headers, or no closing delimiter). The caller then uses lexical
/// redaction. Each part is searched only inside its own bytes, so the work is linear.
fn redact_multipart(text: &str, boundary: &str, redact_fields: &[String]) -> Option<String> {
    let open = format!("--{boundary}");
    let sep = format!("\n{open}");
    let mut out = String::with_capacity(text.len());
    let mut pos = text.find(&open)?;
    out.push_str(text.get(..pos)?);
    loop {
        let after_open = text.get(pos + open.len()..)?;
        if after_open.starts_with("--") {
            out.push_str(text.get(pos..)?);
            return Some(out);
        }
        // The newline that ends the opening delimiter line.
        let delim_nl = pos + open.len() + after_open.find('\n')?;
        let rest = text.get(delim_nl..)?;
        // The next delimiter starts with the newline that ends this part's content.
        let part_len = rest.find(&sep)?;
        let part = rest.get(..part_len)?;
        let blank = match (part.find("\n\r\n"), part.find("\n\n")) {
            (Some(crlf), Some(lf)) if lf < crlf => (lf, 2),
            (Some(crlf), _) => (crlf, 3),
            (None, Some(lf)) => (lf, 2),
            (None, None) => return None,
        };
        let body_start = delim_nl + blank.0 + blank.1;
        let body_end = delim_nl + part_len;
        let headers = text.get(delim_nl..body_start)?;
        let content = text.get(body_start..body_end)?;
        let value = content.strip_suffix('\r').unwrap_or(content);
        out.push_str(text.get(pos..body_start)?);
        if part_is_redacted(headers, redact_fields) {
            // Keep the line ending before the next delimiter, so the framing stays intact.
            out.push_str(REDACTED);
            out.push_str(text.get(body_start + value.len()..=body_end)?);
        } else {
            out.push_str(text.get(body_start..=body_end)?);
        }
        pos = body_end + 1;
    }
}

/// Returns true when a part's `Content-Disposition` names a redacted field. Only the `name`
/// parameter counts, so `filename` never names a field.
fn part_is_redacted(headers: &str, redact_fields: &[String]) -> bool {
    headers.lines().any(|line| {
        let Some((field, value)) = line.split_once(':') else {
            return false;
        };
        field.trim().eq_ignore_ascii_case("content-disposition")
            && value
                .split(';')
                .filter_map(|param| param.trim().split_once('='))
                .any(|(key, name)| {
                    key.trim().eq_ignore_ascii_case("name")
                        && is_redacted_key(name.trim().trim_matches('"'), redact_fields)
                })
    })
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
    #[case::semicolon_separates_parameters("password=x;id=1", "password=[REDACTED];id=1")]
    #[case::semicolon_hides_no_payload(
        "a=1;token=t&class_name=<p>",
        "a=1;token=[REDACTED]&class_name=<p>"
    )]
    #[case::semicolon_keeps_ordinary_names(
        "class_name=1;business_name=2",
        "class_name=1;business_name=2"
    )]
    #[case::trailing_separators_are_kept("token=t;&", "token=[REDACTED];&")]
    fn sensitive_query_parameters_are_redacted(#[case] query: &str, #[case] expected: &str) {
        assert_eq!(redact_query(query, &[]), expected);
    }

    #[rstest]
    #[case::empty_query_is_none("", None)]
    #[case::only_separators_is_none("&", None)]
    #[case::empty_pieces_are_none("&&;", None)]
    #[case::number_value_is_num("p=123", Some("p=<num>"))]
    #[case::word_value_is_word("feed=rss2", Some("feed=<word>"))]
    #[case::plus_makes_text("s=hello+world", Some("s=<text>"))]
    #[case::dash_and_underscore_are_word_characters("q=new-item_2", Some("q=<word>"))]
    #[case::empty_value_is_empty("q=", Some("q=<empty>"))]
    #[case::piece_without_equals_is_bare("abc", Some("<bare>"))]
    #[case::semicolon_separates("a=1;b=x", Some("a=<num>&b=<word>"))]
    #[case::percent_encoded_name_is_decoded("%70=1", Some("p=<num>"))]
    #[case::name_with_space_is_not_plain("a+b=1", Some("<name>=<num>"))]
    #[case::thirty_three_char_name_is_not_plain(
        "abcdefghijklmnopqrstuvwxyzabcdefg=1",
        Some("<name>=<num>")
    )]
    #[case::thirty_two_char_name_is_plain(
        "abcdefghijklmnopqrstuvwxyzabcdef=1",
        Some("abcdefghijklmnopqrstuvwxyzabcdef=<num>")
    )]
    #[case::twenty_one_digits_is_word("n=123456789012345678901", Some("n=<word>"))]
    #[case::twenty_digits_is_num("n=12345678901234567890", Some("n=<num>"))]
    #[case::sixty_five_chars_is_text(
        "v=abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmno",
        Some("v=<text>")
    )]
    #[case::sixty_four_chars_is_word(
        "v=abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl",
        Some("v=<word>")
    )]
    #[case::seventeen_parameters_show_sixteen_then_more(
        "a=1&b=1&c=1&d=1&e=1&f=1&g=1&h=1&i=1&j=1&k=1&l=1&m=1&n=1&o=1&p=1&q=1",
        Some(
            "a=<num>&b=<num>&c=<num>&d=<num>&e=<num>&f=<num>&g=<num>&h=<num>&i=<num>&j=<num>&k=<num>&l=<num>&m=<num>&n=<num>&o=<num>&p=<num>&<more>"
        )
    )]
    #[case::sixteen_parameters_have_no_more(
        "a=1&b=1&c=1&d=1&e=1&f=1&g=1&h=1&i=1&j=1&k=1&l=1&m=1&n=1&o=1&p=1",
        Some(
            "a=<num>&b=<num>&c=<num>&d=<num>&e=<num>&f=<num>&g=<num>&h=<num>&i=<num>&j=<num>&k=<num>&l=<num>&m=<num>&n=<num>&o=<num>&p=<num>"
        )
    )]
    fn query_shape_describes_names_and_value_classes(
        #[case] query: &str,
        #[case] expected: Option<&str>,
    ) {
        assert_eq!(query_shape(query).as_deref(), expected);
    }

    #[test]
    fn query_shape_never_contains_value_text() {
        let shape = query_shape("token=Secr3tValue&email=a%40b.example");
        assert_eq!(shape.as_deref(), Some("token=<word>&email=<text>"));
        let shape = shape.unwrap_or_default();
        assert!(!shape.contains("Secr3tValue"));
        assert!(!shape.contains("b.example"));
    }

    proptest! {
        #[test]
        fn query_shape_output_uses_only_shape_characters(query in "\\PC{0,128}") {
            let shape = query_shape(&query).unwrap_or_default();
            prop_assert!(shape.chars().all(|c| c.is_ascii_alphanumeric()
                || matches!(c, '_' | '.' | '-' | '[' | ']' | '<' | '>' | '=' | '&')));
        }
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

    #[test]
    fn truncation_at_a_multibyte_boundary_finishes_and_keeps_whole_characters() {
        let (text, cut) = finishes_within(Duration::from_secs(10), || {
            truncate_utf8("日本語".to_owned(), 4)
        });
        assert_eq!((text.as_str(), cut), ("日", true));
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
    fn multipart_ordinary_part_is_kept_and_sensitive_part_redacted() {
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
             Content-Type: image/png\r\n\r\nbinary\r\n--BB--\r\n"
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
                &fields
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
