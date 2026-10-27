//! Access-log formats: compiling `log_format` strings and rendering one line.
//!
//! A format is text with variables such as `$client_ip` and `$http_user_agent`.
//! Variables are escaped according to the format's `escape` option, so a value
//! can never add a line break or a control character to the log.

use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use http::{HeaderMap, HeaderName};

/// Request headers that may never appear in a log, whatever the configuration.
pub(crate) const FORBIDDEN_HEADERS: [&str; 5] = [
    "cookie",
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
];

/// How variable values are escaped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Escape {
    /// nginx style: `"`, `\` and bytes outside 0x20..=0x7e are escaped.
    Default,
    /// JSON string style, for output that is parsed as JSON.
    Json,
}

/// A value the log can show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Field {
    TimeIso8601,
    TimeLocal,
    Msec,
    RequestId,
    RuleId,
    ClientIp,
    RemoteAddr,
    Site,
    Host,
    Method,
    Path,
    QueryShape,
    Status,
    Action,
    Reason,
    WouldHave,
    Attack,
    AiInstruction,
    Category,
    DecisionError,
    RetryAfter,
    InputTokens,
    UpstreamStatus,
    UpstreamError,
    LatencyMs,
    LimitReqStatus,
    LimitConnStatus,
}

impl Field {
    fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "time_iso8601" => Self::TimeIso8601,
            "time_local" => Self::TimeLocal,
            "msec" => Self::Msec,
            "request_id" => Self::RequestId,
            "rule_id" => Self::RuleId,
            "client_ip" => Self::ClientIp,
            "remote_addr" => Self::RemoteAddr,
            "site" => Self::Site,
            "host" => Self::Host,
            "method" => Self::Method,
            "path" => Self::Path,
            "query_shape" => Self::QueryShape,
            "status" => Self::Status,
            "action" => Self::Action,
            "reason" => Self::Reason,
            "would_have" => Self::WouldHave,
            "attack" => Self::Attack,
            "ai_instruction" => Self::AiInstruction,
            "category" => Self::Category,
            "decision_error" => Self::DecisionError,
            "retry_after" => Self::RetryAfter,
            "input_tokens" => Self::InputTokens,
            "upstream_status" => Self::UpstreamStatus,
            "upstream_error" => Self::UpstreamError,
            "latency_ms" => Self::LatencyMs,
            "limit_req_status" => Self::LimitReqStatus,
            "limit_conn_status" => Self::LimitConnStatus,
            _ => return None,
        })
    }
}

/// One part of a compiled format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Piece {
    /// Text copied as written.
    Literal(String),
    /// A value from the record.
    Field(Field),
    /// A request header, lowercase, from a `$http_<name>` variable.
    Header(HeaderName),
}

/// A compiled `log_format`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogFormat {
    /// The name the format was given, or `json` and `main` for the built-in formats.
    pub(crate) name: String,
    pub(crate) escape: Escape,
    pub(crate) pieces: Vec<Piece>,
}

impl LogFormat {
    /// Compiles `text`. `redact` lists header names that must not be logged.
    ///
    /// # Errors
    ///
    /// Returns a message for an unknown variable, a lone `$`, a header that may
    /// not be logged, or an empty header name.
    pub(crate) fn compile(
        name: &str,
        escape: Escape,
        text: &str,
        redact: &[String],
    ) -> Result<Self, String> {
        let chars: Vec<char> = text.chars().collect();
        let mut pieces = Vec::new();
        let mut literal = String::new();
        let mut index = 0;
        while let Some(&c) = chars.get(index) {
            if c != '$' {
                literal.push(c);
                index += 1;
                continue;
            }
            let (variable, next) = read_variable(&chars, index)?;
            if !literal.is_empty() {
                pieces.push(Piece::Literal(std::mem::take(&mut literal)));
            }
            pieces.push(piece_for(&variable, redact)?);
            index = next;
        }
        if !literal.is_empty() {
            pieces.push(Piece::Literal(literal));
        }
        Ok(Self {
            name: name.to_owned(),
            escape,
            pieces,
        })
    }

    /// The built-in `json` format: every decision field as a JSON object.
    pub(crate) fn json() -> Self {
        Self::compile("json", Escape::Json, JSON_TEMPLATE, &[]).unwrap_or_else(|_| Self::empty())
    }

    /// The built-in `main` format: one readable line.
    pub(crate) fn main() -> Self {
        Self::compile("main", Escape::Default, MAIN_TEMPLATE, &[]).unwrap_or_else(|_| Self::empty())
    }

    fn empty() -> Self {
        Self {
            name: String::new(),
            escape: Escape::Default,
            pieces: Vec::new(),
        }
    }

    /// Renders one line for `record`. The line has no line break at the end.
    pub(crate) fn render(&self, record: &AccessRecord<'_>, headers: &HeaderMap) -> String {
        let mut out = String::new();
        for piece in &self.pieces {
            match piece {
                Piece::Literal(text) => out.push_str(text),
                Piece::Field(field) => {
                    let value = field_value(*field, record);
                    write_value(&mut out, value.as_deref(), self.escape);
                }
                Piece::Header(name) => {
                    let value = headers
                        .get(name)
                        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned());
                    write_value(&mut out, value.as_deref(), self.escape);
                }
            }
        }
        out
    }
}

/// The built-in JSON template. Every value is a JSON string; a missing value is `""`.
const JSON_TEMPLATE: &str = concat!(
    r#"{"time":"$time_iso8601","request_id":"$request_id","client_ip":"$client_ip","#,
    r#""site":"$site","host":"$host","method":"$method","path":"$path","query_shape":"$query_shape","status":"$status","#,
    r#""action":"$action","reason":"$reason","rule_id":"$rule_id","would_have":"$would_have","attack":"$attack","#,
    r#""ai_instruction":"$ai_instruction","category":"$category","#,
    r#""decision_error":"$decision_error","retry_after":"$retry_after","#,
    r#""input_tokens":"$input_tokens","latency_ms":"$latency_ms"}"#
);

/// The built-in `main` template. The free-text values are quoted, so a value with spaces or `=` cannot add a field.
const MAIN_TEMPLATE: &str = concat!(
    "$time_iso8601 $client_ip $site \"$method $path\" $status ",
    "action=$action reason=$reason would_have=$would_have ",
    "attack=$attack ai_instruction=$ai_instruction category=\"$category\" ",
    "decision_error=$decision_error retry_after=\"$retry_after\" ",
    "input_tokens=$input_tokens latency_ms=$latency_ms request_id=\"$request_id\""
);

/// Reads `$name` or `${name}` starting at the `$` at `start`.
fn read_variable(chars: &[char], start: usize) -> Result<(String, usize), String> {
    if chars.get(start + 1) == Some(&'{') {
        let mut name = String::new();
        let mut index = start + 2;
        loop {
            match chars.get(index) {
                Some('}') => return Ok((name, index + 1)),
                Some(&c) if c.is_ascii_alphanumeric() || c == '_' => {
                    name.push(c);
                    index += 1;
                }
                _ => return Err("unterminated or invalid ${...} variable".to_owned()),
            }
        }
    }
    let mut name = String::new();
    let mut index = start + 1;
    while let Some(&c) = chars.get(index) {
        if c.is_ascii_alphanumeric() || c == '_' {
            name.push(c);
            index += 1;
        } else {
            break;
        }
    }
    if name.is_empty() {
        return Err("a \"$\" must be followed by a variable name".to_owned());
    }
    Ok((name, index))
}

fn piece_for(name: &str, redact: &[String]) -> Result<Piece, String> {
    if let Some(header) = name.strip_prefix("http_") {
        if header.is_empty() {
            return Err("$http_ needs a header name".to_owned());
        }
        let header_name = header.replace('_', "-").to_ascii_lowercase();
        let forbidden = FORBIDDEN_HEADERS.contains(&header_name.as_str())
            || redact.iter().any(|r| r.eq_ignore_ascii_case(&header_name));
        if forbidden {
            return Err(format!(
                "$http_{header} is not allowed: the header is never logged"
            ));
        }
        let parsed = HeaderName::from_bytes(header_name.as_bytes())
            .map_err(|_| format!("$http_{header} is not a valid header name"))?;
        return Ok(Piece::Header(parsed));
    }
    Field::from_name(name)
        .map(Piece::Field)
        .ok_or_else(|| format!("unknown variable ${name}"))
}

/// The values one request contributes to a log line.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AccessRecord<'a> {
    /// When the request was answered.
    pub(crate) time: SystemTime,
    /// The configured request-id header, when the request sent one.
    pub(crate) request_id: Option<&'a str>,
    /// The client address after real-IP selection.
    pub(crate) client_ip: &'a str,
    /// The address of the connection's peer.
    pub(crate) remote_addr: &'a str,
    /// First host of the matched site; empty when no site matched.
    pub(crate) site: &'a str,
    /// The `Host` header as sent, or empty.
    pub(crate) host: &'a str,
    /// Request method.
    pub(crate) method: &'a str,
    /// Raw request path without the query.
    pub(crate) path: &'a str,
    /// Raw query string, without the "?", when the request had one.
    pub(crate) query: Option<&'a str>,
    /// Status of the response.
    pub(crate) status: u16,
    /// `allow`, `block`, `redirect`, or `reject` for requests answered before a decision.
    pub(crate) action: &'a str,
    /// Why the action was chosen.
    pub(crate) reason: &'a str,
    /// The id of the rule that decided the request, empty when no rule did.
    pub(crate) rule_id: &'a str,
    /// In shadow mode, the action that would have been taken.
    pub(crate) would_have: Option<&'a str>,
    /// Attack score, when a backend answered.
    pub(crate) attack: Option<f64>,
    /// AI-instruction score, when a backend answered.
    pub(crate) ai_instruction: Option<f64>,
    /// Attack category, when the backend named one.
    pub(crate) category: Option<&'a str>,
    /// Specific cause of a decision failure.
    pub(crate) decision_error: Option<&'a str>,
    /// `Retry-After` of a 429, when sent.
    pub(crate) retry_after: Option<&'a str>,
    /// Input tokens the backend reported.
    pub(crate) input_tokens: Option<u64>,
    /// Status the upstream answered with, when it answered.
    pub(crate) upstream_status: Option<u16>,
    /// Why the upstream did not give a response: `connect_timeout`, `connect_failed`,
    /// `read_timeout`, `send_timeout` or `upstream_failed`.
    pub(crate) upstream_error: Option<&'a str>,
    /// Time from the start of the request to the answer, in milliseconds.
    pub(crate) latency_ms: u64,
    /// `$limit_req_status`: the worst `limit_req` outcome, when a zone applied.
    pub(crate) limit_req_status: Option<&'a str>,
    /// `$limit_conn_status`: the worst `limit_conn` outcome, when a zone applied.
    pub(crate) limit_conn_status: Option<&'a str>,
}

/// The value of a field, or `None` when it has none.
fn field_value(field: Field, record: &AccessRecord<'_>) -> Option<String> {
    let text = |value: &str| (!value.is_empty()).then(|| value.to_owned());
    match field {
        Field::TimeIso8601 => Some(iso8601(record.time)),
        Field::TimeLocal => Some(time_local(record.time)),
        Field::Msec => Some(msec(record.time)),
        Field::RequestId => record.request_id.and_then(text),
        Field::RuleId => text(record.rule_id),
        Field::ClientIp => text(record.client_ip),
        Field::RemoteAddr => text(record.remote_addr),
        Field::Site => text(record.site),
        Field::Host => text(record.host),
        Field::Method => text(record.method),
        Field::Path => text(record.path),
        Field::QueryShape => record.query.and_then(crate::sanitize::query_shape),
        Field::Status => Some(record.status.to_string()),
        Field::Action => text(record.action),
        Field::Reason => text(record.reason),
        Field::WouldHave => record.would_have.and_then(text),
        Field::Attack => record.attack.map(|v| v.to_string()),
        Field::AiInstruction => record.ai_instruction.map(|v| v.to_string()),
        Field::Category => record.category.and_then(text),
        Field::DecisionError => record.decision_error.and_then(text),
        Field::RetryAfter => record.retry_after.and_then(text),
        Field::InputTokens => record.input_tokens.map(|v| v.to_string()),
        Field::UpstreamStatus => record.upstream_status.map(|v| v.to_string()),
        Field::UpstreamError => record.upstream_error.and_then(text),
        Field::LatencyMs => Some(record.latency_ms.to_string()),
        Field::LimitReqStatus => record.limit_req_status.and_then(text),
        Field::LimitConnStatus => record.limit_conn_status.and_then(text),
    }
}

fn write_value(out: &mut String, value: Option<&str>, escape: Escape) {
    match value {
        Some(value) => escape_into(out, value, escape),
        None => match escape {
            Escape::Default => out.push('-'),
            Escape::Json => {}
        },
    }
}

/// Characters a log line must never contain: controls (C0, DEL and C1), and the Unicode line separators.
fn is_log_breaking_char(c: char) -> bool {
    c.is_control() || c == '\u{2028}' || c == '\u{2029}'
}

/// Appends `value` escaped for `escape`.
///
/// `Escape::Default` writes every byte outside printable ASCII as `\xNN`. `Escape::Json`
/// keeps printable non-ASCII text (such as Japanese) and writes the breaking characters as `\uXXXX`.
pub(crate) fn escape_into(out: &mut String, value: &str, escape: Escape) {
    match escape {
        Escape::Default => {
            for c in value.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    c if (' '..='~').contains(&c) => out.push(c),
                    c => {
                        let mut buffer = [0u8; 4];
                        for byte in c.encode_utf8(&mut buffer).as_bytes() {
                            let _ = write!(out, "\\x{byte:02X}");
                        }
                    }
                }
            }
        }
        Escape::Json => {
            for c in value.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if is_log_breaking_char(c) => {
                        let _ = write!(out, "\\u{:04x}", c as u32);
                    }
                    c => out.push(c),
                }
            }
        }
    }
}

/// Narrows a calendar component to `u32`. Every component fits, so the fallback is never used.
fn component(value: i64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// Splits Unix seconds into (year, month, day, hour, minute, second), in UTC.
pub(crate) fn civil(seconds: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    // Days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = component(doy - (153 * mp + 2) / 5 + 1);
    let month = component(if mp < 10 { mp + 3 } else { mp - 9 });
    let year = yoe + era * 400 + i64::from(month <= 2);
    (
        year,
        month,
        day,
        component(rest / 3600),
        component((rest % 3600) / 60),
        component(rest % 60),
    )
}

fn unix_parts(time: SystemTime) -> (i64, u32) {
    match time.duration_since(UNIX_EPOCH) {
        Ok(elapsed) => (
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX),
            elapsed.subsec_millis(),
        ),
        Err(before) => {
            let back = i64::try_from(before.duration().as_secs()).unwrap_or(i64::MAX);
            (-back, 0)
        }
    }
}

/// `2026-10-25T08:00:00+00:00`, in UTC.
pub(crate) fn iso8601(time: SystemTime) -> String {
    let (y, mo, d, h, mi, s) = civil(unix_parts(time).0);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}+00:00")
}

/// `25/Oct/2026:08:00:00 +0000`, in UTC. There is no timezone database, so local time is UTC.
pub(crate) fn time_local(time: SystemTime) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (y, mo, d, h, mi, s) = civil(unix_parts(time).0);
    let name = MONTHS
        .get(mo.saturating_sub(1) as usize)
        .copied()
        .unwrap_or("Jan");
    format!("{d:02}/{name}/{y:04}:{h:02}:{mi:02}:{s:02} +0000")
}

/// Unix time with milliseconds, like nginx's `$msec`.
pub(crate) fn msec(time: SystemTime) -> String {
    let (seconds, millis) = unix_parts(time);
    format!("{seconds}.{millis:03}")
}

/// `Oct 25 08:00:00`, the RFC 3164 timestamp used for syslog, in UTC.
pub(crate) fn syslog_stamp(time: SystemTime) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (_, mo, d, h, mi, s) = civil(unix_parts(time).0);
    let name = MONTHS
        .get(mo.saturating_sub(1) as usize)
        .copied()
        .unwrap_or("Jan");
    format!("{name} {d:>2} {h:02}:{mi:02}:{s:02}")
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use http::HeaderValue;
    use proptest::prelude::*;
    use rstest::rstest;

    use super::*;

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    fn record(time: SystemTime) -> AccessRecord<'static> {
        AccessRecord {
            time,
            request_id: Some("req-1"),
            client_ip: "203.0.113.7",
            remote_addr: "10.0.0.2",
            site: "example.com",
            host: "example.com",
            method: "GET",
            path: "/articles",
            query: None,
            status: 200,
            action: "allow",
            reason: "model",
            rule_id: "",
            would_have: None,
            attack: Some(0.97),
            ai_instruction: None,
            category: Some("sql_injection"),
            decision_error: None,
            retry_after: None,
            limit_req_status: None,
            limit_conn_status: None,
            input_tokens: Some(1234),
            upstream_status: Some(200),
            upstream_error: None,
            latency_ms: 17,
        }
    }

    fn render(
        text: &str,
        escape: Escape,
        record: &AccessRecord<'_>,
        headers: &HeaderMap,
    ) -> String {
        LogFormat::compile("test", escape, text, &[])
            .map(|format| format.render(record, headers))
            .unwrap_or_default()
    }

    #[rstest]
    #[case::client_ip("$client_ip", "203.0.113.7")]
    #[case::remote_addr("$remote_addr", "10.0.0.2")]
    #[case::site("$site", "example.com")]
    #[case::method_and_path("$method $path", "GET /articles")]
    #[case::status("$status", "200")]
    #[case::action_and_reason("$action/$reason", "allow/model")]
    #[case::attack("$attack", "0.97")]
    #[case::category("$category", "sql_injection")]
    #[case::input_tokens("$input_tokens", "1234")]
    #[case::latency("$latency_ms", "17")]
    #[case::request_id("$request_id", "req-1")]
    #[case::braced_variable("${site}_x", "example.com_x")]
    fn variables_render_their_values(#[case] format: &str, #[case] expected: &str) {
        let headers = HeaderMap::new();
        assert_eq!(
            render(format, Escape::Default, &record(at(0)), &headers),
            expected
        );
    }

    #[test]
    fn missing_values_render_as_a_dash_by_default_and_empty_in_json() {
        let mut missing = record(at(0));
        missing.request_id = None;
        missing.attack = None;
        let headers = HeaderMap::new();
        assert_eq!(
            render("$request_id|$attack", Escape::Default, &missing, &headers),
            "-|-"
        );
        assert_eq!(
            render("$request_id|$attack", Escape::Json, &missing, &headers),
            "|"
        );
    }

    #[test]
    fn time_variables_use_the_utc_calendar() {
        let headers = HeaderMap::new();
        let t = at(1_761_379_200); // 2025-10-25T08:00:00Z
        assert_eq!(
            render("$time_iso8601", Escape::Default, &record(t), &headers),
            "2025-10-25T08:00:00+00:00"
        );
        assert_eq!(
            render("$time_local", Escape::Default, &record(t), &headers),
            "25/Oct/2025:08:00:00 +0000"
        );
        assert_eq!(
            render(
                "$msec",
                Escape::Default,
                &record(at(1_761_379_200)),
                &headers
            ),
            "1761379200.000"
        );
        assert_eq!(syslog_stamp(t), "Oct 25 08:00:00");
    }

    #[test]
    fn leap_days_are_placed_correctly() {
        assert_eq!(civil(951_782_400), (2000, 2, 29, 0, 0, 0));
        assert_eq!(civil(0), (1970, 1, 1, 0, 0, 0));
    }

    fn days_in_month(year: i64, month: u32) -> u32 {
        match month {
            2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
            2 => 28,
            4 | 6 | 9 | 11 => 30,
            _ => 31,
        }
    }

    #[test]
    fn civil_matches_the_gregorian_calendar_for_every_day_from_1600_to_2400() {
        // 1600-01-01T00:00:00Z, then every following day with a fixed time of day.
        let mut seconds: i64 = -11_676_096_000;
        let (mut year, mut month, mut day) = (1600_i64, 1_u32, 1_u32);
        while year <= 2400 {
            assert_eq!(
                civil(seconds + 13 * 3600 + 37 * 60 + 42),
                (year, month, day, 13, 37, 42),
                "unix seconds {seconds}"
            );
            seconds += 86_400;
            day += 1;
            if day > days_in_month(year, month) {
                day = 1;
                month += 1;
                if month > 12 {
                    month = 1;
                    year += 1;
                }
            }
        }
    }

    #[test]
    fn times_before_the_epoch_are_placed_before_it() {
        let before = UNIX_EPOCH - Duration::from_secs(1);
        assert_eq!(iso8601(before), "1969-12-31T23:59:59+00:00");
        assert_eq!(time_local(before), "31/Dec/1969:23:59:59 +0000");
    }

    #[test]
    fn a_request_header_is_logged_under_its_underscore_name() {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", HeaderValue::from_static("curl/8.4"));
        assert_eq!(
            render(
                "$http_user_agent",
                Escape::Default,
                &record(at(0)),
                &headers
            ),
            "curl/8.4"
        );
        assert_eq!(
            render("$http_accept", Escape::Default, &record(at(0)), &headers),
            "-"
        );
    }

    #[rstest]
    #[case::cookie("$http_cookie")]
    #[case::authorization("$http_authorization")]
    #[case::proxy_authorization("$http_proxy_authorization")]
    #[case::api_key("$http_x_api_key")]
    #[case::auth_token("$http_x_auth_token")]
    fn credential_headers_are_rejected_at_compile_time(#[case] text: &str) {
        assert!(LogFormat::compile("x", Escape::Default, text, &[]).is_err());
    }

    #[test]
    fn a_redacted_header_is_rejected_too() {
        let redact = vec!["X-Session".to_owned()];
        assert!(LogFormat::compile("x", Escape::Default, "$http_x_session", &redact).is_err());
        assert!(LogFormat::compile("x", Escape::Default, "$http_x_other", &redact).is_ok());
    }

    #[test]
    fn a_braced_variable_name_ends_at_the_first_character_outside_the_name() {
        assert!(LogFormat::compile("x", Escape::Default, "${http_x-y}", &[]).is_err());
        assert!(LogFormat::compile("x", Escape::Default, "${http_x}-y", &[]).is_ok());
    }

    #[test]
    fn braced_variable_names_may_contain_underscores() {
        let headers = HeaderMap::new();
        assert_eq!(
            render("${input_tokens}", Escape::Default, &record(at(0)), &headers),
            "1234"
        );
    }

    #[rstest]
    #[case::unknown("$no_such_variable")]
    #[case::lone_dollar("cost $ 5")]
    #[case::empty_header("$http_")]
    #[case::unterminated_braces("${site")]
    fn invalid_formats_are_rejected(#[case] text: &str) {
        assert!(LogFormat::compile("x", Escape::Default, text, &[]).is_err());
    }

    #[test]
    fn default_escape_quotes_backslashes_and_bytes_outside_printable_ascii() {
        let mut value = record(at(0));
        value.path = "/a\"b\\c\u{1}é";
        let headers = HeaderMap::new();
        assert_eq!(
            render("$path", Escape::Default, &value, &headers),
            "/a\\\"b\\\\c\\x01\\xC3\\xA9"
        );
    }

    #[test]
    fn json_escape_produces_valid_json_strings() {
        let mut value = record(at(0));
        value.path = "a\"b\nc\u{2}";
        let headers = HeaderMap::new();
        let rendered = render("\"$path\"", Escape::Json, &value, &headers);
        assert_eq!(rendered, "\"a\\\"b\\nc\\u0002\"");
    }

    #[test]
    fn built_in_json_format_is_valid_json() {
        let headers = HeaderMap::new();
        let line = LogFormat::json().render(&record(at(0)), &headers);
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&line);
        assert!(parsed.is_ok(), "not JSON: {line}");
    }

    #[test]
    fn json_escape_hides_c1_controls_and_line_separators() {
        let mut out = String::new();
        escape_into(&mut out, "a\u{9b}31m\u{85}b\u{2028}c\u{2029}", Escape::Json);
        assert_eq!(out, "a\\u009b31m\\u0085b\\u2028c\\u2029");
    }

    #[test]
    fn json_escape_keeps_printable_japanese_readable() {
        let mut out = String::new();
        escape_into(&mut out, "日本語 テキスト", Escape::Json);
        assert_eq!(out, "日本語 テキスト");
    }

    #[test]
    fn main_format_keeps_a_spaced_request_id_inside_its_quotes() {
        let mut value = record(at(0));
        value.request_id = Some("x action=allow reason=none attack=0 category=none");
        value.category = Some("a b=c");
        let rendered = LogFormat::main().render(&value, &HeaderMap::new());
        // Text outside quotes, where a field name is recognized (this test has no escaped quotes).
        let unquoted: String = rendered.split('"').step_by(2).collect::<Vec<_>>().join(" ");
        assert_eq!(unquoted.matches(" action=").count(), 1, "{rendered}");
        assert!(
            rendered.ends_with("request_id=\"x action=allow reason=none attack=0 category=none\""),
            "{rendered}"
        );
        assert!(rendered.contains("category=\"a b=c\""), "{rendered}");
    }

    proptest::proptest! {
        #[test]
        // Any char, control characters and newlines included: they are what the
        // escaping has to neutralise.
        fn default_escape_never_emits_control_characters(chars in proptest::collection::vec(proptest::arbitrary::any::<char>(), 0..64)) {
            let value: String = chars.into_iter().collect();
            let mut out = String::new();
            escape_into(&mut out, &value, Escape::Default);
            prop_assert!(out.chars().all(|c| (' '..='~').contains(&c)));
        }

        #[test]
        fn json_escape_never_emits_raw_control_characters(chars in proptest::collection::vec(proptest::arbitrary::any::<char>(), 0..64)) {
            let value: String = chars.into_iter().collect();
            let mut out = String::new();
            escape_into(&mut out, &value, Escape::Json);
            prop_assert!(out.chars().all(|c| !c.is_control()));
        }

        #[test]
        fn escapes_never_emit_c1_controls_or_line_separators(
            chars in proptest::collection::vec(
                prop_oneof![
                    3 => proptest::arbitrary::any::<char>(),
                    1 => proptest::sample::select(vec!['\u{7f}', '\u{85}', '\u{9b}', '\u{9d}', '\u{2028}', '\u{2029}']),
                ],
                0..64,
            ),
        ) {
            let value: String = chars.into_iter().collect();
            for escape in [Escape::Default, Escape::Json] {
                let mut out = String::new();
                escape_into(&mut out, &value, escape);
                prop_assert!(!out.chars().any(is_log_breaking_char));
            }
        }
    }
}
