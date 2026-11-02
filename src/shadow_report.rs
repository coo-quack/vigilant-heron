//! The `shadow-report` command: summarizes `json` access logs from a shadow trial, so
//! the log can be read before the switch to enforce.
//!
//! The report is plain text, for a person to read or to paste into an issue. Nothing is
//! sent to a backend, and the configuration is never read. Client addresses are
//! shortened unless the caller asks for them in full, so a report does not carry a
//! full client address by default.

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};
use std::io::{self, BufRead};
use std::net::{IpAddr, Ipv4Addr};

use serde_json::Value;

use crate::log_lines::{
    Line, for_each_line, is_block, number_field, object_line, text_field, whole_field,
};

/// A minute is listed as a burst when one client sends this many `client_busy` lines in
/// it, or more.
const BURST_LINES: usize = 5;

/// The most paths that a burst lists, most used first.
const BURST_PATHS: usize = 3;

/// The `decision_error` causes that come from a call to the backend. The lines with
/// `client_busy`, `backend_busy` or `request` never reached the backend, so they are not
/// calls. `parse` can also come from encoding the request, before any call; it is counted
/// as a call anyway.
const BACKEND_CAUSES: [&str; 9] = [
    "timeout",
    "rate_limited",
    "connection",
    "http_status",
    "body",
    "parse",
    "rejected",
    "invalid_response",
    "invalid_score",
];

/// The options of one run. The defaults are the ones the documentation states.
#[derive(Debug, Clone, PartialEq)]
pub struct ShadowOptions {
    /// The most would-block and block lines that are listed. The rest are counted.
    pub max_lines: usize,
    /// The price in USD of one million input tokens, when the cost should be estimated.
    pub usd_per_mtok: Option<f64>,
    /// Prints client addresses in full instead of the shortened form.
    pub full_addresses: bool,
}

impl Default for ShadowOptions {
    fn default() -> Self {
        Self {
            max_lines: 50,
            usd_per_mtok: None,
            full_addresses: false,
        }
    }
}

/// The counts of one UTC day.
#[derive(Debug, Clone, Default)]
struct DayCounts {
    lines: usize,
    /// The lines that reached the backend: those with an `attack` score, or with a `decision_error` from the backend (see `BACKEND_CAUSES`).
    calls: usize,
    /// The lines that a skip rule or the static skip forwarded without the backend.
    skips: usize,
    /// The lines that would be blocked or redirected, or were.
    blocked: usize,
    decision_errors: usize,
    timeouts: usize,
}

/// The `client_busy` lines of one client in one minute.
#[derive(Debug, Clone, Default)]
struct Burst {
    lines: usize,
    /// The number of lines per path.
    paths: BTreeMap<String, usize>,
}

/// The backend calls of one UTC hour.
#[derive(Debug, Clone, Default)]
struct Hour {
    calls: usize,
    timeouts: usize,
    /// The `latency_ms` of the calls that got a score.
    latencies: Vec<u64>,
}

/// The report of the logs read so far. Logs are added with [`ShadowReport::read_log`].
/// `Display` renders the plain text report from the same data.
#[derive(Debug, Clone)]
pub struct ShadowReport {
    options: ShadowOptions,
    files: usize,
    /// Every line that was read, a JSON object or not.
    lines: usize,
    /// The lines that are JSON objects.
    objects: usize,
    first_time: Option<String>,
    last_time: Option<String>,
    reasons: BTreeMap<String, usize>,
    decision_errors: BTreeMap<String, usize>,
    days: BTreeMap<String, DayCounts>,
    blocked_total: usize,
    /// The first would-block and block lines, up to `max_lines`, rendered for the report.
    blocked_lines: Vec<String>,
    /// Keyed by the minute and the client label.
    bursts: BTreeMap<(String, String), Burst>,
    hours: BTreeMap<String, Hour>,
    input_tokens: u64,
}

impl ShadowReport {
    /// An empty report, with the options of the run.
    #[must_use]
    pub fn new(options: &ShadowOptions) -> Self {
        Self {
            options: options.clone(),
            files: 0,
            lines: 0,
            objects: 0,
            first_time: None,
            last_time: None,
            reasons: BTreeMap::new(),
            decision_errors: BTreeMap::new(),
            days: BTreeMap::new(),
            blocked_total: 0,
            blocked_lines: Vec::new(),
            bursts: BTreeMap::new(),
            hours: BTreeMap::new(),
            input_tokens: 0,
        }
    }

    /// Reads the lines of one log into the report, after the logs already read. A line
    /// that is not a JSON object, or is too long to keep, is counted as malformed.
    ///
    /// # Errors
    ///
    /// Returns the error of a failed read from `input`. The lines read before the error
    /// stay in the report.
    pub fn read_log<R: BufRead>(&mut self, input: R) -> io::Result<()> {
        self.files += 1;
        for_each_line(input, |line| self.add_line(line))
    }

    fn add_line(&mut self, line: Line<'_>) {
        self.lines += 1;
        if let Line::Text(text) = line
            && let Some(value) = object_line(text)
        {
            self.objects += 1;
            self.add_object(&value);
        }
    }

    fn add_object(&mut self, value: &Value) {
        let time = text_field(value, "time");
        self.add_time(time);

        let reason = text_field(value, "reason");
        let reason_label = if reason.is_empty() { "(none)" } else { reason };
        *self.reasons.entry(reason_label.to_owned()).or_default() += 1;

        let decision_error = text_field(value, "decision_error");
        let score = number_field(value, "attack");
        let call = score.is_some() || BACKEND_CAUSES.contains(&decision_error);
        let skipped = matches!(reason, "skip" | "skip_rule");
        let blocked =
            is_block(text_field(value, "action")) || is_block(text_field(value, "would_have"));

        let day = self.days.entry(day_label(time)).or_default();
        day.lines += 1;
        day.calls += usize::from(call);
        day.skips += usize::from(skipped);
        day.blocked += usize::from(blocked);
        day.decision_errors += usize::from(!decision_error.is_empty());
        day.timeouts += usize::from(decision_error == "timeout");

        if !decision_error.is_empty() {
            *self
                .decision_errors
                .entry(decision_error.to_owned())
                .or_default() += 1;
        }
        if blocked {
            self.add_blocked(value);
        }
        if decision_error == "client_busy" {
            self.add_busy(value, time);
        }
        if call {
            self.add_call(value, time, decision_error, score.is_some());
        }
        if let Some(tokens) = whole_field(value, "input_tokens") {
            self.input_tokens = self.input_tokens.saturating_add(tokens);
        }
    }

    /// Keeps the earliest and the latest time of the logs. The times are ISO 8601 in UTC,
    /// so they compare as text.
    fn add_time(&mut self, time: &str) {
        if time.is_empty() {
            return;
        }
        let first = self
            .first_time
            .as_deref()
            .map_or(time, |first| first.min(time));
        self.first_time = Some(first.to_owned());
        let last = self
            .last_time
            .as_deref()
            .map_or(time, |last| last.max(time));
        self.last_time = Some(last.to_owned());
    }

    fn add_blocked(&mut self, value: &Value) {
        self.blocked_total += 1;
        if self.blocked_lines.len() < self.options.max_lines {
            self.blocked_lines
                .push(blocked_line(value, self.options.full_addresses));
        }
    }

    fn add_busy(&mut self, value: &Value, time: &str) {
        let key = (
            minute_label(time),
            client_label(value, self.options.full_addresses),
        );
        let burst = self.bursts.entry(key).or_default();
        burst.lines += 1;
        *burst
            .paths
            .entry(or_dash(text_field(value, "path")).to_owned())
            .or_default() += 1;
    }

    fn add_call(&mut self, value: &Value, time: &str, decision_error: &str, scored: bool) {
        let hour = self.hours.entry(hour_label(time)).or_default();
        hour.calls += 1;
        hour.timeouts += usize::from(decision_error == "timeout");
        if scored && let Some(latency) = whole_field(value, "latency_ms") {
            hour.latencies.push(latency);
        }
    }

    fn write_overview(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Files read: {}", self.files)?;
        writeln!(
            f,
            "Lines read: {} ({} JSON objects, {} malformed lines skipped)",
            self.lines,
            self.objects,
            self.lines - self.objects
        )?;
        match (&self.first_time, &self.last_time) {
            (Some(first), Some(last)) => {
                writeln!(f, "Time range: {} to {}", visible(first), visible(last))?;
            }
            _ => writeln!(f, "Time range: none, no line has a time")?,
        }
        writeln!(f)?;
        writeln!(f, "Counts by reason:")?;
        write_counts(f, &self.reasons, "  no lines")?;
        writeln!(f)?;
        writeln!(f, "Decision errors by cause:")?;
        write_counts(f, &self.decision_errors, "  none")
    }

    fn write_days(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Per day (UTC):")?;
        if self.days.is_empty() {
            writeln!(f, "  no lines")?;
        }
        for (day, counts) in &self.days {
            writeln!(
                f,
                "  {day}  lines {}  backend calls {}  skips {}  blocked or redirected {}  decision errors {}  timeouts {}",
                counts.lines,
                counts.calls,
                counts.skips,
                counts.blocked,
                counts.decision_errors,
                counts.timeouts
            )?;
        }
        Ok(())
    }

    fn write_blocked(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let listed = self.blocked_lines.len();
        if self.blocked_total > listed {
            writeln!(
                f,
                "Blocked or redirected lines: {} (listing the first {listed}; {} more not shown, use --max-lines to list more)",
                self.blocked_total,
                self.blocked_total - listed
            )?;
        } else {
            writeln!(f, "Blocked or redirected lines: {}", self.blocked_total)?;
        }
        for line in &self.blocked_lines {
            writeln!(f, "  {line}")?;
        }
        Ok(())
    }

    fn write_bursts(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "client_busy bursts ({BURST_LINES} or more client_busy lines from one client in one minute):"
        )?;
        let bursts: Vec<_> = self
            .bursts
            .iter()
            .filter(|(_, burst)| burst.lines >= BURST_LINES)
            .collect();
        if bursts.is_empty() {
            writeln!(f, "  none")?;
        }
        for ((minute, client), burst) in bursts {
            writeln!(
                f,
                "  {minute} {client}: {} lines; top paths: {}",
                burst.lines,
                top_paths(&burst.paths)
            )?;
        }
        Ok(())
    }

    fn write_hours(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Backend per hour (UTC), hours with backend calls:")?;
        if self.hours.is_empty() {
            writeln!(f, "  none")?;
        }
        for (hour, counts) in &self.hours {
            let mut latencies = counts.latencies.clone();
            latencies.sort_unstable();
            writeln!(
                f,
                "  {hour}  calls {}  timeouts {}  latency p50 {} ms, p99 {} ms",
                counts.calls,
                counts.timeouts,
                percentile_text(&latencies, 50),
                percentile_text(&latencies, 99)
            )?;
        }
        Ok(())
    }

    #[expect(
        clippy::cast_precision_loss,
        reason = "a token count stays far below 2^53, where u64 values convert to f64 exactly"
    )]
    fn write_tokens(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Input tokens: {}", self.input_tokens)?;
        match self.options.usd_per_mtok {
            Some(price) => {
                let cost = self.input_tokens as f64 / 1_000_000.0 * price;
                writeln!(
                    f,
                    "Estimated input cost: ${cost:.4} at ${price} per million input tokens (the log has no output tokens)"
                )
            }
            None => writeln!(
                f,
                "Cost: not estimated; give --usd-per-mtok <price> to estimate it"
            ),
        }
    }
}

impl fmt::Display for ShadowReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_overview(f)?;
        writeln!(f)?;
        self.write_days(f)?;
        writeln!(f)?;
        self.write_blocked(f)?;
        writeln!(f)?;
        self.write_bursts(f)?;
        writeln!(f)?;
        self.write_hours(f)?;
        writeln!(f)?;
        self.write_tokens(f)
    }
}

/// Writes `counts` as `  name: count` lines, most counted first. `empty` is written when there are none.
fn write_counts(
    f: &mut fmt::Formatter<'_>,
    counts: &BTreeMap<String, usize>,
    empty: &str,
) -> fmt::Result {
    if counts.is_empty() {
        return writeln!(f, "{empty}");
    }
    for (name, count) in most_first(counts) {
        writeln!(f, "  {}: {count}", visible(name))?;
    }
    Ok(())
}

/// The names with their counts, most counted first. Equal counts keep the name order.
fn most_first(counts: &BTreeMap<String, usize>) -> Vec<(&str, usize)> {
    let mut ranked: Vec<(&str, usize)> = counts
        .iter()
        .map(|(name, count)| (name.as_str(), *count))
        .collect();
    ranked.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    ranked
}

/// The most used paths of a burst, as `path (count)` joined by commas.
fn top_paths(paths: &BTreeMap<String, usize>) -> String {
    most_first(paths)
        .into_iter()
        .take(BURST_PATHS)
        .map(|(path, count)| format!("{} ({count})", visible(path)))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The UTC day of a time, such as `2026-11-02`. A missing time is `-`.
fn day_label(time: &str) -> String {
    visible(time.get(..10).unwrap_or("-"))
}

/// The UTC hour of a time, such as `2026-11-02 10:00`. A missing time is `-`.
fn hour_label(time: &str) -> String {
    match (time.get(..10), time.get(11..13)) {
        (Some(day), Some(hour)) => visible(&format!("{day} {hour}:00")),
        _ => "-".to_owned(),
    }
}

/// The UTC minute of a time, such as `2026-11-02 10:05`. A missing time is `-`.
fn minute_label(time: &str) -> String {
    match (time.get(..10), time.get(11..13), time.get(14..16)) {
        (Some(day), Some(hour), Some(minute)) => visible(&format!("{day} {hour}:{minute}")),
        _ => "-".to_owned(),
    }
}

/// The client as the report shows it: shortened, or in full when asked. An empty or
/// unreadable address is `-`.
fn client_label(value: &Value, full: bool) -> String {
    let text = text_field(value, "client_ip");
    if text.is_empty() {
        return "-".to_owned();
    }
    if full {
        return visible(text);
    }
    shorten_address(text)
}

/// The shortened form of a client address. An IPv4 address keeps its first three octets
/// (`192.0.2.x`), an IPv6 address its first three groups (`2001:db8:1::`). An IPv4-mapped
/// IPv6 address is shortened as the IPv4 address it holds.
fn shorten_address(text: &str) -> String {
    match text.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => shorten_v4(address),
        Ok(IpAddr::V6(address)) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                shorten_v4(mapped)
            } else {
                let [a, b, c, ..] = address.segments();
                format!("{a:x}:{b:x}:{c:x}::")
            }
        }
        Err(_) => "-".to_owned(),
    }
}

fn shorten_v4(address: Ipv4Addr) -> String {
    let [a, b, c, _] = address.octets();
    format!("{a}.{b}.{c}.x")
}

/// One would-block or block line: time, client, method, path, query shape, rule or
/// category, and attack score. A missing value is `-`.
fn blocked_line(value: &Value, full: bool) -> String {
    let field = |name: &str| visible(or_dash(text_field(value, name)));
    let rule = match (text_field(value, "rule_id"), text_field(value, "category")) {
        ("", "") => "-".to_owned(),
        (rule, "") => format!("rule={}", visible(rule)),
        ("", category) => format!("category={}", visible(category)),
        (rule, category) => format!("rule={} category={}", visible(rule), visible(category)),
    };
    format!(
        "{} {} {} {} query={} {rule} attack={}",
        field("time"),
        client_label(value, full),
        field("method"),
        field("path"),
        field("query_shape"),
        field("attack"),
    )
}

fn or_dash(text: &str) -> &str {
    if text.is_empty() { "-" } else { text }
}

/// Makes a value from the log safe to print. The characters that [`needs_escape`] names are
/// written as `\u{..}` escapes. Other text is kept as it is.
fn visible(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if needs_escape(c) {
            // Writing to a String cannot fail.
            let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    out
}

/// Whether a character is written as an escape. These are the control characters, the line
/// separators, the bidirectional controls, which can reverse the order of the text shown,
/// and the zero-width characters, which can hide text. Any of them could make the report
/// show something other than what the log holds.
fn needs_escape(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{2060}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
        )
}

/// The nearest-rank percentile of sorted values: the value at rank `ceil(percent * n / 100)`,
/// counting from 1. `None` when there are no values.
fn percentile(sorted: &[u64], percent: usize) -> Option<u64> {
    let rank = (percent * sorted.len()).div_ceil(100).max(1);
    sorted.get(rank - 1).copied()
}

/// A percentile as text in milliseconds, or `-` when there are no values.
fn percentile_text(sorted: &[u64], percent: usize) -> String {
    percentile(sorted, percent).map_or_else(|| "-".to_owned(), |value| value.to_string())
}

#[cfg(test)]
mod tests;
