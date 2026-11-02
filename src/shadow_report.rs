//! The `shadow-report` command: summarizes `json` access logs from a shadow trial, so
//! the log can be read before the switch to enforce.
//!
//! The report is plain text, for a person to read or to paste into an issue. Nothing is
//! sent to a backend, and the configuration is never read. Client addresses are
//! shortened unless the caller asks for them in full, so a report does not carry a
//! full client address by default.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, BufRead};
use std::net::{IpAddr, Ipv4Addr};

use serde_json::Value;

use crate::log_lines::{
    for_each_line, is_block, number_field, object_line, text_field, whole_field,
};

/// The most `client_busy` lines that one client may send in one minute before the minute
/// is listed as a burst.
const BURST_LINES: usize = 5;

/// The most paths that a burst lists, most used first.
const BURST_PATHS: usize = 3;

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
    /// The lines that reached the backend: those with an `attack` score or a `decision_error`.
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

/// The result of a run. `Display` renders the plain text report from the same data.
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
    fn new(options: &ShadowOptions) -> Self {
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

    /// Adds one line of a log. A line that is not a JSON object is counted and ignored.
    fn add_line(&mut self, line: &str) {
        self.lines += 1;
        if let Some(value) = object_line(line) {
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
        let call = score.is_some() || !decision_error.is_empty();
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
        if self.first_time.as_deref().is_none_or(|first| time < first) {
            self.first_time = Some(time.to_owned());
        }
        if self.last_time.as_deref().is_none_or(|last| time > last) {
            self.last_time = Some(time.to_owned());
        }
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
            (Some(first), Some(last)) => writeln!(f, "Time range: {first} to {last}")?,
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

/// Summarizes the lines of each log in `inputs`, read in the order given, into one report.
///
/// # Errors
///
/// Returns the error of a failed read from any of the inputs.
pub fn shadow_report<R: BufRead>(
    inputs: impl IntoIterator<Item = R>,
    options: &ShadowOptions,
) -> io::Result<ShadowReport> {
    let mut report = ShadowReport::new(options);
    for input in inputs {
        report.files += 1;
        for_each_line(input, |line| report.add_line(line))?;
    }
    Ok(report)
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
        writeln!(f, "  {name}: {count}")?;
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
        .map(|(path, count)| format!("{path} ({count})"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The UTC day of a time, such as `2026-11-02`. A missing time is `-`.
fn day_label(time: &str) -> String {
    time.get(..10).unwrap_or("-").to_owned()
}

/// The UTC hour of a time, such as `2026-11-02 10:00`. A missing time is `-`.
fn hour_label(time: &str) -> String {
    match (time.get(..10), time.get(11..13)) {
        (Some(day), Some(hour)) => format!("{day} {hour}:00"),
        _ => "-".to_owned(),
    }
}

/// The UTC minute of a time, such as `2026-11-02 10:05`. A missing time is `-`.
fn minute_label(time: &str) -> String {
    match (time.get(..10), time.get(11..13), time.get(14..16)) {
        (Some(day), Some(hour), Some(minute)) => format!("{day} {hour}:{minute}"),
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
        return text.to_owned();
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
    let rule = match (text_field(value, "rule_id"), text_field(value, "category")) {
        ("", "") => "-".to_owned(),
        (rule, "") => format!("rule={rule}"),
        ("", category) => format!("category={category}"),
        (rule, category) => format!("rule={rule} category={category}"),
    };
    format!(
        "{} {} {} {} query={} {rule} attack={}",
        or_dash(text_field(value, "time")),
        client_label(value, full),
        or_dash(text_field(value, "method")),
        or_dash(text_field(value, "path")),
        or_dash(text_field(value, "query_shape")),
        or_dash(text_field(value, "attack")),
    )
}

fn or_dash(text: &str) -> &str {
    if text.is_empty() { "-" } else { text }
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
mod tests {
    use super::*;
    use rstest::rstest;
    use serde_json::{Map, json};

    /// The fields of the `json` format, which a line without them does not have.
    const FIELDS: &[&str] = &[
        "time",
        "request_id",
        "client_ip",
        "site",
        "host",
        "method",
        "path",
        "query_shape",
        "status",
        "action",
        "reason",
        "rule_id",
        "would_have",
        "attack",
        "ai_instruction",
        "category",
        "decision_error",
        "retry_after",
        "input_tokens",
        "latency_ms",
    ];

    /// One `json` access log line. Every field is an empty string unless `overrides` sets it.
    fn line(overrides: &[(&str, &str)]) -> String {
        let mut object = Map::new();
        for field in FIELDS {
            object.insert((*field).to_owned(), json!(""));
        }
        object.insert("time".to_owned(), json!("2026-11-02T10:00:00+00:00"));
        object.insert("client_ip".to_owned(), json!("192.0.2.77"));
        object.insert("method".to_owned(), json!("GET"));
        object.insert("path".to_owned(), json!("/"));
        object.insert("action".to_owned(), json!("allow"));
        object.insert("reason".to_owned(), json!("model"));
        for (field, value) in overrides {
            object.insert((*field).to_owned(), json!(value));
        }
        Value::Object(object).to_string()
    }

    /// A log of the given lines, one per line.
    fn log(lines: &[String]) -> String {
        lines.join("\n")
    }

    /// The report of one log, read with the given options.
    fn render_with(text: &str, options: &ShadowOptions) -> String {
        shadow_report([text.as_bytes()], options)
            .unwrap_or_else(|error| panic!("reading from memory failed: {error}"))
            .to_string()
    }

    /// The report of one log, read with the default options.
    fn render(text: &str) -> String {
        render_with(text, &ShadowOptions::default())
    }

    /// The per-day line of `day`, or a message that the day is missing.
    fn day_line(report: &str, day: &str) -> String {
        report
            .lines()
            .find(|line| line.starts_with(&format!("  {day}  ")))
            .unwrap_or_else(|| panic!("no per-day line for {day} in:\n{report}"))
            .to_owned()
    }

    /// A reader whose every read fails, to check that the error is returned.
    struct FailingReader;

    impl io::Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("the disk went away"))
        }
    }

    #[test]
    fn the_sections_are_written_in_the_order_of_the_design() {
        let report = render(&line(&[]));
        let headings = [
            "Files read:",
            "Counts by reason:",
            "Decision errors by cause:",
            "Per day (UTC):",
            "Blocked or redirected lines:",
            "client_busy bursts",
            "Backend per hour (UTC)",
            "Input tokens:",
        ];
        let positions: Vec<usize> = headings
            .iter()
            .map(|heading| {
                report
                    .find(heading)
                    .unwrap_or_else(|| panic!("no {heading} in:\n{report}"))
            })
            .collect();
        assert!(
            positions.windows(2).all(|pair| pair[0] < pair[1]),
            "{report}"
        );
    }

    #[test]
    fn the_overview_counts_lines_objects_and_malformed_lines() {
        let text = log(&[
            line(&[]),
            line(&[]),
            "not json".to_owned(),
            "[1, 2]".to_owned(),
        ]);
        let report = render(&text);
        assert!(report.contains("Files read: 1\n"), "{report}");
        assert!(
            report.contains("Lines read: 4 (2 JSON objects, 2 malformed lines skipped)"),
            "{report}"
        );
    }

    #[test]
    fn the_time_range_runs_from_the_earliest_to_the_latest_time_across_files() {
        let first = log(&[line(&[("time", "2026-11-02T11:00:00+00:00")])]);
        let second = log(&[
            line(&[("time", "2026-11-01T09:30:00+00:00")]),
            line(&[("time", "2026-11-03T08:00:00+00:00")]),
        ]);
        let report = shadow_report(
            [first.as_bytes(), second.as_bytes()],
            &ShadowOptions::default(),
        )
        .unwrap_or_else(|error| panic!("reading from memory failed: {error}"))
        .to_string();
        assert!(report.contains("Files read: 2\n"), "{report}");
        assert!(
            report.contains("Time range: 2026-11-01T09:30:00+00:00 to 2026-11-03T08:00:00+00:00"),
            "{report}"
        );
    }

    #[test]
    fn the_time_range_says_none_when_no_line_has_a_time() {
        let report = render(&line(&[("time", "")]));
        assert!(
            report.contains("Time range: none, no line has a time"),
            "{report}"
        );
    }

    #[test]
    fn reasons_are_counted_most_first_and_a_missing_reason_is_none() {
        let text = log(&[
            line(&[("reason", "below_threshold")]),
            line(&[("reason", "model")]),
            line(&[("reason", "model")]),
            line(&[("reason", "")]),
        ]);
        let report = render(&text);
        let model = report.find("  model: 2").unwrap_or(usize::MAX);
        let below = report.find("  below_threshold: 1").unwrap_or(usize::MAX);
        let missing = report.find("  (none): 1").unwrap_or(usize::MAX);
        assert!(model < below && model < missing, "{report}");
        assert!(below != usize::MAX && missing != usize::MAX, "{report}");
    }

    #[test]
    fn decision_errors_are_counted_by_cause() {
        let text = log(&[
            line(&[("decision_error", "timeout")]),
            line(&[("decision_error", "timeout")]),
            line(&[("decision_error", "http_status")]),
        ]);
        let report = render(&text);
        assert!(
            report.contains("Decision errors by cause:\n  timeout: 2\n  http_status: 1\n"),
            "{report}"
        );
    }

    #[test]
    fn the_decision_errors_section_says_none_when_there_are_none() {
        let report = render(&line(&[]));
        assert!(
            report.contains("Decision errors by cause:\n  none\n"),
            "{report}"
        );
    }

    #[rstest]
    #[case::score_only(&[("attack", "0.1")], 1)]
    #[case::decision_error_only(&[("decision_error", "timeout")], 1)]
    #[case::score_and_error(&[("attack", "0.1"), ("decision_error", "http_status")], 1)]
    #[case::neither(&[], 0)]
    fn a_call_is_a_line_with_a_score_or_a_decision_error(
        #[case] overrides: &[(&str, &str)],
        #[case] calls: usize,
    ) {
        let report = render(&line(overrides));
        assert!(
            day_line(&report, "2026-11-02").contains(&format!("backend calls {calls}  ")),
            "{report}"
        );
    }

    #[rstest]
    #[case::skip(&[("reason", "skip")], 1)]
    #[case::skip_rule(&[("reason", "skip_rule")], 1)]
    #[case::model(&[("reason", "model")], 0)]
    #[case::access_denied(&[("reason", "access_denied")], 0)]
    fn a_skip_reason_counts_as_a_skip(#[case] overrides: &[(&str, &str)], #[case] skips: usize) {
        let report = render(&line(overrides));
        assert!(
            day_line(&report, "2026-11-02").contains(&format!("skips {skips}  ")),
            "{report}"
        );
    }

    #[rstest]
    #[case::action_block(&[("action", "block")], 1)]
    #[case::action_redirect(&[("action", "redirect")], 1)]
    #[case::would_have_block(&[("would_have", "block")], 1)]
    #[case::would_have_redirect(&[("would_have", "redirect")], 1)]
    #[case::allowed(&[("action", "allow")], 0)]
    #[case::rejected(&[("action", "reject")], 0)]
    fn block_and_redirect_in_either_action_field_count_as_blocked(
        #[case] overrides: &[(&str, &str)],
        #[case] blocked: usize,
    ) {
        let report = render(&line(overrides));
        assert!(
            day_line(&report, "2026-11-02").contains(&format!("blocked or redirected {blocked}  ")),
            "{report}"
        );
    }

    #[test]
    fn the_per_day_section_splits_the_counts_by_utc_day() {
        let text = log(&[
            line(&[("time", "2026-11-01T23:59:59+00:00"), ("attack", "0.1")]),
            line(&[("time", "2026-11-02T00:00:00+00:00"), ("attack", "0.2")]),
            line(&[("time", "2026-11-02T12:00:00+00:00"), ("reason", "skip")]),
        ]);
        let report = render(&text);
        assert!(
            day_line(&report, "2026-11-01").ends_with(
                "lines 1  backend calls 1  skips 0  blocked or redirected 0  decision errors 0  timeouts 0"
            ),
            "{report}"
        );
        assert!(
            day_line(&report, "2026-11-02").ends_with(
                "lines 2  backend calls 1  skips 1  blocked or redirected 0  decision errors 0  timeouts 0"
            ),
            "{report}"
        );
    }

    #[test]
    fn a_timeout_counts_as_a_decision_error_and_a_timeout_per_day() {
        let text = log(&[
            line(&[("decision_error", "timeout")]),
            line(&[("decision_error", "http_status")]),
        ]);
        let report = render(&text);
        assert!(
            day_line(&report, "2026-11-02").ends_with(
                "lines 2  backend calls 2  skips 0  blocked or redirected 0  decision errors 2  timeouts 1"
            ),
            "{report}"
        );
    }

    #[test]
    fn a_line_without_a_time_is_counted_under_a_dash_day() {
        let report = render(&line(&[("time", "")]));
        assert!(
            day_line(&report, "-").starts_with("  -  lines 1"),
            "{report}"
        );
    }

    #[test]
    fn the_per_day_section_says_no_lines_when_the_log_is_empty() {
        let report = render("");
        assert!(report.contains("Per day (UTC):\n  no lines\n"), "{report}");
    }

    #[test]
    fn a_blocked_line_shows_time_client_method_path_query_shape_rule_and_attack() {
        let report = render(&line(&[
            ("action", "block"),
            ("method", "POST"),
            ("path", "/xmlrpc.php"),
            ("query_shape", "p=<num>"),
            ("rule_id", "wp-xmlrpc"),
            ("attack", "0.91"),
        ]));
        assert!(
            report.contains(
                "  2026-11-02T10:00:00+00:00 192.0.2.x POST /xmlrpc.php query=p=<num> rule=wp-xmlrpc attack=0.91\n"
            ),
            "{report}"
        );
    }

    #[rstest]
    #[case::rule_only(&[("rule_id", "r1")], "rule=r1 attack=")]
    #[case::category_only(&[("category", "sqli")], "category=sqli attack=")]
    #[case::rule_and_category(&[("rule_id", "r1"), ("category", "sqli")], "rule=r1 category=sqli attack=")]
    #[case::neither(&[], "query=- - attack=")]
    fn a_blocked_line_shows_the_rule_id_or_the_category(
        #[case] overrides: &[(&str, &str)],
        #[case] expected: &str,
    ) {
        let mut fields = vec![("action", "block")];
        fields.extend_from_slice(overrides);
        let report = render(&line(&fields));
        assert!(report.contains(expected), "{expected:?} not in:\n{report}");
    }

    #[test]
    fn a_blocked_line_shows_a_dash_for_a_missing_path_query_shape_rule_and_score() {
        let report = render(&line(&[("action", "block"), ("path", "")]));
        assert!(
            report.contains("  2026-11-02T10:00:00+00:00 192.0.2.x GET - query=- - attack=-\n"),
            "{report}"
        );
    }

    #[test]
    fn blocked_lines_are_capped_at_max_lines_in_log_order_and_the_rest_are_counted() {
        let text = log(&[
            line(&[("action", "block"), ("path", "/one")]),
            line(&[("action", "block"), ("path", "/two")]),
            line(&[("action", "block"), ("path", "/three")]),
        ]);
        let options = ShadowOptions {
            max_lines: 2,
            ..ShadowOptions::default()
        };
        let report = render_with(&text, &options);
        assert!(
            report.contains(
                "Blocked or redirected lines: 3 (listing the first 2; 1 more not shown, use --max-lines to list more)"
            ),
            "{report}"
        );
        assert!(report.contains(" GET /one "), "{report}");
        assert!(report.contains(" GET /two "), "{report}");
        assert!(!report.contains(" GET /three "), "{report}");
    }

    #[test]
    fn the_blocked_section_gives_the_total_when_every_line_is_listed() {
        let report = render(&line(&[("action", "block")]));
        assert!(
            report.contains("Blocked or redirected lines: 1\n"),
            "{report}"
        );
    }

    #[test]
    fn a_client_busy_burst_needs_five_lines_in_one_minute_from_one_client() {
        let four: Vec<String> = (0..4)
            .map(|_| line(&[("decision_error", "client_busy")]))
            .collect();
        let report = render(&log(&four));
        assert!(
            report.contains("client_busy bursts (5 or more client_busy lines from one client in one minute):\n  none\n"),
            "{report}"
        );

        let mut five: Vec<String> = (0..5)
            .map(|_| line(&[("decision_error", "client_busy")]))
            .collect();
        five.push(line(&[
            ("decision_error", "client_busy"),
            ("client_ip", "198.51.100.9"),
        ]));
        let report = render(&log(&five));
        assert!(
            report.contains("  2026-11-02 10:00 192.0.2.x: 5 lines; top paths: / (5)\n"),
            "{report}"
        );
        assert!(!report.contains("198.51.100.x:"), "{report}");
    }

    #[test]
    fn a_burst_is_split_by_minute() {
        let mut lines: Vec<String> = Vec::new();
        for minute in ["10:00", "10:01"] {
            for _ in 0..3 {
                lines.push(line(&[
                    ("decision_error", "client_busy"),
                    ("time", &format!("2026-11-02T{minute}:30+00:00")),
                ]));
            }
        }
        let report = render(&log(&lines));
        assert!(report.contains("in one minute):\n  none\n"), "{report}");
    }

    #[test]
    fn a_burst_lists_its_three_most_used_paths() {
        let mut lines: Vec<String> = Vec::new();
        for (path, count) in [("/a", 4), ("/b", 2), ("/c", 2), ("/d", 1)] {
            for _ in 0..count {
                lines.push(line(&[("decision_error", "client_busy"), ("path", path)]));
            }
        }
        let report = render(&log(&lines));
        assert!(
            report.contains("top paths: /a (4), /b (2), /c (2)\n"),
            "{report}"
        );
        assert!(!report.contains("/d (1)"), "{report}");
    }

    #[test]
    fn the_nearest_rank_percentile_of_one_hundred_values_is_the_rank_itself() {
        let sorted: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile(&sorted, 50), Some(50));
        assert_eq!(percentile(&sorted, 99), Some(99));
    }

    #[test]
    fn the_percentile_of_one_value_is_that_value_and_of_none_is_none() {
        assert_eq!(percentile(&[7], 50), Some(7));
        assert_eq!(percentile(&[7], 99), Some(7));
        assert_eq!(percentile(&[], 50), None);
        assert_eq!(percentile_text(&[], 99), "-");
    }

    #[test]
    fn hourly_latency_percentiles_are_read_from_the_scored_calls() {
        let lines: Vec<String> = (1..=100)
            .map(|latency| line(&[("attack", "0.1"), ("latency_ms", &latency.to_string())]))
            .collect();
        let report = render(&log(&lines));
        assert!(
            report.contains(
                "  2026-11-02 10:00  calls 100  timeouts 0  latency p50 50 ms, p99 99 ms\n"
            ),
            "{report}"
        );
    }

    #[test]
    fn latency_comes_only_from_lines_with_a_score_but_timeouts_count_as_calls() {
        let report = render(&log(&[
            line(&[("attack", "0.1"), ("latency_ms", "10")]),
            line(&[("decision_error", "timeout"), ("latency_ms", "9000")]),
        ]));
        assert!(
            report.contains(
                "  2026-11-02 10:00  calls 2  timeouts 1  latency p50 10 ms, p99 10 ms\n"
            ),
            "{report}"
        );
    }

    #[test]
    fn an_hour_with_no_backend_call_is_not_listed() {
        let report = render(&line(&[("reason", "skip"), ("latency_ms", "3")]));
        assert!(
            report.contains("Backend per hour (UTC), hours with backend calls:\n  none\n"),
            "{report}"
        );
    }

    #[test]
    fn hours_are_listed_in_order_with_their_own_calls() {
        let report = render(&log(&[
            line(&[("attack", "0.1"), ("time", "2026-11-02T11:00:00+00:00")]),
            line(&[("attack", "0.1"), ("time", "2026-11-02T09:59:00+00:00")]),
        ]));
        let nine = report
            .find("  2026-11-02 09:00  calls 1")
            .unwrap_or(usize::MAX);
        let eleven = report
            .find("  2026-11-02 11:00  calls 1")
            .unwrap_or(usize::MAX);
        assert!(nine < eleven, "{report}");
    }

    #[test]
    fn input_tokens_are_summed_over_all_lines() {
        let report = render(&log(&[
            line(&[("input_tokens", "1200")]),
            line(&[("input_tokens", "300")]),
            line(&[("input_tokens", "")]),
        ]));
        assert!(report.contains("Input tokens: 1500\n"), "{report}");
    }

    #[test]
    fn the_cost_is_estimated_from_input_tokens_when_a_price_is_given() {
        let options = ShadowOptions {
            usd_per_mtok: Some(3.0),
            ..ShadowOptions::default()
        };
        let report = render_with(&line(&[("input_tokens", "2000000")]), &options);
        assert!(
            report.contains(
                "Estimated input cost: $6.0000 at $3 per million input tokens (the log has no output tokens)"
            ),
            "{report}"
        );
    }

    #[test]
    fn the_cost_is_not_estimated_without_a_price() {
        let report = render(&line(&[("input_tokens", "2000000")]));
        assert!(
            report.contains("Cost: not estimated; give --usd-per-mtok <price> to estimate it"),
            "{report}"
        );
    }

    #[test]
    fn client_addresses_are_shortened_by_default() {
        let report = render(&line(&[
            ("action", "block"),
            ("client_ip", "2001:db8:1:2::5"),
        ]));
        assert!(report.contains(" 2001:db8:1:: "), "{report}");
        assert!(!report.contains("2001:db8:1:2::5"), "{report}");

        let report = render(&line(&[("action", "block")]));
        assert!(report.contains(" 192.0.2.x "), "{report}");
        assert!(!report.contains("192.0.2.77"), "{report}");
    }

    #[test]
    fn full_addresses_print_each_client_address_in_full() {
        let options = ShadowOptions {
            full_addresses: true,
            ..ShadowOptions::default()
        };
        let report = render_with(
            &log(&[
                line(&[("action", "block")]),
                line(&[("action", "block"), ("client_ip", "2001:db8:1:2::5")]),
            ]),
            &options,
        );
        assert!(report.contains(" 192.0.2.77 "), "{report}");
        assert!(report.contains(" 2001:db8:1:2::5 "), "{report}");
    }

    #[test]
    fn an_ipv4_mapped_ipv6_address_is_shortened_as_its_ipv4_address() {
        let report = render(&line(&[
            ("action", "block"),
            ("client_ip", "::ffff:192.0.2.77"),
        ]));
        assert!(report.contains(" 192.0.2.x "), "{report}");
        assert!(!report.contains("192.0.2.77"), "{report}");
    }

    #[rstest]
    #[case::empty("", "-")]
    #[case::not_an_address("not-an-address", "-")]
    #[case::ipv4_loopback("127.0.0.1", "127.0.0.x")]
    fn a_client_address_is_shortened_or_shown_as_a_dash(
        #[case] address: &str,
        #[case] expected: &str,
    ) {
        assert_eq!(shorten_address(address), expected);
        let value = json!({"client_ip": address});
        assert_eq!(client_label(&value, false), expected);
    }

    #[test]
    fn a_report_of_no_input_is_empty_but_well_formed() {
        let report = shadow_report(Vec::<&[u8]>::new(), &ShadowOptions::default())
            .unwrap_or_else(|error| panic!("reading from memory failed: {error}"))
            .to_string();
        assert!(report.contains("Files read: 0\n"), "{report}");
        assert!(report.contains("Time range: none"), "{report}");
    }

    #[test]
    fn a_failed_read_is_returned_as_an_error() {
        let result = shadow_report(
            [io::BufReader::new(FailingReader)],
            &ShadowOptions::default(),
        );
        assert_eq!(
            result
                .map(|report| report.to_string())
                .map_err(|error| error.to_string()),
            Err("the disk went away".to_owned())
        );
    }
}
