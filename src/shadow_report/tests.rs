//! Unit tests of the shadow report: the sections, the escaping and the reading of the logs.

use super::*;
use crate::log_lines::MAX_LINE_BYTES;
use crate::test_support::FailingReader;
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
    let mut report = ShadowReport::new(options);
    read_or_panic(&mut report, text.as_bytes());
    report.to_string()
}

/// Reads one log into the report, failing the test when the read fails.
fn read_or_panic(report: &mut ShadowReport, input: &[u8]) {
    report
        .read_log(input)
        .unwrap_or_else(|error| panic!("reading from memory failed: {error}"));
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
    let mut report = ShadowReport::new(&ShadowOptions::default());
    read_or_panic(&mut report, first.as_bytes());
    read_or_panic(&mut report, second.as_bytes());
    let report = report.to_string();
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
#[case::client_busy_is_not_a_call(&[("decision_error", "client_busy")], 0)]
#[case::backend_busy_is_not_a_call(&[("decision_error", "backend_busy")], 0)]
#[case::request_error_is_not_a_call(&[("decision_error", "request")], 0)]
#[case::rate_limited_is_a_call(&[("decision_error", "rate_limited")], 1)]
#[case::connection_error_is_a_call(&[("decision_error", "connection")], 1)]
#[case::invalid_score_is_a_call(&[("decision_error", "invalid_score")], 1)]
#[case::http_status_is_a_call(&[("decision_error", "http_status")], 1)]
#[case::body_is_a_call(&[("decision_error", "body")], 1)]
#[case::parse_is_a_call(&[("decision_error", "parse")], 1)]
#[case::rejected_is_a_call(&[("decision_error", "rejected")], 1)]
#[case::invalid_response_is_a_call(&[("decision_error", "invalid_response")], 1)]
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
        report
            .contains("  2026-11-02 10:00  calls 100  timeouts 0  latency p50 50 ms, p99 99 ms\n"),
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
        report.contains("  2026-11-02 10:00  calls 2  timeouts 1  latency p50 10 ms, p99 10 ms\n"),
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
fn a_client_address_is_shortened_or_shown_as_a_dash(#[case] address: &str, #[case] expected: &str) {
    assert_eq!(shorten_address(address), expected);
    let value = json!({"client_ip": address});
    assert_eq!(client_label(&value, false), expected);
}

#[test]
fn a_report_of_no_input_is_empty_but_well_formed() {
    let report = ShadowReport::new(&ShadowOptions::default()).to_string();
    assert!(report.contains("Files read: 0\n"), "{report}");
    assert!(report.contains("Time range: none"), "{report}");
}

#[test]
fn a_failed_read_is_returned_as_an_error() {
    let mut report = ShadowReport::new(&ShadowOptions::default());
    let result = report.read_log(io::BufReader::new(FailingReader));
    assert_eq!(
        result.map_err(|error| error.to_string()),
        Err("the disk went away".to_owned())
    );
}

#[test]
fn the_median_of_three_values_is_the_middle_one() {
    assert_eq!(percentile(&[1, 2, 3], 50), Some(2));
}

#[rstest]
#[case::escape_character("\u{1b}[31m", "\\u{1b}[31m")]
#[case::nul("a\u{0}b", "a\\u{0}b")]
#[case::tab("\t", "\\u{9}")]
#[case::delete("\u{7f}", "\\u{7f}")]
#[case::c1_control("\u{9b}", "\\u{9b}")]
#[case::line_separator("\u{2028}", "\\u{2028}")]
#[case::paragraph_separator("\u{2029}", "\\u{2029}")]
#[case::japanese_is_kept("日本語", "日本語")]
#[case::backslash_is_kept("a\\b", "a\\b")]
fn control_characters_and_line_separators_are_written_as_escapes(
    #[case] text: &str,
    #[case] expected: &str,
) {
    assert_eq!(visible(text), expected);
}

#[test]
fn escape_characters_from_the_log_do_not_reach_the_output() {
    let text = log(&[line(&[
        ("action", "block"),
        ("path", "/\u{1b}]0;title\u{7}x"),
        ("category", "\u{1b}[31mred"),
        ("reason", "re\u{1b}ason"),
        ("decision_error", "time\u{1b}out"),
        ("rule_id", "r\u{1b}1"),
        ("client_ip", "192.0.2.77\u{1b}"),
    ])]);
    let report = render(&text);
    assert!(
        !report.chars().any(|c| c.is_control() && c != '\n'),
        "{report:?}"
    );
    assert!(report.contains("/\\u{1b}]0;title\\u{7}x"), "{report}");
    assert!(
        report.contains("rule=r\\u{1b}1 category=\\u{1b}[31mred"),
        "{report}"
    );
    assert!(report.contains("  re\\u{1b}ason: 1"), "{report}");
    assert!(report.contains("  time\\u{1b}out: 1"), "{report}");
}

#[test]
fn a_line_longer_than_the_limit_is_counted_as_malformed() {
    let mut text = vec![b'x'; MAX_LINE_BYTES + 1];
    text.push(b'\n');
    text.extend_from_slice(line(&[]).as_bytes());
    text.push(b'\n');
    let mut report = ShadowReport::new(&ShadowOptions::default());
    read_or_panic(&mut report, &text);
    let report = report.to_string();
    assert!(
        report.contains("Lines read: 2 (1 JSON objects, 1 malformed lines skipped)"),
        "{report}"
    );
}
