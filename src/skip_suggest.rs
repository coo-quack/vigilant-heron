//! The `suggest-skip-rules` command: learns skip-rule candidates from a `json` access log.
//!
//! Each line of the log is read on its own. A usable line is a JSON object with a
//! `query_shape` string, which the `json` format writes from the version that added
//! that field. The usable lines are grouped by site, method, path and query shape,
//! and each group is judged against fixed thresholds.
//!
//! The report only lists rule text for a person to review. Nothing is applied: the
//! configuration is never read, and nothing is contacted.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::io::{self, BufRead};

use serde_json::Value;

/// The filter and thresholds of one run. The defaults are the thresholds that the documentation states.
#[derive(Debug, Clone, PartialEq)]
pub struct SuggestOptions {
    /// Keeps only the groups of this site, when set.
    pub site: Option<String>,
    /// The fewest judged requests a shape needs.
    pub min_judged: usize,
    /// The fewest distinct clients among the judged requests of a shape.
    pub min_clients: usize,
    /// The fewest distinct UTC dates among the judged requests of a shape.
    pub min_days: usize,
    /// The highest `attack` score that any judged request of a shape may have.
    pub max_attack: f64,
    /// The highest `ai_instruction` score that any judged request of a shape may have.
    pub max_ai_instruction: f64,
}

impl Default for SuggestOptions {
    fn default() -> Self {
        Self {
            site: None,
            min_judged: 50,
            min_clients: 10,
            min_days: 3,
            max_attack: 0.3,
            max_ai_instruction: 0.3,
        }
    }
}

/// The result of a run. `Display` renders the plain text report from the same data.
#[derive(Debug, Clone, PartialEq)]
pub struct SuggestReport {
    /// Every line that was read, usable or not.
    pub total_lines: usize,
    /// The lines that have a `query_shape` and so take part in the grouping.
    pub usable_lines: usize,
    /// The lines that are not a JSON object with a `query_shape` string.
    pub unusable_lines: usize,
    /// The options the run used.
    pub options: SuggestOptions,
    /// Shapes that meet the thresholds and have a rule, in output order. Each has its rule text.
    pub candidates: Vec<Candidate>,
    /// Shapes that meet the thresholds but have values that are not numbers. They have no rule text.
    pub needs_review: Vec<Candidate>,
    /// The number of shapes that a skip rule or the static skip already covers.
    pub skipped_shapes: usize,
    /// The number of requests in those shapes.
    pub skipped_lines: usize,
}

/// A shape that meets the learning thresholds, with its evidence.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    /// The site name, as the access log writes it.
    pub site: String,
    /// The request method.
    pub method: String,
    /// The request path.
    pub path: String,
    /// The query shape, empty when the request has no query.
    pub query_shape: String,
    /// The requests that the model answered.
    pub judged: usize,
    /// The distinct clients among the judged requests.
    pub clients: usize,
    /// The distinct UTC dates among the judged requests.
    pub days: usize,
    /// The highest `attack` score among the judged requests.
    pub max_attack: f64,
    /// The highest `ai_instruction` score among the judged requests, with a missing score counted as 0.
    pub max_ai_instruction: f64,
    /// The rule text, numbered from 1 in output order. `None` for a shape that needs review.
    pub rule: Option<String>,
}

/// The fields that identify a group of requests.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct GroupKey {
    site: String,
    method: String,
    path: String,
    query_shape: String,
}

/// The counts and maxima of one group, built from its lines.
struct Group {
    /// Every line of the group, judged or not.
    lines: usize,
    /// The lines whose `attack` is a number.
    judged: usize,
    clients: HashSet<String>,
    days: HashSet<String>,
    max_attack: f64,
    max_ai_instruction: f64,
    /// Lines that were blocked or redirected, judged or not.
    blocked: usize,
    /// Lines that a skip rule or the static skip forwarded, judged or not.
    skipped: usize,
}

impl Default for Group {
    fn default() -> Self {
        Self {
            lines: 0,
            judged: 0,
            clients: HashSet::new(),
            days: HashSet::new(),
            max_attack: f64::NEG_INFINITY,
            max_ai_instruction: f64::NEG_INFINITY,
            blocked: 0,
            skipped: 0,
        }
    }
}

impl Group {
    /// Adds one usable line to the group.
    fn add(&mut self, value: &Value) {
        self.lines += 1;
        if is_block(text_field(value, "action")) || is_block(text_field(value, "would_have")) {
            self.blocked += 1;
        }
        if matches!(text_field(value, "reason"), "skip_rule" | "skip") {
            self.skipped += 1;
        }
        let Some(attack) = number_field(value, "attack") else {
            return;
        };
        self.judged += 1;
        let client = text_field(value, "client_ip");
        if !client.is_empty() {
            self.clients.insert(client.to_owned());
        }
        if let Some(day) = text_field(value, "time").get(..10) {
            self.days.insert(day.to_owned());
        }
        let ai_instruction = number_field(value, "ai_instruction").unwrap_or(0.0);
        self.max_attack = self.max_attack.max(attack);
        self.max_ai_instruction = self.max_ai_instruction.max(ai_instruction);
    }

    /// Whether the group meets every learning threshold.
    fn meets_thresholds(&self, options: &SuggestOptions) -> bool {
        self.judged > 0
            && self.judged >= options.min_judged
            && self.clients.len() >= options.min_clients
            && self.days.len() >= options.min_days
            && self.max_attack <= options.max_attack
            && self.max_ai_instruction <= options.max_ai_instruction
            && self.blocked == 0
    }
}

/// Learns skip-rule candidates from the lines of a `json` access log.
///
/// `input` holds the log, one request per line. It is read one line at a time, so a
/// large log is never held in memory whole. A line that is not valid UTF-8 is read
/// with the invalid bytes replaced. Lines that are not usable are counted and otherwise
/// ignored.
///
/// # Errors
///
/// Returns the error of a failed read from `input`.
pub fn suggest_skip_rules<R: BufRead>(
    mut input: R,
    options: &SuggestOptions,
) -> io::Result<SuggestReport> {
    let mut total_lines = 0;
    let mut unusable_lines = 0;
    let mut groups: BTreeMap<GroupKey, Group> = BTreeMap::new();
    let mut buffer = Vec::new();
    loop {
        buffer.clear();
        if input.read_until(b'\n', &mut buffer)? == 0 {
            break;
        }
        let line = String::from_utf8_lossy(&buffer);
        let line = line.trim_end_matches(['\n', '\r']);
        total_lines += 1;
        let Some(value) = usable_line(line) else {
            unusable_lines += 1;
            continue;
        };
        let key = group_key(&value);
        if options.site.as_deref().is_some_and(|site| site != key.site) {
            continue;
        }
        groups.entry(key).or_default().add(&value);
    }

    let mut found: Vec<(Candidate, Option<String>)> = Vec::new();
    let mut skipped_shapes = 0;
    let mut skipped_lines = 0;
    for (key, group) in &groups {
        if group.skipped > 0 {
            skipped_shapes += 1;
            skipped_lines += group.lines;
            continue;
        }
        if group.meets_thresholds(options) {
            found.push((candidate(key, group), learnable_regex(key)));
        }
    }
    found.sort_by(|(a, _), (b, _)| output_order(a, b));

    let mut candidates = Vec::new();
    let mut needs_review = Vec::new();
    for (mut candidate, regex) in found {
        match regex {
            Some(regex) => {
                let number = candidates.len() + 1;
                candidate.rule = Some(rule_text(number, &candidate, &regex));
                candidates.push(candidate);
            }
            None => needs_review.push(candidate),
        }
    }

    Ok(SuggestReport {
        total_lines,
        usable_lines: total_lines - unusable_lines,
        unusable_lines,
        options: options.clone(),
        candidates,
        needs_review,
        skipped_shapes,
        skipped_lines,
    })
}

/// Parses one line. Returns the object when it is a JSON object with a `query_shape` string.
fn usable_line(line: &str) -> Option<Value> {
    let value: Value = serde_json::from_str(line).ok()?;
    if !value.is_object() {
        return None;
    }
    value.get("query_shape").and_then(Value::as_str)?;
    Some(value)
}

/// The group key of a usable line. A missing field is an empty string.
fn group_key(value: &Value) -> GroupKey {
    GroupKey {
        site: text_field(value, "site").to_owned(),
        method: text_field(value, "method").to_owned(),
        path: text_field(value, "path").to_owned(),
        query_shape: text_field(value, "query_shape").to_owned(),
    }
}

/// A string field, or the empty string when it is missing or not a string.
fn text_field<'a>(value: &'a Value, name: &str) -> &'a str {
    value.get(name).and_then(Value::as_str).unwrap_or("")
}

/// A number field. The `json` format writes scores as strings, so a string is parsed
/// too. An empty or non-numeric value gives `None`.
fn number_field(value: &Value, name: &str) -> Option<f64> {
    let number = match value.get(name)? {
        Value::String(text) => text.parse::<f64>().ok()?,
        Value::Number(number) => number.as_f64()?,
        _ => return None,
    };
    number.is_finite().then_some(number)
}

/// Whether an action or `would_have` value blocks the request.
fn is_block(text: &str) -> bool {
    matches!(text, "block" | "redirect")
}

/// The report entry of a group.
fn candidate(key: &GroupKey, group: &Group) -> Candidate {
    Candidate {
        site: key.site.clone(),
        method: key.method.clone(),
        path: key.path.clone(),
        query_shape: key.query_shape.clone(),
        judged: group.judged,
        clients: group.clients.len(),
        days: group.days.len(),
        max_attack: group.max_attack,
        max_ai_instruction: group.max_ai_instruction,
        rule: None,
    }
}

/// The order of the report: most judged requests first, then site, method, path and shape.
fn output_order(a: &Candidate, b: &Candidate) -> Ordering {
    b.judged
        .cmp(&a.judged)
        .then_with(|| a.site.cmp(&b.site))
        .then_with(|| a.method.cmp(&b.method))
        .then_with(|| a.path.cmp(&b.path))
        .then_with(|| a.query_shape.cmp(&b.query_shape))
}

/// The query regex of a group that can become a rule, or `None` when it needs review.
///
/// Only GET and HEAD requests on a plain path qualify, and the query shape must hold
/// only numbers and empty values. A free-text value would let any value through, so
/// such a shape is left for a person to write.
fn learnable_regex(key: &GroupKey) -> Option<String> {
    if !matches!(key.method.as_str(), "GET" | "HEAD")
        || !plain_site(&key.site)
        || !plain_path(&key.path)
    {
        return None;
    }
    shape_regex(&key.query_shape)
}

/// Whether the site name can be written unquoted in a rule: a host name made of ASCII
/// letters, digits, `.`, `-`, `_` and `*`. A site named by a regex goes to review.
fn plain_site(site: &str) -> bool {
    !site.is_empty()
        && site
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '*'))
}

/// Whether the path has a leading `/` and only ASCII letters, digits and `/ _ . - ~`.
fn plain_path(path: &str) -> bool {
    path.starts_with('/')
        && path
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '.' | '-' | '~'))
}

/// The regex that matches only queries of this shape. `None` when a piece is not a
/// number or an empty value under a plain name.
fn shape_regex(shape: &str) -> Option<String> {
    if shape.is_empty() {
        return Some("^$".to_owned());
    }
    let pieces = shape
        .split('&')
        .map(plain_piece)
        .collect::<Option<Vec<String>>>()?;
    Some(format!("^{}$", pieces.join("&")))
}

/// The regex of one `name=<num>` or `name=<empty>` piece.
fn plain_piece(piece: &str) -> Option<String> {
    let (name, value) = piece.split_once('=')?;
    if !plain_name(name) {
        return None;
    }
    let name = escape_name(name);
    match value {
        "<num>" => Some(format!("{name}=[0-9]{{1,20}}")),
        "<empty>" => Some(format!("{name}=")),
        _ => None,
    }
}

/// Whether a parameter name has only ASCII letters, digits and `_ . - [ ]`, and is not empty.
fn plain_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | '[' | ']'))
}

/// Escapes the characters of a parameter name that are special in a regex.
fn escape_name(name: &str) -> String {
    let mut escaped = String::with_capacity(name.len());
    for c in name.chars() {
        if matches!(c, '.' | '[' | ']' | '-') {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    escaped
}

/// The rule block for a candidate. The regex has no `"` or backslash escape that the
/// configuration lexer would change, so it reaches the rule as written.
fn rule_text(number: usize, candidate: &Candidate, regex: &str) -> String {
    format!(
        "rule learned-{number} {{\n    description \"learned from the access log: {method} {path} {shape}\";\n    action skip;\n    site {site};\n    method {method};\n    path = {path};\n    query ~ \"{regex}\";\n}}",
        method = candidate.method,
        path = candidate.path,
        shape = shape_label(&candidate.query_shape),
        site = candidate.site,
    )
}

/// The shape as the report shows it. An empty shape is `(no query)`.
fn shape_label(shape: &str) -> &str {
    if shape.is_empty() {
        "(no query)"
    } else {
        shape
    }
}

/// The evidence line of a candidate, without the leading marker.
fn evidence(candidate: &Candidate) -> String {
    format!(
        "{} {} {} {}: {} judged, {} clients, {} days, max attack {}, max ai_instruction {}",
        candidate.method,
        candidate.site,
        candidate.path,
        shape_label(&candidate.query_shape),
        candidate.judged,
        candidate.clients,
        candidate.days,
        candidate.max_attack,
        candidate.max_ai_instruction,
    )
}

/// Printed under the candidate count: what a learned rule leaves to the model.
const LEARNED_SKIP_NOTE: &str = "A learned rule forwards matching requests without the model, so the model no longer judges their headers or body. Block rules, built-in and your own, still run first.";

impl fmt::Display for SuggestReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let options = &self.options;
        writeln!(
            f,
            "Read {} lines: {} with query_shape, {} without (written by a version before query_shape, or not the json format).",
            self.total_lines, self.usable_lines, self.unusable_lines
        )?;
        writeln!(
            f,
            "Learning thresholds: judged >= {}, clients >= {}, days >= {}, attack <= {}, ai_instruction <= {}, never blocked.",
            options.min_judged,
            options.min_clients,
            options.min_days,
            options.max_attack,
            options.max_ai_instruction
        )?;
        writeln!(f)?;
        writeln!(f, "Candidates: {}", self.candidates.len())?;
        if !self.candidates.is_empty() {
            writeln!(f, "{LEARNED_SKIP_NOTE}")?;
        }
        if self.candidates.is_empty() && self.needs_review.is_empty() {
            writeln!(f, "No shape meets the thresholds.")?;
        }
        for candidate in &self.candidates {
            writeln!(f, "# {}", evidence(candidate))?;
            if let Some(rule) = &candidate.rule {
                writeln!(f, "{rule}")?;
            }
            writeln!(f)?;
        }
        if self.candidates.is_empty() {
            writeln!(f)?;
        }
        writeln!(
            f,
            "Needs review: {} (they meet the thresholds, but have values that are not numbers; no rule is written for them)",
            self.needs_review.len()
        )?;
        for candidate in &self.needs_review {
            writeln!(f, "- {}", evidence(candidate))?;
        }
        writeln!(f)?;
        writeln!(
            f,
            "Already skipped by a rule or the static skip: {} shapes, {} requests.",
            self.skipped_shapes, self.skipped_lines
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use serde_json::json;

    /// A judged request in the `json` format: the model answered `attack` and `ai_instruction`.
    fn judged_value(
        client: usize,
        day: usize,
        method: &str,
        path: &str,
        shape: &str,
        attack: &str,
        ai_instruction: &str,
    ) -> Value {
        json!({
            "time": format!("2026-01-{:02}T10:00:00Z", day + 1),
            "client_ip": format!("192.0.2.{client}"),
            "site": "example.test",
            "method": method,
            "path": path,
            "query_shape": shape,
            "action": "allow",
            "reason": "model",
            "would_have": "",
            "attack": attack,
            "ai_instruction": ai_instruction,
        })
    }

    /// `count` judged GET / requests with shape `p=<num>`, spread over `clients` clients and `days` days.
    fn spread(count: usize, clients: usize, days: usize, attack: &str, ai: &str) -> Vec<Value> {
        (0..count)
            .map(|i| judged_value(i % clients, i % days, "GET", "/", "p=<num>", attack, ai))
            .collect()
    }

    /// Sets one field of a line.
    fn set(mut value: Value, key: &str, field: &str) -> Value {
        if let Some(map) = value.as_object_mut() {
            map.insert(key.to_owned(), json!(field));
        }
        value
    }

    /// Runs the command with the default options on the given lines.
    fn run(lines: &[Value]) -> SuggestReport {
        let text = lines
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        suggest_skip_rules(text.as_bytes(), &SuggestOptions::default())
            .unwrap_or_else(|error| panic!("reading from memory failed: {error}"))
    }

    /// The query regex inside a rule text.
    fn query_regex(rule: &str) -> String {
        rule.split_once("query ~ \"")
            .and_then(|(_, rest)| rest.split_once("\";"))
            .map(|(regex, _)| regex.to_owned())
            .unwrap_or_default()
    }

    #[rstest]
    #[case::judged_just_below(49, 10, 3, "0.1", "0.1", 0)]
    #[case::judged_at_minimum(50, 10, 3, "0.1", "0.1", 1)]
    #[case::clients_just_below(50, 9, 3, "0.1", "0.1", 0)]
    #[case::clients_at_minimum(50, 10, 3, "0.1", "0.1", 1)]
    #[case::days_just_below(50, 10, 2, "0.1", "0.1", 0)]
    #[case::days_at_minimum(50, 10, 3, "0.1", "0.1", 1)]
    #[case::attack_just_above(50, 10, 3, "0.31", "0.1", 0)]
    #[case::attack_at_maximum(50, 10, 3, "0.3", "0.1", 1)]
    #[case::ai_instruction_just_above(50, 10, 3, "0.1", "0.31", 0)]
    #[case::ai_instruction_at_maximum(50, 10, 3, "0.1", "0.3", 1)]
    fn each_threshold_rejects_just_below_and_accepts_at_the_limit(
        #[case] count: usize,
        #[case] clients: usize,
        #[case] days: usize,
        #[case] attack: &str,
        #[case] ai: &str,
        #[case] expected: usize,
    ) {
        let report = run(&spread(count, clients, days, attack, ai));
        assert_eq!(report.candidates.len(), expected, "{report}");
        assert!(report.needs_review.is_empty(), "{report}");
    }

    #[rstest]
    #[case::action_block("action", "block")]
    #[case::action_redirect("action", "redirect")]
    #[case::would_have_block("would_have", "block")]
    fn a_group_with_one_blocked_line_is_rejected(#[case] key: &str, #[case] field: &str) {
        let mut lines = spread(50, 10, 3, "0.1", "0.1");
        lines.push(set(
            judged_value(0, 0, "GET", "/", "p=<num>", "0.1", "0.1"),
            key,
            field,
        ));
        let report = run(&lines);
        assert!(report.candidates.is_empty(), "{report}");
        assert!(report.needs_review.is_empty(), "{report}");
    }

    #[rstest]
    #[case::skip_rule("skip_rule")]
    #[case::static_skip("skip")]
    fn an_already_skipped_group_is_excluded_and_counted(#[case] reason: &str) {
        let mut lines = spread(50, 10, 3, "0.1", "0.1");
        lines.push(set(
            judged_value(0, 0, "GET", "/", "p=<num>", "0.1", "0.1"),
            "reason",
            reason,
        ));
        lines.push(judged_value(1, 1, "GET", "/other", "q=<num>", "0.1", "0.1"));
        let report = run(&lines);
        assert!(report.candidates.is_empty(), "{report}");
        assert_eq!(report.skipped_shapes, 1, "{report}");
        assert_eq!(report.skipped_lines, 51, "{report}");
    }

    #[test]
    fn unusable_lines_are_counted_and_ignored() {
        let usable = judged_value(0, 0, "GET", "/", "p=<num>", "0.1", "0.1").to_string();
        let input = [
            "not json",
            "[1, 2]",
            "{\"site\":\"example.test\"}",
            "{\"query_shape\": 3}",
            "",
            usable.as_str(),
        ]
        .join("\n");
        let report = suggest_skip_rules(input.as_bytes(), &SuggestOptions::default())
            .unwrap_or_else(|error| panic!("reading from memory failed: {error}"));
        assert_eq!(report.total_lines, 6, "{report}");
        assert_eq!(report.unusable_lines, 5, "{report}");
        assert_eq!(report.usable_lines, 1, "{report}");
        assert!(report.candidates.is_empty(), "{report}");
    }

    #[test]
    fn only_judged_lines_count_for_clients_and_days() {
        let mut lines = spread(50, 10, 3, "0.1", "0.1");
        for i in 0..20 {
            lines.push(set(
                judged_value(100 + i, 10 + i, "GET", "/", "p=<num>", "0.1", "0.1"),
                "attack",
                "",
            ));
        }
        let report = run(&lines);
        let candidate = report.candidates.first();
        assert_eq!(candidate.map(|c| c.judged), Some(50), "{report}");
        assert_eq!(candidate.map(|c| c.clients), Some(10), "{report}");
        assert_eq!(candidate.map(|c| c.days), Some(3), "{report}");
    }

    #[rstest]
    #[case::post("POST", "/", "p=<num>")]
    #[case::put("PUT", "/", "p=<num>")]
    #[case::lowercase_get("get", "/", "p=<num>")]
    #[case::bad_path("GET", "/a%2fb", "p=<num>")]
    #[case::space_in_path("GET", "/a b", "p=<num>")]
    #[case::word_value("GET", "/", "q=<word>")]
    #[case::text_value("GET", "/", "q=<text>")]
    #[case::bare_piece("GET", "/", "q")]
    #[case::hidden_name("GET", "/", "<name>=<num>")]
    #[case::more_marker("GET", "/", "p=<num>&<more>")]
    #[case::one_bad_piece("GET", "/", "p=<num>&q=<word>")]
    fn a_learned_shape_that_is_not_plain_goes_to_needs_review(
        #[case] method: &str,
        #[case] path: &str,
        #[case] shape: &str,
    ) {
        let lines: Vec<Value> = (0..50)
            .map(|i| judged_value(i % 10, i % 3, method, path, shape, "0.1", "0.1"))
            .collect();
        let report = run(&lines);
        assert!(report.candidates.is_empty(), "{report}");
        assert_eq!(report.needs_review.len(), 1, "{report}");
        assert!(
            report
                .needs_review
                .first()
                .is_some_and(|c| c.rule.is_none()),
            "{report}"
        );
    }

    #[rstest]
    #[case::regex_site("~^(www\\.)?example\\.test$")]
    #[case::site_with_space("example test")]
    #[case::site_with_quote("example\"test")]
    fn a_site_that_cannot_be_written_unquoted_goes_to_needs_review(#[case] site: &str) {
        let lines: Vec<Value> = (0..50)
            .map(|i| {
                let mut value = judged_value(i % 10, i % 3, "GET", "/", "p=<num>", "0.1", "0.1");
                if let Some(object) = value.as_object_mut() {
                    object.insert("site".to_owned(), Value::from(site));
                }
                value
            })
            .collect();
        let report = run(&lines);
        assert!(report.candidates.is_empty(), "{report}");
        assert_eq!(report.needs_review.len(), 1, "{report}");
    }

    #[rstest]
    #[case::get("GET", "/wp-json/v1/items.json~1", "p=<num>&q=<empty>")]
    #[case::head("HEAD", "/a-b_c.d", "p=<num>")]
    fn a_plain_get_or_head_shape_gets_a_rule(
        #[case] method: &str,
        #[case] path: &str,
        #[case] shape: &str,
    ) {
        let lines: Vec<Value> = (0..50)
            .map(|i| judged_value(i % 10, i % 3, method, path, shape, "0.1", "0.1"))
            .collect();
        let report = run(&lines);
        assert_eq!(report.candidates.len(), 1, "{report}");
        assert!(report.needs_review.is_empty(), "{report}");
    }

    #[test]
    fn an_empty_query_shape_gets_the_regex_for_no_query() {
        let lines: Vec<Value> = (0..50)
            .map(|i| judged_value(i % 10, i % 3, "GET", "/", "", "0.1", "0.1"))
            .collect();
        let report = run(&lines);
        let rule = report
            .candidates
            .first()
            .and_then(|c| c.rule.clone())
            .unwrap_or_default();
        assert_eq!(query_regex(&rule), "^$", "{rule}");
        assert!(rule.contains("(no query)"), "{rule}");
    }

    #[test]
    fn an_empty_value_piece_becomes_a_name_with_no_value() {
        assert_eq!(shape_regex("q=<empty>").as_deref(), Some("^q=$"));
        assert_eq!(
            shape_regex("p=<num>&q=<empty>").as_deref(),
            Some("^p=[0-9]{1,20}&q=$")
        );
    }

    #[test]
    fn the_regex_escapes_the_special_characters_of_a_parameter_name() {
        let regex = shape_regex("a.b[0]=<num>").unwrap_or_default();
        assert_eq!(regex, r"^a\.b\[0\]=[0-9]{1,20}$");
        let compiled = regex::Regex::new(&regex);
        assert!(compiled.as_ref().is_ok_and(|re| re.is_match("a.b[0]=12")));
        assert!(compiled.as_ref().is_ok_and(|re| !re.is_match("axb0=12")));
        let dashed = regex::Regex::new(&shape_regex("a-b=<num>").unwrap_or_default());
        assert!(dashed.is_ok_and(|re| re.is_match("a-b=1")));
    }

    #[test]
    fn a_name_with_characters_outside_the_plain_set_is_not_learned() {
        assert_eq!(shape_regex("a(b)=<num>"), None);
        assert_eq!(shape_regex("=<num>"), None);
    }

    #[test]
    fn a_rule_is_written_with_the_fields_of_the_learned_shape() {
        let lines: Vec<Value> = (0..50)
            .map(|i| judged_value(i % 10, i % 3, "GET", "/", "p=<num>", "0.1", "0.1"))
            .collect();
        let report = run(&lines);
        let rule = report
            .candidates
            .first()
            .and_then(|c| c.rule.clone())
            .unwrap_or_default();
        let expected = "rule learned-1 {\n    description \"learned from the access log: GET / p=<num>\";\n    action skip;\n    site example.test;\n    method GET;\n    path = /;\n    query ~ \"^p=[0-9]{1,20}$\";\n}";
        assert_eq!(rule, expected);
    }

    #[test]
    fn the_site_option_keeps_only_the_groups_of_that_site() {
        let mut lines = spread(50, 10, 3, "0.1", "0.1");
        for i in 0..50 {
            lines.push(set(
                judged_value(i % 10, i % 3, "GET", "/", "p=<num>", "0.1", "0.1"),
                "site",
                "other.test",
            ));
        }
        let options = SuggestOptions {
            site: Some("other.test".to_owned()),
            ..SuggestOptions::default()
        };
        let text = lines
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        let report = suggest_skip_rules(text.as_bytes(), &options)
            .unwrap_or_else(|error| panic!("reading from memory failed: {error}"));
        assert_eq!(report.candidates.len(), 1, "{report}");
        assert_eq!(
            report.candidates.first().map(|c| c.site.as_str()),
            Some("other.test")
        );
    }

    #[test]
    fn candidates_are_sorted_by_judged_then_by_key_and_numbered_in_that_order() {
        let mut lines = spread(50, 10, 3, "0.1", "0.1");
        lines.extend(
            (0..50).map(|i| judged_value(i % 10, i % 3, "GET", "/z", "p=<num>", "0.1", "0.1")),
        );
        lines.extend(
            (0..80).map(|i| judged_value(i % 10, i % 3, "GET", "/m", "p=<num>", "0.1", "0.1")),
        );
        let report = run(&lines);
        let paths: Vec<&str> = report.candidates.iter().map(|c| c.path.as_str()).collect();
        assert_eq!(paths, ["/m", "/", "/z"], "{report}");
        let rules: Vec<String> = report
            .candidates
            .iter()
            .filter_map(|c| c.rule.clone())
            .collect();
        assert!(
            rules
                .first()
                .is_some_and(|r| r.starts_with("rule learned-1 "))
        );
        assert!(
            rules
                .get(2)
                .is_some_and(|r| r.starts_with("rule learned-3 "))
        );
    }

    #[test]
    fn an_empty_run_says_no_shape_meets_the_thresholds() {
        let report = suggest_skip_rules("".as_bytes(), &SuggestOptions::default())
            .unwrap_or_else(|error| panic!("reading from memory failed: {error}"));
        let text = report.to_string();
        assert!(
            text.contains("Candidates: 0\nNo shape meets the thresholds.\n"),
            "{text}"
        );
        assert!(text.contains("Needs review: 0 ("), "{text}");
        assert!(
            text.contains("Already skipped by a rule or the static skip: 0 shapes, 0 requests."),
            "{text}"
        );
    }

    #[test]
    fn the_report_notes_that_learned_rules_skip_the_model_for_headers_and_body() {
        let lines = spread(50, 10, 3, "0.1", "0.1");
        let text = run(&lines).to_string();
        assert!(text.contains("Candidates: 1\nA learned rule forwards matching requests without the model, so the model no longer judges their headers or body. Block rules, built-in and your own, still run first.\n") , "{text}");
        let empty = suggest_skip_rules("".as_bytes(), &SuggestOptions::default())
            .unwrap_or_else(|error| panic!("reading from memory failed: {error}"))
            .to_string();
        assert!(!empty.contains("forwards matching requests"), "{empty}");
    }

    #[test]
    fn the_report_shows_the_evidence_and_the_rule_of_a_candidate() {
        let lines = spread(50, 10, 3, "0.1", "0.1");
        let text = run(&lines).to_string();
        assert!(text.contains("# GET example.test / p=<num>: 50 judged, 10 clients, 3 days, max attack 0.1, max ai_instruction 0.1"), "{text}");
        assert!(text.contains("rule learned-1 {"), "{text}");
        assert!(text.contains("Learning thresholds: judged >= 50, clients >= 10, days >= 3, attack <= 0.3, ai_instruction <= 0.3, never blocked."), "{text}");
    }
}
