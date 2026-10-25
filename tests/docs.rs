//! Keeps the documentation under `docs/` in step with the parser and the built-in rules.
//!
//! The directive names come from the parser's own lists, so a directive that the
//! parser accepts but the reference does not describe fails this test.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::path::PathBuf;

use vigilant_heron::directives::{DECISION_DIRECTIVES, SITE_DIRECTIVES, TOP_LEVEL_DIRECTIVES};

type TestResult = Result<(), Box<dyn Error>>;

fn read(relative: &str) -> Result<String, Box<dyn Error>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    Ok(std::fs::read_to_string(path)?)
}

/// Returns the text of the `## <title>` section, up to the next level-2 heading.
fn section<'a>(doc: &'a str, title: &str) -> Option<&'a str> {
    let heading = format!("\n## {title}\n");
    let start = doc.find(&heading)? + heading.len();
    let body = doc.get(start..)?;
    match body.find("\n## ") {
        Some(end) => body.get(..end),
        None => Some(body),
    }
}

fn missing_directives<'a>(section_text: &str, names: &[&'a str]) -> Vec<&'a str> {
    names
        .iter()
        .copied()
        .filter(|name| !section_text.contains(&format!("`{name}`")))
        .collect()
}

#[test]
fn every_directive_the_parser_accepts_is_documented() -> TestResult {
    let doc = read("docs/configuration.md")?;
    let cases = [
        ("Top level", TOP_LEVEL_DIRECTIVES),
        ("Decision block", DECISION_DIRECTIVES),
        ("Site block", SITE_DIRECTIVES),
    ];
    for (title, names) in cases {
        let text = section(&doc, title)
            .ok_or_else(|| format!("docs/configuration.md has no \"## {title}\" section"))?;
        let missing = missing_directives(text, names);
        assert!(
            missing.is_empty(),
            "directives accepted by the parser but not documented under \"{title}\" in docs/configuration.md: {missing:?}"
        );
    }
    Ok(())
}

#[test]
fn builtin_rule_table_lists_exactly_the_built_in_rules() -> TestResult {
    let conf_ids: BTreeSet<String> = read("src/rules/builtin.conf")?
        .lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("rule ")?;
            Some(rest.split_whitespace().next()?.to_owned())
        })
        .collect();
    assert!(
        !conf_ids.is_empty(),
        "no rules found in src/rules/builtin.conf"
    );

    let doc_rows: Vec<String> = read("docs/builtin-rules.md")?
        .lines()
        .filter_map(|line| {
            let cell = line.strip_prefix("| `")?;
            let id = cell.split('`').next()?;
            id.starts_with("vh-").then(|| id.to_owned())
        })
        .collect();
    let doc_ids: BTreeSet<String> = doc_rows.iter().cloned().collect();
    assert_eq!(
        doc_rows.len(),
        doc_ids.len(),
        "docs/builtin-rules.md lists a rule id more than once"
    );

    let missing: Vec<&String> = conf_ids.difference(&doc_ids).collect();
    let unknown: Vec<&String> = doc_ids.difference(&conf_ids).collect();
    assert!(
        missing.is_empty(),
        "built-in rules missing from docs/builtin-rules.md: {missing:?}"
    );
    assert!(
        unknown.is_empty(),
        "docs/builtin-rules.md lists ids that src/rules/builtin.conf does not define: {unknown:?}"
    );
    Ok(())
}

#[test]
fn builtin_rule_default_column_matches_the_default_off_directives() -> TestResult {
    // The ids whose rule block in builtin.conf says `default off;`.
    let mut off_in_conf = BTreeSet::new();
    let mut current: Option<String> = None;
    for line in read("src/rules/builtin.conf")?.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("rule ") {
            current = rest.split_whitespace().next().map(str::to_owned);
        } else if trimmed == "default off;"
            && let Some(id) = &current
        {
            off_in_conf.insert(id.clone());
        }
    }
    assert!(
        !off_in_conf.is_empty(),
        "no rule in builtin.conf is off by default"
    );

    // The Default column is the third cell; ids and categories contain no `|`.
    let mut table: BTreeMap<String, String> = BTreeMap::new();
    for line in read("docs/builtin-rules.md")?.lines() {
        let mut cells = line.split('|');
        let (Some(_), Some(id_cell), Some(_category), Some(default_cell)) =
            (cells.next(), cells.next(), cells.next(), cells.next())
        else {
            continue;
        };
        let Some(id) = id_cell
            .trim()
            .strip_prefix('`')
            .and_then(|rest| rest.strip_suffix('`'))
        else {
            continue;
        };
        if id.starts_with("vh-") {
            table.insert(id.to_owned(), default_cell.trim().to_owned());
        }
    }

    for (id, default) in &table {
        let expected = if off_in_conf.contains(id) {
            "off"
        } else {
            "on"
        };
        assert_eq!(
            default, expected,
            "docs/builtin-rules.md gives {id} the default \"{default}\", builtin.conf says \"{expected}\""
        );
    }
    let missing: Vec<&String> = off_in_conf
        .iter()
        .filter(|id| !table.contains_key(*id))
        .collect();
    assert!(missing.is_empty(), "no Default cell for {missing:?}");
    Ok(())
}
