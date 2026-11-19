//! Opt-in built-in rules: parsing, activation and matching.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use http::{HeaderMap, Method};
use proptest::prelude::*;
use rstest::rstest;

use super::builtin::builtin_hit;
use super::{UA, attack_text, config, first_site, ids, message, site_with};
use crate::conf;
use crate::config::Config;
use crate::error::ConfigError;
use crate::rules::{ParsedRule, RuleInput, Scope, builtin_rules, matching, parse_rule};

/// Parses a rule written in the built-in scope, with the id `vh-test-001`.
fn parse_builtin_rule(body: &str) -> Result<ParsedRule, ConfigError> {
    let text = format!("rule vh-test-001 {{\n{body}\n}}\n");
    let directives = conf::parse_source(&text, "builtin.conf")?;
    let directive = directives.first().ok_or_else(|| ConfigError::Invalid {
        file: "builtin.conf".to_owned(),
        line: 1,
        message: "no directive".to_owned(),
    })?;
    parse_rule(directive, Scope::Builtin)
}

#[rstest]
#[case::off_in_the_built_in_file("description \"d\";\ndefault off;\naction block;\npath /x;", true)]
#[case::on_is_not_written("default on;\naction block;\npath /x;", false)]
#[case::repeated("default off;\ndefault off;\naction block;\npath /x;", false)]
fn default_is_read_only_in_the_built_in_file(#[case] body: &str, #[case] accepted: bool) {
    let parsed = parse_builtin_rule(body);
    assert_eq!(parsed.is_ok(), accepted, "{parsed:?}");
}

#[test]
fn default_on_is_refused_in_the_built_in_file() {
    let text = parse_builtin_rule("description \"d\";\ndefault on;\naction block;\npath /x;")
        .err()
        .map_or_default(|error| error.to_string());
    assert!(text.contains("\"default\" must be \"off\""), "{text}");
}

#[test]
fn default_off_is_refused_in_a_user_rule_with_its_line() {
    let text = message(config(
        "rule user-off {\n    description \"d\";\n    default off;\n    action block;\n    path /x;\n}\n",
        "",
    ));
    assert!(
        text.contains("\"default\" is only valid in a built-in rule"),
        "{text}"
    );
    assert!(text.contains("test.conf:4"), "{text}");
}

#[test]
fn a_built_in_rule_without_default_is_on() -> Result<(), ConfigError> {
    let parsed = parse_builtin_rule("action block;\npath /x;\ndescription \"d\";")?;
    assert!(parsed.rule.default_on);
    Ok(())
}

#[test]
fn default_off_is_parsed_into_the_rule() -> Result<(), ConfigError> {
    let parsed = parse_builtin_rule("description \"d\";\ndefault off;\naction block;\npath /x;")?;
    assert!(!parsed.rule.default_on);
    Ok(())
}

#[test]
fn enable_rule_must_name_a_built_in_rule() {
    let text = message(config("enable_rule vh-nope-001;", ""));
    assert!(
        text.contains("\"enable_rule\" names no built-in rule: vh-nope-001"),
        "{text}"
    );
    assert!(config("enable_rule vh-cve-2026-9103 vh-sqli-001;", "").is_ok());
    assert!(message(config("enable_rule;", "")).contains("needs at least one rule id"));
}

const ON: &str = "vh-sqli-001";
const OFF: &str = "vh-cve-2026-9103";

/// The ids of the block rules one site runs, for a configuration with `top` and `site_lines`.
fn block_ids(top: &str, site_lines: &str) -> Result<Vec<String>, ConfigError> {
    let cfg = config(top, site_lines)?;
    Ok(ids(&first_site(&cfg)?.rules.block))
}

#[rstest]
#[case::default_on_runs_without_any_switch("", "", ON, true)]
#[case::default_off_stays_off_without_a_switch("", "", OFF, false)]
#[case::top_level_enable_turns_on_a_default_off_rule(
    "enable_rule vh-cve-2026-9103;",
    "",
    OFF,
    true
)]
#[case::enabling_a_default_on_rule_is_harmless("enable_rule vh-sqli-001;", "", ON, true)]
#[case::top_level_disable_turns_off_a_default_on_rule("disable_rule vh-sqli-001;", "", ON, false)]
#[case::same_level_disable_wins_over_enable(
    "enable_rule vh-cve-2026-9103;\ndisable_rule vh-cve-2026-9103;",
    "",
    OFF,
    false
)]
#[case::site_enable_overrides_inherited_top_disable(
    "disable_rule vh-cve-2026-9103;",
    "enable_rule vh-cve-2026-9103;",
    OFF,
    true
)]
#[case::site_disable_overrides_inherited_top_enable(
    "enable_rule vh-cve-2026-9103;",
    "disable_rule vh-cve-2026-9103;",
    OFF,
    false
)]
#[case::site_enable_without_a_top_switch("", "enable_rule vh-cve-2026-9103;", OFF, true)]
#[case::same_level_disable_wins_at_a_site(
    "",
    "enable_rule vh-cve-2026-9103;\ndisable_rule vh-cve-2026-9103;",
    OFF,
    false
)]
#[case::builtin_off_keeps_a_default_on_rule_off("builtin_rules off;", "", ON, false)]
#[case::builtin_off_still_runs_an_enabled_rule(
    "builtin_rules off;",
    "enable_rule vh-cve-2026-9103;",
    OFF,
    true
)]
#[case::builtin_off_at_site_still_runs_a_top_enabled_rule(
    "enable_rule vh-cve-2026-9103;",
    "builtin_rules off;",
    OFF,
    true
)]
#[case::builtin_off_at_site_keeps_a_default_on_rule_off(
    "",
    "builtin_rules off;\nenable_rule vh-cve-2026-9103;",
    ON,
    false
)]
#[case::site_disable_beats_top_enable_on_a_default_on_rule(
    "enable_rule vh-sqli-001;",
    "disable_rule vh-sqli-001;",
    ON,
    false
)]
fn a_built_in_rule_runs_at_a_site_only_as_its_switches_decide(
    #[case] top: &str,
    #[case] site_lines: &str,
    #[case] id: &str,
    #[case] active: bool,
) -> Result<(), ConfigError> {
    let block = block_ids(top, site_lines)?;
    assert_eq!(block.iter().any(|name| name == id), active, "{block:?}");
    Ok(())
}

#[test]
fn an_enabled_rule_runs_on_the_site_that_enables_it_only() -> Result<(), ConfigError> {
    let text = "listen 127.0.0.1:8080;\n\
        decision {\n    backend http;\n    url http://stub-decider:9000/decide;\n}\n\
        site langflow.example {\n    upstream http://upstream:80;\n    enable_rule vh-cve-2026-9103 vh-cve-2026-8481;\n}\n\
        site other.example {\n    upstream http://upstream:80;\n}\n";
    let cfg = Config::parse_str(text, "test.conf")?;
    for site in &cfg.sites {
        let block = ids(&site.rules.block);
        let enabled = site.hosts.iter().any(|host| host == "langflow.example");
        assert_eq!(block.contains(&OFF.to_owned()), enabled, "{block:?}");
        assert_eq!(
            block.contains(&"vh-cve-2026-8481".to_owned()),
            enabled,
            "{block:?}"
        );
    }
    Ok(())
}

#[rstest]
#[case::exact_path("GET", "/api/v1/login/auto_login")]
#[case::any_method_post("POST", "/api/v1/login/auto_login")]
#[case::trailing_slash("GET", "/api/v1/login/auto_login/")]
#[case::trailing_segment("GET", "/api/v1/login/auto_login/extra")]
#[case::double_slash("GET", "//api/v1/login/auto_login")]
#[case::percent_encoded_letter("GET", "/api/v1/login/%61uto_login")]
#[case::dot_segment("GET", "/api/v1/login/../login/auto_login")]
#[case::semicolon_suffix("GET", "/api/v1/login/auto_login;x")]
fn cve_9103_matches_the_endpoint_in_its_normalized_forms(#[case] method: &str, #[case] path: &str) {
    assert_eq!(
        builtin_hit(method, path, None, UA, b"").as_deref(),
        Some("vh-cve-2026-9103")
    );
}

#[rstest]
#[case::upper("GET", "/API/V1/LOGIN/AUTO_LOGIN")]
#[case::mixed("GET", "/Api/V1/Login/Auto_Login")]
#[case::upper_post("POST", "/API/V1/LOGIN/AUTO_LOGIN")]
#[case::upper_trailing_segment("GET", "/API/V1/LOGIN/AUTO_LOGIN/extra")]
#[case::upper_semicolon_suffix("GET", "/API/V1/LOGIN/AUTO_LOGIN;x")]
fn cve_2026_9103_blocks_the_endpoint_in_any_case(#[case] method: &str, #[case] path: &str) {
    assert_eq!(
        builtin_hit(method, path, None, UA, b"").as_deref(),
        Some("vh-cve-2026-9103")
    );
}

#[rstest]
#[case::login_root("/api/v1/login")]
#[case::login_root_slash("/api/v1/login/")]
#[case::other_endpoint("/api/v1/logout")]
#[case::lookalike_segment("/api/v1/login/autologin")]
fn cve_9103_leaves_other_login_paths_alone(#[case] path: &str) {
    assert_eq!(builtin_hit("GET", path, None, UA, b""), None);
}

#[rstest]
#[case::exact_path("/api/v1/validate/code")]
#[case::trailing_slash("/api/v1/validate/code/")]
#[case::double_slash("//api/v1/validate/code")]
#[case::percent_encoded_letter("/api/v1/validate/%63ode")]
fn cve_8481_blocks_post_to_the_endpoint_in_its_normalized_forms(#[case] path: &str) {
    assert_eq!(
        builtin_hit("POST", path, None, UA, b"{\"code\": \"x\"}").as_deref(),
        Some("vh-cve-2026-8481")
    );
}

#[rstest]
#[case::upper("/API/V1/VALIDATE/CODE")]
#[case::mixed("/Api/V1/Validate/Code")]
#[case::upper_trailing_slash("/API/V1/VALIDATE/CODE/")]
fn cve_2026_8481_blocks_the_endpoint_in_any_case(#[case] path: &str) {
    assert_eq!(
        builtin_hit("POST", path, None, UA, b"{\"code\": \"x\"}").as_deref(),
        Some("vh-cve-2026-8481")
    );
}

#[rstest]
#[case::get("GET", "/api/v1/validate/code")]
#[case::put("PUT", "/api/v1/validate/code")]
#[case::delete("DELETE", "/api/v1/validate/code")]
#[case::post_to_another_endpoint("POST", "/api/v1/validate/prompt")]
#[case::post_to_the_parent("POST", "/api/v1/validate")]
fn cve_8481_leaves_other_methods_and_paths_alone(#[case] method: &str, #[case] path: &str) {
    assert_eq!(builtin_hit(method, path, None, UA, b""), None);
}

proptest! {
    #[test]
    fn a_default_off_rule_never_matches_unless_it_is_enabled(
        method in proptest::sample::select(vec!["GET", "POST", "PUT", "DELETE"]),
        path in "(/api/v1/login/auto_login|/api/v1/validate/code|/api/v1/login|/)[a-zA-Z0-9/;.%_-]{0,24}",
        query in proptest::option::of(attack_text()),
    ) {
        let site = site_with("", "");
        prop_assert!(site.is_ok(), "the fixture must parse");
        if let Ok(site) = site {
            prop_assert!(site.rules.block.iter().all(|rule| rule.default_on));
            let shipped_off: Vec<Arc<str>> = builtin_rules()
                .unwrap_or(&[])
                .iter()
                .filter(|rule| !rule.default_on)
                .map(|rule| Arc::clone(&rule.id))
                .collect();
            prop_assert!(shipped_off.len() >= 2, "the CVE rules are shipped off");
            let map = HeaderMap::new();
            let client = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
            let method = Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET);
            let input = RuleInput::new(&method, &path, query.as_deref(), &map, b"", client);
            let hit = matching::first_match(&site.rules.block, &input);
            prop_assert!(hit.is_none_or(|rule| !shipped_off.contains(&rule.id)));
        }
    }
}
