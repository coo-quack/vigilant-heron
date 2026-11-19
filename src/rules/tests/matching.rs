//! Matching of user rules, the screening order, normalization of the inputs and property tests.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use http::{HeaderMap, HeaderName, HeaderValue, Method};
use proptest::prelude::*;

use super::builtin::builtin_hit;
use super::{UA, attack_text, site_with};
use crate::error::ConfigError;
use crate::prefilter::{self, Screening};
use crate::rules::matching::{form_value, header_value};
use crate::rules::{Pattern, RuleInput};

// Matching of user rules and the screening order.

fn screen_request(
    site: &crate::config::SiteConfig,
    method: &str,
    path: &str,
    query: Option<&str>,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Screening {
    let method = Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET);
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_bytes(value.as_bytes()),
        ) {
            map.append(name, value);
        }
    }
    let client = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let input = RuleInput::new(&method, path, query, &map, body, client);
    let lowered: Vec<String> = prefilter::path_views(path)
        .iter()
        .map(|view| view.to_lowercase())
        .collect();
    prefilter::screen(site, &input, &lowered, body.is_empty())
}

const USER_RULES: &str = "\
rule block-admin {\n    description \"admin probe\";\n    action block;\n    path ^~ /admin;\n    method POST;\n}\n\
rule skip-health {\n    description \"health checks\";\n    action skip;\n    path = /health;\n}\n\
rule skip-any {\n    description \"skip everything named skip\";\n    action skip;\n    any ~* \"attack\";\n}\n";

#[test]
fn a_user_block_rule_matches_on_its_conditions_only() -> Result<(), ConfigError> {
    let site = site_with(USER_RULES, "")?;
    assert_eq!(
        screen_request(&site, "POST", "/admin/login", None, &[], b"x"),
        Screening::Rule(Some(Arc::from("block-admin")))
    );
    assert_ne!(
        screen_request(&site, "GET", "/admin/login", None, &[], b""),
        Screening::Rule(Some(Arc::from("block-admin")))
    );
    Ok(())
}

#[test]
fn a_skip_rule_skips_the_backend_and_a_block_rule_wins_over_it() -> Result<(), ConfigError> {
    let site = site_with(USER_RULES, "")?;
    assert_eq!(
        screen_request(&site, "GET", "/health", None, &[], b""),
        Screening::SkipRule(Arc::from("skip-health"))
    );
    // The request matches a skip rule and a block rule: it is blocked.
    assert_eq!(
        screen_request(&site, "POST", "/admin/health", None, &[], b""),
        Screening::Rule(Some(Arc::from("block-admin")))
    );
    Ok(())
}

#[test]
fn a_skip_rule_cannot_let_through_a_request_a_block_rule_matches() -> Result<(), ConfigError> {
    let site = site_with(
        "rule block-q {\n    description \"blocked\";\n    action block;\n    query ~ \"evil\";\n}\n\
         rule skip-all {\n    description \"skips\";\n    action skip;\n    method GET;\n}\n",
        "",
    )?;
    assert_eq!(
        screen_request(&site, "GET", "/x", Some("evil=1"), &[], b""),
        Screening::Rule(Some(Arc::from("block-q")))
    );
    assert_eq!(
        screen_request(&site, "GET", "/x", Some("fine=1"), &[], b""),
        Screening::SkipRule(Arc::from("skip-all"))
    );
    Ok(())
}

#[test]
fn deny_path_is_checked_before_any_rule() -> Result<(), ConfigError> {
    let site = site_with(
        "rule block-all {\n    description \"d\";\n    action block;\n    method GET;\n}\n",
        "deny_path /xmlrpc.php;\n",
    )?;
    assert_eq!(
        screen_request(&site, "GET", "/xmlrpc.php", None, &[], b""),
        Screening::Rule(None)
    );
    Ok(())
}

#[test]
fn static_skip_comes_after_block_rules() -> Result<(), ConfigError> {
    let site = site_with(
        "rule block-css {\n    description \"d\";\n    action block;\n    path /style.css;\n}\n",
        "",
    )?;
    assert_eq!(
        screen_request(&site, "GET", "/style.css", None, &[], b""),
        Screening::Rule(Some(Arc::from("block-css")))
    );
    assert_eq!(
        screen_request(&site, "GET", "/app.css", None, &[], b""),
        Screening::Skip
    );
    Ok(())
}

#[test]
fn client_conditions_match_the_realip_address() -> Result<(), ConfigError> {
    let site = site_with(
        "rule from-lan {\n    description \"d\";\n    action block;\n    client 192.0.2.0/24;\n}\n",
        "",
    )?;
    assert_eq!(
        screen_request(&site, "GET", "/", None, &[], b""),
        Screening::Rule(Some(Arc::from("from-lan")))
    );
    Ok(())
}

#[test]
fn header_conditions_must_all_match_and_an_absent_header_does_not_match() -> Result<(), ConfigError>
{
    let site = site_with(
        "rule two-headers {\n    description \"d\";\n    action block;\n    header x-a ~ \"one\";\n    header x-b ~ \"two\";\n}\n",
        "",
    )?;
    assert_eq!(
        screen_request(
            &site,
            "GET",
            "/",
            None,
            &[("x-a", "one"), ("x-b", "two")],
            b""
        ),
        Screening::Rule(Some(Arc::from("two-headers")))
    );
    assert_eq!(
        screen_request(&site, "GET", "/", None, &[("x-a", "one")], b""),
        Screening::Inspect
    );
    Ok(())
}

#[test]
fn a_case_sensitive_path_regex_does_not_match_another_case() -> Result<(), ConfigError> {
    let site = site_with(
        "rule cs {\n    description \"d\";\n    action block;\n    path ~ \"^/Admin\";\n}\n\
         rule ci {\n    description \"d\";\n    action block;\n    path ~* \"^/Other\";\n}\n",
        "",
    )?;
    assert_eq!(
        screen_request(&site, "GET", "/admin", None, &[], b""),
        Screening::Inspect
    );
    assert_eq!(
        screen_request(&site, "GET", "/Admin", None, &[], b""),
        Screening::Rule(Some(Arc::from("cs")))
    );
    assert_eq!(
        screen_request(&site, "GET", "/other", None, &[], b""),
        Screening::Rule(Some(Arc::from("ci")))
    );
    Ok(())
}

#[test]
fn a_body_condition_sees_only_the_inspected_prefix() -> Result<(), ConfigError> {
    let site = site_with(
        "rule body-x {\n    description \"d\";\n    action block;\n    body ~ \"evil\";\n}\n",
        "",
    )?;
    assert_eq!(
        screen_request(&site, "POST", "/", None, &[], b"evil"),
        Screening::Rule(Some(Arc::from("body-x")))
    );
    assert_eq!(
        screen_request(&site, "POST", "/", None, &[], b"fine"),
        Screening::Inspect
    );
    Ok(())
}

// Normalization of the inputs.

#[test]
fn a_plus_in_the_query_matches_a_space_and_a_double_encoded_quote_matches_a_quote() {
    assert!(builtin_hit("GET", "/", Some("q=union+select"), UA, b"").is_some());
    assert!(builtin_hit("GET", "/", Some("q=%2527+or+1%3D1--"), UA, b"").is_some());
}

#[test]
fn a_nul_byte_inside_a_keyword_is_removed_before_matching() {
    // NUL is dropped after decoding, so "un%00ion" reads as "union".
    assert_eq!(
        builtin_hit("GET", "/", Some("q=un%00ion%20select"), UA, b""),
        Some("vh-sqli-001".to_owned())
    );
    assert_eq!(
        builtin_hit("GET", "/", Some("q=uni%00on+select"), UA, b""),
        Some("vh-sqli-001".to_owned())
    );
    assert_eq!(
        builtin_hit("GET", "/", Some("q=union%00+select"), UA, b""),
        Some("vh-sqli-001".to_owned())
    );
}

#[test]
fn normalized_path_has_no_nul_for_rule_matching() {
    let path = prefilter::decoded_path("/a%00b").replace('\0', "");
    assert_eq!(path, "/ab");
}

// Property tests.

/// Text made of characters that encode to something after decoding: no `%`, `+` or NUL.
fn plain_text() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9 /.'\"<>;:=()_-]{0,40}"
}

fn percent_encode_all(text: &str) -> String {
    text.bytes()
        .map(|byte| format!("%{byte:02X}"))
        .collect::<Vec<String>>()
        .concat()
}

proptest! {
    #[test]
    fn matching_never_panics_on_arbitrary_input(
        path in attack_text(),
        query in proptest::option::of(attack_text()),
        header in attack_text(),
        body in attack_text(),
    ) {
        let site = site_with(
            "rule r1 {\n    description \"d\";\n    action block;\n    path ~* \"%2e\";\n    query ~ \"%\";\n    header user-agent ~* \"x\";\n    body ~ \"a\\\\.b\";\n    any ~* \"(a+)+$\";\n}\n",
            "",
        );
        prop_assert!(site.is_ok(), "the fixture must parse");
        if let Ok(site) = site {
            let value = HeaderValue::from_bytes(header.as_bytes()).unwrap_or(HeaderValue::from_static("x"));
            let headers = [("user-agent", value.to_str().unwrap_or("x"))];
            let _ = screen_request(&site, "GET", &path, query.as_deref(), &headers, body.as_bytes());
            let _ = builtin_hit("POST", &path, query.as_deref(), &headers, body.as_bytes());
        }
    }

    #[test]
    fn normalization_removes_two_levels_of_encoding(text in plain_text()) {
        let encoded_twice = percent_encode_all(&percent_encode_all(&text));
        prop_assert_eq!(form_value(&encoded_twice), text.clone());
        prop_assert_eq!(header_value(&encoded_twice), text);
    }

    #[test]
    fn normalized_values_have_no_nul_and_no_escapes_left_after_a_second_pass(text in attack_text()) {
        let once = form_value(&text);
        prop_assert!(!once.contains('\0'));
        if !once.contains('%') && !once.contains('+') {
            prop_assert_eq!(form_value(&once), once.clone());
        }
    }
}

#[test]
fn patterns_are_equal_when_source_and_operator_are_equal() -> Result<(), String> {
    let plain = Pattern::new("a+", false)?;
    assert_eq!(plain, Pattern::new("a+", false)?);
    assert_ne!(plain, Pattern::new("a+", true)?);
    assert_ne!(plain, Pattern::new("b+", false)?);
    Ok(())
}
