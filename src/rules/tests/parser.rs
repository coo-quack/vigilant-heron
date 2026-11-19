//! Parsing and validation of rule blocks, and the access list and rule inheritance of a configuration.

use std::sync::Arc;

use http::Method;
use rstest::rstest;

use super::{config, first_site, ids, message};
use crate::conf;
use crate::config::Config;
use crate::error::ConfigError;
use crate::rules::matching::MAX_REGEX_BYTES;
use crate::rules::parse::MAX_RULES;
use crate::rules::{ParsedRule, PathMatch, Rule, RuleAction, Scope, builtin_rules, parse_rule};

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

// Parser and validation. In these tables the rule is on line 1, so the first line of its body
// is line 2. A rule that lacks something is reported at the line of the rule.

#[rstest]
#[case::missing_description("action block;\npath /x;", "needs a \"description\"", 1)]
#[case::missing_action("description \"d\";\npath /x;", "needs an \"action\"", 1)]
#[case::no_condition("description \"d\";\naction block;", "needs at least one condition", 1)]
#[case::unknown_action(
    "description \"d\";\naction allow;\npath /x;",
    "must be \"block\" or \"skip\"",
    3
)]
#[case::empty_description("description \" \";\naction block;\npath /x;", "must not be empty", 2)]
#[case::duplicate_description(
    "description \"a\";\ndescription \"b\";\naction block;\npath /x;",
    "duplicate directive \"description\"",
    3
)]
#[case::unknown_directive(
    "description \"d\";\naction block;\nfoo bar;",
    "unknown directive \"foo\" in rule",
    4
)]
#[case::path_without_slash(
    "description \"d\";\naction block;\npath x;",
    "must start with \"/\"",
    4
)]
#[case::path_bad_modifier(
    "description \"d\";\naction block;\npath ~~ /x;",
    "modifier must be",
    4
)]
#[case::path_exact_without_slash(
    "description \"d\";\naction block;\npath = x;",
    "must start with \"/\"",
    4
)]
#[case::path_too_many_arguments(
    "description \"d\";\naction block;\npath a b c;",
    "takes a value",
    4
)]
#[case::duplicate_path(
    "description \"d\";\naction block;\npath /a;\npath /b;",
    "duplicate directive \"path\"",
    5
)]
#[case::query_without_operator(
    "description \"d\";\naction block;\nquery x;",
    "takes an operator and a regex",
    4
)]
#[case::query_with_bad_operator(
    "description \"d\";\naction block;\nquery = \"x\";",
    "takes ~ or ~*",
    4
)]
#[case::bad_regex(
    "description \"d\";\naction block;\nquery ~ \"(\";",
    "invalid regex",
    4
)]
#[case::regex_too_large_for_the_limit(
    "description \"d\";\naction block;\nany ~ \"(a{1000}){1000}\";",
    "invalid regex",
    4
)]
#[case::bad_header_name(
    "description \"d\";\naction block;\nheader \"bad name\" ~ \"x\";",
    "not a header name",
    4
)]
#[case::header_missing_regex(
    "description \"d\";\naction block;\nheader user-agent ~*;",
    "takes a name, an operator and a regex",
    4
)]
#[case::empty_method(
    "description \"d\";\naction block;\nmethod \"\";",
    "not a valid method",
    4
)]
#[case::method_needs_an_argument(
    "description \"d\";\naction block;\nmethod;",
    "needs at least one method",
    4
)]
#[case::bad_client(
    "description \"d\";\naction block;\nclient 10.0.0.300;",
    "not an address or network",
    4
)]
#[case::client_needs_an_argument(
    "description \"d\";\naction block;\nclient;",
    "needs at least one address",
    4
)]
#[case::site_with_no_host(
    "description \"d\";\naction block;\npath /x;\nsite;",
    "site\" needs at least one host name",
    5
)]
#[case::site_with_an_invalid_host(
    "description \"d\";\naction block;\npath /x;\nsite :8080;",
    "\"site\" has an invalid host name: :8080",
    5
)]
fn invalid_rule_directives_are_rejected_with_their_line(
    #[case] body: &str,
    #[case] expected: &str,
    #[case] line: usize,
) {
    let error = parse_top_rule(body).err().map_or_default(|e| e.to_string());
    assert!(error.starts_with(&format!("test.conf:{line}: ")), "{error}");
    assert!(error.contains(expected), "{error}");
}

#[rstest]
#[case::action(
    "description \"d\";\naction block;\naction skip;\npath /x;",
    "action",
    4
)]
#[case::method(
    "description \"d\";\naction block;\nmethod GET;\nmethod POST;",
    "method",
    5
)]
#[case::client(
    "description \"d\";\naction block;\nclient 10.0.0.1;\nclient 10.0.0.2;",
    "client",
    5
)]
#[case::site(
    "description \"d\";\naction block;\npath /x;\nsite a.test;\nsite b.test;",
    "site",
    6
)]
fn a_single_use_rule_directive_written_twice_is_rejected_at_the_second_one(
    #[case] body: &str,
    #[case] name: &str,
    #[case] line: usize,
) {
    let error = parse_top_rule(body).err().map_or_default(|e| e.to_string());
    assert_eq!(
        error,
        format!("test.conf:{line}: duplicate directive \"{name}\"")
    );
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
        .map_or_default(|e| e.to_string());
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
