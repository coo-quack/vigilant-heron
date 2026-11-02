//! The optional `WordPress` rule file, `examples/rules.d/wordpress.conf`.
//!
//! Each sample request is checked through a configuration that includes a copy of the
//! file, the way a site does, so the rules are loaded and matched as the router loads
//! and matches them. A few requests also go through the running proxy, to show that a
//! skip never reaches the decision backend.

mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use common::{BoxError, StubDecider, TestResult, Upstream, send, start_proxy_config};
use http::{Method, StatusCode};
use rstest::rstest;
use vigilant_heron::{Config, Outcome, check_request_with};

/// The client address of the checks: loopback, with no `real_ip` setting.
const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// The binary under test.
const BIN: &str = env!("CARGO_BIN_EXE_vigilant-heron");

/// What the router must decide for one sample request.
#[derive(Debug, Clone, Copy)]
enum Expected {
    /// Forwarded by the skip rule with this id, without the decision backend.
    Skip(&'static str),
    /// Blocked by the rule with this id.
    Block(&'static str),
    /// No rule decides, so the decision backend is asked.
    Model,
}

/// Counts the directories made by [`fresh_dir`], so parallel tests never share one.
static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

/// A new directory with an empty `rules.d/`, unique to this process and call.
fn fresh_dir() -> Result<PathBuf, BoxError> {
    let n = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("vh-wp-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("rules.d"))?;
    Ok(dir)
}

/// The text of the shipped rule file.
fn shipped_rules() -> Result<String, BoxError> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/rules.d/wordpress.conf");
    Ok(std::fs::read_to_string(path)?)
}

/// Writes `rules` to `rules.d/wordpress.conf` in `dir`, and a router configuration beside it
/// that includes the file from the top level. The configuration has an enforce site and a
/// shadow site, both forwarding to `upstream` and deciding with `decide`.
fn write_router(
    dir: &Path,
    rules: &str,
    upstream: &str,
    decide: &str,
) -> Result<PathBuf, BoxError> {
    std::fs::write(dir.join("rules.d/wordpress.conf"), rules)?;
    let conf = dir.join("router.conf");
    let text = format!(
        r#"listen 127.0.0.1:0;
client_max_body_size 1024;
decision {{
    backend http;
    url "{decide}";
    timeout 2000ms;
    inspect_body 512;
}}
default_status 421;
include rules.d/wordpress.conf;

site enforce.test {{
    upstream "{upstream}";
    mode enforce;
    action block;
    block_threshold 0.9;
    instruction_threshold 0.5;
}}

site shadow.test {{
    upstream "{upstream}";
    mode shadow;
    action block;
    block_threshold 0.9;
    instruction_threshold 0.5;
}}
"#
    );
    std::fs::write(&conf, text)?;
    Ok(conf)
}

/// The loaded configuration that includes `rules`. The upstream and the backend are not
/// called by the request check, so their addresses are placeholders.
fn config_with_rules(rules: &str) -> Result<Config, BoxError> {
    let dir = fresh_dir()?;
    let conf = write_router(
        &dir,
        rules,
        "http://127.0.0.1:9",
        "http://127.0.0.1:9/decide",
    )?;
    Ok(Config::load(&conf)?)
}

/// The raw request for one sample: the request line, the Host header, and a zero-length
/// body for a POST.
fn raw_request(method: &str, target: &str, host: &str) -> Vec<u8> {
    let length = if method == "POST" {
        "content-length: 0\r\n"
    } else {
        ""
    };
    format!("{method} {target} HTTP/1.1\r\nHost: {host}\r\n{length}\r\n").into_bytes()
}

/// Checks one sample request against `config` and asserts the decision.
fn assert_decision(
    config: &Config,
    host: &str,
    method: &str,
    target: &str,
    expected: Expected,
) -> TestResult {
    let check = check_request_with(config, &raw_request(method, target, host), CLIENT)?;
    let rule = check.rule_id.as_deref().unwrap_or("");
    let label = format!("{method} {target} on {host}");
    match expected {
        Expected::Skip(id) => {
            assert_eq!(check.outcome, Outcome::Forwarded, "{label}: outcome");
            assert_eq!(check.reason, Some("skip_rule"), "{label}: reason");
            assert_eq!(rule, id, "{label}: rule");
        }
        Expected::Block(id) => {
            assert_eq!(check.outcome, Outcome::Blocked(403), "{label}: outcome");
            assert_eq!(check.reason, Some("rule"), "{label}: reason");
            assert_eq!(rule, id, "{label}: rule");
        }
        Expected::Model => {
            assert_eq!(check.outcome, Outcome::BackendDecides, "{label}: outcome");
            assert_eq!(check.reason, None, "{label}: reason");
            assert_eq!(rule, "", "{label}: rule");
        }
    }
    Ok(())
}

/// The stdout and then the stderr of a command, as one string, for an assertion message.
fn stdout_and_stderr(output: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

// ---------------------------------------------------------------------------
// Each rule: its matching requests and its near misses, on the enforce site
// ---------------------------------------------------------------------------

#[rstest]
// wp-public-pages: the front page with numeric parameters, feeds and sitemaps
#[case::front_page("GET", "/", Expected::Skip("wp-public-pages"))]
#[case::post_id("GET", "/?p=123", Expected::Skip("wp-public-pages"))]
#[case::page_id_and_paged("GET", "/?page_id=2&paged=3", Expected::Skip("wp-public-pages"))]
#[case::category_and_post("GET", "/?cat=5&p=7", Expected::Skip("wp-public-pages"))]
#[case::month("GET", "/?m=202610", Expected::Skip("wp-public-pages"))]
#[case::attachment("GET", "/?attachment_id=9", Expected::Skip("wp-public-pages"))]
#[case::feed_rss2("GET", "/?feed=rss2", Expected::Skip("wp-public-pages"))]
#[case::feed_atom_with_post("GET", "/?feed=atom&p=4", Expected::Skip("wp-public-pages"))]
#[case::sitemap_with_page(
    "GET",
    "/?sitemap=wp-sitemap-posts-post-1&paged=2",
    Expected::Skip("wp-public-pages")
)]
#[case::head_request("HEAD", "/?p=1", Expected::Skip("wp-public-pages"))]
#[case::quote_in_value("GET", "/?p=1%27", Expected::Model)]
#[case::markup_in_value("GET", "/?p=%3Cscript%3E", Expected::Block("vh-xss-001"))]
#[case::extra_parameter("GET", "/?p=1&utm_source=mail", Expected::Model)]
#[case::newline_escape("GET", "/?p=1%0a", Expected::Model)]
#[case::post_request("POST", "/?p=1", Expected::Model)]
#[case::other_path("GET", "/page/2?p=1", Expected::Model)]
#[case::index_php_suffix("GET", "/index.php/x", Expected::Model)]
#[case::second_parameter_outside_the_list("GET", "/?p=1&attachment_id=9", Expected::Model)]
#[case::second_parameter_from_analytics("GET", "/?p=1&utm_source=1", Expected::Model)]
#[case::plus_in_value("GET", "/?p=1+", Expected::Model)]
// The NUL byte is removed from the query before matching, so `p=1%00` matches as `p=1`
// and the skip applies.
#[case::nul_in_value_is_removed_before_matching(
    "GET",
    "/?p=1%00",
    Expected::Skip("wp-public-pages")
)]
// `<b>` matches no built-in block rule and not the skip regex, so the model decides.
#[case::markup_no_built_in_rule_blocks("GET", "/?p=%3Cb%3E", Expected::Model)]
#[case::block_rule_wins_over_the_skip(
    "GET",
    "/?p=1%20UNION%20SELECT%20password%20FROM%20users",
    Expected::Block("vh-sqli-001")
)]
// wp-login-page: the login form, GET and HEAD with any query
#[case::login_form("GET", "/wp-login.php", Expected::Skip("wp-login-page"))]
#[case::login_redirect_from_wp_admin(
    "HEAD",
    "/wp-login.php?redirect_to=https%3A%2F%2Fexample.com%2Fwp-admin%2Fpost-new.php&reauth=1",
    Expected::Skip("wp-login-page")
)]
#[case::login_post("POST", "/wp-login.php", Expected::Model)]
#[case::login_path_suffix("GET", "/wp-login.php/x", Expected::Model)]
#[case::login_path_case("GET", "/WP-LOGIN.php", Expected::Model)]
#[case::login_query_the_model_never_sees(
    "GET",
    "/wp-login.php?foo=bar",
    Expected::Skip("wp-login-page")
)]
#[case::login_path_with_an_extra_letter("GET", "/wp-login.phpx", Expected::Model)]
// Reading 2 of `/wp-login.php;x` is `/wp-login.php`, cut at the `;`. A rule that accepted any
// reading would skip this request; `wp-login-page` needs every reading to match.
#[case::login_path_with_a_semicolon_suffix("GET", "/wp-login.php;x", Expected::Model)]
#[case::javascript_url_wins_over_the_skip(
    "GET",
    "/wp-login.php?redirect_to=javascript:alert(1)",
    Expected::Block("vh-xss-002")
)]
// wp-admin-assets: the admin script and style loaders, with handle names only
#[case::scripts_loader(
    "GET",
    "/wp-admin/load-scripts.php?c=0&load%5Bchunk_0%5D=jquery-core,jquery-migrate,utils&ver=80582909d2",
    Expected::Skip("wp-admin-assets")
)]
#[case::styles_loader(
    "GET",
    "/wp-admin/load-styles.php?c=0&dir=ltr&load%5Bchunk_0%5D=dashicons,admin-bar,abo&load%5Bchunk_1%5D=,site-icon,wp-commands&ver=80582909d2",
    Expected::Skip("wp-admin-assets")
)]
#[case::rtl_styles_with_flag_one(
    "GET",
    "/wp-admin/load-styles.php?c=1&dir=rtl&load%5Bchunk_0%5D=common&ver=6.8",
    Expected::Skip("wp-admin-assets")
)]
#[case::head_loader(
    "HEAD",
    "/wp-admin/load-scripts.php?c=0&load%5Bchunk_0%5D=utils&ver=6.8.2",
    Expected::Skip("wp-admin-assets")
)]
#[case::quote_in_handle(
    "GET",
    "/wp-admin/load-scripts.php?c=0&load%5Bchunk_0%5D=jquery%27&ver=6.8",
    Expected::Model
)]
#[case::markup_in_handle(
    "GET",
    "/wp-admin/load-scripts.php?c=0&load%5Bchunk_0%5D=%3Cscript%3E&ver=6.8",
    Expected::Block("vh-xss-001")
)]
#[case::extra_parameter(
    "GET",
    "/wp-admin/load-scripts.php?c=0&load%5Bchunk_0%5D=utils&ver=6.8&x=1",
    Expected::Model
)]
#[case::newline_in_handle(
    "GET",
    "/wp-admin/load-scripts.php?c=0&load%5Bchunk_0%5D=utils%0a&ver=6.8",
    Expected::Model
)]
#[case::post_loader(
    "POST",
    "/wp-admin/load-scripts.php?c=0&load%5Bchunk_0%5D=utils&ver=6.8",
    Expected::Model
)]
#[case::other_admin_script(
    "GET",
    "/wp-admin/load-other.php?c=0&load%5Bchunk_0%5D=utils&ver=6.8",
    Expected::Model
)]
#[case::flag_other_than_zero_or_one(
    "GET",
    "/wp-admin/load-scripts.php?c=2&load%5Bchunk_0%5D=utils&ver=6.8",
    Expected::Model
)]
#[case::no_version(
    "GET",
    "/wp-admin/load-scripts.php?c=0&load%5Bchunk_0%5D=utils",
    Expected::Model
)]
#[case::empty_version(
    "GET",
    "/wp-admin/load-scripts.php?c=0&load%5Bchunk_0%5D=utils&ver=",
    Expected::Model
)]
#[case::version_of_forty_characters(
    "GET",
    "/wp-admin/load-scripts.php?c=0&load%5Bchunk_0%5D=utils&ver=0123456789abcdefghijklmnopqrstuvwxyzABCD",
    Expected::Skip("wp-admin-assets")
)]
#[case::version_of_forty_one_characters(
    "GET",
    "/wp-admin/load-scripts.php?c=0&load%5Bchunk_0%5D=utils&ver=0123456789abcdefghijklmnopqrstuvwxyzABCDE",
    Expected::Model
)]
#[case::last_chunk_is_nine(
    "GET",
    "/wp-admin/load-scripts.php?c=0&load%5Bchunk_9%5D=utils&ver=6.8",
    Expected::Skip("wp-admin-assets")
)]
#[case::two_digit_chunk_is_not_allowed(
    "GET",
    "/wp-admin/load-scripts.php?c=0&load%5Bchunk_10%5D=utils&ver=6.8",
    Expected::Model
)]
#[case::path_with_a_suffix(
    "GET",
    "/wp-admin/load-scripts.php/x?c=0&load%5Bchunk_0%5D=utils&ver=6.8",
    Expected::Model
)]
#[case::path_with_an_extra_letter(
    "GET",
    "/wp-admin/load-scripts.phpx?c=0&load%5Bchunk_0%5D=utils&ver=6.8",
    Expected::Model
)]
// wp-robots: robots.txt with no query
#[case::robots("GET", "/robots.txt", Expected::Skip("wp-robots"))]
#[case::robots_head("HEAD", "/robots.txt", Expected::Skip("wp-robots"))]
#[case::robots_with_query("GET", "/robots.txt?x=1", Expected::Model)]
#[case::robots_post("POST", "/robots.txt", Expected::Model)]
#[case::robots_trailing_slash("GET", "/robots.txt/", Expected::Model)]
// Reading 2 of `/robots.txt%3Bx` is `/robots.txt`, cut at the `;`. A rule that accepted any
// reading would skip this request; `wp-robots` needs every reading to match.
#[case::robots_with_an_encoded_semicolon("GET", "/robots.txt%3Bx", Expected::Model)]
fn each_rule_skips_its_requests_and_only_those(
    #[case] method: &str,
    #[case] target: &str,
    #[case] expected: Expected,
) -> TestResult {
    let config = config_with_rules(&shipped_rules()?)?;
    assert_decision(&config, "enforce.test", method, target, expected)
}

// ---------------------------------------------------------------------------
// Where the rules apply
// ---------------------------------------------------------------------------

#[test]
fn the_rules_apply_to_every_site_that_includes_the_file() -> TestResult {
    let config = config_with_rules(&shipped_rules()?)?;
    assert_decision(
        &config,
        "shadow.test",
        "GET",
        "/robots.txt",
        Expected::Skip("wp-robots"),
    )?;
    assert_decision(
        &config,
        "shadow.test",
        "GET",
        "/wp-login.php",
        Expected::Skip("wp-login-page"),
    )
}

/// The shipped rules with `from` replaced by `to`. `from` must occur in the file.
fn shipped_with_edit(from: &str, to: &str) -> Result<String, BoxError> {
    let shipped = shipped_rules()?;
    assert!(
        shipped.contains(from),
        "the shipped file no longer contains {from:?}"
    );
    Ok(shipped.replacen(from, to, 1))
}

/// A configuration whose `wp-robots` rule has a `site enforce.test;` line.
fn robots_limited_to_the_enforce_site() -> Result<Config, BoxError> {
    config_with_rules(&shipped_with_edit(
        "rule wp-robots {\n",
        "rule wp-robots {\n    site enforce.test;\n",
    )?)
}

#[test]
fn a_site_line_makes_its_rule_apply_to_the_named_site() -> TestResult {
    let config = robots_limited_to_the_enforce_site()?;
    assert_decision(
        &config,
        "enforce.test",
        "GET",
        "/robots.txt",
        Expected::Skip("wp-robots"),
    )
}

#[test]
fn a_site_line_keeps_its_rule_from_applying_to_another_site() -> TestResult {
    let config = robots_limited_to_the_enforce_site()?;
    assert_decision(
        &config,
        "shadow.test",
        "GET",
        "/robots.txt",
        Expected::Model,
    )
}

#[test]
fn a_site_line_leaves_the_other_rules_on_every_site() -> TestResult {
    let config = robots_limited_to_the_enforce_site()?;
    assert_decision(
        &config,
        "shadow.test",
        "GET",
        "/wp-login.php",
        Expected::Skip("wp-login-page"),
    )
}

#[test]
fn a_query_line_narrows_the_login_skip_to_the_queries_it_names() -> TestResult {
    // The login rule with a query condition: only a query that matches `^$` is still skipped.
    let config = config_with_rules(&shipped_with_edit(
        "    path = /wp-login.php;\n",
        "    path = /wp-login.php;\n    query ~ \"^$\";\n",
    )?)?;
    assert_decision(
        &config,
        "enforce.test",
        "GET",
        "/wp-login.php",
        Expected::Skip("wp-login-page"),
    )?;
    assert_decision(
        &config,
        "enforce.test",
        "GET",
        "/wp-login.php?foo=bar",
        Expected::Model,
    )
}

#[test]
fn a_skip_rule_does_not_look_at_the_headers_or_the_body() -> TestResult {
    let config = config_with_rules(&shipped_rules()?)?;
    let raw = b"GET /robots.txt HTTP/1.1\r\nHost: enforce.test\r\nCookie: session=abc\r\nX-Note: anything\r\nContent-Length: 4\r\n\r\nx=1y";
    let check = check_request_with(&config, raw, CLIENT)?;
    assert_eq!(check.outcome, Outcome::Forwarded);
    assert_eq!(check.reason, Some("skip_rule"));
    assert_eq!(check.rule_id.as_deref(), Some("wp-robots"));
    Ok(())
}

#[test]
fn a_built_in_block_rule_still_reads_the_headers_of_a_skipped_request() -> TestResult {
    let config = config_with_rules(&shipped_rules()?)?;
    let raw = b"GET /robots.txt HTTP/1.1\r\nHost: enforce.test\r\nUser-Agent: sqlmap/1.8\r\n\r\n";
    let check = check_request_with(&config, raw, CLIENT)?;
    assert_eq!(check.outcome, Outcome::Blocked(403));
    assert_eq!(check.reason, Some("rule"));
    assert_eq!(check.rule_id.as_deref(), Some("vh-scanner-001"));
    Ok(())
}

#[test]
fn a_block_rule_of_the_site_wins_over_a_wordpress_skip_whatever_its_position() -> TestResult {
    // The site's own block rule comes after the skip rule in the file.
    let rules = format!(
        "{}\nrule local-login-block {{\n    description \"login page closed to this site\";\n    action block;\n    path = /wp-login.php;\n}}\n",
        shipped_rules()?
    );
    let config = config_with_rules(&rules)?;
    assert_decision(
        &config,
        "enforce.test",
        "GET",
        "/wp-login.php",
        Expected::Block("local-login-block"),
    )
}

#[test]
fn the_wordpress_file_defines_the_four_rules_in_order() -> TestResult {
    let shipped = shipped_rules()?;
    let ids: Vec<&str> = shipped
        .lines()
        .filter_map(|line| line.strip_prefix("rule ")?.strip_suffix(" {"))
        .collect();
    assert_eq!(
        ids,
        [
            "wp-public-pages",
            "wp-login-page",
            "wp-admin-assets",
            "wp-robots"
        ]
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The running proxy
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_skipped_request_is_forwarded_without_a_decision_backend_call() -> TestResult {
    let stub = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let dir = fresh_dir()?;
    let conf = write_router(&dir, &shipped_rules()?, &upstream.url(), &stub.decide_url())?;
    let proxy = start_proxy_config(Config::load(&conf)?).await?;

    let before = stub.calls();
    let reply = send(
        &proxy.base(),
        Method::GET,
        "/robots.txt",
        "enforce.test",
        &[],
        Bytes::new(),
    )
    .await?;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert_eq!(stub.calls(), before, "the skip rule called the backend");

    // A request that no rule matches is still decided by the backend.
    let _ = send(
        &proxy.base(),
        Method::GET,
        "/?p=1&utm_source=mail",
        "enforce.test",
        &[],
        Bytes::new(),
    )
    .await?;
    assert_eq!(
        stub.calls(),
        before + 1,
        "the unmatched request skipped the backend"
    );

    proxy.stop().await?;
    Ok(())
}

#[tokio::test]
async fn a_skipped_request_with_a_cookie_and_a_body_does_not_call_the_backend() -> TestResult {
    let stub = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let dir = fresh_dir()?;
    let conf = write_router(&dir, &shipped_rules()?, &upstream.url(), &stub.decide_url())?;
    let proxy = start_proxy_config(Config::load(&conf)?).await?;

    let before = stub.calls();
    let reply = send(
        &proxy.base(),
        Method::GET,
        "/robots.txt",
        "enforce.test",
        &[("cookie", "session=abc")],
        Bytes::from_static(b"x=1y"),
    )
    .await?;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert_eq!(
        stub.calls(),
        before,
        "the skipped request reached the backend"
    );

    proxy.stop().await?;
    Ok(())
}

#[tokio::test]
async fn a_block_rule_refuses_a_request_that_a_skip_rule_also_matches_without_calling_the_backend()
-> TestResult {
    let stub = StubDecider::start().await?;
    let upstream = Upstream::start().await?;
    let dir = fresh_dir()?;
    let conf = write_router(&dir, &shipped_rules()?, &upstream.url(), &stub.decide_url())?;
    let proxy = start_proxy_config(Config::load(&conf)?).await?;

    let before = stub.calls();
    let reply = send(
        &proxy.base(),
        Method::GET,
        "/wp-login.php?redirect_to=javascript:alert(1)",
        "enforce.test",
        &[],
        Bytes::new(),
    )
    .await?;
    assert_eq!(reply.status, StatusCode::FORBIDDEN, "{}", reply.text());
    assert_eq!(
        stub.calls(),
        before,
        "the block rule let the request reach the backend"
    );

    proxy.stop().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// The file in an example configuration, through the command line
// ---------------------------------------------------------------------------

#[test]
fn the_example_configuration_with_the_wordpress_file_passes_the_test() -> TestResult {
    let dir = fresh_dir()?;
    std::fs::write(dir.join("rules.d/wordpress.conf"), shipped_rules()?)?;
    let example = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/vigilant-heron.conf"),
    )?;
    let included = example.replacen(
        "# include rules.d/*.conf;",
        "include rules.d/wordpress.conf;",
        1,
    );
    assert_ne!(
        included, example,
        "the example configuration has no commented include line to uncomment"
    );
    let conf = dir.join("vigilant-heron.conf");
    std::fs::write(&conf, included)?;

    let run = |args: &[&str]| -> std::io::Result<Output> {
        Command::new(BIN)
            .args(args)
            .arg(&conf)
            .env("TYPESAFE_API_KEY", "test-token")
            .env_remove("VIGILANT_HERON_CONFIG")
            .output()
    };

    let test = run(&["-t", "-c"])?;
    assert_eq!(test.status.code(), Some(0), "{}", stdout_and_stderr(&test));

    let dump = run(&["-T", "-c"])?;
    assert_eq!(dump.status.code(), Some(0), "{}", stdout_and_stderr(&dump));
    let printed = String::from_utf8_lossy(&dump.stdout);
    assert!(
        printed.contains("rule wp-robots {"),
        "the dump does not show the included WordPress rules: {}",
        stdout_and_stderr(&dump)
    );
    Ok(())
}
