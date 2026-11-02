//! Builds the request of `test-request --url`, from a URL and the options given with it.
//!
//! The request is written as a raw HTTP/1.1 file would hold it, so the report is the same
//! as for the same request in a file. The URL is split by hand, and the host is checked
//! with `http::uri::Authority`, the parser the router's own requests go through.

use http::Uri;
use http::uri::Authority;

/// The refusal of a path or query that a request target may not hold.
const TARGET_MESSAGE: &str = "--url path or query has a character that a request target may not hold; percent-encode it, for example é as %C3%A9 or < as %3C";

/// The request that `--url` describes, checked by the same code as a request file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UrlRequest {
    /// The method, in uppercase.
    pub(crate) method: String,
    /// The Host header: the URL's host, or the `--host` name.
    pub(crate) host: String,
    /// The request target: the path and the query.
    pub(crate) target: String,
    /// The `Name: value` lines given with `--header`, in the order given.
    pub(crate) headers: Vec<String>,
}

impl UrlRequest {
    /// Reads `url` with the `--host`, `--method` and `--header` options given with it.
    ///
    /// A `http://` or `https://` URL sets the Host from its authority, without a default
    /// port (80 for http, 443 for https). A URL that starts with `/` is a path, and it
    /// needs `--host`. The method defaults to GET.
    ///
    /// # Errors
    ///
    /// Returns the reason when the URL has a fragment, spaces, user information or an
    /// unknown scheme, when `--host` is missing for a path or given with an absolute
    /// URL, or when a method, a host or a header is not valid.
    pub(crate) fn new(
        url: &str,
        host: Option<&str>,
        method: Option<&str>,
        headers: &[String],
    ) -> Result<Self, String> {
        if url.is_empty() {
            return Err("--url needs a URL".to_owned());
        }
        if url.contains('#') {
            return Err(
                "--url must not contain a fragment (#): a fragment is never sent to the server"
                    .to_owned(),
            );
        }
        if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err("--url must not contain spaces or control characters".to_owned());
        }
        let (host_from_url, target) = if url.starts_with('/') && !url.starts_with("//") {
            (None, url.to_owned())
        } else {
            match url.split_once("://") {
                Some((scheme, rest))
                    if scheme.eq_ignore_ascii_case("http")
                        || scheme.eq_ignore_ascii_case("https") =>
                {
                    let (host, target) = authority_and_target(&scheme.to_ascii_lowercase(), rest)?;
                    (Some(host), target)
                }
                Some((scheme, _)) if scheme.chars().all(|c| c.is_ascii_alphanumeric()) => {
                    return Err(format!(
                        "--url must use http:// or https://, not \"{scheme}://\""
                    ));
                }
                _ => {
                    return Err(
                        "--url must start with http:// or https://, or with / (then give --host)"
                            .to_owned(),
                    );
                }
            }
        };
        check_target(&target)?;
        let host = match (host_from_url, host) {
            (Some(host), None) => host,
            (Some(_), Some(_)) => {
                return Err("--host is only used with a URL that starts with /".to_owned());
            }
            (None, Some(name)) => valid_host(name)?,
            (None, None) => return Err("a URL that starts with / needs --host <name>".to_owned()),
        };
        let method = match method {
            Some(text) if !text.is_empty() && text.chars().all(is_token_char) => {
                text.to_ascii_uppercase()
            }
            Some(text) => return Err(format!("--method must be a method name, not \"{text}\"")),
            None => "GET".to_owned(),
        };
        let headers = headers
            .iter()
            .map(String::as_str)
            .map(header_line)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            method,
            host,
            target,
            headers,
        })
    }

    /// The request as raw HTTP/1.1 text, with CRLF line endings, as a request file holds it.
    pub(crate) fn to_raw(&self) -> Vec<u8> {
        let mut raw = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\n",
            self.method, self.target, self.host
        );
        for header in &self.headers {
            raw.push_str(header);
            raw.push_str("\r\n");
        }
        raw.push_str("\r\n");
        raw.into_bytes()
    }
}

/// Splits the part of an absolute URL after `scheme://` into the Host header and the
/// request target. The target is the path and query, and `/` when the path is empty.
/// `scheme` is `http` or `https`, in lowercase.
fn authority_and_target(scheme: &str, rest: &str) -> Result<(String, String), String> {
    let split = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority_text, path) = rest.split_at_checked(split).unwrap_or((rest, ""));
    if authority_text.contains('@') {
        return Err("--url must not contain user information (the part before @)".to_owned());
    }
    if authority_text.is_empty() {
        return Err("--url has no host name".to_owned());
    }
    let invalid_host = || format!("invalid host \"{authority_text}\" in --url");
    // A backslash or a percent sign is refused here, so the message names the reason.
    if authority_text.contains(['\\', '%']) {
        return Err(invalid_host());
    }
    let authority = authority_text
        .parse::<Authority>()
        .map_err(|_| invalid_host())?;
    let name = authority.host();
    if name.is_empty() {
        return Err("--url has no host name".to_owned());
    }
    let port = match authority_text.strip_prefix(name).ok_or_else(invalid_host)? {
        "" => None,
        after_host => match after_host.strip_prefix(':') {
            Some(text) => Some(parse_port(text)?),
            None => return Err(invalid_host()),
        },
    };
    let default_port = if scheme == "https" { 443 } else { 80 };
    let host = match port {
        Some(number) if number != default_port => format!("{name}:{number}"),
        _ => name.to_owned(),
    };
    let target = if path.is_empty() {
        "/".to_owned()
    } else if path.starts_with('?') {
        format!("/{path}")
    } else {
        path.to_owned()
    };
    Ok((host, target))
}

/// Reads the digits of a port. Only ASCII digits are accepted, so a sign or a space is refused.
fn parse_port(text: &str) -> Result<u16, String> {
    let digits = !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
    match text.parse::<u16>() {
        Ok(port) if digits => Ok(port),
        _ => Err(format!("invalid port \"{text}\" in --url")),
    }
}

/// Refuses a request target that the request parser would reject, or that is not ASCII.
/// The message says how to write the character instead.
fn check_target(target: &str) -> Result<(), String> {
    if target.is_ascii() && target.parse::<Uri>().is_ok() {
        return Ok(());
    }
    Err(TARGET_MESSAGE.to_owned())
}

/// Reads the `--host` name, which must not be empty and must not hold spaces.
fn valid_host(name: &str) -> Result<String, String> {
    if name.is_empty() || name.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!("--host must be a host name, not \"{name}\""));
    }
    Ok(name.to_owned())
}

/// Reads one `--header` value, `Name: value`, into the line a request file would hold.
fn header_line(text: &str) -> Result<String, String> {
    if text.chars().any(char::is_control) {
        return Err("--header must not contain line breaks or control characters".to_owned());
    }
    let (name, value) = text
        .split_once(':')
        .ok_or_else(|| format!("--header needs \"Name: value\", not \"{text}\""))?;
    let name = name.trim();
    if name.is_empty() || !name.chars().all(is_token_char) {
        return Err(format!("--header has an invalid name in \"{text}\""));
    }
    if name.eq_ignore_ascii_case("host") {
        return Err("--header cannot set Host: give the URL, or --host".to_owned());
    }
    Ok(format!("{name}: {}", value.trim_matches([' ', '\t'])))
}

/// Whether `c` may appear in a method or a header name, as an RFC 9110 token character.
fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn request(url: &str) -> Result<UrlRequest, String> {
        UrlRequest::new(url, None, None, &[])
    }

    #[rstest]
    #[case::path_and_query("http://example.com/items?id=1", "example.com", "/items?id=1")]
    #[case::empty_path_is_a_slash("https://example.com", "example.com", "/")]
    #[case::query_without_a_path("http://example.com?x=1", "example.com", "/?x=1")]
    #[case::default_http_port_is_dropped("http://example.com:80/", "example.com", "/")]
    #[case::default_https_port_is_dropped("https://example.com:443/", "example.com", "/")]
    #[case::other_port_is_kept("http://example.com:8080/", "example.com:8080", "/")]
    #[case::http_port_on_https_is_kept("https://example.com:80/", "example.com:80", "/")]
    #[case::ipv6_literal_keeps_brackets("http://[::1]:8080/", "[::1]:8080", "/")]
    #[case::ipv6_literal_without_port("http://[::1]/", "[::1]", "/")]
    #[case::uppercase_scheme_keeps_the_host_as_written(
        "HTTP://Example.com:80/x",
        "Example.com",
        "/x"
    )]
    #[case::mixed_case_https_drops_its_default_port("Https://example.com:443/", "example.com", "/")]
    #[case::leading_zeros_in_the_port_are_digits(
        "http://example.com:08080/",
        "example.com:8080",
        "/"
    )]
    fn an_absolute_url_gives_the_host_and_target(
        #[case] url: &str,
        #[case] host: &str,
        #[case] target: &str,
    ) -> Result<(), String> {
        let parsed = request(url)?;
        assert_eq!(parsed.host, host);
        assert_eq!(parsed.target, target);
        Ok(())
    }

    #[test]
    fn a_path_takes_the_host_option() -> Result<(), String> {
        let parsed = UrlRequest::new("/p?q=1", Some("example.com"), None, &[])?;
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.target, "/p?q=1");
        Ok(())
    }

    #[rstest]
    #[case::path_without_host("/p", None, "a URL that starts with / needs --host <name>")]
    #[case::host_with_absolute_url(
        "http://example.com/",
        Some("other.test"),
        "--host is only used with a URL that starts with /"
    )]
    #[case::fragment(
        "http://example.com/#top",
        None,
        "--url must not contain a fragment (#): a fragment is never sent to the server"
    )]
    #[case::space(
        "http://example.com/a b",
        None,
        "--url must not contain spaces or control characters"
    )]
    #[case::tab(
        "http://example.com/\t",
        None,
        "--url must not contain spaces or control characters"
    )]
    #[case::user_information(
        "http://user@example.com/",
        None,
        "--url must not contain user information (the part before @)"
    )]
    #[case::unknown_scheme(
        "ftp://example.com/",
        None,
        "--url must use http:// or https://, not \"ftp://\""
    )]
    #[case::no_scheme(
        "example.com/path",
        None,
        "--url must start with http:// or https://, or with / (then give --host)"
    )]
    #[case::protocol_relative(
        "//example.com/",
        None,
        "--url must start with http:// or https://, or with / (then give --host)"
    )]
    #[case::empty("", None, "--url needs a URL")]
    #[case::no_host("http:///x", None, "--url has no host name")]
    #[case::port_not_a_number("http://example.com:x/", None, "invalid port \"x\" in --url")]
    #[case::port_too_large("http://example.com:70000/", None, "invalid port \"70000\" in --url")]
    #[case::two_colons("http://a:b:80/", None, "invalid host \"a:b:80\" in --url")]
    #[case::ipv6_without_closing_bracket("http://[::1/", None, "invalid host \"[::1\" in --url")]
    #[case::relative_path_with_a_url_in_its_query(
        "/go?to=http://example.com",
        None,
        "a URL that starts with / needs --host <name>"
    )]
    #[case::text_after_ipv6("http://[::1]x/", None, "invalid host \"[::1]x\" in --url")]
    #[case::backslash_in_host(
        "http://exa\\mple.com/",
        None,
        "invalid host \"exa\\mple.com\" in --url"
    )]
    #[case::percent_in_host(
        "http://example.com%2e/",
        None,
        "invalid host \"example.com%2e\" in --url"
    )]
    #[case::plus_in_port("http://example.com:+80/", None, "invalid port \"+80\" in --url")]
    #[case::empty_port("http://example.com:/", None, "invalid port \"\" in --url")]
    #[case::non_ascii_path("http://example.com/café", None, TARGET_MESSAGE)]
    #[case::non_ascii_relative_path("/café", Some("example.com"), TARGET_MESSAGE)]
    #[case::angle_bracket_in_query("http://example.com/?q=<x>", None, TARGET_MESSAGE)]
    #[case::backtick_in_path("http://example.com/a`b", None, TARGET_MESSAGE)]
    #[case::host_with_space(
        "/p",
        Some("exa mple.com"),
        "--host must be a host name, not \"exa mple.com\""
    )]
    #[case::empty_host("/p", Some(""), "--host must be a host name, not \"\"")]
    fn a_bad_url_or_option_is_refused_with_its_reason(
        #[case] url: &str,
        #[case] host: Option<&str>,
        #[case] message: &str,
    ) {
        assert_eq!(
            UrlRequest::new(url, host, None, &[]),
            Err(message.to_owned())
        );
    }

    #[rstest]
    #[case::default_is_get(None, "GET")]
    #[case::lowercase_is_uppercased(Some("post"), "POST")]
    #[case::custom_token(Some("M-SEARCH"), "M-SEARCH")]
    fn the_method_defaults_to_get_and_is_uppercased(
        #[case] method: Option<&str>,
        #[case] expected: &str,
    ) -> Result<(), String> {
        let parsed = UrlRequest::new("http://example.com/", None, method, &[])?;
        assert_eq!(parsed.method, expected);
        Ok(())
    }

    #[test]
    fn a_method_that_is_not_a_token_is_refused() {
        assert_eq!(
            UrlRequest::new("http://example.com/", None, Some("G T"), &[]),
            Err("--method must be a method name, not \"G T\"".to_owned())
        );
        assert_eq!(
            UrlRequest::new("http://example.com/", None, Some(""), &[]),
            Err("--method must be a method name, not \"\"".to_owned())
        );
    }

    #[rstest]
    #[case::spaced("X-Test: 1", "X-Test: 1")]
    #[case::no_space_after_colon("X-Test:2", "X-Test: 2")]
    #[case::extra_spaces("X-Test:   3  ", "X-Test: 3")]
    #[case::value_keeps_inner_colons("X-Time: 10:30", "X-Time: 10:30")]
    fn a_header_is_written_as_name_and_value(#[case] given: &str, #[case] line: &str) {
        assert_eq!(header_line(given), Ok(line.to_owned()));
    }

    #[rstest]
    #[case::no_colon("X-Test 1", "--header needs \"Name: value\", not \"X-Test 1\"")]
    #[case::empty_name(": 1", "--header has an invalid name in \": 1\"")]
    #[case::space_in_name("X Test: 1", "--header has an invalid name in \"X Test: 1\"")]
    #[case::host(
        "Host: example.org",
        "--header cannot set Host: give the URL, or --host"
    )]
    #[case::host_any_case(
        "hOsT: example.org",
        "--header cannot set Host: give the URL, or --host"
    )]
    #[case::line_break(
        "X-Test: 1\r\nX-Other: 2",
        "--header must not contain line breaks or control characters"
    )]
    fn a_bad_header_is_refused(#[case] given: &str, #[case] message: &str) {
        assert_eq!(header_line(given), Err(message.to_owned()));
    }

    #[test]
    fn the_headers_are_kept_in_the_order_given() -> Result<(), String> {
        let headers = vec!["X-A: 1".to_owned(), "X-B: 2".to_owned()];
        let parsed = UrlRequest::new("http://example.com/", None, None, &headers)?;
        assert_eq!(parsed.headers, ["X-A: 1", "X-B: 2"]);
        Ok(())
    }

    #[test]
    fn the_raw_request_is_the_request_a_file_would_hold() -> Result<(), String> {
        let headers = vec!["X-Test: 1".to_owned()];
        let parsed = UrlRequest::new("http://example.com:8080/p?q=1", None, Some("put"), &headers)?;
        assert_eq!(
            parsed.to_raw(),
            b"PUT /p?q=1 HTTP/1.1\r\nHost: example.com:8080\r\nX-Test: 1\r\n\r\n"
        );
        Ok(())
    }

    #[test]
    fn the_raw_request_of_a_path_uses_the_host_option() -> Result<(), String> {
        let parsed = UrlRequest::new("/", Some("example.com"), None, &[])?;
        assert_eq!(
            parsed.to_raw(),
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        );
        Ok(())
    }
}
