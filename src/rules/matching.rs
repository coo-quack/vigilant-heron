//! Matching a request against rules: normalization of each input and the checks of each condition.
//!
//! Patterns are compiled by the `regex` crate, which matches in linear time and
//! never backtracks, so a pattern cannot make a request take longer in
//! proportion to a pathological input.

use std::borrow::Cow;
use std::cell::OnceCell;
use std::net::IpAddr;

use http::{HeaderMap, HeaderName, Method};
use regex::RegexBuilder;

use super::Rule;
use crate::prefilter::percent_decode_lossy;
use crate::realip::IpNet;

/// Longest regex source, in bytes.
pub(crate) const MAX_REGEX_BYTES: usize = 512;

/// Size limit of each compiled regex, in bytes.
const REGEX_SIZE_LIMIT: usize = 1024 * 1024;

/// A compiled regex and the operator it was written with.
#[derive(Debug, Clone)]
pub(crate) struct Pattern {
    /// The regex as written in the configuration.
    source: String,
    /// True for `~*`, false for `~`.
    case_insensitive: bool,
    /// The compiled regex.
    regex: regex::Regex,
}

impl Pattern {
    /// Compiles `source`, with `~*` when `case_insensitive` is set.
    ///
    /// # Errors
    ///
    /// Returns a message when the source is longer than [`MAX_REGEX_BYTES`],
    /// or when the regex does not compile within the size limit.
    pub(crate) fn new(source: &str, case_insensitive: bool) -> Result<Self, String> {
        if source.len() > MAX_REGEX_BYTES {
            return Err(format!("regex is longer than {MAX_REGEX_BYTES} bytes"));
        }
        let regex = RegexBuilder::new(source)
            .case_insensitive(case_insensitive)
            .size_limit(REGEX_SIZE_LIMIT)
            .dfa_size_limit(REGEX_SIZE_LIMIT)
            .build()
            .map_err(|error| format!("invalid regex: {error}"))?;
        Ok(Self {
            source: source.to_owned(),
            case_insensitive,
            regex,
        })
    }

    /// Returns true when the regex matches somewhere in `text`.
    fn is_match(&self, text: &str) -> bool {
        self.regex.is_match(text)
    }
}

impl PartialEq for Pattern {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source && self.case_insensitive == other.case_insensitive
    }
}

/// How a `path` directive matches the request path.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum PathMatch {
    /// The path starts with this text. Case-sensitive, as in nginx.
    Prefix(String),
    /// The path is exactly this text. Case-sensitive, as in nginx.
    Exact(String),
    /// The path matches the regex.
    Regex(Pattern),
}

impl PathMatch {
    /// Returns true when `path` matches.
    fn matches(&self, path: &str) -> bool {
        match self {
            Self::Prefix(prefix) => path.starts_with(prefix.as_str()),
            Self::Exact(exact) => path == exact,
            Self::Regex(pattern) => pattern.is_match(path),
        }
    }
}

/// Decodes percent escapes at most twice, so double encoding is undone too, and drops NUL bytes.
fn decode_twice(raw: &str) -> String {
    let once = percent_decode_lossy(raw);
    let twice = percent_decode_lossy(&once);
    twice.replace('\0', "")
}

/// Normalizes a query string or form body: `+` becomes a space, then [`decode_twice`].
#[must_use]
pub(crate) fn form_value(raw: &str) -> String {
    decode_twice(&raw.replace('+', " "))
}

/// Normalizes a header value: [`decode_twice`] only, because `+` is literal in headers.
#[must_use]
pub(crate) fn header_value(raw: &str) -> String {
    decode_twice(raw)
}

/// How the path views of a request are combined by a path condition.
///
/// A block rule matches when its path condition holds for any view, so no reading of
/// the path escapes it. A skip rule matches only when the condition holds for every
/// view, so a skip never relies on one reading alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathScope {
    /// The condition holds for at least one view.
    Any,
    /// The condition holds for every view.
    All,
}

/// The inputs a rule can look at, normalized on first use.
///
/// The path is read in each way of [`crate::prefilter::path_views`], and the views
/// keep their case, so `path ~` is case-sensitive and `path ~*` is not. The body is
/// the inspected prefix only: a match cannot see bytes past `inspect_body`.
pub(crate) struct RuleInput<'a> {
    /// The request method.
    pub(crate) method: &'a Method,
    /// The path as received, which the static skip inspects.
    pub(crate) raw_path: &'a str,
    /// The path in each reading of [`crate::prefilter::path_views`]. Case is kept.
    /// Borrowed when the caller has already computed the views of this request.
    pub(crate) paths: Cow<'a, [String]>,
    /// The raw query string, if the request has one.
    query: Option<&'a str>,
    /// The request headers.
    headers: &'a HeaderMap,
    /// The inspected prefix of the body.
    body: &'a [u8],
    /// The client address chosen by the realip settings.
    client: IpAddr,
    /// The normalized query, computed when a rule first needs it.
    normalized_query: OnceCell<String>,
    /// The normalized body prefix, computed when a rule first needs it.
    normalized_body: OnceCell<String>,
    /// Every header value, normalized, with its name. Computed once per request.
    normalized_headers: OnceCell<Vec<(HeaderName, String)>>,
}

impl<'a> RuleInput<'a> {
    /// Collects the inputs of one request. `raw_path` is the path as received.
    /// The server and `test-request` use [`Self::with_views`]; this computes the views itself.
    #[cfg(test)]
    pub(crate) fn new(
        method: &'a Method,
        raw_path: &'a str,
        query: Option<&'a str>,
        headers: &'a HeaderMap,
        body: &'a [u8],
        client: IpAddr,
    ) -> Self {
        let paths = Cow::Owned(crate::prefilter::path_views(raw_path));
        Self::build(method, raw_path, paths, query, headers, body, client)
    }

    /// Collects the inputs of one request whose path views `views` were computed once
    /// from `raw_path` with [`crate::prefilter::path_views`].
    pub(crate) fn with_views(
        method: &'a Method,
        raw_path: &'a str,
        views: &'a [String],
        query: Option<&'a str>,
        headers: &'a HeaderMap,
        body: &'a [u8],
        client: IpAddr,
    ) -> Self {
        Self::build(
            method,
            raw_path,
            Cow::Borrowed(views),
            query,
            headers,
            body,
            client,
        )
    }

    fn build(
        method: &'a Method,
        raw_path: &'a str,
        paths: Cow<'a, [String]>,
        query: Option<&'a str>,
        headers: &'a HeaderMap,
        body: &'a [u8],
        client: IpAddr,
    ) -> Self {
        Self {
            method,
            raw_path,
            paths,
            query,
            headers,
            body,
            client,
            normalized_query: OnceCell::new(),
            normalized_body: OnceCell::new(),
            normalized_headers: OnceCell::new(),
        }
    }

    /// Whether the request has a query string, even an empty one.
    pub(crate) fn has_query(&self) -> bool {
        self.query.is_some()
    }

    fn query_text(&self) -> &str {
        self.normalized_query
            .get_or_init(|| form_value(self.query.unwrap_or("")))
    }

    fn body_text(&self) -> &str {
        self.normalized_body
            .get_or_init(|| form_value(&String::from_utf8_lossy(self.body)))
    }

    /// Every header value, normalized, with its name. Computed on first use.
    fn headers_text(&self) -> &[(HeaderName, String)] {
        self.normalized_headers.get_or_init(|| {
            self.headers
                .iter()
                .map(|(name, value)| {
                    (
                        name.clone(),
                        header_value(&String::from_utf8_lossy(value.as_bytes())),
                    )
                })
                .collect()
        })
    }

    /// The normalized values of the header `name`.
    fn header_texts<'s>(&'s self, name: &'s HeaderName) -> impl Iterator<Item = &'s str> + 's {
        self.headers_text()
            .iter()
            .filter(move |(header, _)| header == name)
            .map(|(_, text)| text.as_str())
    }

    /// Whether `path` holds for the path views, combined with `scope`.
    fn path_holds(&self, scope: PathScope, path: impl Fn(&str) -> bool) -> bool {
        match scope {
            PathScope::Any => self.paths.iter().any(|view| path(view)),
            PathScope::All => self.paths.iter().all(|view| path(view)),
        }
    }

    /// Whether `pattern` matches the path, the query, any header value or the body prefix.
    fn any_matches(&self, pattern: &Pattern, scope: PathScope) -> bool {
        self.path_holds(scope, |view| pattern.is_match(view))
            || pattern.is_match(self.query_text())
            || self
                .headers_text()
                .iter()
                .any(|(_, text)| pattern.is_match(text))
            || pattern.is_match(self.body_text())
    }
}

impl Rule {
    /// The path readings that satisfy the rule's `path` condition, for `test-request`.
    /// Empty when the rule has no path condition.
    pub(crate) fn path_readings(&self, input: &RuleInput<'_>) -> Vec<String> {
        self.path.as_ref().map_or_else(Vec::new, |path| {
            input
                .paths
                .iter()
                .filter(|view| path.matches(view.as_str()))
                .cloned()
                .collect()
        })
    }

    /// Returns true when every condition of the rule matches the request.
    ///
    /// The path conditions are combined with `scope`. A condition that names an
    /// input the request does not have (for example a header that is absent) does
    /// not match.
    pub(crate) fn matches(&self, input: &RuleInput<'_>, scope: PathScope) -> bool {
        self.methods
            .as_ref()
            .is_none_or(|methods| methods.contains(input.method))
            && self
                .clients
                .as_ref()
                .is_none_or(|nets| nets.iter().any(|net: &IpNet| net.contains(input.client)))
            && self
                .path
                .as_ref()
                .is_none_or(|path| input.path_holds(scope, |view| path.matches(view)))
            && self
                .query
                .iter()
                .all(|pattern| pattern.is_match(input.query_text()))
            && self
                .body
                .iter()
                .all(|pattern| pattern.is_match(input.body_text()))
            && self
                .headers
                .iter()
                .all(|(name, pattern)| input.header_texts(name).any(|text| pattern.is_match(text)))
            && self
                .any
                .iter()
                .all(|pattern| input.any_matches(pattern, scope))
    }
}

/// Returns the first block rule in `rules` that matches the request, reading the path with [`PathScope::Any`].
pub(crate) fn first_match<'r>(
    rules: &'r [std::sync::Arc<Rule>],
    input: &RuleInput<'_>,
) -> Option<&'r std::sync::Arc<Rule>> {
    rules
        .iter()
        .find(|rule| rule.matches(input, PathScope::Any))
}

/// Returns the first skip rule in `rules` that matches the request, reading the path with [`PathScope::All`].
pub(crate) fn first_skip_match<'r>(
    rules: &'r [std::sync::Arc<Rule>],
    input: &RuleInput<'_>,
) -> Option<&'r std::sync::Arc<Rule>> {
    rules
        .iter()
        .find(|rule| rule.matches(input, PathScope::All))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plus_is_a_space_in_forms_but_literal_in_headers() {
        assert_eq!(form_value("a+b"), "a b");
        assert_eq!(header_value("a+b"), "a+b");
    }

    #[test]
    fn form_values_decode_a_double_encoded_escape() {
        // %2527 is %27 after one decode, and ' after two.
        assert_eq!(form_value("x%2527"), "x'");
        assert_eq!(header_value("x%2527"), "x'");
    }

    #[test]
    fn a_third_level_escape_is_not_decoded() {
        // %252527 needs three decodes to reach the quote.
        assert_eq!(form_value("%252527"), "%27");
    }

    #[test]
    fn nul_bytes_are_removed_whether_literal_or_encoded() {
        assert_eq!(form_value("a\0b%00c"), "abc");
        assert_eq!(header_value("%00x"), "x");
    }

    #[test]
    fn a_plain_percent_sign_survives() {
        assert_eq!(form_value("100%"), "100%");
        assert_eq!(form_value("%zz"), "%zz");
    }

    #[test]
    fn path_match_prefix_and_exact_are_case_sensitive() {
        let prefix = PathMatch::Prefix("/Admin".to_owned());
        assert!(prefix.matches("/Admin/x"));
        assert!(!prefix.matches("/admin/x"));
        let exact = PathMatch::Exact("/a".to_owned());
        assert!(exact.matches("/a"));
        assert!(!exact.matches("/a/"));
    }
}
