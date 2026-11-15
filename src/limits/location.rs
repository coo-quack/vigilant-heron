//! The `location` blocks of a site and the choice of one for a request path.

use std::collections::HashSet;
use std::fmt;

use super::config::{LIMIT_NAMES, LimitOverrides, LimitSet, LimitZone};
use crate::block::{BLOCK_NAMES, BlockOverrides, BlockResponse};
use crate::conf::Directive;
use crate::config::{block, invalid, once, one_arg, parse_bool};
use crate::error::ConfigError;
use crate::proxy::HeaderOp;

/// How a location's path is matched, as nginx's `location` modifiers.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Matcher {
    /// `location = /path`: the whole path is equal.
    Exact(String),
    /// `location /path`: the path starts with this text.
    Prefix(String),
    /// `location ^~ /path`: a prefix that stops the search for regexes.
    PrefixPriority(String),
    /// `location ~ regex` and `location ~* regex`.
    Regex(Pattern),
}

impl Matcher {
    /// The path that nginx keeps unique among a site's plain locations: exact
    /// paths among themselves, and prefix paths with or without `^~` together.
    /// Regexes may repeat, so they have none.
    pub(crate) fn unique_path(&self) -> Option<(bool, &str)> {
        match self {
            Self::Exact(path) => Some((true, path)),
            Self::Prefix(path) | Self::PrefixPriority(path) => Some((false, path)),
            Self::Regex(_) => None,
        }
    }
}

/// A compiled regex location.
#[derive(Debug, Clone)]
pub(crate) struct Pattern {
    source: String,
    caseless: bool,
    regex: regex::Regex,
}

impl PartialEq for Pattern {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source && self.caseless == other.caseless
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.source)
    }
}

/// A location block whose limits are not yet resolved against its site.
#[derive(Debug)]
pub(crate) struct PendingLocation<'a> {
    /// The `location` directive, for error messages.
    pub(crate) directive: &'a Directive,
    /// How the location matches.
    pub(crate) matcher: Matcher,
    /// The limit directives written in the block.
    pub(crate) overrides: LimitOverrides,
    /// The block response directives written in the block.
    pub(crate) block: BlockOverrides,
    /// The `proxy_set_header` operations of the block, which replace the site's when present.
    pub(crate) headers: Option<Vec<HeaderOp>>,
    /// The `proxy_websocket` setting of the block, when it has one.
    pub(crate) websocket: Option<bool>,
}

/// Parses `location [=|~|~*|^~] <path> { ... }`, with only limit directives inside.
///
/// Plain paths are lowercased, as `deny_path` is, and must start with `/`. Regex
/// locations match the decoded path; `~*` ignores case and `~` does not.
///
/// # Errors
///
/// Returns the directive's line for a bad modifier, path or regex, for a limit
/// directive that is invalid, and for any other directive inside the block.
pub(crate) fn parse_location<'a>(
    directive: &'a Directive,
    zones: &[LimitZone],
) -> Result<PendingLocation<'a>, ConfigError> {
    let (modifier, path) = match directive.args.as_slice() {
        [path] => (None, path.as_str()),
        [modifier, path] => (Some(modifier.as_str()), path.as_str()),
        _ => {
            return Err(invalid(
                directive,
                "\"location\" takes an optional modifier and one path",
            ));
        }
    };
    let matcher = match modifier {
        None => Matcher::Prefix(plain_path(directive, path)?),
        Some("=") => Matcher::Exact(plain_path(directive, path)?),
        Some("^~") => Matcher::PrefixPriority(plain_path(directive, path)?),
        Some(sign @ ("~" | "~*")) => {
            let caseless = sign == "~*";
            let source = path.to_owned();
            let compiled = if caseless {
                format!("(?i){path}")
            } else {
                path.to_owned()
            };
            let regex = regex::Regex::new(&compiled).map_err(|error| {
                invalid(
                    directive,
                    format!("\"location\" regex is not valid: {error}"),
                )
            })?;
            Matcher::Regex(Pattern {
                source,
                caseless,
                regex,
            })
        }
        Some(other) => {
            return Err(invalid(
                directive,
                format!("\"location\" modifier must be =, ~, ~* or ^~, got {other}"),
            ));
        }
    };
    let mut overrides = LimitOverrides::default();
    let mut block_overrides = BlockOverrides::default();
    let mut headers: Option<Vec<HeaderOp>> = None;
    let mut websocket: Option<bool> = None;
    let mut seen = HashSet::new();
    for child in block(directive)? {
        let name = child.name.as_str();
        if BLOCK_NAMES.contains(&name) {
            block_overrides.apply(child, &mut seen)?;
        } else if name == "proxy_websocket" {
            once(&mut seen, child)?;
            websocket = Some(parse_bool(child, one_arg(child)?)?);
        } else if name == "proxy_set_header" {
            headers
                .get_or_insert_with(Vec::new)
                .push(HeaderOp::parse(child)?);
        } else if LIMIT_NAMES.contains(&name) {
            overrides.apply(child, zones, &mut seen)?;
        } else {
            return Err(invalid(
                child,
                format!("unknown directive \"{}\" in location", child.name),
            ));
        }
    }
    Ok(PendingLocation {
        directive,
        matcher,
        overrides,
        block: block_overrides,
        headers,
        websocket,
    })
}

fn plain_path(directive: &Directive, path: &str) -> Result<String, ConfigError> {
    if !path.starts_with('/') {
        return Err(invalid(
            directive,
            format!("\"location\" path must start with /, got {path}"),
        ));
    }
    Ok(path.to_lowercase())
}

/// One location of a site, with its limits resolved.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct LocationConfig {
    /// How the location matches.
    pub(crate) matcher: Matcher,
    /// The limits that apply to requests this location selects.
    pub(crate) limits: LimitSet,
    /// The block response for requests this location selects.
    pub(crate) block: BlockResponse,
    /// The `proxy_set_header` operations for requests this location selects.
    pub(crate) proxy_headers: Vec<HeaderOp>,
    /// Whether this location tunnels Upgrade requests.
    pub(crate) websocket: bool,
}

/// The distinct locations that the path views select, in the order they are found.
///
/// A view is one reading of the path, see [`crate::prefilter::path_views`]. Limits
/// are applied to every location found, so the reading the upstream uses cannot pick
/// a location with looser limits.
pub(crate) fn select_locations<'a>(
    locations: &'a [LocationConfig],
    views: &[String],
) -> Vec<&'a LocationConfig> {
    let mut selected: Vec<&LocationConfig> = Vec::new();
    for view in views {
        if let Some(location) = select_location(locations, view)
            && !selected.iter().any(|known| std::ptr::eq(*known, location))
        {
            selected.push(location);
        }
    }
    selected
}

/// Chooses the location for a request path, with nginx's precedence.
///
/// `decoded` is the decoded path with case kept. An exact match wins at once.
/// Otherwise the longest prefix is found. A `^~` prefix wins over the regexes.
/// Then the regexes are tried in configuration order, and the first that matches
/// wins. Without a regex match the longest prefix is used.
pub(crate) fn select_location<'a>(
    locations: &'a [LocationConfig],
    decoded: &str,
) -> Option<&'a LocationConfig> {
    let lower = decoded.to_lowercase();
    let mut longest: Option<(&LocationConfig, usize)> = None;
    for location in locations {
        match &location.matcher {
            Matcher::Exact(path) if *path == lower => return Some(location),
            Matcher::Prefix(path) | Matcher::PrefixPriority(path)
                if lower.starts_with(path.as_str()) =>
            {
                let better = longest.is_none_or(|(_, length)| path.len() > length);
                if better {
                    longest = Some((location, path.len()));
                }
            }
            _ => {}
        }
    }
    if let Some((location, _)) = longest
        && matches!(location.matcher, Matcher::PrefixPriority(_))
    {
        return Some(location);
    }
    for location in locations {
        if let Matcher::Regex(pattern) = &location.matcher
            && pattern.regex.is_match(decoded)
        {
            return Some(location);
        }
    }
    longest.map(|(location, _)| location)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::error::ConfigError;
    use crate::limits::test_helpers::{ONE, TWO, message, parse};

    #[rstest]
    #[case(
        "location /a { deny_path /x; }",
        "unknown directive \"deny_path\" in location"
    )]
    #[case(
        "location /a { limit_req zone=one; limit_req_zone $client_ip zone=x:1m rate=1r/s; }",
        "in location"
    )]
    #[case("location = foo { limit_req_status 429; }", "must start with /")]
    #[case("location ?? /x { limit_req_status 429; }", "modifier must be")]
    #[case("location ~ (unclosed { limit_req_status 429; }", "regex is not valid")]
    #[case("location /a /b { limit_req_status 429; }", "modifier must be")]
    #[case(
        "location /a /b /c { limit_req_status 429; }",
        "takes an optional modifier and one path"
    )]
    #[case(
        "location /a { limit_req_status 429; limit_req_status 418; }",
        "duplicate directive"
    )]
    #[case(
        "location /a { limit_req zone=two; }",
        "was not defined by limit_req_zone"
    )]
    fn invalid_locations_name_the_problem(#[case] block: &str, #[case] expected: &str) {
        let text = message(parse(&format!("{ONE}\n{TWO}"), block));
        assert!(text.contains(expected), "{text}");
        assert!(text.contains("test.conf:"), "{text}");
    }

    #[test]
    fn a_repeated_location_with_the_same_modifier_and_path_is_rejected() {
        let text = message(parse(
            &format!("{ONE}\n{TWO}"),
            "location /a { } location /A { }",
        ));
        assert!(text.contains("duplicate \"location\""), "{text}");
    }

    #[rstest]
    #[case::prefix_then_priority("location /img/ { } location ^~ /img/ { }")]
    #[case::priority_then_prefix("location ^~ /img/ { } location /IMG/ { }")]
    #[case::exact_twice("location = /img/ { } location = /img/ { }")]
    fn a_plain_path_used_twice_is_rejected_as_in_nginx(#[case] block: &str) {
        let text = message(parse(&format!("{ONE}\n{TWO}"), block));
        assert!(text.contains("duplicate \"location\" \"/img/\""), "{text}");
    }

    #[test]
    fn an_exact_and_a_prefix_location_may_share_a_path_as_in_nginx() {
        assert!(
            parse(
                &format!("{ONE}\n{TWO}"),
                "location = /img/ { } location /img/ { }"
            )
            .is_ok()
        );
    }

    #[test]
    fn a_repeated_regex_location_is_accepted_as_in_nginx() {
        let text = message(parse(
            &format!("{ONE}\n{TWO}"),
            "location ~ /a { } location ~ /a { }",
        ));
        assert_eq!(text, "accepted");
    }

    #[rstest]
    #[case("/exact", "exact")]
    #[case("/wp-login.php", "regex-php")]
    #[case("/index.PHP", "regex-caseless")]
    #[case("/static/app.js", "priority")]
    #[case("/wp-admin/", "regex-wp")]
    #[case("/about", "root")]
    #[case("/Wp-Login", "prefix-wp")]
    #[case("/EXACT", "exact")]
    fn location_selection_follows_nginx_precedence(
        #[case] path: &str,
        #[case] expected: &str,
    ) -> Result<(), ConfigError> {
        let block = "location = /exact { limit_req_status 415; }\n\
            location / { limit_req_status 410; }\n\
            location /wp- { limit_req_status 411; }\n\
            location ^~ /static/ { limit_req_status 412; }\n\
            location ~ \\.php$ { limit_req_status 413; }\n\
            location ~* \\.PHP$ { limit_req_status 414; }\n\
            location ~ /wp- { limit_req_status 416; }";
        let config = parse(ONE, block)?;
        let site = config.sites.first().ok_or(ConfigError::Invalid {
            file: "test.conf".to_owned(),
            line: 1,
            message: "no site".to_owned(),
        })?;
        let code = match expected {
            "exact" => 415,
            "regex-php" => 413,
            "regex-caseless" => 414,
            "priority" => 412,
            "regex-wp" => 416,
            "root" => 410,
            _ => 411,
        };
        let chosen = select_location(&site.locations, path);
        assert_eq!(
            chosen.map(|l| l.limits.req_status.as_u16()),
            Some(code),
            "{path}"
        );
        Ok(())
    }

    #[test]
    fn a_request_with_no_matching_location_uses_the_site_limits() -> Result<(), ConfigError> {
        let config = parse(ONE, "location /login { limit_req_status 429; }")?;
        let site = config.sites.first().ok_or(ConfigError::Invalid {
            file: "test.conf".to_owned(),
            line: 1,
            message: "no site".to_owned(),
        })?;
        assert!(select_location(&site.locations, "/other").is_none());
        Ok(())
    }

    /// A regex pattern built the way `parse_location` builds one.
    fn regex_pattern(source: &str, caseless: bool) -> Result<Pattern, regex::Error> {
        let compiled = if caseless {
            format!("(?i){source}")
        } else {
            source.to_owned()
        };
        Ok(Pattern {
            source: source.to_owned(),
            caseless,
            regex: regex::Regex::new(&compiled)?,
        })
    }

    #[test]
    fn regex_patterns_compare_by_source_and_operator() -> Result<(), regex::Error> {
        let plain = regex_pattern("a+", false)?;
        assert_eq!(plain, regex_pattern("a+", false)?);
        assert_ne!(plain, regex_pattern("a+", true)?);
        assert_ne!(plain, regex_pattern("b+", false)?);
        Ok(())
    }

    #[test]
    fn a_regex_pattern_displays_its_source_as_written() -> Result<(), regex::Error> {
        let pattern = regex_pattern(r"\.php$", true)?;
        assert_eq!(pattern.to_string(), r"\.php$");
        Ok(())
    }
}
