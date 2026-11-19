//! Helpers that the tests of the prefilter modules share.

use std::net::{IpAddr, Ipv4Addr};

use http::{HeaderMap, Method};

use super::{Screening, path_views, screen};
use crate::config::SiteConfig;
use crate::rules::RuleInput;

/// Screens a request with no headers and no body prefix, given its raw path.
pub(crate) fn screen_path(
    site: &SiteConfig,
    method: &Method,
    raw_path: &str,
    has_query: bool,
    body_is_empty: bool,
) -> Screening {
    let headers = HeaderMap::new();
    let query = has_query.then_some("x=1");
    let client = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let input = RuleInput::new(method, raw_path, query, &headers, &[], client);
    screen(site, &input, &lower_views(raw_path), body_is_empty)
}

/// The lowercase views of a raw path, as the pipeline passes them to the checks.
pub(crate) fn lower_views(raw: &str) -> Vec<String> {
    path_views(raw)
        .iter()
        .map(|view| view.to_lowercase())
        .collect()
}

/// Screens a GET of `raw_path?query` with no body.
pub(crate) fn screen_query(site: &SiteConfig, raw_path: &str, query: &str) -> Screening {
    let headers = HeaderMap::new();
    let client = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let input = RuleInput::new(&Method::GET, raw_path, Some(query), &headers, &[], client);
    screen(site, &input, &lower_views(raw_path), true)
}
