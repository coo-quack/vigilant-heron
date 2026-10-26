//! Block responses: `block_status` and `block_page`, at the top level, in a site and in a location.
//!
//! A request that a rule or the decision backend judges to be an attack gets
//! the block response of its site, or of its location when one is selected. A
//! `block_status` of 444 closes the connection without writing a response, as
//! nginx does. A `block_page` is an HTML file read at load time, at most 64 KiB,
//! and it is served with `Content-Type: text/html; charset=utf-8`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use bytes::Bytes;
use http::StatusCode;

use crate::conf::Directive;
use crate::config::{invalid, once, one_arg};
use crate::error::ConfigError;

/// Largest `block_page` file, in bytes.
pub(crate) const MAX_PAGE_BYTES: usize = 64 * 1024;

/// The directives that set a block response. Each may appear at any level.
pub(crate) const BLOCK_NAMES: [&str; 2] = ["block_status", "block_page"];

/// What a block response sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockStatus {
    /// Answer with this 4xx or 5xx status.
    Respond(StatusCode),
    /// Close the connection without a response (status 444 in the configuration).
    Close,
}

/// The response to a request that is blocked.
#[derive(Debug, Clone, PartialEq)]
pub struct BlockResponse {
    /// The status, or the decision to close without a response.
    pub status: BlockStatus,
    /// The body, served as HTML, when a `block_page` is set.
    pub page: Option<Bytes>,
}

impl Default for BlockResponse {
    /// The status is 403 and there is no page, as in nginx's `deny`.
    fn default() -> Self {
        Self {
            status: BlockStatus::Respond(StatusCode::FORBIDDEN),
            page: None,
        }
    }
}

/// The block directives written at one level, before they are merged with the inherited values.
#[derive(Debug, Default, Clone)]
pub(crate) struct BlockOverrides {
    status: Option<BlockStatus>,
    page: Option<Bytes>,
}

impl BlockOverrides {
    /// Applies one `block_status` or `block_page` directive.
    ///
    /// # Errors
    ///
    /// Returns an error for a repeated directive, a bad status, a missing or
    /// oversized page file, and for a directive that is not a block directive.
    pub(crate) fn apply(
        &mut self,
        directive: &Directive,
        seen: &mut HashSet<String>,
    ) -> Result<(), ConfigError> {
        once(seen, directive)?;
        match directive.name.as_str() {
            "block_status" => self.status = Some(parse_status(directive)?),
            "block_page" => self.page = Some(read_page(directive)?),
            _ => {
                return Err(invalid(
                    directive,
                    format!("\"{}\" is not a block directive", directive.name),
                ));
            }
        }
        Ok(())
    }

    /// Merges these values over the inherited response.
    pub(crate) fn resolve(&self, inherited: &BlockResponse) -> BlockResponse {
        BlockResponse {
            status: self.status.unwrap_or(inherited.status),
            page: self.page.clone().or_else(|| inherited.page.clone()),
        }
    }
}

/// Reads `block_status <code>`: 444, or a 4xx or 5xx code.
fn parse_status(directive: &Directive) -> Result<BlockStatus, ConfigError> {
    let text = one_arg(directive)?;
    let code: u16 = text.parse().map_err(|_| {
        invalid(
            directive,
            format!("\"block_status\" must be a status code, got {text}"),
        )
    })?;
    if code == 444 {
        return Ok(BlockStatus::Close);
    }
    match StatusCode::from_u16(code) {
        Ok(status) if status.is_client_error() || status.is_server_error() => {
            Ok(BlockStatus::Respond(status))
        }
        _ => Err(invalid(
            directive,
            format!("\"block_status\" must be 444 or a 4xx or 5xx code, got {text}"),
        )),
    }
}

/// Reads the page file at load time. A relative path is relative to the file that holds the directive.
fn read_page(directive: &Directive) -> Result<Bytes, ConfigError> {
    let name = one_arg(directive)?;
    let path = if Path::new(name).is_absolute() {
        PathBuf::from(name)
    } else {
        Path::new(directive.file.as_ref())
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
            .join(name)
    };
    let bytes = std::fs::read(&path).map_err(|source| {
        invalid(
            directive,
            format!("\"block_page\" cannot read {}: {source}", path.display()),
        )
    })?;
    if bytes.len() > MAX_PAGE_BYTES {
        return Err(invalid(
            directive,
            format!("\"block_page\" is larger than 64 KiB: {name}"),
        ));
    }
    Ok(Bytes::from(bytes))
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::config::Config;

    /// Parses a configuration with `block` lines inside the site block.
    fn site_with(lines: &str) -> Result<Config, ConfigError> {
        let text = format!(
            "listen 127.0.0.1:0;\ndecision {{\n    backend http;\n    url http://127.0.0.1:9/decide;\n}}\nsite example.com {{\n    upstream http://127.0.0.1:9;\n    {lines}\n}}\n"
        );
        Config::parse_str(&text, "block.conf")
    }

    #[rstest]
    #[case::forbidden("403", BlockStatus::Respond(StatusCode::FORBIDDEN))]
    #[case::not_found("404", BlockStatus::Respond(StatusCode::NOT_FOUND))]
    #[case::server_error("503", BlockStatus::Respond(StatusCode::SERVICE_UNAVAILABLE))]
    #[case::close("444", BlockStatus::Close)]
    fn block_status_accepts_4xx_5xx_and_444(#[case] code: &str, #[case] expected: BlockStatus) {
        let config = site_with(&format!("block_status {code};"));
        let status = config.map(|c| c.sites.first().map(|s| s.block.status));
        assert_eq!(status.ok().flatten(), Some(expected));
    }

    #[rstest]
    #[case::success("200")]
    #[case::redirect("302")]
    #[case::not_a_number("forbidden")]
    #[case::too_large("1000")]
    fn block_status_rejects_other_codes(#[case] code: &str) {
        let result = site_with(&format!("block_status {code};"));
        assert!(result.is_err());
    }

    #[test]
    fn a_site_without_block_directives_keeps_403_and_no_page() -> Result<(), ConfigError> {
        let config = site_with("")?;
        let site = config.sites.first().ok_or_else(invalid_fixture)?;
        assert_eq!(site.block, BlockResponse::default());
        Ok(())
    }

    #[test]
    fn block_page_is_read_when_the_configuration_loads() -> Result<(), ConfigError> {
        let dir = std::env::temp_dir().join("vh-block-page-test");
        std::fs::create_dir_all(&dir).map_err(|source| ConfigError::Read {
            path: dir.clone(),
            source,
        })?;
        let page = dir.join("blocked.html");
        std::fs::write(&page, "<h1>Blocked</h1>").map_err(|source| ConfigError::Read {
            path: page.clone(),
            source,
        })?;
        let main = dir.join("main.conf");
        let text = "listen 127.0.0.1:0;\ndecision {\n    backend http;\n    url http://127.0.0.1:9/decide;\n}\nblock_page blocked.html;\nsite example.com {\n    upstream http://127.0.0.1:9;\n}\n";
        std::fs::write(&main, text).map_err(|source| ConfigError::Read {
            path: main.clone(),
            source,
        })?;
        let config = Config::load(&main)?;
        let site = config.sites.first().ok_or_else(invalid_fixture)?;
        assert_eq!(site.block.page.as_deref(), Some(&b"<h1>Blocked</h1>"[..]));
        Ok(())
    }

    #[test]
    fn a_block_page_over_64_kib_is_rejected() {
        let dir = std::env::temp_dir().join("vh-block-page-large-test");
        let _ = std::fs::create_dir_all(&dir);
        let page = dir.join("large.html");
        let _ = std::fs::write(&page, vec![b'a'; MAX_PAGE_BYTES + 1]);
        let main = dir.join("main.conf");
        let text = "listen 127.0.0.1:0;\ndecision {\n    backend http;\n    url http://127.0.0.1:9/decide;\n}\nsite example.com {\n    upstream http://127.0.0.1:9;\n    block_page large.html;\n}\n";
        let _ = std::fs::write(&main, text);
        let result = Config::load(&main);
        assert!(
            matches!(&result, Err(ConfigError::Invalid { message, .. }) if message.contains("larger than 64 KiB")),
            "{result:?}"
        );
    }

    #[test]
    fn a_missing_block_page_names_the_path() {
        let result = site_with("block_page /nonexistent/vigilant-heron/page.html;");
        assert!(
            matches!(&result, Err(ConfigError::Invalid { message, .. }) if message.contains("cannot read")),
            "{result:?}"
        );
    }

    #[test]
    fn a_repeated_block_status_is_rejected() {
        let result = site_with("block_status 404;\n    block_status 410;");
        assert!(result.is_err());
    }

    fn invalid_fixture() -> ConfigError {
        ConfigError::Invalid {
            file: "block.conf".to_owned(),
            line: 1,
            message: "no site in the fixture".to_owned(),
        }
    }
}
