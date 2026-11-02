//! Helpers shared by the unit tests.

use std::io::BufRead;

use crate::config::{Config, SiteConfig};
use crate::error::ConfigError;

/// Builds one site from `site_fields`, written as configuration directives.
///
/// The defaults are `mode enforce;` and `action block;`, and each one is left
/// out when `site_fields` already sets that directive.
pub(crate) fn site(site_fields: &str) -> Result<SiteConfig, ConfigError> {
    let sets = |name: &str| {
        site_fields
            .lines()
            .any(|line| line.trim_start().starts_with(name))
    };
    let mode = if sets("mode ") { "" } else { "mode enforce;" };
    let action = if sets("action ") { "" } else { "action block;" };
    let input = format!(
        r"
listen 127.0.0.1:8080;

client_max_body_size 10m;
decision {{
    backend http;
    url http://stub-decider:9000/decide;
    timeout 150ms;
    inspect_body 8k;
}}

default_status 421;

site example.com {{
    upstream http://upstream:80;
    {mode}
    {action}
    block_threshold 0.9;
    instruction_threshold 0.5;
    {site_fields}
}}
"
    );
    let config = Config::parse_str(&input, "test.conf")?;
    config
        .sites
        .into_iter()
        .next()
        .ok_or_else(|| ConfigError::Invalid {
            file: "test.conf".to_owned(),
            line: 1,
            message: "no site in the test fixture".to_owned(),
        })
}

/// A reader whose every read fails, to check that a read error is returned or named.
pub(crate) struct FailingReader;

impl std::io::Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("the disk went away"))
    }
}

/// A reader over `data` that reports the end of the input once. A read after that is an
/// error, so a loop that does not stop at the end of the input fails instead of running on.
pub(crate) struct EndsOnce<'a> {
    data: &'a [u8],
    ended: bool,
}

impl<'a> EndsOnce<'a> {
    /// A reader over `data`.
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, ended: false }
    }
}

impl std::io::Read for EndsOnce<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = {
            let available = self.fill_buf()?;
            let count = available.len().min(buffer.len());
            buffer[..count].copy_from_slice(&available[..count]);
            count
        };
        self.consume(count);
        Ok(count)
    }
}

impl std::io::BufRead for EndsOnce<'_> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        if self.data.is_empty() {
            if self.ended {
                return Err(std::io::Error::other("read after the end of the input"));
            }
            self.ended = true;
        }
        Ok(self.data)
    }

    fn consume(&mut self, amount: usize) {
        self.data = self.data.get(amount..).unwrap_or_default();
    }
}
