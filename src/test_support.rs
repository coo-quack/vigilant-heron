//! Helpers shared by the unit tests.

use std::io::{self, BufRead};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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

/// A socket stand-in that records what reaches it. It accepts at most `per_write`
/// bytes per write, reports `vectored` from `is_write_vectored`, and can refuse flushes.
/// Reads report end of file, and an error once they have been called too often.
pub(crate) struct Recorder {
    pub(crate) per_write: usize,
    pub(crate) vectored: bool,
    pub(crate) fail_flush: bool,
    pub(crate) written: Vec<u8>,
    pub(crate) reads: usize,
    pub(crate) flushes: usize,
    pub(crate) shutdowns: usize,
}

impl Recorder {
    pub(crate) fn new() -> Self {
        Self {
            per_write: usize::MAX,
            vectored: false,
            fail_flush: false,
            written: Vec::new(),
            reads: 0,
            flushes: 0,
            shutdowns: 0,
        }
    }
}

impl AsyncRead for Recorder {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.reads += 1;
        if this.reads > 100 {
            return Poll::Ready(Err(io::Error::other("read again after end of file")));
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Recorder {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let take = buf.len().min(this.per_write);
        this.written
            .extend_from_slice(buf.get(..take).unwrap_or_default());
        Poll::Ready(Ok(take))
    }

    fn is_write_vectored(&self) -> bool {
        self.vectored
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.flushes += 1;
        if this.fail_flush {
            Poll::Ready(Err(io::Error::other("flush refused")))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.shutdowns += 1;
        Poll::Ready(Ok(()))
    }
}
