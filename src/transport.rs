//! Socket wrappers that enforce connection timers and header limits.
//!
//! [`ClientIo`] wraps a client socket. It bounds the wait for a request header
//! (`client_header_timeout`), the idle time between requests (`keepalive_timeout`),
//! the wait between writes (`send_timeout`), and checks the request line and
//! header fields against `large_client_header_buffers` before hyper parses them.
//! [`UpstreamIo`] wraps an upstream socket and bounds the wait between writes
//! (`proxy_send_timeout`). Body timers live in [`crate::body`].
//!
//! hyper's own header timeout is not used: it also runs while a connection is
//! idle, so it cannot tell the header timer from the keep-alive timer, and it
//! answers oversized headers with 431 rather than nginx's 414 and 400.

use std::future::Future;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use hyper_util::client::legacy::connect::{Connected, Connection};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;

use crate::config::{ConnectionConfig, HeaderBuffers};

/// Written to a client that stopped while sending its request header.
const RESPONSE_408: &[u8] =
    b"HTTP/1.1 408 Request Time-out\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
/// Written when the request line is longer than one header buffer.
const RESPONSE_414: &[u8] =
    b"HTTP/1.1 414 URI Too Long\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
/// Written when a header field, or the whole header section, is too large.
const RESPONSE_400: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

/// hyper's default read buffer per connection (`DEFAULT_MAX_BUFFER_SIZE` in hyper 1.12).
pub(crate) const HYPER_DEFAULT_BUFFER: usize = 8192 + 4096 * 100;

const PHASE_HEADER: u8 = 0;
const PHASE_KEEP_ALIVE: u8 = 1;
const PHASE_BUSY: u8 = 2;
const PHASE_CLOSING: u8 = 3;

/// What a client connection is waiting for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// Waiting for a request header. Bounded by `client_header_timeout`.
    AwaitingHeader,
    /// Idle between two requests. Bounded by `keepalive_timeout`.
    AwaitingKeepAlive,
    /// A request is being handled. Reads are not timed here.
    Busy,
    /// The response is complete but the request body is not. Reads report end of
    /// stream, so the connection closes instead of reading the rest of the body.
    Closing,
}

/// The phase of one client connection, shared by its transport and its request handler.
#[derive(Debug)]
pub(crate) struct PhaseCell {
    phase: AtomicU8,
    /// The task that reads the connection, woken on a phase change.
    waker: Mutex<Option<Waker>>,
}

impl PhaseCell {
    /// Starts a connection in the wait for its first request header.
    pub(crate) fn new() -> Self {
        Self {
            phase: AtomicU8::new(PHASE_HEADER),
            waker: Mutex::new(None),
        }
    }

    /// Remembers the task that reads the connection, so `set` can wake it.
    fn watch(&self, waker: &Waker) {
        *lock(&self.waker) = Some(waker.clone());
    }

    /// Returns the current phase.
    pub(crate) fn get(&self) -> Phase {
        match self.phase.load(Ordering::Acquire) {
            PHASE_KEEP_ALIVE => Phase::AwaitingKeepAlive,
            PHASE_BUSY => Phase::Busy,
            PHASE_CLOSING => Phase::Closing,
            _ => Phase::AwaitingHeader,
        }
    }

    /// Sets the phase.
    pub(crate) fn set(&self, phase: Phase) {
        let code = match phase {
            Phase::AwaitingHeader => PHASE_HEADER,
            Phase::AwaitingKeepAlive => PHASE_KEEP_ALIVE,
            Phase::Busy => PHASE_BUSY,
            Phase::Closing => PHASE_CLOSING,
        };
        self.phase.store(code, Ordering::Release);
        // A parked reader may have no timer armed for the new phase, so it is woken.
        if let Some(waker) = lock(&self.waker).take() {
            waker.wake();
        }
    }

    /// Moves an idle connection to the wait for a header. Returns false in any other phase.
    fn begin_header(&self) -> bool {
        self.phase
            .compare_exchange(
                PHASE_KEEP_ALIVE,
                PHASE_HEADER,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
}

/// A response the transport sent itself, logged once the connection ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Rejection {
    /// Status sent, or the one that would have been sent.
    pub(crate) status: u16,
    /// Short name of the cause, as logged in `$reason`.
    pub(crate) reason: &'static str,
}

/// Holds the rejection of a connection until its access record is written.
pub(crate) type RejectionSlot = Arc<Mutex<Option<Rejection>>>;

/// Locks a mutex, ignoring poisoning: the guarded values stay valid after a panic elsewhere.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Limits on the request line and header section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HeadLimits {
    /// Most bytes in one line, not counting its line ending.
    pub(crate) line: usize,
    /// Most bytes in the whole header section, counting line endings.
    pub(crate) total: usize,
}

impl HeadLimits {
    /// Derives the limits from `large_client_header_buffers`: one line per buffer,
    /// and the whole section within `count` buffers.
    pub(crate) fn from_buffers(buffers: HeaderBuffers) -> Self {
        Self {
            line: buffers.size,
            total: buffers.count.saturating_mul(buffers.size),
        }
    }
}

/// Why a request header was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeadViolation {
    /// The request line is longer than one buffer. Answered with 414.
    RequestLineTooLong,
    /// A header field, or the whole section, is too large. Answered with 400.
    HeaderTooLarge,
}

/// Checks the bytes of one request header as they arrive, without parsing them.
#[derive(Debug, Clone)]
pub(crate) struct HeadScanner {
    limits: HeadLimits,
    total: usize,
    line_len: usize,
    completed_lines: usize,
    done: bool,
}

impl HeadScanner {
    /// Creates a scanner that expects the start of a request header.
    pub(crate) fn new(limits: HeadLimits) -> Self {
        Self {
            limits,
            total: 0,
            line_len: 0,
            completed_lines: 0,
            done: false,
        }
    }

    /// Prepares the scanner for the next request header.
    pub(crate) fn reset(&mut self) {
        self.total = 0;
        self.line_len = 0;
        self.completed_lines = 0;
        self.done = false;
    }

    /// Feeds the next bytes of a request header. Returns `Ok(true)` once the
    /// blank line that ends the header has been seen. Bytes after that are ignored.
    ///
    /// # Errors
    ///
    /// Returns the violation at the first byte that exceeds a limit.
    pub(crate) fn feed(&mut self, bytes: &[u8]) -> Result<bool, HeadViolation> {
        for &byte in bytes {
            if self.done {
                break;
            }
            match byte {
                b'\n' => {
                    if self.line_len > 0 {
                        self.completed_lines += 1;
                        self.line_len = 0;
                    } else if self.completed_lines > 0 {
                        // The blank line that ends the header.
                        self.done = true;
                    }
                    // Empty lines before the request line are ignored, as RFC 9112 allows.
                }
                b'\r' => {}
                _ => {
                    self.line_len += 1;
                    if self.line_len > self.limits.line {
                        return Err(if self.completed_lines == 0 {
                            HeadViolation::RequestLineTooLong
                        } else {
                            HeadViolation::HeaderTooLarge
                        });
                    }
                }
            }
            self.total += 1;
            if self.total > self.limits.total {
                return Err(HeadViolation::HeaderTooLarge);
            }
        }
        Ok(self.done)
    }
}

/// The timers and limits of client connections, copied out of the configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClientTimers {
    /// Time allowed for a whole request header.
    pub(crate) header: Duration,
    /// Idle time between requests. Zero disables keep-alive.
    pub(crate) keep_alive: Duration,
    /// Longest wait between two writes to the client.
    pub(crate) send: Duration,
    /// Header limits.
    pub(crate) head: HeadLimits,
}

impl ClientTimers {
    /// Copies the timers out of the top-level configuration.
    pub(crate) fn from_config(config: &ConnectionConfig) -> Self {
        Self {
            header: config.client_header_timeout,
            keep_alive: config.keepalive_timeout,
            send: config.send_timeout,
            head: HeadLimits::from_buffers(config.large_header_buffers),
        }
    }
}

/// Starts or checks the timer in `slot`. Returns true once `limit` has passed since it started.
pub(crate) fn expired(
    slot: &mut Option<Pin<Box<Sleep>>>,
    limit: Duration,
    cx: &mut Context<'_>,
) -> bool {
    slot.get_or_insert_with(|| Box::pin(tokio::time::sleep(limit)))
        .as_mut()
        .poll(cx)
        .is_ready()
}

/// A client socket with the connection timers and the header limits applied.
pub(crate) struct ClientIo<S> {
    inner: S,
    phase: Arc<PhaseCell>,
    timers: ClientTimers,
    rejection: RejectionSlot,
    /// The timer of the current read wait, with the phase it was started for.
    read_timer: Option<(Phase, Pin<Box<Sleep>>)>,
    write_timer: Option<Pin<Box<Sleep>>>,
    scanner: HeadScanner,
    /// Whether any byte of the current request header has arrived.
    head_started: bool,
}

impl<S> ClientIo<S> {
    /// Wraps `inner`, a new client socket, in the first wait for a request header.
    pub(crate) fn new(
        inner: S,
        phase: Arc<PhaseCell>,
        timers: ClientTimers,
        rejection: RejectionSlot,
    ) -> Self {
        Self {
            inner,
            phase,
            timers,
            rejection,
            read_timer: None,
            write_timer: None,
            scanner: HeadScanner::new(timers.head),
            head_started: false,
        }
    }

    /// Records a rejection for the access log. The first one wins.
    fn record(&self, rejection: Rejection) {
        lock(&self.rejection).get_or_insert(rejection);
    }

    /// Stops reads from being timed: the connection is closing or a request is being handled.
    fn stop_timing_reads(&mut self) {
        self.read_timer = None;
    }

    /// Starts the header timer for a request whose first byte has just arrived.
    fn start_header_timer(&mut self) {
        self.read_timer = Some((
            Phase::AwaitingHeader,
            Box::pin(tokio::time::sleep(self.timers.header)),
        ));
    }
}

impl<S: AsyncWrite + Unpin> ClientIo<S> {
    /// Writes a fixed answer to the client. Best effort: the answer is a few bytes.
    fn answer(&mut self, cx: &mut Context<'_>, bytes: &[u8], rejection: Rejection) {
        let _ = Pin::new(&mut self.inner).poll_write(cx, bytes);
        self.record(rejection);
    }

    /// Closes the connection after a request header that broke a limit.
    fn header_violation(&mut self, cx: &mut Context<'_>, violation: HeadViolation) -> io::Error {
        self.phase.set(Phase::Busy);
        let (bytes, rejection, reason) = match violation {
            HeadViolation::RequestLineTooLong => (
                RESPONSE_414,
                Rejection {
                    status: 414,
                    reason: "uri_too_long",
                },
                "request line is too long",
            ),
            HeadViolation::HeaderTooLarge => (
                RESPONSE_400,
                Rejection {
                    status: 400,
                    reason: "header_too_large",
                },
                "request header is too large",
            ),
        };
        self.answer(cx, bytes, rejection);
        io::Error::new(io::ErrorKind::InvalidData, reason)
    }

    /// Closes the connection when a read wait runs out.
    fn read_timed_out(&mut self, cx: &mut Context<'_>, phase: Phase) -> io::Error {
        self.read_timer = None;
        match phase {
            Phase::AwaitingHeader => {
                if self.head_started {
                    self.answer(
                        cx,
                        RESPONSE_408,
                        Rejection {
                            status: 408,
                            reason: "header_timeout",
                        },
                    );
                }
                io::Error::new(io::ErrorKind::TimedOut, "client header timeout")
            }
            Phase::AwaitingKeepAlive | Phase::Busy | Phase::Closing => {
                io::Error::new(io::ErrorKind::TimedOut, "keep-alive timeout")
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for ClientIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let phase = this.phase.get();
        match phase {
            Phase::Closing => {
                this.stop_timing_reads();
                return Poll::Ready(Ok(()));
            }
            Phase::Busy => this.stop_timing_reads(),
            Phase::AwaitingHeader | Phase::AwaitingKeepAlive => {
                let armed = this.read_timer.as_ref().map(|(armed, _)| *armed);
                if armed != Some(phase) {
                    let limit = match phase {
                        Phase::AwaitingKeepAlive => this.timers.keep_alive,
                        _ => this.timers.header,
                    };
                    this.read_timer = Some((phase, Box::pin(tokio::time::sleep(limit))));
                }
            }
        }

        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let fresh = buf.filled().get(before..).unwrap_or_default();
                if fresh.is_empty() || this.phase.get() == Phase::Busy {
                    return Poll::Ready(Ok(()));
                }
                if this.phase.begin_header() {
                    // The first byte of the next request arrived, so the header timer starts now.
                    this.scanner.reset();
                    this.head_started = false;
                    this.start_header_timer();
                }
                this.head_started = true;
                match this.scanner.feed(fresh) {
                    Ok(false) => {}
                    Ok(true) => {
                        // The header is complete. Hyper handles the request from here on.
                        this.phase.set(Phase::Busy);
                        this.stop_timing_reads();
                    }
                    Err(violation) => {
                        return Poll::Ready(Err(this.header_violation(cx, violation)));
                    }
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => {
                this.phase.watch(cx.waker());
                let expired = match this.read_timer.as_mut() {
                    Some((armed, sleep)) => {
                        let armed = *armed;
                        sleep.as_mut().poll(cx).is_ready().then_some(armed)
                    }
                    None => None,
                };
                match expired {
                    Some(phase) => Poll::Ready(Err(this.read_timed_out(cx, phase))),
                    None => Poll::Pending,
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> ClientIo<S> {
    /// Applies `send_timeout` to one write attempt.
    fn timed_write(
        &mut self,
        cx: &mut Context<'_>,
        attempt: Poll<io::Result<usize>>,
    ) -> Poll<io::Result<usize>> {
        match attempt {
            Poll::Pending => {
                if expired(&mut self.write_timer, self.timers.send, cx) {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "client send timeout",
                    )))
                } else {
                    Poll::Pending
                }
            }
            Poll::Ready(result) => {
                self.write_timer = None;
                Poll::Ready(result)
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ClientIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let attempt = Pin::new(&mut this.inner).poll_write(cx, buf);
        this.timed_write(cx, attempt)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let attempt = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        this.timed_write(cx, attempt)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// An upstream socket that bounds the wait between writes (`proxy_send_timeout`).
pub(crate) struct UpstreamIo<S> {
    inner: S,
    send: Duration,
    write_timer: Option<Pin<Box<Sleep>>>,
}

impl<S> UpstreamIo<S> {
    /// Wraps `inner`, a connected upstream socket.
    pub(crate) fn new(inner: S, send: Duration) -> Self {
        Self {
            inner,
            send,
            write_timer: None,
        }
    }

    /// Applies `proxy_send_timeout` to one write attempt.
    fn timed_write(
        &mut self,
        cx: &mut Context<'_>,
        attempt: Poll<io::Result<usize>>,
    ) -> Poll<io::Result<usize>> {
        match attempt {
            Poll::Pending => {
                if expired(&mut self.write_timer, self.send, cx) {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "upstream send timeout",
                    )))
                } else {
                    Poll::Pending
                }
            }
            Poll::Ready(result) => {
                self.write_timer = None;
                Poll::Ready(result)
            }
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for UpstreamIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for UpstreamIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let attempt = Pin::new(&mut this.inner).poll_write(cx, buf);
        this.timed_write(cx, attempt)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let attempt = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        this.timed_write(cx, attempt)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S> Connection for UpstreamIo<S> {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rstest::rstest;

    use super::*;

    fn limits(line: usize, total: usize) -> HeadLimits {
        HeadLimits { line, total }
    }

    /// Feeds `head` in pieces of `chunk` bytes and returns the final outcome.
    fn scan_in_chunks(
        head: &[u8],
        chunk: usize,
        limits: HeadLimits,
    ) -> Result<bool, HeadViolation> {
        let mut scanner = HeadScanner::new(limits);
        let mut done = Ok(false);
        for piece in head.chunks(chunk.max(1)) {
            done = scanner.feed(piece);
            match done {
                Ok(true) | Err(_) => break,
                Ok(false) => {}
            }
        }
        done
    }

    #[rstest]
    #[case::request_line_at_the_limit(b"GET /aaaa HTTP/1.1\r\nHost: a\r\n\r\n", 18, 100, Ok(true))]
    #[case::request_line_over_the_limit(
        b"GET /aaaaaa HTTP/1.1\r\n\r\n",
        10,
        100,
        Err(HeadViolation::RequestLineTooLong)
    )]
    #[case::header_field_over_the_limit(
        b"GET / HTTP/1.1\r\nX: 01234567890123456\r\n\r\n",
        16,
        200,
        Err(HeadViolation::HeaderTooLarge)
    )]
    #[case::section_over_the_total(
        b"GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\n\r\n",
        100,
        20,
        Err(HeadViolation::HeaderTooLarge)
    )]
    #[case::leading_empty_lines_are_ignored(b"\r\n\r\nGET / HTTP/1.1\r\n\r\n", 100, 100, Ok(true))]
    fn the_scanner_applies_each_limit_where_nginx_does(
        #[case] head: &[u8],
        #[case] line: usize,
        #[case] total: usize,
        #[case] expected: Result<bool, HeadViolation>,
    ) {
        assert_eq!(scan_in_chunks(head, 1, limits(line, total)), expected);
        assert_eq!(scan_in_chunks(head, 4096, limits(line, total)), expected);
    }

    #[test]
    fn bytes_after_the_blank_line_are_not_scanned() {
        let mut scanner = HeadScanner::new(limits(100, 100));
        let body = [b'x'; 200];
        let mut bytes = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        bytes.extend_from_slice(&body);
        let result = scanner.feed(&bytes);
        assert_eq!(result, Ok(true));
    }

    #[test]
    fn reset_lets_the_scanner_check_the_next_header() {
        let mut scanner = HeadScanner::new(limits(100, 100));
        assert_eq!(scanner.feed(b"GET / HTTP/1.1\r\n\r\n"), Ok(true));
        scanner.reset();
        assert_eq!(scanner.feed(b"GET / HTTP/1.1\r\n"), Ok(false));
    }

    fn head_text(lines: &[usize]) -> Vec<u8> {
        let mut out = Vec::new();
        for (index, len) in lines.iter().enumerate() {
            let prefix = if index == 0 { b'G' } else { b'H' };
            out.push(prefix);
            out.extend(std::iter::repeat_n(b'a', len.saturating_sub(1)));
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out
    }

    proptest! {
        /// A header is accepted exactly when every line fits the line limit and the
        /// whole section, with its line endings, fits the total limit.
        #[test]
        fn acceptance_matches_the_limit_arithmetic(
            lines in prop::collection::vec(1usize..40, 1..8),
            line_limit in 1usize..40,
            total_limit in 1usize..300,
            chunk in 1usize..17,
        ) {
            let head = head_text(&lines);
            let lines_fit = lines.iter().all(|len| *len <= line_limit);
            let section = lines.iter().map(|len| len + 2).sum::<usize>() + 2;
            let total_fits = section <= total_limit;
            let result = scan_in_chunks(&head, chunk, limits(line_limit, total_limit));
            if lines_fit && total_fits {
                prop_assert_eq!(result, Ok(true));
            } else {
                prop_assert!(result.is_err(), "expected a violation, got {result:?}");
            }
        }

        /// Where the head is split into reads does not change the outcome.
        #[test]
        fn chunking_does_not_change_the_outcome(
            lines in prop::collection::vec(1usize..40, 1..8),
            line_limit in 1usize..40,
            total_limit in 1usize..300,
            chunk in 1usize..17,
        ) {
            let head = head_text(&lines);
            let whole = scan_in_chunks(&head, head.len().max(1), limits(line_limit, total_limit));
            let pieces = scan_in_chunks(&head, chunk, limits(line_limit, total_limit));
            prop_assert_eq!(whole, pieces);
        }
    }
}
