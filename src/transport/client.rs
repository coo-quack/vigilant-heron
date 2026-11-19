//! [`ClientIo`], the client socket wrapper, with the timers it applies and the
//! rejections it records.

use std::future::Future;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;

use super::head::{HeadLimits, HeadScanner, HeadViolation};
use crate::config::{ConnectionConfig, LingeringClose};
use crate::phase::{Phase, PhaseCell};
use crate::sync::lock;

/// Written to a client that stopped while sending its request header.
const RESPONSE_408: &[u8] =
    b"HTTP/1.1 408 Request Time-out\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
/// Written when the request line is longer than one header buffer.
const RESPONSE_414: &[u8] =
    b"HTTP/1.1 414 URI Too Long\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
/// Written when a header field, or the whole header section, is too large.
const RESPONSE_400: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

/// Bytes read and discarded at a time by a lingering close. Its memory is bounded by this.
const LINGER_BUFFER: usize = 4096;

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
    /// When a connection lingers before it closes.
    pub(crate) linger: LingeringClose,
    /// Longest total time of one lingering close.
    pub(crate) linger_time: Duration,
    /// Longest silence that one lingering close waits for.
    pub(crate) linger_timeout: Duration,
}

impl ClientTimers {
    /// Copies the timers out of the top-level configuration.
    pub(crate) fn from_config(config: &ConnectionConfig) -> Self {
        Self {
            header: config.client_header_timeout,
            keep_alive: config.keepalive_timeout,
            send: config.send_timeout,
            head: HeadLimits::from_buffers(config.large_header_buffers),
            linger: config.lingering_close,
            linger_time: config.lingering_time,
            linger_timeout: config.lingering_timeout,
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

/// A client socket with the connection timers, the header limits and lingering close applied.
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
    /// Whether any byte of any request header has arrived on this connection.
    saw_request: bool,
    /// The lingering close in progress, once the connection has decided to close.
    linger: Option<Box<Lingering>>,
    /// Set once a lingering close has finished, so later calls do not linger again.
    lingered: bool,
}

/// State of a lingering close: the answer still to be written, the flush and
/// half-close, then the discarding of the client's data.
struct Lingering {
    /// Bytes of a fixed answer not yet written.
    answer: &'static [u8],
    /// Whether the write side has been flushed since the answer was written.
    flushed: bool,
    /// Whether the write side has been shut down.
    half_closed: bool,
    /// Whether client data is read and discarded. False closes at once after the answer.
    discard: bool,
    /// Bounds the whole lingering close, from its start.
    total: Pin<Box<Sleep>>,
    /// Bounds the silence between two reads of client data. Restarted on each read.
    silence: Pin<Box<Sleep>>,
    /// Receives the discarded client data. Its size bounds the memory of a lingering close.
    buffer: Box<[u8]>,
    /// The error the connection ends with, returned once the lingering close is over.
    error: Option<io::Error>,
    /// The `lingering_timeout` that restarts `silence` on each read.
    silence_limit: Duration,
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
            saw_request: false,
            linger: None,
            lingered: false,
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

    /// Whether a normal close, after hyper has finished the response, lingers.
    ///
    /// `on` lingers when the body was not read in full, which is the `Closing` phase.
    /// `always` lingers once the connection has carried a request.
    fn lingers_on_close(&self) -> bool {
        // A tunnel closes when its own splice ends; there is no unread request to discard.
        if self.phase.get() == Phase::Tunnelling {
            return false;
        }
        match self.timers.linger {
            LingeringClose::Off => false,
            LingeringClose::Always => self.saw_request,
            LingeringClose::On => self.phase.get() == Phase::Closing,
        }
    }

    /// Starts a lingering close. `answer` is written in full first, then flushed.
    /// With `discard` false the connection closes once the answer is flushed.
    fn begin_linger(&mut self, answer: &'static [u8], error: Option<io::Error>, discard: bool) {
        self.read_timer = None;
        self.linger = Some(Box::new(Lingering {
            answer,
            flushed: false,
            half_closed: false,
            discard,
            total: Box::pin(tokio::time::sleep(self.timers.linger_time)),
            silence: Box::pin(tokio::time::sleep(self.timers.linger_timeout)),
            buffer: vec![0u8; LINGER_BUFFER].into_boxed_slice(),
            error,
            silence_limit: self.timers.linger_timeout,
        }));
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> ClientIo<S> {
    /// Advances the lingering close. Returns `Ready` once it is over, with the error
    /// the connection ends with, if any.
    ///
    /// The steps run in order: the pending answer is written, the write side is
    /// flushed, the write side is shut down, and client data is read and discarded
    /// until EOF, until `lingering_timeout` passes without data, or until
    /// `lingering_time` has passed in total. A write error or a flush error ends
    /// the answer, since the peer is gone.
    fn poll_linger(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(mut linger) = self.linger.take() else {
            return Poll::Ready(Ok(()));
        };
        let mut pending = false;
        loop {
            if !linger.answer.is_empty() {
                match Pin::new(&mut self.inner).poll_write(cx, linger.answer) {
                    Poll::Ready(Ok(written)) if written > 0 => {
                        linger.answer = linger.answer.get(written..).unwrap_or_default();
                        continue;
                    }
                    Poll::Ready(_) => linger.answer = &[],
                    Poll::Pending => {
                        pending = true;
                        break;
                    }
                }
            }
            if !linger.flushed {
                match Pin::new(&mut self.inner).poll_flush(cx) {
                    Poll::Ready(_) => linger.flushed = true,
                    Poll::Pending => {
                        pending = true;
                        break;
                    }
                }
            }
            if !linger.discard {
                break;
            }
            if !linger.half_closed {
                match Pin::new(&mut self.inner).poll_shutdown(cx) {
                    Poll::Ready(_) => linger.half_closed = true,
                    Poll::Pending => {
                        pending = true;
                        break;
                    }
                }
            }
            let mut read = ReadBuf::new(&mut linger.buffer);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read) {
                Poll::Ready(Ok(())) if !read.filled().is_empty() => {
                    linger.silence = Box::pin(tokio::time::sleep(linger.silence_limit));
                }
                // EOF or an error: the peer has gone, so there is nothing left to wait for.
                Poll::Ready(_) => break,
                Poll::Pending => {
                    pending = true;
                    break;
                }
            }
        }
        if pending {
            let total_passed = linger.total.as_mut().poll(cx).is_ready();
            let silent = linger.silence.as_mut().poll(cx).is_ready();
            if !(total_passed || silent) {
                self.linger = Some(linger);
                return Poll::Pending;
            }
        }
        self.lingered = true;
        Poll::Ready(match linger.error.take() {
            Some(error) => Err(error),
            None => Ok(()),
        })
    }

    /// Closes the connection after a request header that broke a limit. The answer is
    /// written in full before the connection lingers or closes.
    fn header_violation(
        &mut self,
        cx: &mut Context<'_>,
        violation: HeadViolation,
    ) -> Poll<io::Result<()>> {
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
        self.record(rejection);
        // The rest of the header is unread, so the connection lingers unless lingering is off.
        let discard = self.timers.linger != LingeringClose::Off;
        self.begin_linger(
            bytes,
            Some(io::Error::new(io::ErrorKind::InvalidData, reason)),
            discard,
        );
        self.poll_linger(cx)
    }

    /// Closes the connection when a read wait runs out.
    fn read_timed_out(&mut self, cx: &mut Context<'_>, phase: Phase) -> Poll<io::Result<()>> {
        self.read_timer = None;
        match phase {
            Phase::AwaitingHeader if self.head_started => {
                self.record(Rejection {
                    status: 408,
                    reason: "header_timeout",
                });
                // A client that is still sending its header may still be sending: linger.
                let discard = self.timers.linger != LingeringClose::Off;
                self.begin_linger(
                    RESPONSE_408,
                    Some(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "client header timeout",
                    )),
                    discard,
                );
                self.poll_linger(cx)
            }
            Phase::AwaitingHeader => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "client header timeout",
            ))),
            Phase::AwaitingKeepAlive | Phase::Busy | Phase::Closing | Phase::Tunnelling => {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "keep-alive timeout",
                )))
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
        if this.linger.is_some() {
            // The connection is lingering: client data is discarded, not handed to hyper.
            return this.poll_linger(cx);
        }
        let phase = this.phase.get();
        if phase == Phase::Tunnelling {
            // The connection is a tunnel: bytes are copied, never parsed or timed.
            this.stop_timing_reads();
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
        match phase {
            Phase::Closing => {
                this.stop_timing_reads();
                return Poll::Ready(Ok(()));
            }
            Phase::Busy | Phase::Tunnelling => this.stop_timing_reads(),
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
                this.saw_request = true;
                match this.scanner.feed(fresh) {
                    Ok(false) => {}
                    Ok(true) => {
                        // The header is complete. Hyper handles the request from here on.
                        this.phase.set(Phase::Busy);
                        this.stop_timing_reads();
                    }
                    Err(violation) => return this.header_violation(cx, violation),
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
                    Some(phase) => this.read_timed_out(cx, phase),
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

/// The error for a write after the connection has started to close.
fn closing_write_error() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "connection is closing")
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ClientIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.linger.is_some() || this.lingered {
            return Poll::Ready(Err(closing_write_error()));
        }
        let attempt = Pin::new(&mut this.inner).poll_write(cx, buf);
        this.timed_write(cx, attempt)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.linger.is_some() || this.lingered {
            return Poll::Ready(Err(closing_write_error()));
        }
        let attempt = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        this.timed_write(cx, attempt)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.linger.is_some() || this.lingered {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    /// Ends the connection. With lingering on, the write side is half-closed only
    /// after the response is flushed, and the client's data is discarded until the
    /// linger ends. Hyper calls this after the response is complete.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.linger.is_some() {
            return this.poll_linger(cx);
        }
        if this.lingered {
            return Poll::Ready(Ok(()));
        }
        if this.lingers_on_close() {
            this.begin_linger(&[], None, true);
            return this.poll_linger(cx);
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rstest::rstest;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::test_support::Recorder;
    use crate::transport::test_helpers::limits;

    type BoxError = Box<dyn Error + Send + Sync>;

    /// A connected pair of sockets: the client end, and the server end that the router wraps.
    async fn socket_pair() -> io::Result<(TcpStream, TcpStream)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let client = TcpStream::connect(listener.local_addr()?).await?;
        let (server, _) = listener.accept().await?;
        Ok((client, server))
    }

    fn linger_timers(
        linger: LingeringClose,
        linger_time: Duration,
        linger_timeout: Duration,
    ) -> ClientTimers {
        ClientTimers {
            header: Duration::from_secs(5),
            keep_alive: Duration::from_secs(5),
            send: Duration::from_secs(5),
            head: limits(64, 512),
            linger,
            linger_time,
            linger_timeout,
        }
    }

    /// Wraps the server end in a client socket that is about to close after a response.
    fn closing(server: TcpStream, timers: ClientTimers) -> ClientIo<TcpStream> {
        let phase = Arc::new(PhaseCell::new());
        phase.set(Phase::Closing);
        ClientIo::new(server, phase, timers, Arc::new(Mutex::new(None)))
    }

    #[tokio::test]
    async fn lingering_ends_after_the_silence_limit_when_the_client_stays_quiet()
    -> Result<(), BoxError> {
        let (_client, server) = socket_pair().await?;
        let timers = linger_timers(
            LingeringClose::On,
            Duration::from_secs(5),
            Duration::from_millis(200),
        );
        let mut io = closing(server, timers);
        let started = std::time::Instant::now();
        io.shutdown().await?;
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(180),
            "lingering ended before the silence limit: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "lingering waited past the silence limit: {elapsed:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn lingering_ends_at_the_total_time_while_the_client_keeps_sending()
    -> Result<(), BoxError> {
        let (mut client, server) = socket_pair().await?;
        let writer = tokio::spawn(async move {
            for _ in 0..40 {
                if client.write_all(&[b'x'; 10]).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
        let timers = linger_timers(
            LingeringClose::On,
            Duration::from_millis(600),
            Duration::from_millis(200),
        );
        let mut io = closing(server, timers);
        let started = std::time::Instant::now();
        io.shutdown().await?;
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(550),
            "lingering ended before the total time: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_millis(1500),
            "data arriving every 50 ms must not extend lingering past lingering_time: {elapsed:?}"
        );
        writer.abort();
        Ok(())
    }

    #[tokio::test]
    async fn lingering_ends_at_once_when_the_client_closes() -> Result<(), BoxError> {
        let (mut client, server) = socket_pair().await?;
        client.write_all(b"tail").await?;
        drop(client);
        let timers = linger_timers(
            LingeringClose::On,
            Duration::from_secs(30),
            Duration::from_secs(5),
        );
        let mut io = closing(server, timers);
        let started = std::time::Instant::now();
        io.shutdown().await?;
        assert!(started.elapsed() < Duration::from_secs(2));
        Ok(())
    }

    #[tokio::test]
    async fn a_header_violation_answer_is_written_in_full_before_the_close() -> Result<(), BoxError>
    {
        let (mut client, server) = socket_pair().await?;
        let timers = linger_timers(
            LingeringClose::On,
            Duration::from_secs(5),
            Duration::from_millis(200),
        );
        let mut io = ClientIo::new(
            server,
            Arc::new(PhaseCell::new()),
            timers,
            Arc::new(Mutex::new(None)),
        );
        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 256];
            while io.read(&mut buf).await.is_ok_and(|read| read > 0) {}
            io
        });
        // The request line is longer than the 64-byte limit, so the answer is 414.
        client
            .write_all(b"GET /aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa HTTP/1.1\r\n\r\n")
            .await?;
        let mut answer = Vec::new();
        client.read_to_end(&mut answer).await?;
        assert_eq!(answer, RESPONSE_414);
        let _ = reader.await?;
        Ok(())
    }

    #[tokio::test]
    async fn a_header_violation_with_lingering_off_still_writes_the_whole_answer()
    -> Result<(), BoxError> {
        let (mut client, server) = socket_pair().await?;
        let timers = linger_timers(
            LingeringClose::Off,
            Duration::from_secs(5),
            Duration::from_millis(200),
        );
        let mut io = ClientIo::new(
            server,
            Arc::new(PhaseCell::new()),
            timers,
            Arc::new(Mutex::new(None)),
        );
        client
            .write_all(b"GET /aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa HTTP/1.1\r\n\r\n")
            .await?;
        let mut buf = [0u8; 256];
        let error = io.read(&mut buf).await.err();
        assert_eq!(
            error.map(|error| error.kind()),
            Some(io::ErrorKind::InvalidData)
        );
        drop(io);
        let mut answer = Vec::new();
        client.read_to_end(&mut answer).await?;
        assert_eq!(answer, RESPONSE_414);
        Ok(())
    }

    /// A writer that accepts no bytes on its first write, then records every byte it gets.
    #[derive(Default)]
    struct RefusingOnce {
        refused: bool,
        written: Vec<u8>,
    }

    impl AsyncRead for RefusingOnce {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for RefusingOnce {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if this.refused {
                this.written.extend_from_slice(buf);
                Poll::Ready(Ok(buf.len()))
            } else {
                this.refused = true;
                Poll::Ready(Ok(0))
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn an_answer_that_the_socket_refuses_is_not_retried() -> Result<(), BoxError> {
        let timers = linger_timers(
            LingeringClose::On,
            Duration::from_secs(5),
            Duration::from_millis(200),
        );
        let mut io = ClientIo::new(
            RefusingOnce::default(),
            Arc::new(PhaseCell::new()),
            timers,
            Arc::new(Mutex::new(None)),
        );
        io.begin_linger(RESPONSE_408, None, false);
        io.shutdown().await?;
        assert!(
            io.inner.written.is_empty(),
            "a write that accepts no bytes ends the answer"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_write_during_a_lingering_close_fails() -> Result<(), BoxError> {
        let (_client, server) = socket_pair().await?;
        let timers = linger_timers(
            LingeringClose::On,
            Duration::from_secs(5),
            Duration::from_millis(200),
        );
        let mut io = ClientIo::new(
            server,
            Arc::new(PhaseCell::new()),
            timers,
            Arc::new(Mutex::new(None)),
        );
        io.begin_linger(&[], None, true);
        let single = io.write(b"x").await.err().map(|error| error.kind());
        assert_eq!(single, Some(io::ErrorKind::BrokenPipe));
        let vectored = io
            .write_vectored(&[IoSlice::new(b"x")])
            .await
            .err()
            .map(|error| error.kind());
        assert_eq!(vectored, Some(io::ErrorKind::BrokenPipe));
        Ok(())
    }

    #[tokio::test]
    async fn a_write_after_a_lingering_close_has_ended_fails() -> Result<(), BoxError> {
        let (_client, server) = socket_pair().await?;
        let timers = linger_timers(
            LingeringClose::On,
            Duration::from_secs(5),
            Duration::from_millis(200),
        );
        let mut io = closing(server, timers);
        io.shutdown().await?;
        let single = io.write(b"x").await.err().map(|error| error.kind());
        assert_eq!(single, Some(io::ErrorKind::BrokenPipe));
        let vectored = io
            .write_vectored(&[IoSlice::new(b"x")])
            .await
            .err()
            .map(|error| error.kind());
        assert_eq!(vectored, Some(io::ErrorKind::BrokenPipe));
        Ok(())
    }

    #[tokio::test]
    async fn an_answer_the_socket_takes_in_parts_is_written_in_full() -> Result<(), BoxError> {
        let timers = linger_timers(
            LingeringClose::On,
            Duration::from_secs(5),
            Duration::from_millis(200),
        );
        let mut recorder = Recorder::new();
        recorder.per_write = 3;
        let mut io = ClientIo::new(
            recorder,
            Arc::new(PhaseCell::new()),
            timers,
            Arc::new(Mutex::new(None)),
        );
        io.begin_linger(RESPONSE_408, None, false);
        io.shutdown().await?;
        assert_eq!(io.inner.written, RESPONSE_408);
        Ok(())
    }

    #[tokio::test]
    async fn a_lingering_close_flushes_the_answer_before_it_shuts_the_write_side()
    -> Result<(), BoxError> {
        let timers = linger_timers(
            LingeringClose::On,
            Duration::from_secs(5),
            Duration::from_millis(200),
        );
        let mut io = ClientIo::new(
            Recorder::new(),
            Arc::new(PhaseCell::new()),
            timers,
            Arc::new(Mutex::new(None)),
        );
        io.begin_linger(RESPONSE_408, None, true);
        io.shutdown().await?;
        assert_eq!(io.inner.written, RESPONSE_408);
        assert!(io.inner.flushes > 0, "the answer was not flushed");
        assert_eq!(io.inner.shutdowns, 1);
        Ok(())
    }

    #[tokio::test]
    async fn a_lingering_close_ends_at_once_when_the_client_reaches_end_of_file()
    -> Result<(), BoxError> {
        let timers = linger_timers(
            LingeringClose::On,
            Duration::from_secs(30),
            Duration::from_secs(30),
        );
        let mut io = ClientIo::new(
            Recorder::new(),
            Arc::new(PhaseCell::new()),
            timers,
            Arc::new(Mutex::new(None)),
        );
        io.begin_linger(&[], None, true);
        io.shutdown().await?;
        assert!(
            io.inner.reads <= 2,
            "end of file must end the lingering close, but it read {} times",
            io.inner.reads
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_header_timeout_with_lingering_on_keeps_discarding_what_the_client_sends()
    -> Result<(), BoxError> {
        let (mut client, server) = socket_pair().await?;
        let timers = ClientTimers {
            header: Duration::from_millis(100),
            ..linger_timers(
                LingeringClose::On,
                Duration::from_secs(10),
                Duration::from_secs(1),
            )
        };
        let mut io = ClientIo::new(
            server,
            Arc::new(PhaseCell::new()),
            timers,
            Arc::new(Mutex::new(None)),
        );
        let sender = tokio::spawn(async move {
            client.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n").await?;
            // The header never ends. The client keeps sending for about 600 ms after the header timeout starts.
            for _ in 0..20 {
                client.write_all(b"x").await?;
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
            Ok::<(), io::Error>(())
        });
        let started = std::time::Instant::now();
        let mut buf = [0u8; 256];
        let error = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Err(error) = io.read(&mut buf).await {
                    break error;
                }
            }
        })
        .await?;
        let elapsed = started.elapsed();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(
            elapsed >= Duration::from_millis(500),
            "the connection closed at the header timeout while the client was still sending: {elapsed:?}"
        );
        sender.await??;
        Ok(())
    }

    /// The clock is paused, so the timers are measured exactly and the test does not sleep.
    #[tokio::test(start_paused = true)]
    async fn the_header_timer_of_a_kept_alive_connection_counts_from_the_first_byte()
    -> Result<(), BoxError> {
        let (mut client, server) = tokio::io::duplex(1024);
        let timers = ClientTimers {
            header: Duration::from_millis(100),
            keep_alive: Duration::from_secs(60),
            ..linger_timers(
                LingeringClose::Off,
                Duration::from_secs(5),
                Duration::from_millis(200),
            )
        };
        let phase = Arc::new(PhaseCell::new());
        phase.set(Phase::AwaitingKeepAlive);
        let mut io = ClientIo::new(server, phase, timers, Arc::new(Mutex::new(None)));
        client.write_all(b"G").await?;
        let mut buf = [0u8; 16];
        assert_eq!(io.read(&mut buf).await?, 1);
        let first_byte = tokio::time::Instant::now();
        // The connection is not read again for 60 ms, as when the runtime is busy.
        tokio::time::advance(Duration::from_millis(60)).await;
        let error = io.read(&mut buf).await.err();
        let waited = first_byte.elapsed();
        assert_eq!(
            error.map(|error| error.kind()),
            Some(io::ErrorKind::TimedOut)
        );
        assert!(
            waited >= Duration::from_millis(100) && waited < Duration::from_millis(150),
            "the header timer ended {waited:?} after the first byte, not after the header timeout of 100 ms"
        );
        Ok(())
    }

    #[tokio::test]
    async fn bytes_read_while_a_request_is_busy_are_not_scanned_as_a_header() -> Result<(), BoxError>
    {
        let (mut client, server) = socket_pair().await?;
        let phase = Arc::new(PhaseCell::new());
        phase.set(Phase::Busy);
        let timers = linger_timers(
            LingeringClose::On,
            Duration::from_secs(5),
            Duration::from_millis(200),
        );
        let mut io = ClientIo::new(server, phase, timers, Arc::new(Mutex::new(None)));
        // Without a line break, these bytes would break the request line limit if they were scanned as a header.
        client.write_all(&[b'x'; 300]).await?;
        let mut buf = [0u8; 512];
        let mut total = 0;
        tokio::time::timeout(Duration::from_secs(10), async {
            while total < 300 {
                total += io.read(&mut buf).await?;
            }
            Ok::<(), io::Error>(())
        })
        .await??;
        assert_eq!(total, 300);
        Ok(())
    }

    #[rstest]
    #[case::vectored(true)]
    #[case::not_vectored(false)]
    fn a_client_socket_reports_whether_its_inner_socket_writes_vectored(#[case] vectored: bool) {
        let mut recorder = Recorder::new();
        recorder.vectored = vectored;
        let timers = linger_timers(
            LingeringClose::On,
            Duration::from_secs(5),
            Duration::from_millis(200),
        );
        let io = ClientIo::new(
            recorder,
            Arc::new(PhaseCell::new()),
            timers,
            Arc::new(Mutex::new(None)),
        );
        assert_eq!(io.is_write_vectored(), vectored);
    }

    #[tokio::test]
    async fn a_client_flush_reaches_the_client_socket() -> Result<(), BoxError> {
        let timers = linger_timers(
            LingeringClose::On,
            Duration::from_secs(5),
            Duration::from_millis(200),
        );
        let mut io = ClientIo::new(
            Recorder::new(),
            Arc::new(PhaseCell::new()),
            timers,
            Arc::new(Mutex::new(None)),
        );
        io.flush().await?;
        assert_eq!(io.inner.flushes, 1);
        Ok(())
    }

    #[tokio::test]
    async fn a_client_flush_does_not_touch_the_socket_while_or_after_lingering()
    -> Result<(), BoxError> {
        let timers = linger_timers(
            LingeringClose::On,
            Duration::from_secs(5),
            Duration::from_millis(200),
        );
        let mut recorder = Recorder::new();
        recorder.fail_flush = true;
        let mut io = ClientIo::new(
            recorder,
            Arc::new(PhaseCell::new()),
            timers,
            Arc::new(Mutex::new(None)),
        );
        io.begin_linger(&[], None, true);
        io.flush().await?;
        io.shutdown().await?;
        io.flush().await?;
        Ok(())
    }
}
