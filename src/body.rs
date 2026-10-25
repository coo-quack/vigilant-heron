//! Request and response bodies with frame timers and the client body limit.
//!
//! A request body is read in two steps. The first `inspect_body` bytes are
//! sniffed for the decision, and the rest stays unread until the upstream
//! asks for it, so a request is forwarded without being buffered in memory.

use std::collections::VecDeque;
use std::error::Error;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt, combinators::UnsyncBoxBody};
use hyper::body::Incoming;
use tokio::time::Sleep;

use crate::limits::ConnPermit;
use crate::transport::expired;

/// An error that a body can return.
pub(crate) type BoxError = Box<dyn Error + Send + Sync>;

/// Wraps a body and fails when no frame arrives within `timeout` of the last one.
pub(crate) struct FrameTimeout<B> {
    inner: B,
    timeout: Duration,
    sleep: Option<Pin<Box<Sleep>>>,
}

impl<B> FrameTimeout<B> {
    /// Wraps `inner`, which must produce its next frame within `timeout`.
    pub(crate) fn new(inner: B, timeout: Duration) -> Self {
        Self {
            inner,
            timeout,
            sleep: None,
        }
    }
}

impl<B> Body for FrameTimeout<B>
where
    B: Body + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = B::Data;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, BoxError>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(frame) => {
                this.sleep = None;
                Poll::Ready(frame.map(|item| item.map_err(Into::into)))
            }
            Poll::Pending => {
                if expired(&mut this.sleep, this.timeout, cx) {
                    Poll::Ready(Some(Err(Box::new(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "body read timed out",
                    )))))
                } else {
                    Poll::Pending
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// The request body grew past `client_max_body_size`.
#[derive(Debug)]
pub(crate) struct BodyTooLarge;

impl fmt::Display for BodyTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("client request body is larger than client_max_body_size")
    }
}

impl Error for BodyTooLarge {}

/// Why a request body could not be read in full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyFault {
    /// The body is larger than `client_max_body_size`.
    TooLarge,
    /// The client stopped sending for longer than `client_body_timeout`.
    TimedOut,
    /// The connection failed or the client sent a malformed body.
    Failed,
}

/// The fault of a request body, shared with whoever forwards it.
pub(crate) type FaultSlot = Arc<Mutex<Option<BodyFault>>>;

/// The first bytes of a request body, read for the decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Sniffed {
    /// At most `inspect_body` bytes from the start of the body.
    pub(crate) prefix: Bytes,
    /// Whether the body continues past `prefix`.
    pub(crate) truncated: bool,
}

impl Sniffed {
    /// True when the request has no body at all.
    pub(crate) fn is_empty_body(&self) -> bool {
        self.prefix.is_empty() && !self.truncated
    }
}

/// A request body read from the client, limited and timed.
///
/// Frames read for the decision are kept and replayed in front of the rest,
/// so the upstream receives the whole body.
pub(crate) struct ClientBody {
    /// Frames already read from the client that are still to be sent on.
    replay: VecDeque<Bytes>,
    inner: FrameTimeout<Incoming>,
    limit: Option<usize>,
    received: usize,
    done: Arc<AtomicBool>,
    fault: FaultSlot,
}

impl ClientBody {
    /// Wraps the request body. `done` is set once the body has been read in full,
    /// and starts `true` when the request has no body.
    pub(crate) fn new(
        incoming: Incoming,
        timeout: Duration,
        limit: Option<usize>,
        done: Arc<AtomicBool>,
    ) -> Self {
        Self {
            replay: VecDeque::new(),
            inner: FrameTimeout::new(incoming, timeout),
            limit,
            received: 0,
            done,
            fault: Arc::new(Mutex::new(None)),
        }
    }

    /// Returns the fault slot, which stays readable after the body is moved.
    pub(crate) fn fault_slot(&self) -> FaultSlot {
        Arc::clone(&self.fault)
    }

    /// Reads up to `inspect` bytes for the decision and keeps the rest for forwarding.
    ///
    /// Reading stops as soon as more than `inspect` bytes are known, so at most
    /// one frame beyond the limit is buffered.
    ///
    /// # Errors
    ///
    /// Returns [`BodyTooLarge`], a timeout, or the read error.
    pub(crate) async fn sniff(&mut self, inspect: usize) -> Result<Sniffed, BoxError> {
        let mut frames: Vec<Bytes> = Vec::new();
        let mut total = 0usize;
        while total <= inspect {
            match self.frame().await {
                None => break,
                Some(Err(error)) => return Err(error),
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        total = total.saturating_add(data.len());
                        frames.push(data);
                    }
                }
            }
        }
        let truncated = total > inspect;
        let mut buffer = BytesMut::with_capacity(total);
        for data in &frames {
            buffer.extend_from_slice(data);
        }
        // The whole buffer is replayed, so the upstream gets every byte. The prefix
        // shares the buffer, so it costs no copy.
        let read = buffer.freeze();
        let prefix = read.slice(..read.len().min(inspect));
        if !read.is_empty() {
            self.replay.push_front(read);
        }
        Ok(Sniffed { prefix, truncated })
    }

    /// Whether the body has been read in full.
    pub(crate) fn is_complete(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }

    /// Converts the body for the upstream request.
    pub(crate) fn into_unsync(self) -> UnsyncBoxBody<Bytes, BoxError> {
        self.boxed_unsync()
    }

    /// Records a fault, keeping the first one.
    fn fail(&self, fault: BodyFault) {
        let mut slot = self
            .fault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        slot.get_or_insert(fault);
    }
}

impl Body for ClientBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        if let Some(bytes) = this.replay.pop_front() {
            return Poll::Ready(Some(Ok(Frame::data(bytes))));
        }
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.received = this.received.saturating_add(data.len());
                    if this.limit.is_some_and(|max| this.received > max) {
                        this.fail(BodyFault::TooLarge);
                        return Poll::Ready(Some(Err(Box::new(BodyTooLarge))));
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                let timed_out = error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|io| io.kind() == io::ErrorKind::TimedOut);
                this.fail(if timed_out {
                    BodyFault::TimedOut
                } else {
                    BodyFault::Failed
                });
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                this.done.store(true, Ordering::Release);
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.replay.is_empty() && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        let replayed: u64 = self.replay.iter().map(|bytes| bytes.len() as u64).sum();
        let inner = self.inner.size_hint();
        let mut hint = SizeHint::new();
        hint.set_lower(inner.lower().saturating_add(replayed));
        if let Some(upper) = inner.upper() {
            hint.set_upper(upper.saturating_add(replayed));
        }
        hint
    }
}

/// Ends a connection's use once its response has been sent.
///
/// The connection goes idle for keep-alive only when the request body was read in
/// full. Otherwise it is closed, since the unread rest of the body would otherwise
/// be taken for the next request.
pub(crate) struct Finish<B> {
    inner: B,
    phase: Arc<crate::transport::PhaseCell>,
    body_done: Arc<AtomicBool>,
    /// `limit_conn` counts of the request, released when the response is dropped.
    permits: Vec<ConnPermit>,
}

impl<B> Finish<B> {
    /// Wraps the response body `inner` of the request that `body_done` tracks.
    pub(crate) fn new(
        inner: B,
        phase: Arc<crate::transport::PhaseCell>,
        body_done: Arc<AtomicBool>,
    ) -> Self {
        Self {
            inner,
            phase,
            body_done,
            permits: Vec::new(),
        }
    }

    /// Keeps the `limit_conn` counts of the request until this body is dropped.
    pub(crate) fn holding(mut self, permits: Vec<ConnPermit>) -> Self {
        self.permits = permits;
        self
    }

    /// Ends the response's use of the connection: idle for keep-alive when the request
    /// body was read in full, otherwise closing.
    fn mark_idle(&self) {
        let phase = if self.body_done.load(Ordering::Acquire) {
            crate::transport::Phase::AwaitingKeepAlive
        } else {
            crate::transport::Phase::Closing
        };
        self.phase.set(phase);
    }
}

impl<B: Body + Unpin> Body for Finish<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let item = Pin::new(&mut this.inner).poll_frame(cx);
        if matches!(item, Poll::Ready(None)) {
            this.mark_idle();
        }
        item
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl<B> Drop for Finish<B> {
    fn drop(&mut self) {
        self.mark_idle();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_sniff_is_an_empty_body() {
        let sniffed = Sniffed {
            prefix: Bytes::new(),
            truncated: false,
        };
        assert!(sniffed.is_empty_body());
        let truncated = Sniffed {
            prefix: Bytes::new(),
            truncated: true,
        };
        assert!(!truncated.is_empty_body());
    }
}
