//! The response body wrapper that ends a connection's use once the response is sent:
//! keep-alive or close, and the `limit_conn` permits it holds.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use http_body::{Body, Frame, SizeHint};

use crate::limits::ConnPermit;

/// Ends a connection's use once its response has been sent.
///
/// The connection goes idle for keep-alive only when the request body was read in
/// full. Otherwise it is closed, since the unread rest of the body would otherwise
/// be taken for the next request.
pub(crate) struct Finish<B> {
    inner: B,
    phase: Arc<crate::phase::PhaseCell>,
    body_done: Arc<AtomicBool>,
    /// `limit_conn` counts of the request, released when the response is dropped.
    permits: Vec<ConnPermit>,
}

impl<B> Finish<B> {
    /// Wraps the response body `inner` of the request that `body_done` tracks.
    pub(crate) fn new(
        inner: B,
        phase: Arc<crate::phase::PhaseCell>,
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

    /// Ends the response's use of the connection.
    fn mark_idle(&self) {
        // A tunnelled connection is neither idle nor closing: its bytes are not requests.
        if self.phase.get() == crate::phase::Phase::Tunnelling {
            return;
        }
        let phase = if self.body_done.load(Ordering::Acquire) {
            crate::phase::Phase::AwaitingKeepAlive
        } else {
            crate::phase::Phase::Closing
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
    use bytes::Bytes;
    use http_body_util::Full;
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::an_ended_body(Bytes::new(), true)]
    #[case::a_body_with_data_left(Bytes::from_static(b"data"), false)]
    fn a_finish_body_ends_its_stream_when_the_inner_body_does(
        #[case] data: Bytes,
        #[case] ended: bool,
    ) {
        let phase = Arc::new(crate::phase::PhaseCell::new());
        let body_done = Arc::new(AtomicBool::new(true));
        let body = Finish::new(Full::new(data), phase, body_done);
        assert_eq!(body.is_end_stream(), ended);
    }
}
