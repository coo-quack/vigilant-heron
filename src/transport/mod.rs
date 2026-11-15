//! The client socket wrapper that enforces connection timers and header limits.
//!
//! [`ClientIo`] wraps a client socket. It bounds the wait for a request header
//! (`client_header_timeout`), the idle time between requests (`keepalive_timeout`),
//! the wait between writes (`send_timeout`), and checks the request line and
//! header fields against `large_client_header_buffers` before hyper parses them.
//! When a connection closes while client data may still arrive, [`ClientIo`]
//! lingers first (`lingering_close`): it half-closes after the response and discards
//! the client's bytes until the client closes or a bound passes.
//! Body timers live in [`crate::body`].
//!
//! hyper's own header timeout is not used: it also runs while a connection is
//! idle, so it cannot tell the header timer from the keep-alive timer, and it
//! answers oversized headers with 431 rather than nginx's 414 and 400.

mod client;
mod head;

pub(crate) use client::{ClientIo, ClientTimers, Rejection, RejectionSlot, expired};

/// hyper's default read buffer per connection (`DEFAULT_MAX_BUFFER_SIZE` in hyper 1.12).
pub(crate) const HYPER_DEFAULT_BUFFER: usize = 8192 + 4096 * 100;

#[cfg(test)]
/// A helper that the tests of the submodules share.
pub(crate) mod test_helpers {
    use super::head::HeadLimits;

    pub(crate) fn limits(line: usize, total: usize) -> HeadLimits {
        HeadLimits { line, total }
    }
}
