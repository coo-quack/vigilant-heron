//! The phase of a client connection: what it is waiting for, and the cell that
//! shares it between the client socket and the code that handles its requests.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, Ordering};
use std::task::Waker;

use crate::sync::lock;

const PHASE_HEADER: u8 = 0;
const PHASE_KEEP_ALIVE: u8 = 1;
const PHASE_BUSY: u8 = 2;
const PHASE_CLOSING: u8 = 3;
const PHASE_TUNNEL: u8 = 4;

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
    /// The connection has been upgraded and spliced into a tunnel. The bytes that
    /// follow are not a request: they are neither timed nor scanned.
    Tunnelling,
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
    pub(crate) fn watch(&self, waker: &Waker) {
        *lock(&self.waker) = Some(waker.clone());
    }

    /// Returns the current phase.
    pub(crate) fn get(&self) -> Phase {
        match self.phase.load(Ordering::Acquire) {
            PHASE_KEEP_ALIVE => Phase::AwaitingKeepAlive,
            PHASE_BUSY => Phase::Busy,
            PHASE_CLOSING => Phase::Closing,
            PHASE_TUNNEL => Phase::Tunnelling,
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
            Phase::Tunnelling => PHASE_TUNNEL,
        };
        self.phase.store(code, Ordering::Release);
        // A parked reader may have no timer armed for the new phase, so it is woken.
        if let Some(waker) = lock(&self.waker).take() {
            waker.wake();
        }
    }

    /// Moves an idle connection to the wait for a header. Returns false in any other phase.
    pub(crate) fn begin_header(&self) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_busy_connection_reports_the_busy_phase() {
        let cell = PhaseCell::new();
        cell.set(Phase::Busy);
        assert_eq!(cell.get(), Phase::Busy);
    }

    #[test]
    fn only_an_idle_connection_moves_back_to_the_header_wait() {
        let cell = PhaseCell::new();
        assert!(
            !cell.begin_header(),
            "a connection awaiting its first header is not idle"
        );
        cell.set(Phase::AwaitingKeepAlive);
        assert!(cell.begin_header());
        assert_eq!(cell.get(), Phase::AwaitingHeader);
        cell.set(Phase::Busy);
        assert!(!cell.begin_header(), "a busy connection is not idle");
    }
}
