//! A mutex lock that ignores poisoning.

use std::sync::{Mutex, MutexGuard, PoisonError};

/// Locks a mutex, ignoring poisoning: the guarded values stay valid after a panic elsewhere.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
