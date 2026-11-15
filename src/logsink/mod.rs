//! Where log lines go: the access-log queues in [`access_log`] and the error log in
//! [`error_log`].

mod access_log;
mod error_log;

pub(crate) use access_log::{Writer, spawn_writer};
pub use error_log::{ErrorLogHandle, install_error_log};
