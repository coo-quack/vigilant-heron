//! The log writers: the access log (`accesslog`: the `log_format` compiler, its
//! variables and escaping, and the built-in formats) and the log destinations
//! (`logsink`: the access-log queues, the error log with its reloadable level,
//! and reopening on SIGUSR1).

pub(crate) mod accesslog;
pub(crate) mod logsink;
