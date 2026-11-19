//! The error log: the `tracing` subscriber's output, with its reload and SIGUSR1 reopen.

use std::fs::File;
use std::io::{self, Write as _};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tracing_subscriber::Registry;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::reload;

use super::append_options;
use crate::config::{Destination, ErrorLogConfig, LogLevel};
use crate::error::ConfigError;
use crate::sync::lock;

/// The error log's output. Every write and every reopen takes the lock, so a
/// line is never split, and a swap to another destination never lands inside one.
#[derive(Debug)]
enum ErrorSink {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
    /// A file, appended to and reopened on SIGUSR1.
    File {
        /// Where the file is.
        path: PathBuf,
        /// The open file, when there is one.
        file: Option<File>,
    },
}

impl ErrorSink {
    /// Opens `destination`. A file that cannot be opened is an error.
    fn open(destination: &Destination) -> io::Result<Self> {
        match destination {
            Destination::Stdout => Ok(Self::Stdout),
            Destination::File(path) => Ok(Self::File {
                path: path.clone(),
                file: Some(append_options().open(path)?),
            }),
            _ => Ok(Self::Stderr),
        }
    }

    /// Reopens the file, after logrotate moved it away.
    fn reopen(&mut self) {
        if let Self::File { path, file } = self {
            *file = append_options().open(path).ok();
        }
    }

    fn write_all(&mut self, bytes: &[u8]) {
        match self {
            Self::Stdout => {
                let _ = io::stdout().write_all(bytes);
            }
            Self::Stderr => {
                let _ = io::stderr().write_all(bytes);
            }
            Self::File {
                file: Some(handle), ..
            } => {
                let _ = handle.write_all(bytes);
            }
            Self::File { file: None, .. } => {}
        }
    }
}

/// A checked `error_log` destination and level, waiting for [`ErrorLogHandle::commit`].
#[derive(Debug)]
struct Staged {
    sink: ErrorSink,
    level: LevelFilter,
}

/// Handle to the error log. It reopens the file on SIGUSR1, and applies the
/// `error_log` of a reloaded configuration: [`stage`](Self::stage) checks it and
/// [`commit`](Self::commit) switches to it.
#[derive(Clone)]
pub struct ErrorLogHandle {
    sink: Arc<Mutex<ErrorSink>>,
    level: reload::Handle<LevelFilter, Registry>,
    staged: Arc<Mutex<Option<Staged>>>,
}

impl ErrorLogHandle {
    /// Reopens the error log file, after logrotate moved it away. Other destinations do nothing.
    pub fn reopen(&self) {
        lock(&self.sink).reopen();
    }

    /// Opens the destination of `config` and keeps it for [`commit`](Self::commit).
    /// Nothing that is written changes until `commit`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::ErrorLog`] when the destination cannot be opened.
    pub fn stage(&self, config: &ErrorLogConfig) -> Result<(), ConfigError> {
        let sink =
            ErrorSink::open(&config.destination).map_err(|source| ConfigError::ErrorLog {
                destination: config.destination.label(),
                source,
            })?;
        *lock(&self.staged) = Some(Staged {
            sink,
            level: level_filter(config.level),
        });
        Ok(())
    }

    /// Switches to the staged destination and level. Messages logged after this
    /// call go to the new destination. Does nothing when nothing is staged.
    pub fn commit(&self) {
        let Some(staged) = lock(&self.staged).take() else {
            return;
        };
        // The previous file is closed when its sink is dropped here.
        *lock(&self.sink) = staged.sink;
        // Applying the level cannot fail: the handle's subscriber is alive while this handle is.
        let _ = self.level.modify(|filter| *filter = staged.level);
    }
}

/// Sends `tracing` output to the `error_log` destination at its level, and returns
/// a handle that reloads them. Call it once, before the runtime starts: a second
/// call leaves the first subscriber in place, and its handle changes nothing.
///
/// # Errors
///
/// Returns [`ConfigError::ErrorLog`] when a file destination cannot be opened.
pub fn install_error_log(config: &ErrorLogConfig) -> Result<ErrorLogHandle, ConfigError> {
    let sink = Arc::new(Mutex::new(ErrorSink::Stderr));
    let (level_layer, level) = reload::Layer::new(level_filter(config.level));
    let subscriber = tracing_subscriber::registry().with(level_layer).with(
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(SharedSink(Arc::clone(&sink))),
    );
    let _ = tracing::subscriber::set_global_default(subscriber);
    let handle = ErrorLogHandle {
        sink,
        level,
        staged: Arc::new(Mutex::new(None)),
    };
    handle.stage(config)?;
    handle.commit();
    Ok(handle)
}

/// The `tracing` filter for an `error_log` level.
fn level_filter(level: LogLevel) -> LevelFilter {
    match level {
        LogLevel::Error => LevelFilter::ERROR,
        LogLevel::Warn => LevelFilter::WARN,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Debug => LevelFilter::DEBUG,
    }
}

/// The writer shared by every event: each event is written through the lock.
#[derive(Clone)]
struct SharedSink(Arc<Mutex<ErrorSink>>);

/// Buffers one `tracing` event and writes it in one call.
struct EventWriter {
    buffer: Vec<u8>,
    sink: Arc<Mutex<ErrorSink>>,
}

impl io::Write for EventWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for EventWriter {
    fn drop(&mut self) {
        lock(&self.sink).write_all(&self.buffer);
    }
}

impl<'a> MakeWriter<'a> for SharedSink {
    type Writer = EventWriter;

    fn make_writer(&'a self) -> Self::Writer {
        EventWriter {
            buffer: Vec::new(),
            sink: Arc::clone(&self.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_error_log_file_that_cannot_be_opened_is_named_by_its_path() {
        let (_layer, level) = reload::Layer::new(LevelFilter::ERROR);
        let handle = ErrorLogHandle {
            sink: Arc::new(Mutex::new(ErrorSink::Stderr)),
            level,
            staged: Arc::new(Mutex::new(None)),
        };
        let config = ErrorLogConfig {
            destination: Destination::File(PathBuf::from("/nonexistent-vh-dir/error.log")),
            level: LogLevel::Error,
        };
        let message = match handle.stage(&config) {
            Err(error) => error.to_string(),
            Ok(()) => String::new(),
        };
        assert!(
            message.starts_with("cannot open error log /nonexistent-vh-dir/error.log: "),
            "{message}"
        );
    }
}
