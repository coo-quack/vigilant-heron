//! Where log lines go.
//!
//! Each access-log destination has one bounded queue and one writer task. A
//! request only pushes its line onto the queue: when the queue is full the line
//! is dropped and counted, so a slow disk or syslog server never delays a
//! request. The writer task reports drops periodically and reopens file
//! destinations on SIGUSR1, so `logrotate` can move a file away.

use std::fs::{File, OpenOptions as StdOpenOptions};
use std::io::{self, Write as _};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::mpsc;
use tracing_subscriber::fmt::MakeWriter;

use crate::accesslog;

/// Lines the queue holds before new lines are dropped.
pub(crate) const QUEUE_CAPACITY: usize = 4096;
/// How often drop counts are reported.
const REPORT_INTERVAL: Duration = Duration::from_secs(10);
/// The syslog facility used for every line: `local7`.
const SYSLOG_FACILITY_LOCAL7: u8 = 23;
/// The syslog severity used for every line: `info`.
const SYSLOG_SEVERITY_INFO: u8 = 6;

/// Where an access log or the error log is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
    /// A file, appended to and reopened on SIGUSR1.
    File(PathBuf),
    /// A syslog server over UDP, in RFC 3164 form.
    Syslog {
        /// `host:port` of the server.
        server: String,
        /// The tag that starts each message, `vigilant-heron` by default.
        tag: String,
    },
}

impl Destination {
    /// A name for the destination in messages.
    pub(crate) fn label(&self) -> String {
        match self {
            Self::Stdout => "stdout".to_owned(),
            Self::Stderr => "stderr".to_owned(),
            Self::File(path) => path.display().to_string(),
            Self::Syslog { server, .. } => format!("syslog:{server}"),
        }
    }
}

/// The sending side of one destination's queue.
#[derive(Debug, Clone)]
pub(crate) struct Writer {
    sender: mpsc::Sender<String>,
    dropped: Arc<AtomicU64>,
}

impl Writer {
    /// Queues one line, without the line break. Returns false when the line was dropped.
    pub(crate) fn send(&self, line: String) -> bool {
        if self.sender.try_send(line).is_ok() {
            return true;
        }
        self.dropped.fetch_add(1, Ordering::Relaxed);
        false
    }

    /// Lines dropped so far.
    #[cfg(test)]
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Creates a writer and the receiver of its queue, without starting a task.
pub(crate) fn channel_writer(capacity: usize) -> (Writer, mpsc::Receiver<String>) {
    let (sender, lines) = mpsc::channel(capacity.max(1));
    let writer = Writer {
        sender,
        dropped: Arc::new(AtomicU64::new(0)),
    };
    (writer, lines)
}

/// Starts the writer task for `destination` and returns its sender.
pub(crate) fn spawn_writer(destination: Destination) -> Writer {
    let label = destination.label();
    let (writer, lines) = channel_writer(QUEUE_CAPACITY);
    let dropped = Arc::clone(&writer.dropped);
    tokio::spawn(run_writer(destination, lines, dropped, label));
    writer
}

/// One open output.
enum Output {
    File {
        path: PathBuf,
        file: Option<tokio::fs::File>,
    },
    Stdout,
    Stderr,
    Syslog {
        socket: UdpSocket,
        tag: String,
    },
    Unavailable {
        destination: Destination,
    },
}

impl Output {
    async fn open(destination: &Destination) -> Self {
        match destination {
            Destination::Stdout => Self::Stdout,
            Destination::Stderr => Self::Stderr,
            Destination::File(path) => Self::File {
                path: path.clone(),
                file: open_file(path).await,
            },
            Destination::Syslog { server, tag } => match open_syslog(server).await {
                Some(socket) => Self::Syslog {
                    socket,
                    tag: tag.clone(),
                },
                None => Self::Unavailable {
                    destination: destination.clone(),
                },
            },
        }
    }

    async fn write(&mut self, line: &str, label: &str) {
        match self {
            Self::File { path, file } => {
                if file.is_none() {
                    *file = open_file(path).await;
                }
                if let Some(handle) = file {
                    let mut bytes = line.as_bytes().to_vec();
                    bytes.push(b'\n');
                    let result = async {
                        handle.write_all(&bytes).await?;
                        handle.flush().await
                    }
                    .await;
                    if let Err(error) = result {
                        tracing::error!(destination = label, %error, "cannot write access log line");
                    }
                } else {
                    tracing::error!(
                        destination = label,
                        "cannot open access log file; line dropped"
                    );
                }
            }
            Self::Stdout => write_stream(tokio::io::stdout(), line).await,
            Self::Stderr => write_stream(tokio::io::stderr(), line).await,
            Self::Syslog { socket, tag } => {
                let message = format!(
                    "<{}>{} {}: {}",
                    u16::from(SYSLOG_FACILITY_LOCAL7) * 8 + u16::from(SYSLOG_SEVERITY_INFO),
                    accesslog::syslog_stamp(SystemTime::now()),
                    tag,
                    line
                );
                if let Err(error) = socket.send(message.as_bytes()).await {
                    tracing::error!(destination = label, %error, "cannot send access log line to syslog");
                }
            }
            Self::Unavailable { destination } => {
                tracing::error!(
                    destination = label,
                    "syslog server unavailable; line dropped"
                );
                let _ = destination;
            }
        }
    }

    async fn reopen(&mut self) {
        if let Self::File { path, file } = self {
            *file = None;
            *file = open_file(path).await;
        }
    }
}

async fn write_stream<W: tokio::io::AsyncWrite + Unpin>(mut stream: W, line: &str) {
    let mut bytes = line.as_bytes().to_vec();
    bytes.push(b'\n');
    let _ = stream.write_all(&bytes).await;
    let _ = stream.flush().await;
}

async fn open_file(path: &PathBuf) -> Option<tokio::fs::File> {
    tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
        .ok()
}

async fn open_syslog(server: &str) -> Option<UdpSocket> {
    let target: SocketAddr = tokio::net::lookup_host(server).await.ok()?.next()?;
    let bind = if target.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind).await.ok()?;
    socket.connect(target).await.ok()?;
    Some(socket)
}

/// Waits for SIGUSR1, or never resolves when the signal could not be registered.
async fn sigusr1(signal: &mut Option<Signal>) {
    match signal {
        Some(stream) => {
            stream.recv().await;
        }
        None => std::future::pending::<()>().await,
    }
}

async fn run_writer(
    destination: Destination,
    mut lines: mpsc::Receiver<String>,
    dropped: Arc<AtomicU64>,
    label: String,
) {
    let mut output = Output::open(&destination).await;
    let mut usr1 = signal(SignalKind::user_defined1()).ok();
    let mut report = tokio::time::interval(REPORT_INTERVAL);
    let mut reported = 0_u64;
    loop {
        tokio::select! {
            line = lines.recv() => match line {
                Some(line) => output.write(&line, &label).await,
                None => break,
            },
            () = sigusr1(&mut usr1) => output.reopen().await,
            _ = report.tick() => {
                let total = dropped.load(Ordering::Relaxed);
                if total > reported {
                    tracing::warn!(destination = label.as_str(), dropped = total - reported, "access log lines dropped: queue full");
                    reported = total;
                }
            }
        }
    }
}

/// The error log: where `tracing` events are written.
#[derive(Debug, Clone)]
enum ErrorSink {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
    /// A file, reopened on SIGUSR1.
    File {
        /// Where the file is.
        path: PathBuf,
        /// The open file, when there is one.
        file: Arc<Mutex<Option<File>>>,
    },
}

/// Handle to the error log, used to reopen its file.
#[derive(Debug, Clone)]
pub struct ErrorLogHandle {
    sink: ErrorSink,
}

impl ErrorLogHandle {
    /// Reopens the error log file, after logrotate moved it away. Other destinations do nothing.
    pub fn reopen(&self) {
        self.sink.reopen();
    }
}

/// Sends `tracing` output to the `error_log` destination at its level, and returns a
/// handle for reopening it. Call it once, before the runtime starts.
#[must_use]
pub fn install_error_log(config: &crate::config::ErrorLogConfig) -> ErrorLogHandle {
    let level = match config.level {
        crate::config::LogLevel::Error => tracing::Level::ERROR,
        crate::config::LogLevel::Warn => tracing::Level::WARN,
        crate::config::LogLevel::Info => tracing::Level::INFO,
        crate::config::LogLevel::Debug => tracing::Level::DEBUG,
    };
    let sink = ErrorSink::open(&config.destination);
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_ansi(false)
        .with_writer(sink.clone())
        .finish();
    // Only the first installation takes effect; later calls leave the existing subscriber.
    let _ = tracing::subscriber::set_global_default(subscriber);
    ErrorLogHandle { sink }
}

impl ErrorSink {
    /// Opens the error log for `destination`.
    fn open(destination: &Destination) -> Self {
        match destination {
            Destination::Stdout => Self::Stdout,
            Destination::File(path) => Self::File {
                path: path.clone(),
                file: Arc::new(Mutex::new(open_std_file(path))),
            },
            _ => Self::Stderr,
        }
    }

    /// Reopens the file, after logrotate moved it away.
    fn reopen(&self) {
        if let Self::File { path, file } = self {
            let mut guard = file.lock().unwrap_or_else(PoisonError::into_inner);
            *guard = open_std_file(path);
        }
    }

    fn write_all(&self, bytes: &[u8]) {
        match self {
            Self::Stdout => {
                let _ = io::stdout().write_all(bytes);
            }
            Self::Stderr => {
                let _ = io::stderr().write_all(bytes);
            }
            Self::File { file, .. } => {
                let mut guard = file.lock().unwrap_or_else(PoisonError::into_inner);
                if let Some(handle) = guard.as_mut() {
                    let _ = handle.write_all(bytes);
                }
            }
        }
    }
}

#[must_use]
fn open_std_file(path: &PathBuf) -> Option<File> {
    StdOpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .ok()
}

/// Buffers one `tracing` event and writes it in one call.
struct EventWriter {
    buffer: Vec<u8>,
    sink: ErrorSink,
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
        self.sink.write_all(&self.buffer);
    }
}

impl<'a> MakeWriter<'a> for ErrorSink {
    type Writer = EventWriter;

    fn make_writer(&'a self) -> Self::Writer {
        EventWriter {
            buffer: Vec::new(),
            sink: self.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_full_queue_drops_lines_and_counts_them() {
        let (writer, _lines) = channel_writer(1);
        assert!(writer.send("first".to_owned()));
        assert!(!writer.send("second".to_owned()));
        assert!(!writer.send("third".to_owned()));
        assert_eq!(writer.dropped(), 2);
    }

    #[tokio::test]
    async fn a_queue_with_room_keeps_every_line() {
        let (writer, mut lines) = channel_writer(8);
        for n in 0..5 {
            assert!(writer.send(format!("line {n}")));
        }
        assert_eq!(writer.dropped(), 0);
        assert_eq!(lines.recv().await, Some("line 0".to_owned()));
    }

    #[tokio::test]
    async fn file_destination_is_reopened_after_the_file_is_moved()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!("vh-reopen-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("access.log");
        let moved = dir.join("access.log.1");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&moved);
        let writer = spawn_writer(Destination::File(path.clone()));
        writer.send("before".to_owned());
        // Wait until the first line is on disk.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !std::fs::read_to_string(&path).is_ok_and(|s| s.contains("before")) {
            if std::time::Instant::now() > deadline {
                return Err("first line never reached the file".into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        std::fs::rename(&path, &moved)?;
        // SIGUSR1 is what logrotate sends; the writer task listens for it.
        let status = std::process::Command::new("kill")
            .args(["-USR1", &std::process::id().to_string()])
            .status()?;
        assert!(status.success(), "kill -USR1 failed");
        tokio::time::sleep(Duration::from_millis(100)).await;
        writer.send("after".to_owned());
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !std::fs::read_to_string(&path).is_ok_and(|s| s.contains("after")) {
            if std::time::Instant::now() > deadline {
                return Err("line after reopen never reached the new file".into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(std::fs::read_to_string(&moved)?.contains("before"));
        assert!(!std::fs::read_to_string(&moved)?.contains("after"));
        Ok(())
    }
}
