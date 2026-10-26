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
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::mpsc;
use tracing_subscriber::Registry;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::reload;

use crate::accesslog;
use crate::config::{ErrorLogConfig, LogLevel};
use crate::error::ConfigError;
use crate::transport::lock;

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
    /// A syslog destination whose server could not be reached when it was opened.
    Unavailable,
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
                None => Self::Unavailable,
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
            Self::Unavailable => {
                tracing::error!(
                    destination = label,
                    "syslog server unavailable; line dropped"
                );
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
                file: Some(open_std_file(path)?),
            }),
            _ => Ok(Self::Stderr),
        }
    }

    /// Reopens the file, after logrotate moved it away.
    fn reopen(&mut self) {
        if let Self::File { path, file } = self {
            *file = open_std_file(path).ok();
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
    // Only the first installation takes effect.
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

fn open_std_file(path: &PathBuf) -> io::Result<File> {
    StdOpenOptions::new().create(true).append(true).open(path)
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

    #[tokio::test]
    async fn a_stream_line_is_written_with_its_line_break() {
        use tokio::io::AsyncReadExt as _;

        let (writer_end, mut reader_end) = tokio::io::duplex(64);
        write_stream(writer_end, "access line").await;
        let mut written = String::new();
        let read = reader_end.read_to_string(&mut written).await;
        assert!(read.is_ok());
        assert_eq!(written, "access line\n");
    }

    #[tokio::test]
    async fn a_syslog_destination_sends_each_line_to_the_server()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = UdpSocket::bind("127.0.0.1:0").await?;
        let address = server.local_addr()?;
        let writer = spawn_writer(Destination::Syslog {
            server: address.to_string(),
            tag: "test-tag".to_owned(),
        });
        assert!(writer.send("access line".to_owned()));
        let mut buffer = [0_u8; 2048];
        let received =
            tokio::time::timeout(Duration::from_secs(5), server.recv(&mut buffer)).await??;
        let message = buffer
            .get(..received)
            .ok_or("datagram longer than the buffer")?;
        let message = std::str::from_utf8(message)?;
        assert!(
            message.starts_with('<') && message.ends_with("test-tag: access line"),
            "{message}"
        );
        Ok(())
    }

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
