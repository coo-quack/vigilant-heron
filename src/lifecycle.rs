//! `start`, `stop` and `restart`: run the router in the background on this host.
//!
//! A background router is a child of `start` that keeps running after `start`
//! returns. It is put in its own process group, so a Ctrl-C in the terminal does not
//! reach it, and its standard input and output are not kept. Its pid file is the
//! only handle that `stop` and `restart` use, as `-s` uses it. Under Docker or systemd,
//! run the router in the foreground instead.
//!
//! Signals go through `rustix`, as in [`crate::cli`], so no `unsafe` code is needed.

use std::io::{ErrorKind, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use crate::pidfile;
use anyhow::{Context, anyhow, bail};
use rustix::io::Errno;
use rustix::process::{Pid, Signal, kill_process, test_kill_process};
use vigilant_heron::{Config, Destination};

/// How long `start` waits for the child to write its pid file.
const START_TIMEOUT: Duration = Duration::from_secs(10);
/// The wait `stop` allows when `worker_shutdown_timeout` is not set.
const DEFAULT_STOP_TIMEOUT: Duration = Duration::from_secs(30);
/// Added to the shutdown timeout, so that `stop` waits for the router to finish closing.
const STOP_MARGIN: Duration = Duration::from_secs(5);
/// How often the waits look at the process or the pid file.
const POLL: Duration = Duration::from_millis(50);

/// Removes a file when it goes out of scope, so the startup log never outlives `start`.
struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Checks the configuration as `-t` does, and returns it. Nothing is started on failure.
fn check_configuration(path: &Path) -> anyhow::Result<Config> {
    Config::load(path)
        .map_err(|error| anyhow!("{error}\nconfiguration file {} test failed", path.display()))
}

/// Reads the pid of a running router named by the pid file. A missing or stale file gives
/// `None`: a router counts as running only while it holds the lock of the pid file, so a
/// pid that a crashed router left behind is never taken for a live process. A process owned
/// by another user still counts as live. A malformed file, or one that [`pidfile::read_pid`]
/// does not trust, is an error, and nothing is signalled.
fn live_pid(pid_file: &Path) -> anyhow::Result<Option<i32>> {
    let raw = match pidfile::read_pid(pid_file) {
        Ok(raw) => raw,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("the pid file {}", pid_file.display()));
        }
    };
    let locked = pidfile::lock_held(pid_file)
        .with_context(|| format!("the lock of the pid file {}", pid_file.display()))?;
    if !locked {
        return Ok(None);
    }
    let pid = Pid::from_raw(raw).ok_or_else(|| anyhow!("invalid process id {raw}"))?;
    match test_kill_process(pid) {
        Ok(()) | Err(Errno::PERM) => Ok(Some(raw)),
        Err(Errno::SRCH) => Ok(None),
        Err(error) => Err(anyhow!("checking process {raw}: {error}")),
    }
}

/// Prints one line of status to stdout.
fn say(message: &str) {
    let _ = writeln!(std::io::stdout(), "{message}");
}

/// Whether the pid file names `pid`.
fn pid_file_holds(pid_file: &Path, pid: u32) -> bool {
    std::fs::read_to_string(pid_file)
        .is_ok_and(|text| text.trim().parse::<u32>().is_ok_and(|found| found == pid))
}

/// Polls `done` every `step` until it returns true or `limit` has passed. Returns whether it
/// returned true. `done` is called at least once, even when `limit` is zero.
pub(crate) fn wait_until(limit: Duration, step: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    loop {
        if done() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(step);
    }
}

/// Starts the router in the background with the configuration at `config_path`.
///
/// # Errors
///
/// Returns an error, and starts nothing, when the configuration is invalid, when a
/// live router already has the pid file, or when the child exits or does not write
/// its pid file in time. The child's startup messages are included in the error.
pub(crate) fn start(config_path: &Path) -> anyhow::Result<ExitCode> {
    let config = check_configuration(config_path)?;
    let pid_file = vigilant_heron::process_settings(config_path)
        .with_context(|| format!("loading {}", config_path.display()))?
        .pid_file;
    if let Some(pid) = live_pid(&pid_file)? {
        bail!("already running (pid {pid})");
    }
    let log_path = startup_log_path(&pid_file);
    let log = RemoveOnDrop(log_path.clone());
    let startup_log = pidfile::create_exclusive(&log_path)
        .with_context(|| format!("creating {}", log_path.display()))?;
    let mut child =
        Command::new(std::env::current_exe().context("finding the vigilant-heron binary")?)
            .arg("-c")
            .arg(config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(startup_log))
            .process_group(0)
            .spawn()
            .context("starting the router")?;
    let pid = child.id();
    // Once `try_wait` has reaped the child, its pid may belong to another process, so it is not signalled.
    let mut reaped = false;
    let started = wait_until(START_TIMEOUT, POLL, || {
        if pid_file_holds(&pid_file, pid) {
            return true;
        }
        match child.try_wait() {
            Ok(Some(_status)) => {
                reaped = true;
                true
            }
            _ => false,
        }
    });
    let startup_messages = std::fs::read_to_string(&log.0).unwrap_or_default();
    if !pid_file_holds(&pid_file, pid) {
        if !reaped {
            let _ = kill_process(pid_of(pid)?, Signal::TERM);
        }
        let detail = startup_messages.trim();
        if started {
            bail!("the router exited while starting: {detail}");
        }
        bail!(
            "the router did not write {} within {} seconds{}",
            pid_file.display(),
            START_TIMEOUT.as_secs(),
            if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        );
    }
    drop(log);
    warn_about_lost_output(&config);
    say(&format!("started (pid {pid})"));
    Ok(ExitCode::SUCCESS)
}

/// A background process loses what it writes to a standard stream, so say so when the
/// configuration sends its logs there.
fn warn_about_lost_output(config: &Config) {
    let lost = |destination: &Destination| {
        matches!(destination, Destination::Stdout | Destination::Stderr)
    };
    let mut stderr = std::io::stderr();
    if lost(&config.error_log.destination) {
        let _ = writeln!(
            stderr,
            "vigilant-heron: warning: error_log writes to a standard stream, which a background router does not keep; set error_log to a file"
        );
    }
    if config.access_logs.iter().any(|log| lost(&log.destination)) {
        let _ = writeln!(
            stderr,
            "vigilant-heron: warning: access_log writes to a standard stream, which a background router does not keep; set access_log to a file"
        );
    }
}

/// The startup log of this `start`, next to the pid file. The name carries this
/// process's id, so concurrent starts do not share one.
fn startup_log_path(pid_file: &Path) -> PathBuf {
    pid_file.with_file_name(format!(".vigilant-heron-start-{}.log", std::process::id()))
}

fn pid_of(raw: u32) -> anyhow::Result<Pid> {
    let value = i32::try_from(raw).context("process id out of range")?;
    Pid::from_raw(value).ok_or_else(|| anyhow!("invalid process id {raw}"))
}

/// Stops the background router, gracefully, and waits until it has exited.
///
/// With no pid file, or a stale one, the router is not running: that prints
/// `not running` and succeeds, as `systemctl stop` does.
///
/// # Errors
///
/// Returns an error when the pid file is malformed, the configuration cannot be read,
/// or the router is still running after the wait. The router is not killed then.
pub(crate) fn stop(config_path: &Path) -> anyhow::Result<ExitCode> {
    let settings = vigilant_heron::process_settings(config_path)
        .with_context(|| format!("loading {}", config_path.display()))?;
    let Some(raw) = live_pid(&settings.pid_file)? else {
        say("not running");
        return Ok(ExitCode::SUCCESS);
    };
    let pid = Pid::from_raw(raw).ok_or_else(|| anyhow!("invalid process id {raw}"))?;
    match kill_process(pid, Signal::QUIT) {
        Ok(()) => {}
        Err(Errno::SRCH) => {
            say("not running");
            return Ok(ExitCode::SUCCESS);
        }
        Err(error) => return Err(anyhow!("sending SIGQUIT to process {raw}: {error}")),
    }
    let limit = stop_limit(settings.worker_shutdown_timeout);
    let gone = wait_until(limit, POLL, || {
        matches!(test_kill_process(pid), Err(Errno::SRCH))
    });
    if !gone {
        bail!(
            "process {raw} is still running {} seconds after stop; it was not killed",
            limit.as_secs()
        );
    }
    say(&format!("stopped (pid {raw})"));
    Ok(ExitCode::SUCCESS)
}

/// How long `stop` waits: the shutdown timeout plus the margin, or the default when none is set.
pub(crate) fn stop_limit(shutdown_timeout: Option<Duration>) -> Duration {
    shutdown_timeout.unwrap_or(DEFAULT_STOP_TIMEOUT) + STOP_MARGIN
}

/// Checks the configuration, stops the background router if one runs, and starts it again.
///
/// An invalid configuration fails before anything is stopped, so the running router
/// keeps its pid and keeps serving.
///
/// # Errors
///
/// Returns the errors of [`start`] and [`stop`].
pub(crate) fn restart(config_path: &Path) -> anyhow::Result<ExitCode> {
    check_configuration(config_path)?;
    let settings = vigilant_heron::process_settings(config_path)
        .with_context(|| format!("loading {}", config_path.display()))?;
    if live_pid(&settings.pid_file)?.is_some() {
        stop(config_path)?;
    }
    start(config_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn the_wait_gives_up_after_its_limit() {
        let calls = Cell::new(0);
        let done = wait_until(Duration::from_millis(20), Duration::from_millis(5), || {
            calls.set(calls.get() + 1);
            false
        });
        assert!(!done);
        assert!(calls.get() >= 2, "the probe ran {} times", calls.get());
    }

    #[test]
    fn the_wait_stops_as_soon_as_the_probe_is_true() {
        let calls = Cell::new(0);
        let done = wait_until(Duration::from_secs(5), Duration::from_millis(1), || {
            calls.set(calls.get() + 1);
            calls.get() == 3
        });
        assert!(done);
        assert_eq!(calls.get(), 3);
    }

    #[test]
    fn stop_waits_the_shutdown_timeout_plus_a_margin() {
        assert_eq!(
            stop_limit(Some(Duration::from_secs(10))),
            Duration::from_secs(15)
        );
    }

    #[test]
    fn stop_waits_thirty_seconds_plus_the_margin_without_a_shutdown_timeout() {
        assert_eq!(stop_limit(None), Duration::from_secs(35));
    }

    #[test]
    fn a_symlink_planted_at_the_startup_log_is_not_followed() -> std::io::Result<()> {
        let dir = std::env::temp_dir().join(format!("vh-lifecycle-log-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        let victim = dir.join("victim.txt");
        std::fs::write(&victim, "keep")?;
        let log = startup_log_path(&dir.join("router.pid"));
        std::os::unix::fs::symlink(&victim, &log)?;

        let result = pidfile::create_exclusive(&log).map(drop);
        let kept = std::fs::read_to_string(&victim)?;
        let _ = std::fs::remove_dir_all(&dir);
        result?;
        assert_eq!(kept, "keep", "the victim was written through the symlink");
        Ok(())
    }

    #[test]
    fn the_probe_runs_once_when_the_limit_is_zero() {
        let calls = Cell::new(0);
        let done = wait_until(Duration::ZERO, Duration::from_millis(1), || {
            calls.set(calls.get() + 1);
            false
        });
        assert!(!done);
        assert_eq!(calls.get(), 1);
    }
}
