//! The error log across signals, with the real binary: a SIGHUP reload applies
//! the new `error_log` level and destination, a destination that cannot be opened
//! keeps the old one, and SIGUSR1 reopens the file after it was moved away.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A running binary, killed when the test ends.
struct Server {
    child: Child,
    config: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Server {
    fn start(dir: &Path, config: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let path = dir.join("vigilant-heron.conf");
        std::fs::write(&path, config)?;
        let child = Command::new(env!("CARGO_BIN_EXE_vigilant-heron"))
            .arg("--config")
            .arg(&path)
            .env_remove("VIGILANT_HERON_CONFIG")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        Ok(Self {
            child,
            config: path,
        })
    }

    fn write_config(&self, config: &str) -> TestResult {
        std::fs::write(&self.config, config)?;
        Ok(())
    }

    /// Sends a signal with `kill`, as an operator or logrotate does.
    fn signal(&self, name: &str) -> TestResult {
        let status = Command::new("kill")
            .args([name, &self.child.id().to_string()])
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("kill -{name} failed").into())
        }
    }

    fn reload(&self) -> TestResult {
        self.signal("-HUP")
    }
}

/// A fresh directory for one test.
fn test_dir(name: &str) -> Result<PathBuf, std::io::Error> {
    let dir = std::env::temp_dir().join(format!("vh-error-log-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// The configuration with an `error_log` line and a listen address that takes any free port.
fn config(error_log: &str) -> String {
    format!(
        "listen 127.0.0.1:0;\ndecision {{\n    backend http;\n    url http://127.0.0.1:9/decide;\n}}\nerror_log {error_log};\nsite example.com {{\n    upstream http://127.0.0.1:9;\n}}\n"
    )
}

/// Reads a file, or an empty string when it does not exist yet.
fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// Waits until the file contains `text`, and fails after ten seconds.
fn wait_for(path: &Path, text: &str) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !read(path).contains(text) {
        if Instant::now() > deadline {
            return Err(format!(
                "{text:?} never appeared in {}:\n{}",
                path.display(),
                read(path)
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

/// Gives the process time to finish a reload before the next signal.
fn settle() {
    std::thread::sleep(Duration::from_millis(300));
}

#[test]
fn a_reload_switches_the_error_log_level_both_ways() -> TestResult {
    let dir = test_dir("level")?;
    let log = dir.join("error.log");
    let server = Server::start(&dir, &config(&format!("{} info", log.display())))?;
    // The startup line also shows that the signal handlers are installed.
    wait_for(&log, "vigilant-heron is listening")?;

    // The switch to `error` is committed before the reload's info line is logged, so that line is not written.
    server.write_config(&config(&format!("{} error", log.display())))?;
    server.reload()?;
    settle();
    server.write_config("listen 127.0.0.1:0;\n")?;
    server.reload()?;
    wait_for(&log, "configuration reload failed")?;
    assert!(
        !read(&log).contains("configuration reloaded"),
        "{}",
        read(&log)
    );

    // Back to `info`: the info line of the reload appears again.
    server.write_config(&config(&format!("{} info", log.display())))?;
    server.reload()?;
    wait_for(&log, "configuration reloaded")?;
    Ok(())
}

#[test]
fn a_reload_moves_the_error_log_to_another_file() -> TestResult {
    let dir = test_dir("destination")?;
    let first = dir.join("first.log");
    let second = dir.join("second.log");
    let server = Server::start(&dir, &config(&format!("{} info", first.display())))?;
    wait_for(&first, "vigilant-heron is listening")?;

    server.write_config(&config(&format!("{} info", second.display())))?;
    server.reload()?;
    wait_for(&second, "configuration reloaded")?;
    let first_after = read(&first);
    settle();
    assert_eq!(
        read(&first),
        first_after,
        "the old file still receives lines"
    );
    assert!(!read(&second).contains("vigilant-heron is listening"));
    Ok(())
}

#[test]
fn an_error_log_that_cannot_be_opened_keeps_the_old_one() -> TestResult {
    let dir = test_dir("unopenable")?;
    let log = dir.join("error.log");
    let server = Server::start(&dir, &config(&format!("{} info", log.display())))?;
    wait_for(&log, "vigilant-heron is listening")?;

    let missing = dir.join("no-such-dir").join("error.log");
    server.write_config(&config(&format!("{} info", missing.display())))?;
    server.reload()?;
    wait_for(&log, "configuration reload failed")?;
    assert!(
        read(&log).contains("cannot open error log"),
        "{}",
        read(&log)
    );
    assert!(!missing.exists());

    // The old destination is still in use: a valid reload logs there.
    server.write_config(&config(&format!("{} info", log.display())))?;
    server.reload()?;
    wait_for(&log, "configuration reloaded")?;
    Ok(())
}

#[test]
fn sigusr1_reopens_the_error_log_after_it_was_moved() -> TestResult {
    let dir = test_dir("reopen")?;
    let log = dir.join("error.log");
    let moved = dir.join("error.log.1");
    let server = Server::start(&dir, &config(&format!("{} info", log.display())))?;
    wait_for(&log, "vigilant-heron is listening")?;

    std::fs::rename(&log, &moved)?;
    server.signal("-USR1")?;
    settle();
    // A broken file fails before anything is staged, so the line uses the reopened file.
    server.write_config("listen 127.0.0.1:0;\n")?;
    server.reload()?;
    wait_for(&log, "configuration reload failed")?;
    assert!(!read(&moved).contains("configuration reload failed"));
    Ok(())
}

#[test]
fn a_reload_that_changes_a_restart_setting_warns_that_it_needs_a_restart() -> TestResult {
    let dir = test_dir("restart-warning")?;
    let log = dir.join("error.log");
    let with_limit = |limit: u32| {
        format!(
            "max_connections {limit};\n{}",
            config(&format!("{} info", log.display()))
        )
    };
    let server = Server::start(&dir, &with_limit(10))?;
    wait_for(&log, "vigilant-heron is listening")?;

    server.write_config(&with_limit(20))?;
    server.reload()?;
    wait_for(
        &log,
        "max_connections changed; a restart is needed for it to take effect",
    )?;
    Ok(())
}

/// A configuration for the restart warnings: `listen` and `extra` at the top level, and the error log at `log`.
fn restart_config(log: &Path, listen: &str, extra: &str) -> String {
    format!(
        "listen {listen};\n{extra}\ndecision {{\n    backend http;\n    url http://127.0.0.1:9/decide;\n}}\nerror_log {} info;\nsite example.com {{\n    upstream http://127.0.0.1:9;\n}}\n",
        log.display()
    )
}

/// Starts with `first`, reloads with `second`, and waits for the warning `message` in the error log.
fn reload_warns(
    name: &str,
    first: &dyn Fn(&Path) -> String,
    second: &dyn Fn(&Path) -> String,
    message: &str,
) -> TestResult {
    let dir = test_dir(name)?;
    let log = dir.join("error.log");
    let server = Server::start(&dir, &first(&log))?;
    wait_for(&log, "vigilant-heron is listening")?;

    server.write_config(&second(&log))?;
    server.reload()?;
    wait_for(&log, message)?;
    Ok(())
}

#[test]
fn a_reload_that_changes_the_listen_address_warns_that_it_needs_a_restart() -> TestResult {
    reload_warns(
        "restart-listen",
        &|log| restart_config(log, "127.0.0.1:0", ""),
        &|log| restart_config(log, "127.0.0.2:0", ""),
        "listen changed; a restart is needed for it to take effect",
    )
}

#[test]
fn a_reload_that_changes_the_pid_file_warns_that_it_needs_a_restart() -> TestResult {
    reload_warns(
        "restart-pid",
        &|log| {
            restart_config(
                log,
                "127.0.0.1:0",
                &format!("pid {};", log.with_file_name("first.pid").display()),
            )
        },
        &|log| {
            restart_config(
                log,
                "127.0.0.1:0",
                &format!("pid {};", log.with_file_name("second.pid").display()),
            )
        },
        "pid changed; a restart is needed for it to take effect",
    )
}

#[test]
fn a_reload_that_changes_worker_threads_warns_that_it_needs_a_restart() -> TestResult {
    reload_warns(
        "restart-workers",
        &|log| restart_config(log, "127.0.0.1:0", "worker_threads 1;"),
        &|log| restart_config(log, "127.0.0.1:0", "worker_threads 2;"),
        "worker_threads changed; a restart is needed for it to take effect",
    )
}

#[test]
fn a_reload_that_changes_worker_shutdown_timeout_warns_that_it_needs_a_restart() -> TestResult {
    reload_warns(
        "restart-shutdown",
        &|log| restart_config(log, "127.0.0.1:0", "worker_shutdown_timeout 5s;"),
        &|log| restart_config(log, "127.0.0.1:0", "worker_shutdown_timeout 6s;"),
        "worker_shutdown_timeout changed; a restart is needed for it to take effect",
    )
}

#[test]
fn a_reload_that_changes_a_connection_timer_warns_that_it_needs_a_restart() -> TestResult {
    reload_warns(
        "restart-timers",
        &|log| restart_config(log, "127.0.0.1:0", "client_header_timeout 2s;"),
        &|log| restart_config(log, "127.0.0.1:0", "client_header_timeout 3s;"),
        "connection timers and header limits changed; a restart is needed for them to take effect",
    )
}

#[test]
fn a_reload_that_changes_no_restart_setting_warns_about_none() -> TestResult {
    let dir = test_dir("restart-none")?;
    let log = dir.join("error.log");
    let text = restart_config(
        &log,
        "127.0.0.1:0",
        &format!(
            "pid {};\nworker_threads 1;\nworker_shutdown_timeout 5s;\nmax_connections 10;\nclient_header_timeout 2s;",
            dir.join("restart-none.pid").display()
        ),
    );
    let server = Server::start(&dir, &text)?;
    wait_for(&log, "vigilant-heron is listening")?;

    server.write_config(&text)?;
    server.reload()?;
    wait_for(&log, "configuration reloaded")?;
    assert!(!read(&log).contains("restart is needed"), "{}", read(&log));
    Ok(())
}
