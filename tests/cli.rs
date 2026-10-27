//! The `vigilant-heron` binary, run as a process: every command-line behavior that the
//! documentation in docs/cli.md and docs/install.md states has a test here, named after it.
//!
//! Each test has its own temporary directory, its own free ports and its own pid file.
//! A background router that a test starts is stopped by the fixture's `Drop`, so a
//! failing test leaves nothing running.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

use rustix::process::{Pid, test_kill_process};

/// The binary under test.
const BIN: &str = env!("CARGO_BIN_EXE_vigilant-heron");
/// How long a readiness poll may take before the test fails.
const READY: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A fresh directory for one test, named after the test and this process.
fn test_dir(name: &str) -> Result<PathBuf, std::io::Error> {
    let dir = std::env::temp_dir().join(format!("vh-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// A free loopback port: bound and released, so the router can take it.
fn free_port() -> Result<u16, std::io::Error> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

/// Runs the binary with `args`, with the token variable of the environment removed.
fn run(args: &[&str]) -> Result<Output, std::io::Error> {
    Command::new(BIN)
        .args(args)
        .env_remove("VIGILANT_HERON_CONFIG")
        .output()
}

/// Runs the binary with `args` and extra environment variables.
fn run_env(args: &[&str], envs: &[(&str, &str)]) -> Result<Output, std::io::Error> {
    let mut command = Command::new(BIN);
    command.args(args).env_remove("VIGILANT_HERON_CONFIG");
    for (name, value) in envs {
        command.env(name, value);
    }
    command.output()
}

/// The stdout and stderr of an output, as text, for assertion messages.
fn text(output: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Writes `text` to `name` in `dir`.
fn write_file(dir: &Path, name: &str, text: &str) -> Result<PathBuf, std::io::Error> {
    let path = dir.join(name);
    std::fs::write(&path, text)?;
    Ok(path)
}

/// A complete configuration that listens on `listen`, writes its pid file to `pid`, and
/// forwards `example.com` to `upstream`. `extra` is appended at the top level.
fn router_config(listen: u16, pid: &Path, upstream: u16, extra: &str) -> String {
    format!(
        "listen 127.0.0.1:{listen};\npid {};\ndecision {{\n    backend http;\n    url http://127.0.0.1:9/decide;\n}}\nsite example.com {{\n    upstream http://127.0.0.1:{upstream};\n}}\n{extra}\n",
        pid.display()
    )
}

/// The configuration of the test-mode tests: a valid file whose `extra` lines follow the decision block.
fn config(listen: &str, extra: &str) -> String {
    format!(
        "listen {listen};\ndecision {{\n    backend http;\n    url http://127.0.0.1:9/decide;\n}}\n{extra}\nsite example.com {{\n    upstream http://127.0.0.1:9;\n}}\n"
    )
}

/// Sends a GET and returns the status and the body, or `None` when nothing answers.
fn fetch(port: u16, host: &str, path: &str) -> Option<(u16, String)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).ok()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    let reply = String::from_utf8_lossy(&raw).into_owned();
    let status = reply.split_whitespace().nth(1)?.parse().ok()?;
    let body = reply
        .split_once("\r\n\r\n")
        .map_or_else(String::new, |(_, body)| body.to_owned());
    Some((status, body))
}

/// Polls `fetch` until it returns `expected`, for up to `READY`. Returns the body, or `None`.
fn wait_for(port: u16, host: &str, path: &str, expected: u16) -> Option<String> {
    let deadline = Instant::now() + READY;
    while Instant::now() < deadline {
        if let Some((_, body)) = fetch(port, host, path).filter(|(status, _)| *status == expected) {
            return Some(body);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

/// Polls until the pid file holds a process id, for up to `READY`.
fn wait_for_pid_file(pid_file: &Path) -> Option<u32> {
    let deadline = Instant::now() + READY;
    while Instant::now() < deadline {
        if let Some(pid) = read_pid(pid_file) {
            return Some(pid);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

/// The process id in a pid file, when it holds one.
fn read_pid(pid_file: &Path) -> Option<u32> {
    std::fs::read_to_string(pid_file).ok()?.trim().parse().ok()
}

/// Whether a process with this id exists.
fn alive(pid: u32) -> bool {
    i32::try_from(pid)
        .ok()
        .and_then(Pid::from_raw)
        .is_some_and(|pid| test_kill_process(pid).is_ok())
}

/// A child process that is killed when the value is dropped, even when a test fails.
struct Child(std::process::Child);

impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Waits for a child to exit, for up to `limit`.
fn wait_for_exit(child: &mut Child, limit: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if let Ok(Some(status)) = child.0.try_wait() {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

/// A background router's directory, configuration and pid file. Dropping it stops the
/// router with `stop`, and kills whatever the pid file still names.
struct Fixture {
    dir: PathBuf,
    conf: PathBuf,
    pid: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Result<Self, std::io::Error> {
        let dir = test_dir(name)?;
        Ok(Self {
            conf: dir.join("router.conf"),
            pid: dir.join("router.pid"),
            dir,
        })
    }

    /// Writes the configuration file.
    fn write(&self, text: &str) -> Result<(), std::io::Error> {
        std::fs::write(&self.conf, text)
    }

    /// Runs `word` (start, stop or restart) with this fixture's configuration.
    fn lifecycle(&self, word: &str) -> Result<Output, std::io::Error> {
        Command::new(BIN)
            .arg(word)
            .arg("-c")
            .arg(&self.conf)
            .env_remove("VIGILANT_HERON_CONFIG")
            .output()
    }

    /// Runs `-s <signal>` with this fixture's configuration.
    fn signal(&self, word: &str) -> Result<Output, std::io::Error> {
        Command::new(BIN)
            .arg("-s")
            .arg(word)
            .arg("-c")
            .arg(&self.conf)
            .env_remove("VIGILANT_HERON_CONFIG")
            .output()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.lifecycle("stop");
        if let Some(pid) = read_pid(&self.pid).filter(|pid| alive(*pid)) {
            let _ = Command::new("kill")
                .arg("-KILL")
                .arg(pid.to_string())
                .status();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A local upstream that answers `upstream says hi`. A path that starts with `/slow`
/// is held for 1.5 seconds, and the test is told when that starts.
struct Upstream {
    port: u16,
    slow_started: Receiver<()>,
}

fn spawn_upstream() -> Result<Upstream, std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let (sender, slow_started) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else {
                continue;
            };
            let sender = sender.clone();
            std::thread::spawn(move || answer(stream, &sender));
        }
    });
    Ok(Upstream { port, slow_started })
}

/// Reads one request and writes one response.
fn answer(mut stream: TcpStream, slow_started: &Sender<()>) {
    let mut raw = Vec::new();
    let mut chunk = [0_u8; 1024];
    while !raw.windows(4).any(|window| window == b"\r\n\r\n") {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => raw.extend_from_slice(chunk.get(..read).unwrap_or(&[])),
        }
    }
    let head = String::from_utf8_lossy(&raw).into_owned();
    let path = head.split_whitespace().nth(1).unwrap_or("/").to_owned();
    let body = if path.starts_with("/slow") {
        let _ = slow_started.send(());
        std::thread::sleep(Duration::from_millis(1500));
        "done"
    } else {
        "upstream says hi"
    };
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

// ---------------------------------------------------------------------------
// -h, -v, unknown options
// ---------------------------------------------------------------------------

#[test]
fn help_lists_every_option_and_exits_zero() -> Result<(), std::io::Error> {
    for flag in ["-h", "--help"] {
        let output = run(&[flag])?;
        assert_eq!(output.status.code(), Some(0), "{}", text(&output));
        let stdout = String::from_utf8_lossy(&output.stdout);
        for option in [
            "-h",
            "--help",
            "-v",
            "--version",
            "-c",
            "--config",
            "-t",
            "-T",
            "-s",
            "start",
            "stop",
            "restart",
        ] {
            assert!(stdout.contains(option), "help does not list {option}");
        }
    }
    Ok(())
}

#[test]
fn version_prints_the_crate_version_and_exits_zero() -> Result<(), std::io::Error> {
    for flag in ["-v", "--version"] {
        let output = run(&[flag])?;
        assert_eq!(output.status.code(), Some(0), "{}", text(&output));
        let expected = format!("vigilant-heron version {}", env!("CARGO_PKG_VERSION"));
        assert!(
            String::from_utf8_lossy(&output.stdout).contains(&expected),
            "{}",
            text(&output)
        );
    }
    Ok(())
}

#[test]
fn an_unknown_option_prints_the_usage_on_stderr_and_exits_one() -> Result<(), std::io::Error> {
    let output = run(&["--no-such-option"])?;
    assert_eq!(output.status.code(), Some(1), "{}", text(&output));
    assert!(output.stdout.is_empty(), "{}", text(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown option"), "{stderr}");
    assert!(stderr.contains("Usage:"), "{stderr}");
    Ok(())
}

// ---------------------------------------------------------------------------
// -t and -T
// ---------------------------------------------------------------------------

#[test]
fn a_valid_configuration_passes_the_test() -> Result<(), std::io::Error> {
    let dir = test_dir("valid-test")?;
    let path = write_file(&dir, "valid.conf", &config("127.0.0.1:8080", ""))?;
    let output = run(&["-t", "-c", path.to_str().unwrap_or_default()])?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert!(
        stderr.contains(&format!(
            "configuration file {} test is successful",
            path.display()
        )),
        "{stderr}"
    );
    Ok(())
}

#[test]
fn an_invalid_configuration_fails_the_test_with_its_file_and_line() -> Result<(), std::io::Error> {
    let dir = test_dir("invalid-test")?;
    let path = write_file(
        &dir,
        "invalid.conf",
        &config("127.0.0.1:8080", "default_status 200;"),
    )?;
    let output = run(&["-t", "-c", path.to_str().unwrap_or_default()])?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains(&format!("{}:6:", path.display())),
        "{stderr}"
    );
    assert!(stderr.contains("test failed"), "{stderr}");
    Ok(())
}

#[test]
fn a_missing_block_page_fails_the_test() -> Result<(), std::io::Error> {
    let dir = test_dir("missing-page")?;
    let path = write_file(
        &dir,
        "missing-page.conf",
        &config(
            "127.0.0.1:8080",
            "block_page /nonexistent/vigilant-heron/page.html;",
        ),
    )?;
    let output = run(&["-t", "-c", path.to_str().unwrap_or_default()])?;
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("block_page"));
    Ok(())
}

#[test]
fn the_test_never_binds_the_listen_address() -> Result<(), std::io::Error> {
    // The address is taken by this test, so any bind attempt by the binary would fail.
    let held = TcpListener::bind("127.0.0.1:0")?;
    let listen = held.local_addr()?.to_string();
    let dir = test_dir("bound-test")?;
    let path = write_file(&dir, "bound.conf", &config(&listen, ""))?;
    let output = run(&["-t", "-c", path.to_str().unwrap_or_default()])?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    Ok(())
}

#[test]
fn dump_prints_the_configuration_with_each_include_under_its_header() -> Result<(), std::io::Error>
{
    let dir = test_dir("dump")?;
    write_file(
        &dir,
        "dump-extra.conf",
        "# a comment in the included file\ndefault_status 404;\n",
    )?;
    let main = write_file(
        &dir,
        "dump-main.conf",
        &config("127.0.0.1:8080", "include dump-extra.conf;"),
    )?;
    let output = run(&["-T", "-c", main.to_str().unwrap_or_default()])?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("test is successful"), "{stderr}");
    assert!(
        stdout.contains(&format!("# configuration file {}:", main.display())),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "# configuration file {}:",
            dir.join("dump-extra.conf").display()
        )),
        "{stdout}"
    );
    assert!(stdout.contains("default_status 404;"), "{stdout}");
    assert!(
        stdout.contains("# a comment in the included file"),
        "comments were dropped: {stdout}"
    );
    assert!(stdout.contains("# include dump-extra.conf;"), "{stdout}");
    Ok(())
}

#[test]
fn dump_prints_nothing_to_stdout_for_an_invalid_configuration() -> Result<(), std::io::Error> {
    let dir = test_dir("dump-invalid")?;
    let main = write_file(
        &dir,
        "invalid-dump.conf",
        &config("127.0.0.1:8080", "default_status 200;"),
    )?;
    let output = run(&["-T", "-c", main.to_str().unwrap_or_default()])?;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout.len(), 0);
    assert!(String::from_utf8_lossy(&output.stderr).contains("test failed"));
    Ok(())
}

#[test]
fn dump_never_prints_the_value_of_a_token_variable() -> Result<(), std::io::Error> {
    let dir = test_dir("dump-token")?;
    let secret = "vh-test-secret-value-42";
    let main = write_file(
        &dir,
        "token.conf",
        "listen 127.0.0.1:8080;\ndecision {\n    backend jev;\n    url http://127.0.0.1:9/v1/systemone;\n    api_token_env VH_TEST_TOKEN_NAME;\n}\nsite example.com {\n    upstream http://127.0.0.1:9;\n}\n",
    )?;
    let output = run_env(
        &["-T", "-c", main.to_str().unwrap_or_default()],
        &[("VH_TEST_TOKEN_NAME", secret)],
    )?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("VH_TEST_TOKEN_NAME"), "{stdout}");
    assert!(!stdout.contains(secret), "-T printed the token value");
    Ok(())
}

// ---------------------------------------------------------------------------
// -s reload, reopen, stop, quit
// ---------------------------------------------------------------------------

#[test]
fn signal_with_a_missing_pid_file_fails_with_exit_one() -> Result<(), std::io::Error> {
    let fixture = Fixture::new("signal-missing")?;
    fixture.write(&router_config(1, &fixture.pid, 9, ""))?;
    let output = fixture.signal("reload")?;
    assert_eq!(output.status.code(), Some(1), "{}", text(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot read the pid file"), "{stderr}");
    assert!(
        stderr.contains(&fixture.pid.display().to_string()),
        "{stderr}"
    );
    Ok(())
}

#[test]
fn signal_with_a_pid_file_that_is_not_a_number_fails_with_exit_one() -> Result<(), std::io::Error> {
    let fixture = Fixture::new("signal-garbage")?;
    fixture.write(&router_config(1, &fixture.pid, 9, ""))?;
    std::fs::write(&fixture.pid, "not a process id\n")?;
    let output = fixture.signal("reload")?;
    assert_eq!(output.status.code(), Some(1), "{}", text(&output));
    assert!(String::from_utf8_lossy(&output.stderr).contains("does not hold a process id"));
    Ok(())
}

#[test]
fn signal_with_a_pid_file_holding_minus_one_fails_and_signals_nothing() -> Result<(), std::io::Error>
{
    // -1 would mean every process the user may signal, so nothing may be sent.
    let fixture = Fixture::new("signal-minus-one")?;
    fixture.write(&router_config(1, &fixture.pid, 9, ""))?;
    std::fs::write(&fixture.pid, "-1\n")?;
    let output = fixture.signal("reload")?;
    assert_eq!(output.status.code(), Some(1), "{}", text(&output));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("does not hold a process id"),
        "{}",
        text(&output)
    );
    Ok(())
}

#[test]
fn signal_with_a_stale_pid_file_fails_with_exit_one() -> Result<(), std::io::Error> {
    let fixture = Fixture::new("signal-stale")?;
    fixture.write(&router_config(1, &fixture.pid, 9, ""))?;
    // A process id that no process has.
    std::fs::write(&fixture.pid, "2147483646\n")?;
    let output = fixture.signal("stop")?;
    assert_eq!(output.status.code(), Some(1), "{}", text(&output));
    assert!(String::from_utf8_lossy(&output.stderr).contains("stale"));
    Ok(())
}

/// Starts a `sleep` that the test owns, so a stale pid file can name a live process.
fn live_stranger() -> Result<Child, std::io::Error> {
    Ok(Child(Command::new("sleep").arg("30").spawn()?))
}

#[test]
fn a_stale_pid_file_naming_a_live_process_is_not_signalled() -> Result<(), std::io::Error> {
    // The pid file is left behind with no lock held, as a crashed router leaves it. The pid
    // now belongs to an unrelated process, which must receive no signal.
    let fixture = Fixture::new("signal-live-stale")?;
    fixture.write(&router_config(1, &fixture.pid, 9, ""))?;
    let stranger = live_stranger()?;
    let stranger_pid = stranger.0.id();
    std::fs::write(&fixture.pid, format!("{stranger_pid}\n"))?;
    for word in ["reload", "stop"] {
        let output = fixture.signal(word)?;
        assert_eq!(output.status.code(), Some(1), "{word}: {}", text(&output));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("is stale"), "{word}: {stderr}");
        assert!(
            alive(stranger_pid),
            "-s {word} signalled the unrelated process {stranger_pid}"
        );
    }
    Ok(())
}

#[test]
fn stop_does_not_signal_a_live_process_named_by_a_stale_pid_file() -> Result<(), std::io::Error> {
    let fixture = Fixture::new("stop-live-stale")?;
    fixture.write(&router_config(1, &fixture.pid, 9, ""))?;
    let stranger = live_stranger()?;
    let stranger_pid = stranger.0.id();
    std::fs::write(&fixture.pid, format!("{stranger_pid}\n"))?;
    let output = fixture.lifecycle("stop")?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    assert!(String::from_utf8_lossy(&output.stdout).contains("not running"));
    assert!(
        alive(stranger_pid),
        "stop signalled the unrelated process {stranger_pid}"
    );
    Ok(())
}

#[test]
fn a_second_router_with_the_same_pid_file_exits() -> Result<(), std::io::Error> {
    let fixture = Fixture::new("second-router")?;
    let upstream = spawn_upstream()?;
    let port = free_port()?;
    fixture.write(&router_config(port, &fixture.pid, upstream.port, ""))?;
    assert_eq!(fixture.lifecycle("start")?.status.code(), Some(0));
    let first = read_pid(&fixture.pid).ok_or_else(|| std::io::Error::other("no pid"))?;

    let second_conf = fixture.dir.join("second.conf");
    std::fs::write(
        &second_conf,
        router_config(free_port()?, &fixture.pid, upstream.port, ""),
    )?;
    let mut second = Child(
        Command::new(BIN)
            .arg("-c")
            .arg(&second_conf)
            .env_remove("VIGILANT_HERON_CONFIG")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?,
    );
    let status = wait_for_exit(&mut second, Duration::from_secs(10));
    let mut stderr = String::new();
    if let Some(mut pipe) = second.0.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    assert_eq!(status.and_then(|status| status.code()), Some(1), "{stderr}");
    assert!(
        stderr.contains(&format!(
            "another router is using the pid file {}",
            fixture.pid.display()
        )),
        "{stderr}"
    );
    assert_eq!(read_pid(&fixture.pid), Some(first), "the pid file changed");
    assert!(
        wait_for(port, "example.com", "/", 200).is_some(),
        "the first router stopped serving"
    );
    Ok(())
}

/// The same refusal as `a_second_router_with_the_same_pid_file_exits`, with stderr written to a file.
/// A piped stderr would block the test while a router that did not exit still holds it.
#[test]
fn a_second_router_with_the_same_pid_file_is_refused_when_stderr_goes_to_a_file()
-> Result<(), std::io::Error> {
    let fixture = Fixture::new("second-router-file")?;
    let upstream = spawn_upstream()?;
    let port = free_port()?;
    fixture.write(&router_config(port, &fixture.pid, upstream.port, ""))?;
    assert_eq!(fixture.lifecycle("start")?.status.code(), Some(0));

    let second_conf = fixture.dir.join("second.conf");
    std::fs::write(
        &second_conf,
        router_config(free_port()?, &fixture.pid, upstream.port, ""),
    )?;
    let stderr_path = fixture.dir.join("second.stderr");
    let mut second = Child(
        Command::new(BIN)
            .arg("-c")
            .arg(&second_conf)
            .env_remove("VIGILANT_HERON_CONFIG")
            .stdout(Stdio::null())
            .stderr(Stdio::from(std::fs::File::create(&stderr_path)?))
            .spawn()?,
    );
    let status = wait_for_exit(&mut second, Duration::from_secs(10));
    let stderr = std::fs::read_to_string(&stderr_path)?;
    assert_eq!(status.and_then(|status| status.code()), Some(1), "{stderr}");
    assert!(
        stderr.contains(&format!(
            "another router is using the pid file {}",
            fixture.pid.display()
        )),
        "{stderr}"
    );
    Ok(())
}

/// Starts the router in the foreground with `conf`, and waits until its pid file exists.
fn foreground(conf: &Path, pid: &Path) -> Result<Child, std::io::Error> {
    let child = Child(
        Command::new(BIN)
            .arg("-c")
            .arg(conf)
            .env_remove("VIGILANT_HERON_CONFIG")
            .stderr(Stdio::null())
            .spawn()?,
    );
    assert!(
        wait_for_pid_file(pid).is_some(),
        "the pid file was not written"
    );
    Ok(child)
}

#[test]
fn signal_reload_applies_a_changed_file() -> Result<(), std::io::Error> {
    let fixture = Fixture::new("signal-reload")?;
    let upstream = spawn_upstream()?;
    let port = free_port()?;
    fixture.write(&router_config(
        port,
        &fixture.pid,
        upstream.port,
        "default_status 421;",
    ))?;
    let _router = foreground(&fixture.conf, &fixture.pid)?;
    assert!(
        wait_for(port, "unknown.test", "/", 421).is_some(),
        "the router did not answer 421"
    );

    fixture.write(&router_config(
        port,
        &fixture.pid,
        upstream.port,
        "default_status 404;",
    ))?;
    let output = fixture.signal("reload")?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    assert!(
        output.stdout.is_empty(),
        "-s printed output: {}",
        text(&output)
    );
    assert!(
        wait_for(port, "unknown.test", "/", 404).is_some(),
        "the changed file was not applied"
    );
    Ok(())
}

#[test]
fn sighup_applies_a_valid_file_and_keeps_the_old_one_for_a_broken_file()
-> Result<(), std::io::Error> {
    let dir = test_dir("sighup")?;
    let port = free_port()?;
    let path = write_file(
        &dir,
        "reload.conf",
        &config(&format!("127.0.0.1:{port}"), ""),
    )?;
    let child = Command::new(BIN)
        .arg("--config")
        .arg(&path)
        .env_remove("VIGILANT_HERON_CONFIG")
        .stderr(Stdio::piped())
        .spawn()?;
    let mut child = Child(child);
    assert!(
        wait_for(port, "unknown.test", "/", 421).is_some(),
        "the server did not answer 421"
    );

    // A broken file: SIGHUP logs the error, and the old configuration keeps serving.
    std::fs::write(
        &path,
        config(&format!("127.0.0.1:{port}"), "unknown_directive 1;"),
    )?;
    let signal = Command::new("kill")
        .arg("-HUP")
        .arg(child.0.id().to_string())
        .status()?;
    assert!(signal.success());
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        fetch(port, "unknown.test", "/").map(|(status, _)| status),
        Some(421)
    );

    // A valid file: the next SIGHUP applies it.
    std::fs::write(
        &path,
        config(&format!("127.0.0.1:{port}"), "default_status 404;"),
    )?;
    let signal = Command::new("kill")
        .arg("-HUP")
        .arg(child.0.id().to_string())
        .status()?;
    assert!(signal.success());
    assert!(
        wait_for(port, "unknown.test", "/", 404).is_some(),
        "the valid file was not applied"
    );

    let _ = child.0.kill();
    let _ = child.0.wait();
    let mut stderr = String::new();
    if let Some(mut pipe) = child.0.stderr.take() {
        pipe.read_to_string(&mut stderr)?;
    }
    assert!(stderr.contains("configuration reload failed"), "{stderr}");
    // The broken directive is on line 6 of the file written by `config`.
    assert!(stderr.contains("reload.conf:6:"), "{stderr}");
    Ok(())
}

#[test]
fn signal_reopen_keeps_serving_and_writes_to_a_new_access_log_file() -> Result<(), std::io::Error> {
    let fixture = Fixture::new("signal-reopen")?;
    let upstream = spawn_upstream()?;
    let port = free_port()?;
    let log = fixture.dir.join("access.log");
    fixture.write(&router_config(
        port,
        &fixture.pid,
        upstream.port,
        &format!("access_log {} json;", log.display()),
    ))?;
    let _router = foreground(&fixture.conf, &fixture.pid)?;
    assert!(wait_for(port, "example.com", "/before", 200).is_some());
    std::fs::rename(&log, fixture.dir.join("access.log.1"))?;

    let output = fixture.signal("reopen")?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    // `-s reopen` returns once the signal is sent; the router reopens the file
    // and writes access lines asynchronously. Keep sending requests until one
    // of them is in the new file, within a deadline.
    let deadline = Instant::now() + READY;
    let mut written = String::new();
    while Instant::now() < deadline {
        assert!(
            wait_for(port, "example.com", "/after-reopen", 200).is_some(),
            "the router stopped serving"
        );
        written = std::fs::read_to_string(&log).unwrap_or_default();
        if written.contains("/after-reopen") {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        written.contains("/after-reopen"),
        "the new log file lacks the request: {written}"
    );
    Ok(())
}

#[test]
fn signal_quit_exits_zero_and_removes_the_pid_file() -> Result<(), std::io::Error> {
    let fixture = Fixture::new("signal-quit")?;
    fixture.write(&router_config(free_port()?, &fixture.pid, 9, ""))?;
    let mut router = foreground(&fixture.conf, &fixture.pid)?;
    let output = fixture.signal("quit")?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    let status = wait_for_exit(&mut router, Duration::from_secs(10));
    assert!(
        status.is_some_and(|status| status.success()),
        "the router did not exit with 0"
    );
    assert!(
        !fixture.pid.exists(),
        "the pid file was not removed on exit"
    );
    Ok(())
}

#[test]
fn signal_stop_exits_zero_and_removes_the_pid_file() -> Result<(), std::io::Error> {
    let fixture = Fixture::new("signal-stop")?;
    fixture.write(&router_config(free_port()?, &fixture.pid, 9, ""))?;
    let mut router = foreground(&fixture.conf, &fixture.pid)?;
    let output = fixture.signal("stop")?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    let status = wait_for_exit(&mut router, Duration::from_secs(10));
    assert!(
        status.is_some_and(|status| status.success()),
        "the router did not exit with 0"
    );
    assert!(
        !fixture.pid.exists(),
        "the pid file was not removed on exit"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// start
// ---------------------------------------------------------------------------

#[test]
fn start_proceeds_past_a_stale_pid_file_naming_a_live_process() -> Result<(), std::io::Error> {
    let fixture = Fixture::new("start-live-stale")?;
    let upstream = spawn_upstream()?;
    let port = free_port()?;
    fixture.write(&router_config(port, &fixture.pid, upstream.port, ""))?;
    let stranger = live_stranger()?;
    let stranger_pid = stranger.0.id();
    std::fs::write(&fixture.pid, format!("{stranger_pid}\n"))?;
    let output = fixture.lifecycle("start")?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    let pid = read_pid(&fixture.pid).ok_or_else(|| std::io::Error::other("no pid"))?;
    assert_ne!(pid, stranger_pid, "the pid file still names the stranger");
    assert!(alive(stranger_pid), "start signalled the unrelated process");
    assert!(wait_for(port, "example.com", "/", 200).is_some());
    Ok(())
}

#[test]
fn start_serves_in_the_background_and_writes_the_child_pid() -> Result<(), std::io::Error> {
    let fixture = Fixture::new("start-serves")?;
    let upstream = spawn_upstream()?;
    let port = free_port()?;
    fixture.write(&router_config(port, &fixture.pid, upstream.port, ""))?;
    let output = fixture.lifecycle("start")?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    let pid =
        read_pid(&fixture.pid).ok_or_else(|| std::io::Error::other("no pid in the pid file"))?;
    assert!(
        String::from_utf8_lossy(&output.stdout).contains(&format!("started (pid {pid})")),
        "{}",
        text(&output)
    );
    assert!(alive(pid), "the pid file names no live process");
    let body = wait_for(port, "example.com", "/", 200);
    assert_eq!(body.as_deref(), Some("upstream says hi"));
    Ok(())
}

#[test]
fn start_returns_within_the_startup_bound() -> Result<(), std::io::Error> {
    let fixture = Fixture::new("start-bound")?;
    fixture.write(&router_config(free_port()?, &fixture.pid, 9, ""))?;
    let began = Instant::now();
    let output = fixture.lifecycle("start")?;
    let took = began.elapsed();
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    assert!(took < Duration::from_secs(10), "start took {took:?}");
    Ok(())
}

#[test]
fn start_refuses_when_already_running_and_leaves_the_first_router_serving()
-> Result<(), std::io::Error> {
    let fixture = Fixture::new("start-running")?;
    let upstream = spawn_upstream()?;
    let port = free_port()?;
    fixture.write(&router_config(port, &fixture.pid, upstream.port, ""))?;
    assert_eq!(fixture.lifecycle("start")?.status.code(), Some(0));
    let first = read_pid(&fixture.pid).ok_or_else(|| std::io::Error::other("no pid"))?;

    let output = fixture.lifecycle("start")?;
    assert_eq!(output.status.code(), Some(1), "{}", text(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!("already running (pid {first})")),
        "{stderr}"
    );
    assert_eq!(read_pid(&fixture.pid), Some(first), "the pid file changed");
    assert!(
        wait_for(port, "example.com", "/", 200).is_some(),
        "the first router stopped serving"
    );
    Ok(())
}

#[test]
fn start_with_an_invalid_configuration_fails_and_starts_nothing() -> Result<(), std::io::Error> {
    let fixture = Fixture::new("start-invalid")?;
    fixture.write(&router_config(
        free_port()?,
        &fixture.pid,
        9,
        "default_status 200;",
    ))?;
    let output = fixture.lifecycle("start")?;
    assert_eq!(output.status.code(), Some(1), "{}", text(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("router.conf:"),
        "the error does not name the file and line: {stderr}"
    );
    assert!(stderr.contains("test failed"), "{stderr}");
    assert!(
        !fixture.pid.exists(),
        "a pid file was written for an invalid configuration"
    );
    Ok(())
}

#[test]
fn start_with_a_port_in_use_fails_with_the_bind_error() -> Result<(), std::io::Error> {
    let fixture = Fixture::new("start-port")?;
    let held = TcpListener::bind("127.0.0.1:0")?;
    let port = held.local_addr()?.port();
    fixture.write(&router_config(port, &fixture.pid, 9, ""))?;
    let output = fixture.lifecycle("start")?;
    assert_eq!(output.status.code(), Some(1), "{}", text(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("binding"), "{stderr}");
    assert!(stderr.contains("Address already in use"), "{stderr}");
    assert!(!fixture.pid.exists(), "a pid file was left behind");
    let leftovers: Vec<_> = std::fs::read_dir(&fixture.dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".vigilant-heron-start-"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "the startup log was not removed: {leftovers:?}"
    );
    Ok(())
}

#[test]
fn start_replaces_a_stale_pid_file() -> Result<(), std::io::Error> {
    let fixture = Fixture::new("start-stale")?;
    let upstream = spawn_upstream()?;
    let port = free_port()?;
    fixture.write(&router_config(port, &fixture.pid, upstream.port, ""))?;
    std::fs::write(&fixture.pid, "2147483646\n")?;
    let output = fixture.lifecycle("start")?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    let pid = read_pid(&fixture.pid).ok_or_else(|| std::io::Error::other("no pid"))?;
    assert_ne!(pid, 2_147_483_646);
    assert!(wait_for(port, "example.com", "/", 200).is_some());
    Ok(())
}

#[test]
fn a_pid_file_that_cannot_be_locked_is_warned_about_and_the_router_still_serves()
-> Result<(), std::io::Error> {
    let fixture = Fixture::new("pid-unlockable")?;
    let upstream = spawn_upstream()?;
    let port = free_port()?;
    let log = fixture.dir.join("error.log");
    // The directory of the pid file does not exist, so the lock file cannot be created.
    let pid = fixture.dir.join("missing").join("router.pid");
    fixture.write(&router_config(
        port,
        &pid,
        upstream.port,
        &format!("default_status 421;\nerror_log {} info;", log.display()),
    ))?;
    let _router = Child(
        Command::new(BIN)
            .arg("-c")
            .arg(&fixture.conf)
            .env_remove("VIGILANT_HERON_CONFIG")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    assert!(
        wait_for(port, "unknown.test", "/", 421).is_some(),
        "the router did not serve with an unlockable pid file"
    );
    // The error log is written by its own task, so the line may come a moment after the answer.
    let deadline = Instant::now() + READY;
    loop {
        let logged = std::fs::read_to_string(&log).unwrap_or_default();
        if logged.contains("cannot lock the pid file") {
            break;
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::other(format!(
                "no warning in the error log: {logged}"
            )));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

#[test]
fn start_warns_when_error_log_goes_to_stderr() -> Result<(), std::io::Error> {
    let fixture = Fixture::new("start-warns")?;
    fixture.write(&router_config(
        free_port()?,
        &fixture.pid,
        9,
        "error_log stderr;",
    ))?;
    let output = fixture.lifecycle("start")?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("warning: error_log writes to a standard stream"),
        "{stderr}"
    );
    // The default access log goes to stdout, which a background router does not keep either.
    assert!(
        stderr.contains("warning: access_log writes to a standard stream"),
        "{stderr}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// stop
// ---------------------------------------------------------------------------

#[test]
fn stop_lets_an_in_flight_request_finish_before_the_process_exits() -> Result<(), std::io::Error> {
    let fixture = Fixture::new("stop-in-flight")?;
    let upstream = spawn_upstream()?;
    let port = free_port()?;
    fixture.write(&router_config(
        port,
        &fixture.pid,
        upstream.port,
        "worker_shutdown_timeout 10s;",
    ))?;
    assert_eq!(fixture.lifecycle("start")?.status.code(), Some(0));
    assert!(wait_for(port, "example.com", "/", 200).is_some());

    let slow = std::thread::spawn(move || fetch(port, "example.com", "/slow"));
    upstream
        .slow_started
        .recv_timeout(Duration::from_secs(10))
        .map_err(|_| std::io::Error::other("the slow request never reached the upstream"))?;
    let output = fixture.lifecycle("stop")?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    let response = slow
        .join()
        .map_err(|_| std::io::Error::other("the request thread panicked"))?;
    assert_eq!(
        response,
        Some((200, "done".to_owned())),
        "the in-flight request did not complete"
    );
    Ok(())
}

#[test]
fn stop_returns_only_after_the_process_is_gone_and_removes_the_pid_file()
-> Result<(), std::io::Error> {
    let fixture = Fixture::new("stop-gone")?;
    fixture.write(&router_config(free_port()?, &fixture.pid, 9, ""))?;
    assert_eq!(fixture.lifecycle("start")?.status.code(), Some(0));
    let pid = read_pid(&fixture.pid).ok_or_else(|| std::io::Error::other("no pid"))?;
    let output = fixture.lifecycle("stop")?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains(&format!("stopped (pid {pid})")),
        "{}",
        text(&output)
    );
    assert!(
        !alive(pid),
        "stop returned while the process was still alive"
    );
    assert!(!fixture.pid.exists(), "the pid file was not removed");
    Ok(())
}

#[test]
fn stop_reports_not_running_when_there_is_no_pid_file() -> Result<(), std::io::Error> {
    let fixture = Fixture::new("stop-none")?;
    fixture.write(&router_config(free_port()?, &fixture.pid, 9, ""))?;
    let output = fixture.lifecycle("stop")?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    assert!(String::from_utf8_lossy(&output.stdout).contains("not running"));
    Ok(())
}

#[test]
fn stop_reports_not_running_for_a_stale_pid_file() -> Result<(), std::io::Error> {
    let fixture = Fixture::new("stop-stale")?;
    fixture.write(&router_config(free_port()?, &fixture.pid, 9, ""))?;
    std::fs::write(&fixture.pid, "2147483646\n")?;
    let output = fixture.lifecycle("stop")?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    assert!(String::from_utf8_lossy(&output.stdout).contains("not running"));
    Ok(())
}

#[test]
fn stop_fails_without_killing_a_process_that_outlives_the_bound() -> Result<(), std::io::Error> {
    let fixture = Fixture::new("stop-outlives")?;
    // The shutdown timeout is one second, so stop waits for six seconds before it gives up.
    fixture.write(&router_config(
        free_port()?,
        &fixture.pid,
        9,
        "worker_shutdown_timeout 1s;",
    ))?;
    // A process that ignores SIGQUIT, so stop cannot end it gracefully.
    let mut stubborn = Child(
        Command::new("sh")
            .arg("-c")
            .arg("trap '' QUIT; sleep 60")
            .spawn()?,
    );
    std::fs::write(&fixture.pid, format!("{}\n", stubborn.0.id()))?;
    // A running router holds the lock of its pid file, so the test holds it for the process
    // that stands in for the router. Without the lock, stop would take the file for a stale one.
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(format!("{}.lock", fixture.pid.display()))?;
    // `lock_file` keeps the lock until the test ends.
    rustix::fs::flock(
        &lock_file,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .map_err(std::io::Error::from)?;
    let began = Instant::now();
    let output = fixture.lifecycle("stop")?;
    let took = began.elapsed();
    assert_eq!(output.status.code(), Some(1), "{}", text(&output));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("still running"),
        "{}",
        text(&output)
    );
    assert!(
        took >= Duration::from_secs(5),
        "stop gave up after {took:?}"
    );
    assert!(alive(stubborn.0.id()), "stop killed the process");
    let _ = stubborn.0.kill();
    let _ = stubborn.0.wait();
    Ok(())
}

// ---------------------------------------------------------------------------
// restart
// ---------------------------------------------------------------------------

#[test]
fn restart_gives_a_new_pid_and_serves_again() -> Result<(), std::io::Error> {
    let fixture = Fixture::new("restart-new-pid")?;
    let upstream = spawn_upstream()?;
    let port = free_port()?;
    fixture.write(&router_config(port, &fixture.pid, upstream.port, ""))?;
    assert_eq!(fixture.lifecycle("start")?.status.code(), Some(0));
    let first = read_pid(&fixture.pid).ok_or_else(|| std::io::Error::other("no pid"))?;
    let output = fixture.lifecycle("restart")?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    let second = read_pid(&fixture.pid).ok_or_else(|| std::io::Error::other("no pid"))?;
    assert_ne!(first, second, "restart kept the old process");
    assert!(!alive(first), "the old process is still running");
    assert!(
        wait_for(port, "example.com", "/", 200).is_some(),
        "the restarted router does not serve"
    );
    Ok(())
}

#[test]
fn restart_applies_a_changed_listen_port() -> Result<(), std::io::Error> {
    let fixture = Fixture::new("restart-listen")?;
    let upstream = spawn_upstream()?;
    let old_port = free_port()?;
    fixture.write(&router_config(old_port, &fixture.pid, upstream.port, ""))?;
    assert_eq!(fixture.lifecycle("start")?.status.code(), Some(0));
    assert!(wait_for(old_port, "example.com", "/", 200).is_some());

    let new_port = free_port()?;
    fixture.write(&router_config(new_port, &fixture.pid, upstream.port, ""))?;
    let output = fixture.lifecycle("restart")?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    assert!(
        wait_for(new_port, "example.com", "/", 200).is_some(),
        "the new port does not serve"
    );
    assert!(
        fetch(old_port, "example.com", "/").is_none(),
        "the old port still answers"
    );
    Ok(())
}

#[test]
fn restart_with_an_invalid_configuration_keeps_the_running_router() -> Result<(), std::io::Error> {
    let fixture = Fixture::new("restart-invalid")?;
    let upstream = spawn_upstream()?;
    let port = free_port()?;
    fixture.write(&router_config(port, &fixture.pid, upstream.port, ""))?;
    assert_eq!(fixture.lifecycle("start")?.status.code(), Some(0));
    let running = read_pid(&fixture.pid).ok_or_else(|| std::io::Error::other("no pid"))?;

    fixture.write(&router_config(
        port,
        &fixture.pid,
        upstream.port,
        "default_status 200;",
    ))?;
    let output = fixture.lifecycle("restart")?;
    assert_eq!(output.status.code(), Some(1), "{}", text(&output));
    assert_eq!(
        read_pid(&fixture.pid),
        Some(running),
        "the running router was replaced"
    );
    assert!(alive(running), "the running router was stopped");
    assert!(
        wait_for(port, "example.com", "/", 200).is_some(),
        "the running router stopped serving"
    );
    Ok(())
}

#[test]
fn restart_starts_when_nothing_is_running() -> Result<(), std::io::Error> {
    let fixture = Fixture::new("restart-none")?;
    let upstream = spawn_upstream()?;
    let port = free_port()?;
    fixture.write(&router_config(port, &fixture.pid, upstream.port, ""))?;
    let output = fixture.lifecycle("restart")?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    assert!(wait_for(port, "example.com", "/", 200).is_some());
    Ok(())
}

// ---------------------------------------------------------------------------
// Conflicts
// ---------------------------------------------------------------------------

#[test]
fn lifecycle_words_combined_with_test_dump_or_signal_exit_one_with_usage()
-> Result<(), std::io::Error> {
    let cases: [&[&str]; 8] = [
        &["start", "-t"],
        &["stop", "-T"],
        &["restart", "-t"],
        &["start", "-s", "reload"],
        &["-T", "stop"],
        &["-s", "quit", "restart"],
        &["start", "-c", "/nonexistent.conf", "-t"],
        &["restart", "-T", "-c", "/nonexistent.conf"],
    ];
    for case in cases {
        let output = run(case)?;
        assert_eq!(output.status.code(), Some(1), "{case:?}: {}", text(&output));
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("Usage:"),
            "{case:?}"
        );
    }
    Ok(())
}

#[test]
fn only_one_of_start_stop_and_restart_may_be_given() -> Result<(), std::io::Error> {
    let output = run(&["start", "stop"])?;
    assert_eq!(output.status.code(), Some(1), "{}", text(&output));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("only one of start, stop and restart")
    );
    Ok(())
}

#[test]
fn start_with_a_file_that_does_not_exist_fails_and_starts_nothing() -> Result<(), std::io::Error> {
    let dir = test_dir("start-missing-file")?;
    let missing = dir.join("absent.conf");
    let output = run(&["start", "-c", missing.to_str().unwrap_or_default()])?;
    assert_eq!(output.status.code(), Some(1), "{}", text(&output));
    assert!(String::from_utf8_lossy(&output.stderr).contains("absent.conf"));
    Ok(())
}

#[test]
fn a_missing_token_variable_fails_the_test() -> Result<(), std::io::Error> {
    let dir = test_dir("token-missing")?;
    let main = write_file(
        &dir,
        "token-missing.conf",
        "listen 127.0.0.1:8080;\ndecision {\n    backend jev;\n    url http://127.0.0.1:9/v1/systemone;\n    api_token_env VH_TEST_ABSENT_TOKEN;\n}\nsite example.com {\n    upstream http://127.0.0.1:9;\n}\n",
    )?;
    let output = Command::new(BIN)
        .arg("-t")
        .arg("-c")
        .arg(&main)
        .env_remove("VIGILANT_HERON_CONFIG")
        .env_remove("VH_TEST_ABSENT_TOKEN")
        .output()?;
    assert_eq!(output.status.code(), Some(1), "{}", text(&output));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("VH_TEST_ABSENT_TOKEN"),
        "{}",
        text(&output)
    );
    Ok(())
}

#[test]
fn dump_reports_an_include_that_is_not_alone_on_its_line() -> Result<(), std::io::Error> {
    let dir = test_dir("dump-inline-include")?;
    write_file(&dir, "dump-extra-inline.conf", "default_status 404;\n")?;
    let main = write_file(
        &dir,
        "dump-inline.conf",
        &config(
            "127.0.0.1:8080",
            "include dump-extra-inline.conf; # a trailing comment",
        ),
    )?;
    let output = run(&["-T", "-c", main.to_str().unwrap_or_default()])?;
    assert_eq!(output.status.code(), Some(1), "{}", text(&output));
    assert!(output.stdout.is_empty(), "{}", text(&output));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("alone on one line"),
        "{}",
        text(&output)
    );
    Ok(())
}

#[test]
fn start_runs_the_router_in_its_own_process_group() -> Result<(), std::io::Error> {
    let fixture = Fixture::new("start-group")?;
    fixture.write(&router_config(free_port()?, &fixture.pid, 9, ""))?;
    assert_eq!(fixture.lifecycle("start")?.status.code(), Some(0));
    let pid = read_pid(&fixture.pid).ok_or_else(|| std::io::Error::other("no pid"))?;
    let raw = i32::try_from(pid).map_err(std::io::Error::other)?;
    let pid = Pid::from_raw(raw).ok_or_else(|| std::io::Error::other("bad pid"))?;
    let group = rustix::process::getpgid(Some(pid)).map_err(std::io::Error::from)?;
    assert_eq!(
        group, pid,
        "the router shares the process group of the caller"
    );
    Ok(())
}

#[test]
fn a_router_started_with_start_is_not_restarted_after_a_crash() -> Result<(), std::io::Error> {
    let fixture = Fixture::new("start-crash")?;
    let upstream = spawn_upstream()?;
    let port = free_port()?;
    fixture.write(&router_config(port, &fixture.pid, upstream.port, ""))?;
    assert_eq!(fixture.lifecycle("start")?.status.code(), Some(0));
    assert!(wait_for(port, "example.com", "/", 200).is_some());
    let pid = read_pid(&fixture.pid).ok_or_else(|| std::io::Error::other("no pid"))?;
    let killed = Command::new("kill")
        .arg("-KILL")
        .arg(pid.to_string())
        .status()?;
    assert!(killed.success());
    // Nothing is polled here: this is a negative check, so the router gets two seconds to come back if anything would restart it.
    std::thread::sleep(Duration::from_secs(2));
    assert!(
        fetch(port, "example.com", "/").is_none(),
        "something restarted the router"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// test-request: what the router would do with one sample request
// ---------------------------------------------------------------------------

/// Writes `request` to `name` in `dir` and runs `test-request` on it with the configuration `conf`.
fn test_request(
    dir: &Path,
    name: &str,
    request: &str,
    conf: &Path,
    extra: &[&str],
) -> Result<Output, std::io::Error> {
    let file = write_file(dir, name, request)?;
    let mut args = vec![
        "test-request",
        file.to_str().unwrap_or_default(),
        "-c",
        conf.to_str().unwrap_or_default(),
    ];
    args.extend_from_slice(extra);
    run(&args)
}

/// The stdout of an output, as text.
fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn test_request_reports_a_request_blocked_by_a_built_in_rule() -> Result<(), std::io::Error> {
    let dir = test_dir("test-request-builtin")?;
    let conf = write_file(&dir, "router.conf", &config("127.0.0.1:8080", ""))?;
    let output = test_request(
        &dir,
        "sqli.txt",
        "GET /items?id=1%20UNION%20SELECT%20password%20FROM%20users HTTP/1.1\r\nHost: example.com\r\n\r\n",
        &conf,
        &[],
    )?;
    let stdout = stdout_of(&output);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    assert!(
        stdout.contains("site: example.com (shadow off)"),
        "{stdout}"
    );
    assert!(stdout.contains("access list: allowed"), "{stdout}");
    assert!(
        stdout.contains("rules: vh-sqli-001 matched (block): UNION SELECT in a query string"),
        "{stdout}"
    );
    assert!(
        stdout.contains("result: blocked with 403 by rule vh-sqli-001"),
        "{stdout}"
    );
    Ok(())
}

#[test]
fn test_request_reports_a_request_blocked_by_deny_path() -> Result<(), std::io::Error> {
    let dir = test_dir("test-request-deny-path")?;
    let conf = write_file(
        &dir,
        "router.conf",
        "listen 127.0.0.1:8080;\ndecision {\n    backend http;\n    url http://127.0.0.1:9/decide;\n}\nsite example.com {\n    upstream http://127.0.0.1:9;\n    deny_path /xmlrpc.php;\n}\n",
    )?;
    let output = test_request(
        &dir,
        "xmlrpc.txt",
        "GET /xmlrpc.php HTTP/1.1\nHost: example.com\n\n",
        &conf,
        &[],
    )?;
    let stdout = stdout_of(&output);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    assert!(
        stdout.contains("deny_path: matched \"/xmlrpc.php\""),
        "{stdout}"
    );
    assert!(
        stdout.contains("result: blocked with 403 by deny_path /xmlrpc.php"),
        "{stdout}"
    );
    Ok(())
}

#[test]
fn test_request_reports_a_skip_rule_forwarding_without_the_backend() -> Result<(), std::io::Error> {
    let dir = test_dir("test-request-skip-rule")?;
    let skip = "rule local-health {\n    description \"health probe\";\n    action skip;\n    path = /healthz;\n}\n";
    let conf = write_file(&dir, "router.conf", &config("127.0.0.1:8080", skip))?;
    let output = test_request(
        &dir,
        "healthz.txt",
        "GET /healthz HTTP/1.1\nHost: example.com\n\n",
        &conf,
        &[],
    )?;
    let stdout = stdout_of(&output);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    assert!(
        stdout.contains(
            "rules: local-health matched (skip): health probe; path readings [\"/healthz\"]"
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "result: forwarded to http://127.0.0.1:9/ without the decision backend (skip rule local-health)"
        ),
        "{stdout}"
    );
    assert!(!stdout.contains("would be sent"), "{stdout}");
    Ok(())
}

#[test]
fn test_request_reports_a_request_that_would_go_to_the_backend() -> Result<(), std::io::Error> {
    let dir = test_dir("test-request-backend")?;
    let conf = write_file(&dir, "router.conf", &config("127.0.0.1:8080", ""))?;
    let output = test_request(
        &dir,
        "search.txt",
        "GET /search?q=hello HTTP/1.1\nHost: example.com\n\n",
        &conf,
        &[],
    )?;
    let stdout = stdout_of(&output);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    assert!(
        stdout.contains(
            "result: would be sent to the decision backend (http); the verdict is not known without calling it"
        ),
        "{stdout}"
    );
    Ok(())
}

#[test]
fn test_request_reports_an_access_list_denial_for_the_given_client() -> Result<(), std::io::Error> {
    let dir = test_dir("test-request-access")?;
    let access = "allow 10.0.0.0/8;\ndeny all;\n";
    let conf = write_file(&dir, "router.conf", &config("127.0.0.1:8080", access))?;
    let request = "GET /search?q=hello HTTP/1.1\nHost: example.com\n\n";

    let denied = test_request(
        &dir,
        "denied.txt",
        request,
        &conf,
        &["--client", "203.0.113.9"],
    )?;
    let stdout = stdout_of(&denied);
    assert_eq!(denied.status.code(), Some(0), "{}", text(&denied));
    assert!(stdout.contains("access list: denied"), "{stdout}");
    assert!(
        stdout.contains("result: blocked with 403 by the access list"),
        "{stdout}"
    );

    let allowed = test_request(
        &dir,
        "allowed.txt",
        request,
        &conf,
        &["--client", "10.1.2.3"],
    )?;
    let stdout = stdout_of(&allowed);
    assert_eq!(allowed.status.code(), Some(0), "{}", text(&allowed));
    assert!(stdout.contains("access list: allowed"), "{stdout}");
    Ok(())
}

#[test]
fn test_request_reports_a_shadow_site_that_would_block_and_forwards() -> Result<(), std::io::Error>
{
    let dir = test_dir("test-request-shadow")?;
    let conf = write_file(
        &dir,
        "router.conf",
        "listen 127.0.0.1:8080;\ndecision {\n    backend http;\n    url http://127.0.0.1:9/decide;\n}\nsite example.com {\n    upstream http://127.0.0.1:9;\n    mode shadow;\n}\n",
    )?;
    let output = test_request(
        &dir,
        "sqli.txt",
        "GET /items?id=1%20UNION%20SELECT%20password%20FROM%20users HTTP/1.1\nHost: example.com\n\n",
        &conf,
        &[],
    )?;
    let stdout = stdout_of(&output);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    assert!(stdout.contains("site: example.com (shadow on)"), "{stdout}");
    assert!(
        stdout.contains(
            "result: forwarded to http://127.0.0.1:9/ (shadow mode: would have been blocked with 403 by rule vh-sqli-001)"
        ),
        "{stdout}"
    );
    Ok(())
}

#[test]
fn test_request_reports_an_unknown_host_with_the_default_status() -> Result<(), std::io::Error> {
    let dir = test_dir("test-request-unknown-host")?;
    let conf = write_file(&dir, "router.conf", &config("127.0.0.1:8080", ""))?;
    let output = test_request(
        &dir,
        "other.txt",
        "GET / HTTP/1.1\nHost: other.example\n\n",
        &conf,
        &[],
    )?;
    let stdout = stdout_of(&output);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    assert!(stdout.contains("site: none"), "{stdout}");
    assert!(
        stdout.contains("result: rejected with 421 (unknown host"),
        "{stdout}"
    );
    Ok(())
}

#[test]
fn test_request_refuses_a_malformed_request_file_with_exit_one() -> Result<(), std::io::Error> {
    let dir = test_dir("test-request-malformed")?;
    let conf = write_file(&dir, "router.conf", &config("127.0.0.1:8080", ""))?;
    let output = test_request(
        &dir,
        "broken.txt",
        "GET / HTTP/1.1\nHost example.com\n\n",
        &conf,
        &[],
    )?;
    assert_eq!(output.status.code(), Some(1), "{}", text(&output));
    assert!(output.stdout.is_empty(), "{}", text(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("line 2"), "{stderr}");
    Ok(())
}

// ---------------------------------------------------------------------------
// suggest-skip-rules: learn skip-rule candidates from a json access log
// ---------------------------------------------------------------------------

/// A `json` access log in which `GET /` with shape `p=<num>` is judged 50 times by 10
/// clients on 3 days, with low scores and no block.
fn learnable_access_log() -> String {
    use std::fmt::Write as _;
    let mut log = String::new();
    for i in 0..50 {
        let _ = writeln!(
            log,
            "{{\"time\":\"2026-01-{:02}T10:00:00Z\",\"client_ip\":\"192.0.2.{}\",\"site\":\"example.com\",\"method\":\"GET\",\"path\":\"/\",\"query_shape\":\"p=<num>\",\"action\":\"allow\",\"reason\":\"model\",\"would_have\":\"\",\"attack\":\"0.05\",\"ai_instruction\":\"0.02\"}}",
            1 + i % 3,
            1 + i % 10
        );
    }
    log
}

#[test]
fn suggest_skip_rules_prints_the_learned_candidate_and_its_rule() -> Result<(), std::io::Error> {
    let dir = test_dir("suggest-skip-rules")?;
    let log = write_file(&dir, "access.json", &learnable_access_log())?;
    let output = run(&["suggest-skip-rules", log.to_str().unwrap_or_default()])?;
    let stdout = stdout_of(&output);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    assert!(stdout.contains("Candidates: 1"), "{stdout}");
    assert!(stdout.contains("rule learned-1 {"), "{stdout}");
    assert!(stdout.contains("query ~ \"^p=[0-9]{1,20}$\";"), "{stdout}");
    Ok(())
}

#[test]
fn suggest_skip_rules_refuses_the_config_flag() -> Result<(), std::io::Error> {
    let dir = test_dir("suggest-skip-rules-config")?;
    let log = write_file(&dir, "access.json", &learnable_access_log())?;
    let conf = write_file(&dir, "router.conf", &config("127.0.0.1:8080", ""))?;
    let output = run(&[
        "suggest-skip-rules",
        log.to_str().unwrap_or_default(),
        "-c",
        conf.to_str().unwrap_or_default(),
    ])?;
    assert_eq!(output.status.code(), Some(1), "{}", text(&output));
    assert!(output.stdout.is_empty(), "{}", text(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("suggest-skip-rules reads only the access log; -c is not used"),
        "{stderr}"
    );
    Ok(())
}

/// A configuration with a body limit of 10 bytes and one enforced site, for the body checks of `test-request`.
fn body_limit_config() -> String {
    "listen 127.0.0.1:8080;\nclient_max_body_size 10;\ndecision {\n    backend http;\n    url http://127.0.0.1:9/decide;\n}\nsite example.com {\n    upstream http://127.0.0.1:9;\n}\n".to_owned()
}

#[test]
fn test_request_accepts_a_body_of_exactly_the_limit_when_it_declares_it()
-> Result<(), std::io::Error> {
    let dir = test_dir("test-request-body-exact")?;
    let conf = write_file(&dir, "router.conf", &body_limit_config())?;
    let output = test_request(
        &dir,
        "exact.txt",
        "POST /upload HTTP/1.1\nHost: example.com\nContent-Length: 10\n\naaaaaaaaaa",
        &conf,
        &[],
    )?;
    let stdout = stdout_of(&output);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    assert!(!stdout.contains("body: larger"), "{stdout}");
    assert!(
        stdout.contains("would be sent to the decision backend"),
        "{stdout}"
    );
    Ok(())
}

#[test]
fn test_request_accepts_a_declared_body_that_is_under_the_limit() -> Result<(), std::io::Error> {
    let dir = test_dir("test-request-body-under")?;
    let conf = write_file(&dir, "router.conf", &body_limit_config())?;
    let output = test_request(
        &dir,
        "under.txt",
        "POST /upload HTTP/1.1\nHost: example.com\nContent-Length: 5\n\naaaaa",
        &conf,
        &[],
    )?;
    let stdout = stdout_of(&output);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    assert!(!stdout.contains("body: larger"), "{stdout}");
    assert!(
        stdout.contains("would be sent to the decision backend"),
        "{stdout}"
    );
    Ok(())
}

#[test]
fn test_request_accepts_an_undeclared_body_of_exactly_the_limit() -> Result<(), std::io::Error> {
    let dir = test_dir("test-request-body-exact-undeclared")?;
    let conf = write_file(&dir, "router.conf", &body_limit_config())?;
    let output = test_request(
        &dir,
        "undeclared-exact.txt",
        "POST /upload HTTP/1.1\nHost: example.com\n\naaaaaaaaaa",
        &conf,
        &[],
    )?;
    let stdout = stdout_of(&output);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    assert!(!stdout.contains("body: larger"), "{stdout}");
    Ok(())
}

#[test]
fn test_request_refuses_a_body_one_byte_over_the_limit_with_no_declared_length()
-> Result<(), std::io::Error> {
    let dir = test_dir("test-request-body-over-undeclared")?;
    let conf = write_file(&dir, "router.conf", &body_limit_config())?;
    let output = test_request(
        &dir,
        "undeclared-over.txt",
        "POST /upload HTTP/1.1\nHost: example.com\n\naaaaaaaaaaa",
        &conf,
        &[],
    )?;
    let stdout = stdout_of(&output);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    assert!(
        stdout.contains("body: larger than client_max_body_size (10 bytes)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("result: rejected with 413 (body_too_large)"),
        "{stdout}"
    );
    Ok(())
}

#[test]
fn test_request_refuses_a_declared_length_over_the_limit_even_when_the_sample_body_is_short()
-> Result<(), std::io::Error> {
    let dir = test_dir("test-request-body-over-declared")?;
    let conf = write_file(&dir, "router.conf", &body_limit_config())?;
    let output = test_request(
        &dir,
        "declared-over.txt",
        "POST /upload HTTP/1.1\nHost: example.com\nContent-Length: 20\n\naaaaa",
        &conf,
        &[],
    )?;
    let stdout = stdout_of(&output);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    assert!(
        stdout.contains("result: rejected with 413 (body_too_large)"),
        "{stdout}"
    );
    Ok(())
}

#[test]
fn test_request_refuses_a_declared_length_one_over_the_limit() -> Result<(), std::io::Error> {
    let dir = test_dir("test-request-body-one-over")?;
    let conf = write_file(&dir, "router.conf", &body_limit_config())?;
    let output = test_request(
        &dir,
        "declared-one-over.txt",
        "POST /upload HTTP/1.1\nHost: example.com\nContent-Length: 11\n\naaaaaaaaaaa",
        &conf,
        &[],
    )?;
    let stdout = stdout_of(&output);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    assert!(
        stdout.contains("result: rejected with 413 (body_too_large)"),
        "{stdout}"
    );
    Ok(())
}

#[test]
fn test_request_reports_the_limit_zones_of_the_location_the_path_selects()
-> Result<(), std::io::Error> {
    let dir = test_dir("test-request-limit-zones")?;
    let conf = write_file(
        &dir,
        "router.conf",
        "listen 127.0.0.1:8080;\nlimit_req_zone $client_ip zone=perip:1m rate=10r/s;\nlimit_conn_zone $client_ip zone=conns:1m;\ndecision {\n    backend http;\n    url http://127.0.0.1:9/decide;\n}\nsite example.com {\n    upstream http://127.0.0.1:9;\n    location /login {\n        limit_req zone=perip burst=2;\n        limit_conn conns 4;\n    }\n}\n",
    )?;
    let login = test_request(
        &dir,
        "login.txt",
        "GET /login HTTP/1.1\nHost: example.com\n\n",
        &conf,
        &[],
    )?;
    let stdout = stdout_of(&login);
    assert_eq!(login.status.code(), Some(0), "{}", text(&login));
    assert!(
        stdout.contains("limits: not simulated (counts depend on earlier requests); limit_req zones: perip; limit_conn zones: conns"),
        "{stdout}"
    );

    let other = test_request(
        &dir,
        "other.txt",
        "GET /other HTTP/1.1\nHost: example.com\n\n",
        &conf,
        &[],
    )?;
    let stdout = stdout_of(&other);
    assert_eq!(other.status.code(), Some(0), "{}", text(&other));
    assert!(
        stdout.contains("limit_req zones: none; limit_conn zones: none"),
        "{stdout}"
    );
    Ok(())
}

#[test]
fn test_request_names_a_limit_zone_once_when_two_directives_use_it() -> Result<(), std::io::Error> {
    let dir = test_dir("test-request-limit-zone-once")?;
    let conf = write_file(
        &dir,
        "router.conf",
        "listen 127.0.0.1:8080;\nlimit_req_zone $client_ip zone=perip:1m rate=10r/s;\ndecision {\n    backend http;\n    url http://127.0.0.1:9/decide;\n}\nsite example.com {\n    upstream http://127.0.0.1:9;\n    location /login {\n        limit_req zone=perip burst=2;\n        limit_req zone=perip burst=5;\n    }\n}\n",
    )?;
    let output = test_request(
        &dir,
        "twice.txt",
        "GET /login HTTP/1.1\nHost: example.com\n\n",
        &conf,
        &[],
    )?;
    let stdout = stdout_of(&output);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    assert!(
        stdout.contains("limit_req zones: perip; limit_conn zones: none"),
        "{stdout}"
    );
    Ok(())
}

#[test]
fn test_request_says_a_shadow_site_forwards_what_the_backend_decides() -> Result<(), std::io::Error>
{
    let dir = test_dir("test-request-shadow-backend")?;
    let shadow = write_file(
        &dir,
        "shadow.conf",
        "listen 127.0.0.1:8080;\ndecision {\n    backend http;\n    url http://127.0.0.1:9/decide;\n}\nsite example.com {\n    upstream http://127.0.0.1:9;\n    mode shadow;\n}\n",
    )?;
    let enforce = write_file(&dir, "enforce.conf", &config("127.0.0.1:8080", ""))?;
    let request = "GET /search?q=hello HTTP/1.1\nHost: example.com\n\n";

    let output = test_request(&dir, "shadow.txt", request, &shadow, &[])?;
    let stdout = stdout_of(&output);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    assert!(
        stdout.contains("shadow mode: a verdict of attack"),
        "{stdout}"
    );
    assert!(
        stdout.contains("and the request would be forwarded to http://127.0.0.1:9/"),
        "{stdout}"
    );
    assert!(
        !stdout.contains("otherwise the request would be forwarded"),
        "{stdout}"
    );

    let output = test_request(&dir, "enforce.txt", request, &enforce, &[])?;
    let stdout = stdout_of(&output);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    assert!(
        stdout.contains("otherwise the request would be forwarded to http://127.0.0.1:9/"),
        "{stdout}"
    );
    assert!(!stdout.contains("shadow mode: a verdict"), "{stdout}");
    Ok(())
}

#[test]
fn start_reports_a_router_that_exited_while_starting_without_waiting_out_the_timeout()
-> Result<(), std::io::Error> {
    let fixture = Fixture::new("start-exited")?;
    let held = TcpListener::bind("127.0.0.1:0")?;
    let port = held.local_addr()?.port();
    fixture.write(&router_config(port, &fixture.pid, 9, ""))?;
    let started = std::time::Instant::now();
    let output = fixture.lifecycle("start")?;
    assert_eq!(output.status.code(), Some(1), "{}", text(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("the router exited while starting"),
        "a router that exits is reported as such, not as a missing pid file: {stderr}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the exit was not noticed until the startup timeout passed"
    );
    Ok(())
}
