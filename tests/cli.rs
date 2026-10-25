//! The `vigilant-heron` binary in test mode (`-t`): results, exit codes, and no bind.

use std::io::Read;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output};

/// Writes `text` to a fresh file named `name` in a temporary directory and returns its path.
fn write_config(name: &str, text: &str) -> Result<PathBuf, std::io::Error> {
    let dir = std::env::temp_dir().join(format!("vh-cli-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(name);
    std::fs::write(&path, text)?;
    Ok(path)
}

fn run_test_mode(path: &PathBuf) -> Result<Output, std::io::Error> {
    Command::new(env!("CARGO_BIN_EXE_vigilant-heron"))
        .arg("-t")
        .arg("--config")
        .arg(path)
        .env_remove("VIGILANT_HERON_CONFIG")
        .output()
}

/// The configuration text, with `listen` on `listen` and one extra line after the decision block.
fn config(listen: &str, extra: &str) -> String {
    format!(
        "listen {listen};\ndecision {{\n    backend http;\n    url http://127.0.0.1:9/decide;\n}}\n{extra}\nsite example.com {{\n    upstream http://127.0.0.1:9;\n}}\n"
    )
}

#[test]
fn a_valid_configuration_passes_the_test() -> Result<(), std::io::Error> {
    let path = write_config("valid.conf", &config("127.0.0.1:8080", ""))?;
    let output = run_test_mode(&path)?;
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
fn an_invalid_configuration_fails_with_its_file_and_line() -> Result<(), std::io::Error> {
    let path = write_config(
        "invalid.conf",
        &config("127.0.0.1:8080", "default_status 200;"),
    )?;
    let output = run_test_mode(&path)?;
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
    let path = write_config(
        "missing-page.conf",
        &config(
            "127.0.0.1:8080",
            "block_page /nonexistent/vigilant-heron/page.html;",
        ),
    )?;
    let output = run_test_mode(&path)?;
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("block_page"));
    Ok(())
}

#[test]
fn the_test_never_binds_the_listen_address() -> Result<(), std::io::Error> {
    // The address is taken by this test, so any bind attempt by the binary would fail.
    let held = TcpListener::bind("127.0.0.1:0")?;
    let listen = held.local_addr()?.to_string();
    let path = write_config("bound.conf", &config(&listen, ""))?;
    let output = run_test_mode(&path)?;
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

/// Returns the status line's code for a GET to `port` with `host`, or `None` when nothing answers.
fn status_for(port: u16, host: &str) -> Option<u16> {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .ok()?;
    let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).ok()?;
    let mut reply = String::new();
    stream.read_to_string(&mut reply).ok()?;
    reply.split_whitespace().nth(1)?.parse().ok()
}

/// A free loopback port: bound and released, so the server can take it.
fn free_port() -> Result<u16, std::io::Error> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

/// Waits until `status_for` gives `expected` for an unknown host, or gives up after five seconds.
fn wait_for_status(port: u16, expected: u16) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if status_for(port, "unknown.test") == Some(expected) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    false
}

/// Stops the spawned server even when an assertion fails.
struct Child(std::process::Child);

impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn sighup_applies_a_valid_file_and_keeps_the_old_one_for_a_broken_file()
-> Result<(), std::io::Error> {
    let port = free_port()?;
    let path = write_config("reload.conf", &config(&format!("127.0.0.1:{port}"), ""))?;
    let child = Command::new(env!("CARGO_BIN_EXE_vigilant-heron"))
        .arg("--config")
        .arg(&path)
        .env_remove("VIGILANT_HERON_CONFIG")
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let mut child = Child(child);
    assert!(wait_for_status(port, 421), "the server did not answer 421");

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
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert_eq!(status_for(port, "unknown.test"), Some(421));

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
    assert!(wait_for_status(port, 404), "the valid file was not applied");

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
