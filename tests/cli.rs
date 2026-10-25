//! The `vigilant-heron` binary in test mode (`-t`): results, exit codes, and no bind.

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
