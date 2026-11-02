//! The installer in `packaging/install.sh`, run as a process with `--root` into a temporary
//! directory, and the files it installs. Each test is named after a behavior that
//! docs/install.md or the changelog states, or that the installer prints.
//!
//! The installer creates a user and changes owners only without `--root`, and that path
//! needs root, so these tests do not cover it. A test that runs the installer without
//! `--root` checks only the refusal, which happens before anything is written.

use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

type TestResult = Result<(), Box<dyn Error>>;

/// The binary under test. The installer copies it as if it were the release binary.
const BIN: &str = env!("CARGO_BIN_EXE_vigilant-heron");

fn repo(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
}

/// A fresh directory for one test, named after the test and this process.
fn test_dir(name: &str) -> Result<PathBuf, std::io::Error> {
    let dir = std::env::temp_dir().join(format!("vh-packaging-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Runs the installer from the repository with `--root` and `--binary`.
fn install(root: &Path, binary: &Path) -> Result<Output, std::io::Error> {
    Command::new("sh")
        .arg(repo("packaging/install.sh"))
        .arg("--root")
        .arg(root)
        .arg("--binary")
        .arg(binary)
        .output()
}

/// The standard output and standard error together, for messages in assertions.
fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn succeeded(output: &Output) -> TestResult {
    if output.status.success() {
        return Ok(());
    }
    Err(format!("install.sh failed: {}", text(output)).into())
}

/// The permission bits of a path, such as 0o750.
fn mode(path: &Path) -> Result<u32, std::io::Error> {
    Ok(fs::metadata(path)?.permissions().mode() & 0o777)
}

/// The packaged files the installer copies, as they are in the repository.
fn packaged_unit() -> Result<Vec<u8>, std::io::Error> {
    fs::read(repo("packaging/systemd/vigilant-heron.service"))
}

fn packaged_logrotate() -> Result<Vec<u8>, std::io::Error> {
    fs::read(repo("packaging/logrotate/vigilant-heron"))
}

fn sample_config() -> Result<Vec<u8>, std::io::Error> {
    fs::read(repo("examples/vigilant-heron.conf"))
}

#[test]
fn install_under_root_creates_the_files_with_the_documented_modes() -> TestResult {
    let dir = test_dir("modes")?;
    let root = dir.join("root");
    let output = install(&root, Path::new(BIN))?;
    succeeded(&output)?;
    assert!(
        text(&output).contains("--root given: skipping the user and group"),
        "the installer does not say that it skipped the user step: {}",
        text(&output)
    );

    let bin = root.join("usr/local/bin/vigilant-heron");
    assert_eq!(fs::read(&bin)?, fs::read(BIN)?);
    assert_eq!(mode(&bin)?, 0o755);

    let etc = root.join("etc/vigilant-heron");
    assert_eq!(mode(&etc)?, 0o750, "/etc/vigilant-heron");
    let env = etc.join("env");
    assert_eq!(mode(&env)?, 0o640, "the token file");
    let env_text = fs::read_to_string(&env)?;
    assert!(
        env_text.lines().all(|line| line.starts_with('#')),
        "the token template has an active line, so the service would start with it: {env_text}"
    );
    assert!(env_text.contains("TYPESAFE_API_KEY") && env_text.contains("CLOUDFLARE_AI_TOKEN"));
    let conf = etc.join("vigilant-heron.conf");
    assert_eq!(fs::read(&conf)?, sample_config()?, "the copied sample");
    assert_eq!(mode(&conf)?, 0o640, "the configuration file");

    let log = root.join("var/log/vigilant-heron");
    assert_eq!(mode(&log)?, 0o750, "/var/log/vigilant-heron");

    let unit = root.join("etc/systemd/system/vigilant-heron.service");
    assert_eq!(fs::read(&unit)?, packaged_unit()?);
    assert_eq!(mode(&unit)?, 0o644);

    let logrotate = root.join("etc/logrotate.d/vigilant-heron");
    assert_eq!(fs::read(&logrotate)?, packaged_logrotate()?);
    assert_eq!(mode(&logrotate)?, 0o644);
    Ok(())
}

#[test]
fn a_second_run_keeps_an_edited_configuration_and_token_file() -> TestResult {
    let dir = test_dir("keeps-edits")?;
    let root = dir.join("root");
    succeeded(&install(&root, Path::new(BIN))?)?;

    let etc = root.join("etc/vigilant-heron");
    fs::write(etc.join("vigilant-heron.conf"), "pid /run/edited.pid;\n")?;
    fs::write(etc.join("env"), "TYPESAFE_API_KEY=kept-by-the-operator\n")?;

    let output = install(&root, Path::new(BIN))?;
    succeeded(&output)?;
    assert!(text(&output).contains("kept "), "{}", text(&output));
    assert_eq!(
        fs::read_to_string(etc.join("vigilant-heron.conf"))?,
        "pid /run/edited.pid;\n"
    );
    assert_eq!(
        fs::read_to_string(etc.join("env"))?,
        "TYPESAFE_API_KEY=kept-by-the-operator\n"
    );
    Ok(())
}

#[test]
fn a_second_run_replaces_the_binary_and_the_unit() -> TestResult {
    let dir = test_dir("replaces")?;
    let root = dir.join("root");
    succeeded(&install(&root, Path::new(BIN))?)?;

    let newer = dir.join("newer-binary");
    let mut newer_bytes = fs::read(BIN)?;
    newer_bytes.extend_from_slice(b"newer");
    fs::write(&newer, &newer_bytes)?;
    let unit = root.join("etc/systemd/system/vigilant-heron.service");
    let logrotate = root.join("etc/logrotate.d/vigilant-heron");
    fs::write(&unit, "stale\n")?;
    fs::write(&logrotate, "stale\n")?;

    succeeded(&install(&root, &newer)?)?;
    assert_eq!(
        fs::read(root.join("usr/local/bin/vigilant-heron"))?,
        newer_bytes
    );
    assert_eq!(fs::read(&unit)?, packaged_unit()?);
    assert_eq!(fs::read(&logrotate)?, packaged_logrotate()?);
    Ok(())
}

#[test]
fn install_does_not_run_systemctl_and_prints_the_next_steps() -> TestResult {
    let dir = test_dir("no-systemctl")?;
    let root = dir.join("root");
    // A stand-in systemctl first on PATH, which records each call.
    let fake_bin = dir.join("fake-bin");
    fs::create_dir_all(&fake_bin)?;
    let calls = dir.join("systemctl-calls");
    let fake = fake_bin.join("systemctl");
    fs::write(
        &fake,
        format!("#!/bin/sh\necho \"$@\" >>'{}'\n", calls.display()),
    )?;
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o755))?;
    let path = format!(
        "{}:{}",
        fake_bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let output = Command::new("sh")
        .arg(repo("packaging/install.sh"))
        .arg("--root")
        .arg(&root)
        .arg("--binary")
        .arg(BIN)
        .env("PATH", path)
        .output()?;
    succeeded(&output)?;
    assert!(!calls.exists(), "the installer called systemctl");

    let out = text(&output);
    assert!(out.contains("The service is not started."), "{out}");
    assert!(
        out.contains("pid /run/vigilant-heron/vigilant-heron.pid;"),
        "{out}"
    );
    assert!(
        out.contains("access_log /var/log/vigilant-heron/access.log main;"),
        "{out}"
    );
    assert!(
        out.contains("sudo systemctl enable --now vigilant-heron"),
        "{out}"
    );
    Ok(())
}

#[test]
fn install_refuses_to_run_as_a_normal_user_without_root_dir() -> TestResult {
    let uid = Command::new("id").arg("-u").output()?;
    if String::from_utf8_lossy(&uid.stdout).trim() == "0" {
        // Run as root, the refusal would not happen, and the installer would write to the
        // real system. The refusal is then covered only when the tests run as a normal user.
        return Ok(());
    }
    let output = Command::new("sh")
        .arg(repo("packaging/install.sh"))
        .arg("--binary")
        .arg(BIN)
        .output()?;
    assert!(!output.status.success(), "{}", text(&output));
    assert!(text(&output).contains("run as root"), "{}", text(&output));
    Ok(())
}

#[test]
fn a_missing_binary_stops_before_anything_is_written() -> TestResult {
    let dir = test_dir("missing-binary")?;
    let root = dir.join("root");
    let output = install(&root, &dir.join("no-such-binary"))?;
    assert!(!output.status.success());
    assert!(text(&output).contains("missing file"), "{}", text(&output));
    assert!(
        !root.exists(),
        "the installer wrote into {}",
        root.display()
    );
    Ok(())
}

#[test]
fn the_archive_layout_installs_with_the_default_binary_and_sample() -> TestResult {
    // The layout that release.yml builds: the binary, the packaging folder and the sample.
    let dir = test_dir("archive")?;
    let archive = dir.join("vigilant-heron-x86_64-unknown-linux-gnu");
    let packaging = archive.join("packaging");
    fs::create_dir_all(packaging.join("systemd"))?;
    fs::create_dir_all(packaging.join("logrotate"))?;
    fs::create_dir_all(archive.join("examples"))?;
    fs::copy(BIN, archive.join("vigilant-heron"))?;
    fs::copy(repo("packaging/install.sh"), packaging.join("install.sh"))?;
    fs::copy(
        repo("packaging/systemd/vigilant-heron.service"),
        packaging.join("systemd/vigilant-heron.service"),
    )?;
    fs::copy(
        repo("packaging/logrotate/vigilant-heron"),
        packaging.join("logrotate/vigilant-heron"),
    )?;
    fs::copy(
        repo("examples/vigilant-heron.conf"),
        archive.join("examples/vigilant-heron.conf"),
    )?;

    let root = dir.join("root");
    let output = Command::new("sh")
        .current_dir(&archive)
        .arg("packaging/install.sh")
        .arg("--root")
        .arg(&root)
        .output()?;
    succeeded(&output)?;
    assert_eq!(
        fs::read(root.join("usr/local/bin/vigilant-heron"))?,
        fs::read(BIN)?
    );
    assert_eq!(
        fs::read(root.join("etc/vigilant-heron/vigilant-heron.conf"))?,
        sample_config()?
    );
    Ok(())
}

#[test]
fn the_logrotate_file_rotates_daily_and_sends_sigusr1() -> TestResult {
    let text = String::from_utf8(packaged_logrotate()?)?;
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    for wanted in [
        "/var/log/vigilant-heron/*.log {",
        "daily",
        "rotate 14",
        "compress",
        "delaycompress",
        "missingok",
        "notifempty",
        "create 640 vigilant-heron adm",
        "systemctl kill -s USR1 vigilant-heron.service >/dev/null 2>&1 || true",
    ] {
        assert!(lines.contains(&wanted), "logrotate file lacks {wanted:?}");
    }
    Ok(())
}

#[test]
fn the_unit_runs_as_the_service_user_with_a_runtime_directory_and_a_reload() -> TestResult {
    let text = String::from_utf8(packaged_unit()?)?;
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    for wanted in [
        "User=vigilant-heron",
        "RuntimeDirectory=vigilant-heron",
        "EnvironmentFile=/etc/vigilant-heron/env",
        "ExecReload=/usr/local/bin/vigilant-heron -s reload -c /etc/vigilant-heron/vigilant-heron.conf",
    ] {
        assert!(lines.contains(&wanted), "the unit lacks {wanted:?}");
    }
    Ok(())
}

#[test]
fn release_workflow_adds_packaging_and_the_sample_to_the_archive() -> TestResult {
    let workflow = fs::read_to_string(repo(".github/workflows/release.yml"))?;
    for wanted in [
        r#"cp -R "$GITHUB_WORKSPACE/packaging" "$name/""#,
        r#"cp "$GITHUB_WORKSPACE/examples/vigilant-heron.conf" "$name/examples/""#,
    ] {
        assert!(
            workflow.contains(wanted),
            "release.yml does not package {wanted:?}"
        );
    }
    Ok(())
}
