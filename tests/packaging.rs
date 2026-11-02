//! The installer in `packaging/install.sh`, run as a process with `--root` into a temporary
//! directory, and the files it installs. Each test is named after a behavior that
//! docs/install.md or the changelog states, or that the installer prints.
//!
//! The installer creates a user, changes owners and refuses to run without root on the
//! real system. Those paths need root, so `scripts/check-install.sh` checks them in CI on
//! a throwaway machine. A test here that would reach them checks only the refusal, which
//! happens before anything is written, and it runs only when the tests run as a normal user.

use std::error::Error;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
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

fn running_as_root() -> Result<bool, std::io::Error> {
    let uid = Command::new("id").arg("-u").output()?;
    Ok(String::from_utf8_lossy(&uid.stdout).trim() == "0")
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

/// Lays out the archive that release.yml builds, under `dir`, and returns its path. The
/// sample configuration is copied only when `with_sample` is true.
fn archive(dir: &Path, with_sample: bool) -> Result<PathBuf, std::io::Error> {
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
    if with_sample {
        fs::copy(
            repo("examples/vigilant-heron.conf"),
            archive.join("examples/vigilant-heron.conf"),
        )?;
    }
    Ok(archive)
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
    assert!(
        !text(&output).contains("systemctl restart"),
        "a first install must not ask for a restart"
    );

    let bin = root.join("usr/local/bin/vigilant-heron");
    assert_eq!(fs::read(&bin)?, fs::read(BIN)?);
    assert_eq!(mode(&bin)?, 0o755);

    let etc = root.join("etc/vigilant-heron");
    assert_eq!(mode(&etc)?, 0o750, "/etc/vigilant-heron");
    let env = etc.join("env");
    assert_eq!(mode(&env)?, 0o600, "the token file");
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

    let output = install(&root, &newer)?;
    succeeded(&output)?;
    assert_eq!(
        fs::read(root.join("usr/local/bin/vigilant-heron"))?,
        newer_bytes
    );
    assert_eq!(fs::read(&unit)?, packaged_unit()?);
    assert_eq!(fs::read(&logrotate)?, packaged_logrotate()?);
    assert!(
        text(&output).contains("sudo systemctl restart vigilant-heron"),
        "a re-run that replaces the binary must say that the service needs a restart: {}",
        text(&output)
    );
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
        out.contains("access_log /var/log/vigilant-heron/access.json json;"),
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
    if running_as_root()? {
        eprintln!(
            "skipped install_refuses_to_run_as_a_normal_user_without_root_dir: the tests run as root, \
             and without --root the installer would write to the real system"
        );
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
fn a_root_of_slash_or_an_empty_value_is_the_real_system_not_a_root_directory() -> TestResult {
    if running_as_root()? {
        eprintln!(
            "skipped a_root_of_slash_or_an_empty_value_is_the_real_system_not_a_root_directory: \
             the tests run as root, and without a root directory the installer would write to the real system"
        );
        return Ok(());
    }
    // As a normal user, the real system is refused at the root check. If "/" or "" counted
    // as a root directory, the installer would skip that check and go on.
    for value in ["/", "", "//"] {
        let output = Command::new("sh")
            .arg(repo("packaging/install.sh"))
            .arg("--root")
            .arg(value)
            .arg("--binary")
            .arg(BIN)
            .output()?;
        assert!(
            !output.status.success(),
            "--root {value:?} did not refuse: {}",
            text(&output)
        );
        assert!(
            text(&output).contains("run as root"),
            "--root {value:?}: {}",
            text(&output)
        );
    }
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
fn a_missing_sample_stops_before_anything_is_written() -> TestResult {
    let dir = test_dir("missing-sample")?;
    let archive = archive(&dir, false)?;
    let root = dir.join("root");
    let output = Command::new("sh")
        .current_dir(&archive)
        .arg("packaging/install.sh")
        .arg("--root")
        .arg(&root)
        .output()?;
    assert!(!output.status.success());
    assert!(
        text(&output).contains("missing file")
            && text(&output).contains("examples/vigilant-heron.conf"),
        "{}",
        text(&output)
    );
    assert!(
        !root.exists(),
        "the installer wrote into {}",
        root.display()
    );
    Ok(())
}

#[test]
fn install_refuses_to_follow_a_symbolic_link_before_writing_anything() -> TestResult {
    // Each case replaces one path the installer writes or keeps with a link to a place
    // outside the root. The directory case is a link to an outside directory, and the other
    // two link to an outside file.
    let cases = [
        ("etc/vigilant-heron", true),
        ("etc/vigilant-heron/env", false),
        ("usr/local/bin/vigilant-heron", false),
    ];
    for (name, is_dir) in cases {
        let dir = test_dir(&format!("symlink-{}", name.replace('/', "-")))?;
        let root = dir.join("root");
        let link = root.join(name);
        fs::create_dir_all(link.parent().ok_or("no parent")?)?;
        let outside = dir.join("outside");
        if is_dir {
            fs::create_dir_all(&outside)?;
        }
        symlink(&outside, &link)?;

        let output = install(&root, Path::new(BIN))?;
        assert!(
            !output.status.success(),
            "{name}: the installer did not refuse"
        );
        assert!(
            text(&output).contains("symbolic link"),
            "{name}: {}",
            text(&output)
        );
        assert!(
            fs::symlink_metadata(&link)?.file_type().is_symlink(),
            "{name}: the link was replaced"
        );
        if is_dir {
            assert_eq!(
                fs::read_dir(&outside)?.count(),
                0,
                "{name}: wrote through the link"
            );
        } else {
            assert!(!outside.exists(), "{name}: wrote through the link");
        }
        assert!(
            !root.join("etc/systemd").exists(),
            "{name}: wrote the unit before stopping"
        );
        assert!(
            !root.join("etc/logrotate.d").exists(),
            "{name}: wrote logrotate before stopping"
        );
    }
    Ok(())
}

#[test]
fn the_archive_layout_installs_with_the_default_binary_and_sample() -> TestResult {
    // The layout that release.yml builds: the binary, the packaging folder and the sample.
    let dir = test_dir("archive")?;
    let archive = archive(&dir, true)?;
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
        "su vigilant-heron adm",
        "systemctl kill -s USR1 vigilant-heron.service >/dev/null 2>&1 || true",
    ] {
        assert!(lines.contains(&wanted), "logrotate file lacks {wanted:?}");
    }
    Ok(())
}

#[test]
fn the_unit_runs_the_router_hardened_as_its_user() -> TestResult {
    let text = String::from_utf8(packaged_unit()?)?;
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    for wanted in [
        "User=vigilant-heron",
        "RuntimeDirectory=vigilant-heron",
        "EnvironmentFile=/etc/vigilant-heron/env",
        "ExecReload=/usr/local/bin/vigilant-heron -s reload -c /etc/vigilant-heron/vigilant-heron.conf",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "ReadWritePaths=/var/log/vigilant-heron",
        "ProtectHome=yes",
        "PrivateTmp=yes",
        "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes",
        "ProtectControlGroups=yes",
        "RestrictSUIDSGID=yes",
        "LockPersonality=yes",
        "UMask=0027",
    ] {
        assert!(lines.contains(&wanted), "the unit lacks {wanted:?}");
    }
    Ok(())
}

#[test]
fn the_unit_does_not_restrict_sockets_or_capabilities() -> TestResult {
    // The router listens on sockets, and syslog and future listeners need more than the
    // defaults, so the unit leaves address families and capabilities alone.
    let text = String::from_utf8(packaged_unit()?)?;
    for line in text.lines().map(str::trim) {
        for key in [
            "RestrictAddressFamilies=",
            "CapabilityBoundingSet=",
            "AmbientCapabilities=",
        ] {
            assert!(!line.starts_with(key), "the unit sets {line:?}");
        }
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
