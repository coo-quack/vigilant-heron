//! The PID file: written when the router starts, read by `-s`, and removed on exit.
//!
//! A router that writes the file also holds an exclusive advisory lock on `<pid path>.lock`
//! for its whole life. The commands that read the file treat the router as running only
//! while that lock is held, so a pid file left by a crashed router, whose pid another
//! process may have reused, is never trusted.

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rustix::fs::{FlockOperation, Mode, OFlags, flock};
use rustix::io::Errno;
use rustix::process::geteuid;

/// The permission bit that lets any local user write to a directory.
const OTHERS_WRITE: u32 = 0o002;

/// How many times [`PidFile::lock`] tries the exclusive lock before it reports the pid file as in use.
const LOCK_ATTEMPTS: u32 = 5;
/// The wait between two attempts of [`PidFile::lock`].
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(20);

/// Creates a new file at `path` for writing. A leftover at `path` is removed first:
/// `remove_file` removes a symlink itself, never its target. The file is then opened
/// with `create_new` (`O_EXCL`), which fails rather than follow a symlink or reuse a
/// file that appeared in the meantime, so the write cannot reach another file.
pub(crate) fn create_exclusive(path: &Path) -> std::io::Result<File> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    OpenOptions::new().write(true).create_new(true).open(path)
}

/// The file name of `path`, which both the pid file and its lock file need.
fn file_name_of(path: &Path) -> std::io::Result<String> {
    path.file_name()
        .ok_or_else(|| std::io::Error::from(ErrorKind::InvalidInput))
        .map(|name| name.to_string_lossy().into_owned())
}

/// The directory that holds `path`, or `.` for a bare file name.
fn directory_of(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// The lock file of the pid file at `pid_path`: the same path with `.lock` appended.
pub(crate) fn lock_path(pid_path: &Path) -> std::io::Result<PathBuf> {
    let name = file_name_of(pid_path)?;
    Ok(pid_path.with_file_name(format!("{name}.lock")))
}

/// Refuses a file whose owner is not trusted, by [`is_trusted`] on the mode of its directory.
/// `what` names the file in the message.
fn check_trusted(path: &Path, what: &str, owner: u32) -> std::io::Result<()> {
    let mode = std::fs::metadata(directory_of(path))?.mode();
    if is_trusted(mode, owner, geteuid().as_raw()) {
        return Ok(());
    }
    Err(std::io::Error::new(
        ErrorKind::PermissionDenied,
        format!(
            "is not trusted: the {what} sits in a shared directory that other users can write, and user {owner} owns it; put the pid file in a directory that only the router's user can write"
        ),
    ))
}

/// Opens the lock file at `path` for the router, creating it with mode 0644 when it is
/// missing. `O_NOFOLLOW` makes a symlink an error, and an owner that is not trusted is
/// refused, so the lock is never taken on a file another user controls.
fn open_lock_file(path: &Path) -> std::io::Result<File> {
    let file = File::from(rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o644),
    )?);
    check_trusted(path, "lock file", file.metadata()?.uid())?;
    Ok(file)
}

/// A PID file this process wrote, and the lock that marks this process as the router.
/// The file is removed when the value is dropped, while the lock is still held. The lock
/// is released when the value is dropped, and the lock file itself is never removed.
#[derive(Debug)]
pub(crate) struct PidFile {
    path: PathBuf,
    /// The held lock file. `None` when the lock could not be taken, so the router runs
    /// without one and `-s` and `stop` do not find it.
    _lock: Option<File>,
    /// Whether [`PidFile::write`] has written the file, so that drop removes only our own file.
    written: bool,
}

impl PidFile {
    /// Takes the exclusive lock for the pid file at `path`. Nothing is written yet, so the
    /// caller takes the lock before it binds and calls [`PidFile::write`] once it is listening.
    ///
    /// A lock that another process holds for a moment, such as the shared probe that
    /// `-s` and `stop` take, is retried: the attempt is repeated up to five times, 20 ms
    /// apart, about 80 ms in all. Only when every attempt is refused is the lock held by
    /// another router.
    ///
    /// # Errors
    ///
    /// Returns `WouldBlock` with a message naming the pid file when another process still
    /// holds the lock after the retries. Other I/O errors, and an untrusted lock file, are
    /// returned as they occur.
    pub(crate) async fn lock(path: &Path) -> std::io::Result<Self> {
        let file = open_lock_file(&lock_path(path)?)?;
        for attempt in 1..=LOCK_ATTEMPTS {
            match flock(&file, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => {
                    return Ok(Self {
                        path: path.to_path_buf(),
                        _lock: Some(file),
                        written: false,
                    });
                }
                Err(Errno::WOULDBLOCK) if attempt < LOCK_ATTEMPTS => {
                    tokio::time::sleep(LOCK_RETRY_INTERVAL).await;
                }
                Err(Errno::WOULDBLOCK) => break,
                Err(error) => return Err(error.into()),
            }
        }
        Err(std::io::Error::new(
            ErrorKind::WouldBlock,
            format!("another router is using the pid file {}", path.display()),
        ))
    }

    /// A value for a router that could not take the lock. It writes the pid file as before,
    /// but holds no lock, so the commands that read the file treat the router as not running.
    pub(crate) fn unlocked(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            _lock: None,
            written: false,
        }
    }

    /// Writes the process id to the pid file, replacing any file there. The id goes to a
    /// temporary file in the same directory first, which is then renamed into place,
    /// so a reader never sees a partly written file.
    ///
    /// # Errors
    ///
    /// Returns the I/O error when the file cannot be written or renamed, and
    /// `InvalidInput` when the path has no file name.
    pub(crate) fn write(&mut self) -> std::io::Result<()> {
        let name = file_name_of(&self.path)?;
        let pid = std::process::id();
        let temporary = self.path.with_file_name(format!(".{name}.{pid}.tmp"));
        let written = create_exclusive(&temporary)
            .and_then(|mut file| file.write_all(format!("{pid}\n").as_bytes()));
        if let Err(error) = written.and_then(|()| std::fs::rename(&temporary, &self.path)) {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }
        self.written = true;
        Ok(())
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        if self.written {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Whether a router holds the lock of the pid file at `pid_path`. The lock is probed with a
/// shared lock that is released at once; a probe that fails because the router holds the
/// exclusive lock means the router is running. A missing lock file means no router is.
///
/// # Errors
///
/// Returns an error when the lock file is untrusted or cannot be opened or probed.
pub(crate) fn lock_held(pid_path: &Path) -> std::io::Result<bool> {
    let path = lock_path(pid_path)?;
    let file = match rustix::fs::open(
        &path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => File::from(fd),
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    check_trusted(&path, "lock file", file.metadata()?.uid())?;
    match flock(&file, FlockOperation::NonBlockingLockShared) {
        Ok(()) => {
            let _ = flock(&file, FlockOperation::NonBlockingUnlock);
            Ok(false)
        }
        Err(Errno::WOULDBLOCK) => Ok(true),
        Err(error) => Err(error.into()),
    }
}

/// Decides whether a pid file can be trusted, from the mode of its directory, the owner
/// of the file and the effective user of this process. In a directory that other users
/// can write, the file is trusted only when this process owns it. Elsewhere any owner is
/// trusted, so a service's pid file in a private directory stays usable by root.
pub(crate) fn is_trusted(directory_mode: u32, file_owner: u32, effective_uid: u32) -> bool {
    directory_mode & OTHERS_WRITE == 0 || file_owner == effective_uid
}

/// Parses the text of a pid file: a plain decimal number above zero, with surrounding
/// whitespace allowed. Signs, zero and anything else give `None`.
fn parse_pid(text: &str) -> Option<i32> {
    let digits = text.trim();
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse::<i32>().ok().filter(|pid| *pid > 0)
}

/// Reads the process id that the pid file at `path` holds. `-s`, `start`, `stop` and
/// `restart` signal the process this names, so the file is checked first: the file is
/// opened without following a symlink, its owner and its directory's mode are read, and
/// [`is_trusted`] decides whether to use it.
///
/// # Errors
///
/// Returns `NotFound` when there is no file, `PermissionDenied` when the file is not
/// trusted, `InvalidData` when it does not hold a positive process id, and the other
/// I/O errors when the file or its directory cannot be read.
pub(crate) fn read_pid(path: &Path) -> std::io::Result<i32> {
    let mut file = File::from(rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    check_trusted(path, "pid file", file.metadata()?.uid())?;
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    parse_pid(&text).ok_or_else(|| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            "does not hold a process id (a positive decimal number)",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::os::unix::fs::PermissionsExt;

    /// A fresh directory under the temporary directory, with the given mode.
    fn scratch_dir(name: &str, mode: u32) -> std::io::Result<PathBuf> {
        let dir = std::env::temp_dir().join(format!("vh-pid-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode))?;
        Ok(dir)
    }

    #[rstest]
    #[case::world_writable_sticky_owned_by_us(0o1777, 501, 501, true)]
    #[case::world_writable_sticky_owned_by_another_user(0o1777, 0, 501, false)]
    #[case::world_writable_owned_by_another_user(0o777, 1, 501, false)]
    #[case::private_directory_owned_by_another_user(0o755, 0, 501, true)]
    #[case::private_directory_owned_by_us(0o700, 501, 501, true)]
    #[case::group_writable_only_owned_by_another_user(0o775, 1, 501, true)]
    fn trust_depends_on_the_directory_and_the_owner(
        #[case] directory_mode: u32,
        #[case] file_owner: u32,
        #[case] effective_uid: u32,
        #[case] trusted: bool,
    ) {
        assert_eq!(
            is_trusted(directory_mode, file_owner, effective_uid),
            trusted
        );
    }

    #[rstest]
    #[case::plain("2145", Some(2145))]
    #[case::trailing_newline("2145\n", Some(2145))]
    #[case::zero("0", None)]
    #[case::negative("-1", None)]
    #[case::plus_sign("+7", None)]
    #[case::not_a_number("abc", None)]
    #[case::empty("", None)]
    #[case::fraction("1.5", None)]
    #[case::overflow("99999999999", None)]
    fn only_a_positive_decimal_is_a_pid(#[case] text: &str, #[case] expected: Option<i32>) {
        assert_eq!(parse_pid(text), expected);
    }

    #[test]
    fn a_pid_file_owned_by_us_in_a_sticky_world_writable_directory_is_read() -> std::io::Result<()>
    {
        let dir = scratch_dir("trusted", 0o1777)?;
        let path = dir.join("router.pid");
        std::fs::write(&path, "4242\n")?;
        let read = read_pid(&path);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(read?, 4242);
        Ok(())
    }

    #[rstest]
    #[case::zero("0\n")]
    #[case::negative("-1\n")]
    #[case::not_a_number("abc\n")]
    #[case::empty("")]
    fn a_pid_file_that_holds_no_positive_pid_is_invalid_data(
        #[case] text: &str,
    ) -> std::io::Result<()> {
        let dir = scratch_dir(&format!("invalid-{}", text.len()), 0o700)?;
        let path = dir.join("router.pid");
        std::fs::write(&path, text)?;
        let error = read_pid(&path).err();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            error.map(|error| error.kind()),
            Some(ErrorKind::InvalidData)
        );
        Ok(())
    }

    #[test]
    fn a_missing_pid_file_is_not_found() -> std::io::Result<()> {
        let dir = scratch_dir("missing", 0o700)?;
        let error = read_pid(&dir.join("router.pid")).err();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(error.map(|error| error.kind()), Some(ErrorKind::NotFound));
        Ok(())
    }

    #[test]
    fn a_symlink_planted_as_the_pid_file_is_refused() -> std::io::Result<()> {
        let dir = scratch_dir("symlink", 0o700)?;
        let target = dir.join("target.pid");
        std::fs::write(&target, "4242\n")?;
        let path = dir.join("router.pid");
        std::os::unix::fs::symlink(&target, &path)?;
        let read = read_pid(&path);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(read.is_err(), "a symlink was followed to read a pid");
        Ok(())
    }

    #[tokio::test]
    async fn a_symlink_planted_at_the_temporary_name_is_not_followed() -> std::io::Result<()> {
        let dir = std::env::temp_dir().join(format!("vh-pidfile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        let victim = dir.join("victim.txt");
        std::fs::write(&victim, "keep")?;
        let path = dir.join("router.pid");
        let temporary = dir.join(format!(".router.pid.{}.tmp", std::process::id()));
        std::os::unix::fs::symlink(&victim, &temporary)?;

        let created = PidFile::lock(&path)
            .await
            .and_then(|mut file| file.write().map(|()| file));
        let kept = std::fs::read_to_string(&victim)?;
        let written = std::fs::read_to_string(&path);
        let _ = std::fs::remove_dir_all(&dir);
        created?;
        assert_eq!(kept, "keep", "the victim was written through the symlink");
        assert_eq!(written?.trim(), std::process::id().to_string());
        Ok(())
    }

    #[tokio::test]
    async fn the_lock_is_released_when_the_pid_file_value_is_dropped() -> std::io::Result<()> {
        let dir = scratch_dir("lock-release", 0o700)?;
        let path = dir.join("router.pid");
        let held = PidFile::lock(&path).await?;
        let while_held = lock_held(&path);
        drop(held);
        let after_drop = lock_held(&path);
        let lock_file_kept = lock_path(&path)?.exists();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(while_held?, "the lock was not held");
        assert!(!after_drop?, "the lock outlived the value");
        assert!(lock_file_kept, "the lock file was removed on drop");
        Ok(())
    }

    #[tokio::test]
    async fn a_lock_released_during_the_retry_window_is_acquired() -> std::io::Result<()> {
        let dir = scratch_dir("lock-retry", 0o700)?;
        let path = dir.join("router.pid");
        // A shared lock held by "the probe", released after 30 ms, inside the 80 ms window.
        let probe = open_lock_file(&lock_path(&path)?)?;
        flock(&probe, FlockOperation::NonBlockingLockShared).map_err(std::io::Error::from)?;
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            drop(probe);
        });
        let acquired = PidFile::lock(&path).await;
        let _ = releaser.join();
        let _ = std::fs::remove_dir_all(&dir);
        acquired.map(drop)
    }

    #[tokio::test]
    async fn a_second_lock_on_the_same_pid_file_would_block() -> std::io::Result<()> {
        let dir = scratch_dir("lock-second", 0o700)?;
        let path = dir.join("router.pid");
        let first = PidFile::lock(&path).await?;
        let second = PidFile::lock(&path).await.err();
        drop(first);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            second.as_ref().map(std::io::Error::kind),
            Some(ErrorKind::WouldBlock)
        );
        assert!(
            second
                .map(|error| error.to_string())
                .is_some_and(|text| text.starts_with("another router is using the pid file ")),
        );
        Ok(())
    }

    #[test]
    fn no_lock_file_means_no_lock_is_held() -> std::io::Result<()> {
        let dir = scratch_dir("lock-none", 0o700)?;
        let held = lock_held(&dir.join("router.pid"));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!held?);
        Ok(())
    }

    #[tokio::test]
    async fn a_symlink_planted_as_the_lock_file_is_refused() -> std::io::Result<()> {
        let dir = scratch_dir("lock-symlink", 0o700)?;
        let target = dir.join("target.lock");
        std::fs::write(&target, "")?;
        let path = dir.join("router.pid");
        std::os::unix::fs::symlink(&target, lock_path(&path)?)?;
        let locked = PidFile::lock(&path).await.map(drop);
        let probed = lock_held(&path);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(locked.is_err(), "a symlinked lock file was used");
        assert!(probed.is_err(), "a symlinked lock file was probed");
        Ok(())
    }

    #[tokio::test]
    async fn a_pid_file_written_under_the_lock_is_removed_on_drop() -> std::io::Result<()> {
        let dir = scratch_dir("lock-write", 0o700)?;
        let path = dir.join("router.pid");
        let mut file = PidFile::lock(&path).await?;
        file.write()?;
        let written = read_pid(&path);
        drop(file);
        let removed = !path.exists();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(written?, i32::try_from(std::process::id()).unwrap_or(0));
        assert!(removed, "the pid file was not removed on drop");
        Ok(())
    }

    #[test]
    fn the_directory_of_a_path_is_its_parent() {
        assert_eq!(
            directory_of(Path::new("/run/vigilant-heron/router.pid")),
            Path::new("/run/vigilant-heron")
        );
    }

    #[test]
    fn a_bare_file_name_is_looked_up_in_the_current_directory() {
        assert_eq!(directory_of(Path::new("router.pid")), Path::new("."));
    }

    #[test]
    fn a_directory_at_the_pid_path_is_not_mistaken_for_a_file_that_exists() -> std::io::Result<()> {
        let dir = scratch_dir("directory-at-path", 0o700)?;
        let path = dir.join("router.pid");
        std::fs::create_dir(&path)?;
        std::fs::write(path.join("inside"), "")?;
        let error = create_exclusive(&path).err();
        let still_a_directory = path.is_dir();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(still_a_directory);
        assert!(error.is_some_and(|error| error.kind() != ErrorKind::AlreadyExists));
        Ok(())
    }
}
