//! The PID file: written when the router starts, read by `-s`, and removed on exit.

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};
use rustix::process::geteuid;

/// The permission bit that lets any local user write to a directory.
const OTHERS_WRITE: u32 = 0o002;

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

/// A PID file this process wrote. It is removed when the value is dropped.
#[derive(Debug)]
pub(crate) struct PidFile {
    path: PathBuf,
}

impl PidFile {
    /// Writes the process id to `path`, replacing any file there. The id goes to a
    /// temporary file in the same directory first, which is then renamed into place,
    /// so a reader never sees a partly written file.
    ///
    /// # Errors
    ///
    /// Returns the I/O error when the file cannot be written or renamed, and
    /// `InvalidInput` when `path` has no file name.
    pub(crate) fn create(path: &Path) -> std::io::Result<Self> {
        let name = path
            .file_name()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?
            .to_string_lossy()
            .into_owned();
        let pid = std::process::id();
        let temporary = path.with_file_name(format!(".{name}.{pid}.tmp"));
        let written = create_exclusive(&temporary)
            .and_then(|mut file| file.write_all(format!("{pid}\n").as_bytes()));
        if let Err(error) = written.and_then(|()| std::fs::rename(&temporary, path)) {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }
        Ok(Self {
            path: path.to_path_buf(),
        })
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
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
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let mut file = File::from(rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let owner = file.metadata()?.uid();
    let mode = std::fs::metadata(directory)?.mode();
    let effective_uid = geteuid().as_raw();
    if !is_trusted(mode, owner, effective_uid) {
        return Err(std::io::Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "is not trusted: the pid file sits in a shared directory that other users can write, and user {owner} owns it, so its process id is ignored; put the pid file in a directory that only the router's user can write"
            ),
        ));
    }
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

    #[test]
    fn a_symlink_planted_at_the_temporary_name_is_not_followed() -> std::io::Result<()> {
        let dir = std::env::temp_dir().join(format!("vh-pidfile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        let victim = dir.join("victim.txt");
        std::fs::write(&victim, "keep")?;
        let path = dir.join("router.pid");
        let temporary = dir.join(format!(".router.pid.{}.tmp", std::process::id()));
        std::os::unix::fs::symlink(&victim, &temporary)?;

        let created = PidFile::create(&path);
        let kept = std::fs::read_to_string(&victim)?;
        let written = std::fs::read_to_string(&path);
        let _ = std::fs::remove_dir_all(&dir);
        created?;
        assert_eq!(kept, "keep", "the victim was written through the symlink");
        assert_eq!(written?.trim(), std::process::id().to_string());
        Ok(())
    }
}
