//! The PID file: written when the router starts, read by `-s`, and removed on exit.

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

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

#[cfg(test)]
mod tests {
    use super::*;

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
