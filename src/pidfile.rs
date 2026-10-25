//! The PID file: written when the router starts, read by `-s`, and removed on exit.

use std::path::{Path, PathBuf};

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
        std::fs::write(&temporary, format!("{pid}\n"))?;
        if let Err(error) = std::fs::rename(&temporary, path) {
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
