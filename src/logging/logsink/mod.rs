//! Where log lines go: the access-log queues in [`access_log`] and the error log in
//! [`error_log`].

mod access_log;
mod error_log;

use std::fs::OpenOptions;

pub(crate) use access_log::{Writer, spawn_writer};
pub use error_log::{ErrorLogHandle, install_error_log};

/// How a log file is opened: for appending, and created when it does not exist.
fn append_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    options
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write as _;
    use std::path::PathBuf;

    use super::append_options;

    /// A path of its own in the temporary directory, with no file there.
    fn log_path(name: &str) -> std::io::Result<PathBuf> {
        let dir = std::env::temp_dir().join(format!("vh-append-{name}-{}", std::process::id()));
        fs::create_dir_all(&dir)?;
        let path = dir.join("test.log");
        let _ = fs::remove_file(&path);
        Ok(path)
    }

    #[test]
    fn a_log_file_that_does_not_exist_is_created() -> std::io::Result<()> {
        let path = log_path("created")?;
        append_options().open(&path)?;
        assert!(path.is_file());
        Ok(())
    }

    #[test]
    fn a_log_file_keeps_its_lines_and_new_lines_follow_them() -> std::io::Result<()> {
        let path = log_path("kept")?;
        fs::write(&path, "old line\n")?;
        append_options().open(&path)?.write_all(b"new line\n")?;
        assert_eq!(fs::read_to_string(&path)?, "old line\nnew line\n");
        Ok(())
    }
}
