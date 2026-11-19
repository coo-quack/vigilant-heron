//! What the command-line tools run: `test-request` (`request_check`),
//! `suggest-skip-rules` (`skip_suggest`), `shadow-report` (`shadow_report`), and
//! the json access-log reading that the last two share (`log_lines`). The three
//! tools are part of the library, which exports them, so the binary and the
//! benchmarks call the same functions.

mod log_lines;
pub(crate) mod request_check;
pub(crate) mod shadow_report;
pub(crate) mod skip_suggest;
