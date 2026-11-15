//! The modules of the binary: the options and usage text (`cli`), start, stop and
//! restart (`lifecycle`), the pid file (`pidfile`), and the request that
//! `test-request --url` builds (`request_url`).
//!
//! `main.rs` declares this module and the library does not, which is why these
//! four are not in `tooling` with the library's side of the tools.

pub(crate) mod cli;
pub(crate) mod lifecycle;
pub(crate) mod pidfile;
pub(crate) mod request_url;
