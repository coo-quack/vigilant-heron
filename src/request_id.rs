//! The id of each request: the value of the request-id header when it is usable, else a generated id.
//!
//! The id is logged as `$request_id` and sent back in the `X-Request-ID` response
//! header, so a site owner can quote it when reporting a blocked request.

use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use http::HeaderName;

/// The response header that carries the request id.
pub(crate) const RESPONSE_HEADER: HeaderName = HeaderName::from_static("x-request-id");

/// The longest header value that is used as an id. A longer value is replaced by a generated id.
pub(crate) const MAX_HEADER_ID_BYTES: usize = 64;

/// Fixed for the process at its first use, from the start time and the process id.
static SEED: LazyLock<u64> = LazyLock::new(|| {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let nanos = u64::try_from(nanos).unwrap_or(u64::MAX);
    mix(nanos ^ (u64::from(std::process::id()) << 32))
});

/// Counts the generated ids of the process, so that no two of them are equal.
static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generates an id of 16 lowercase hex digits.
///
/// The seed plus the counter is mixed with a bijection, so two calls in one process never
/// return the same id.
pub(crate) fn generate() -> String {
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{:016x}", mix(SEED.wrapping_add(count)))
}

/// The id that a request-id header value gives, or `None` when the value cannot be used.
///
/// A usable value is 1 to 64 visible ASCII characters (0x21 to 0x7e). Spaces, control
/// characters and non-ASCII bytes are refused, so the id is safe in a header and a log line.
pub(crate) fn from_header(value: &[u8]) -> Option<String> {
    let usable = !value.is_empty()
        && value.len() <= MAX_HEADER_ID_BYTES
        && value.iter().all(u8::is_ascii_graphic);
    usable.then(|| String::from_utf8_lossy(value).into_owned())
}

/// The finalizer of splitmix64, a bijection on `u64`.
fn mix(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use rstest::rstest;

    use super::*;

    #[test]
    fn a_generated_id_is_sixteen_lowercase_hex_digits() {
        let id = generate();

        assert_eq!(id.len(), 16);
        assert!(
            id.bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "not lowercase hex: {id}"
        );
    }

    #[test]
    fn generated_ids_do_not_repeat_within_a_process() {
        let ids: HashSet<String> = (0..10_000).map(|_| generate()).collect();

        assert_eq!(ids.len(), 10_000);
    }

    #[test]
    fn the_mixer_is_injective_on_consecutive_inputs() {
        let outputs: HashSet<u64> = (0..10_000_u64).map(mix).collect();

        assert_eq!(outputs.len(), 10_000);
    }

    #[rstest]
    #[case::letters_and_digits(b"req-2026-0001" as &[u8])]
    #[case::punctuation(b"a.b_c:d/e~f!")]
    #[case::longest_usable(&[b'x'; 64])]
    fn a_header_value_of_visible_ascii_is_used_as_the_id(#[case] value: &[u8]) {
        assert_eq!(
            from_header(value).as_deref().map(str::as_bytes),
            Some(value)
        );
    }

    #[rstest]
    #[case::empty(b"" as &[u8])]
    #[case::space(b"a b")]
    #[case::control(b"a\x7fb")]
    #[case::tab(b"a\tb")]
    #[case::non_ascii("id-é".as_bytes())]
    #[case::too_long(&[b'x'; 65])]
    fn a_header_value_that_is_not_a_usable_id_is_refused(#[case] value: &[u8]) {
        assert_eq!(from_header(value), None);
    }

    #[test]
    fn the_response_header_name_is_x_request_id() {
        assert_eq!(RESPONSE_HEADER.as_str(), "x-request-id");
    }
}
