//! The limits on a request header, and the scanner that checks its bytes as they arrive.

use crate::config::HeaderBuffers;

/// Limits on the request line and header section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HeadLimits {
    /// Most bytes in one line, not counting its line ending.
    pub(crate) line: usize,
    /// Most bytes in the whole header section, counting line endings.
    pub(crate) total: usize,
}

impl HeadLimits {
    /// Derives the limits from `large_client_header_buffers`: one line per buffer,
    /// and the whole section within `count` buffers.
    pub(crate) fn from_buffers(buffers: HeaderBuffers) -> Self {
        Self {
            line: buffers.size,
            total: buffers.count.saturating_mul(buffers.size),
        }
    }
}

/// Why a request header was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeadViolation {
    /// The request line is longer than one buffer. Answered with 414.
    RequestLineTooLong,
    /// A header field, or the whole section, is too large. Answered with 400.
    HeaderTooLarge,
}

/// Checks the bytes of one request header as they arrive, without parsing them.
#[derive(Debug, Clone)]
pub(crate) struct HeadScanner {
    limits: HeadLimits,
    total: usize,
    line_len: usize,
    completed_lines: usize,
    done: bool,
}

impl HeadScanner {
    /// Creates a scanner that expects the start of a request header.
    pub(crate) fn new(limits: HeadLimits) -> Self {
        Self {
            limits,
            total: 0,
            line_len: 0,
            completed_lines: 0,
            done: false,
        }
    }

    /// Prepares the scanner for the next request header.
    pub(crate) fn reset(&mut self) {
        self.total = 0;
        self.line_len = 0;
        self.completed_lines = 0;
        self.done = false;
    }

    /// Feeds the next bytes of a request header. Returns `Ok(true)` once the
    /// blank line that ends the header has been seen. Bytes after that are ignored.
    ///
    /// # Errors
    ///
    /// Returns the violation at the first byte that exceeds a limit.
    pub(crate) fn feed(&mut self, bytes: &[u8]) -> Result<bool, HeadViolation> {
        for &byte in bytes {
            if self.done {
                break;
            }
            match byte {
                b'\n' => {
                    if self.line_len > 0 {
                        self.completed_lines += 1;
                        self.line_len = 0;
                    } else if self.completed_lines > 0 {
                        // The blank line that ends the header.
                        self.done = true;
                    }
                    // Empty lines before the request line are ignored, as RFC 9112 allows.
                }
                b'\r' => {}
                _ => {
                    self.line_len += 1;
                    if self.line_len > self.limits.line {
                        return Err(if self.completed_lines == 0 {
                            HeadViolation::RequestLineTooLong
                        } else {
                            HeadViolation::HeaderTooLarge
                        });
                    }
                }
            }
            self.total += 1;
            if self.total > self.limits.total {
                return Err(HeadViolation::HeaderTooLarge);
            }
        }
        Ok(self.done)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rstest::rstest;

    use super::*;
    use crate::transport::test_helpers::limits;

    /// Feeds `head` in pieces of `chunk` bytes and returns the final outcome.
    fn scan_in_chunks(
        head: &[u8],
        chunk: usize,
        limits: HeadLimits,
    ) -> Result<bool, HeadViolation> {
        let mut scanner = HeadScanner::new(limits);
        let mut done = Ok(false);
        for piece in head.chunks(chunk.max(1)) {
            done = scanner.feed(piece);
            match done {
                Ok(true) | Err(_) => break,
                Ok(false) => {}
            }
        }
        done
    }

    #[rstest]
    #[case::request_line_at_the_limit(b"GET /aaaa HTTP/1.1\r\nHost: a\r\n\r\n", 18, 100, Ok(true))]
    #[case::request_line_over_the_limit(
        b"GET /aaaaaa HTTP/1.1\r\n\r\n",
        10,
        100,
        Err(HeadViolation::RequestLineTooLong)
    )]
    #[case::header_field_over_the_limit(
        b"GET / HTTP/1.1\r\nX: 01234567890123456\r\n\r\n",
        16,
        200,
        Err(HeadViolation::HeaderTooLarge)
    )]
    #[case::section_over_the_total(
        b"GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\n\r\n",
        100,
        20,
        Err(HeadViolation::HeaderTooLarge)
    )]
    #[case::leading_empty_lines_are_ignored(b"\r\n\r\nGET / HTTP/1.1\r\n\r\n", 100, 100, Ok(true))]
    fn the_scanner_applies_each_limit_where_nginx_does(
        #[case] head: &[u8],
        #[case] line: usize,
        #[case] total: usize,
        #[case] expected: Result<bool, HeadViolation>,
    ) {
        assert_eq!(scan_in_chunks(head, 1, limits(line, total)), expected);
        assert_eq!(scan_in_chunks(head, 4096, limits(line, total)), expected);
    }

    #[test]
    fn bytes_after_the_blank_line_are_not_scanned() {
        let mut scanner = HeadScanner::new(limits(100, 100));
        let body = [b'x'; 200];
        let mut bytes = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        bytes.extend_from_slice(&body);
        let result = scanner.feed(&bytes);
        assert_eq!(result, Ok(true));
    }

    #[test]
    fn reset_lets_the_scanner_check_the_next_header() {
        let mut scanner = HeadScanner::new(limits(100, 100));
        assert_eq!(scanner.feed(b"GET / HTTP/1.1\r\n\r\n"), Ok(true));
        scanner.reset();
        assert_eq!(scanner.feed(b"GET / HTTP/1.1\r\n"), Ok(false));
    }

    fn head_text(lines: &[usize]) -> Vec<u8> {
        let mut out = Vec::new();
        for (index, len) in lines.iter().enumerate() {
            let prefix = if index == 0 { b'G' } else { b'H' };
            out.push(prefix);
            out.extend(std::iter::repeat_n(b'a', len.saturating_sub(1)));
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out
    }

    proptest! {
        /// A header is accepted exactly when every line fits the line limit and the
        /// whole section, with its line endings, fits the total limit.
        #[test]
        fn acceptance_matches_the_limit_arithmetic(
            lines in prop::collection::vec(1usize..40, 1..8),
            line_limit in 1usize..40,
            total_limit in 1usize..300,
            chunk in 1usize..17,
        ) {
            let head = head_text(&lines);
            let lines_fit = lines.iter().all(|len| *len <= line_limit);
            let section = lines.iter().map(|len| len + 2).sum::<usize>() + 2;
            let total_fits = section <= total_limit;
            let result = scan_in_chunks(&head, chunk, limits(line_limit, total_limit));
            if lines_fit && total_fits {
                prop_assert_eq!(result, Ok(true));
            } else {
                prop_assert!(result.is_err(), "expected a violation, got {result:?}");
            }
        }

        /// Where the head is split into reads does not change the outcome.
        #[test]
        fn chunking_does_not_change_the_outcome(
            lines in prop::collection::vec(1usize..40, 1..8),
            line_limit in 1usize..40,
            total_limit in 1usize..300,
            chunk in 1usize..17,
        ) {
            let head = head_text(&lines);
            let whole = scan_in_chunks(&head, head.len().max(1), limits(line_limit, total_limit));
            let pieces = scan_in_chunks(&head, chunk, limits(line_limit, total_limit));
            prop_assert_eq!(whole, pieces);
        }
    }

    #[rstest]
    #[case::at_the_line_limit(14, Ok(true))]
    #[case::one_byte_over_the_line_limit(13, Err(HeadViolation::RequestLineTooLong))]
    fn a_request_line_is_refused_only_past_its_limit(
        #[case] line: usize,
        #[case] expected: Result<bool, HeadViolation>,
    ) {
        // "GET / HTTP/1.1" is 14 bytes.
        assert_eq!(
            scan_in_chunks(b"GET / HTTP/1.1\r\n\r\n", 1, limits(line, 100)),
            expected
        );
    }

    #[rstest]
    #[case::exactly_the_total_limit(18, Ok(true))]
    #[case::one_byte_over_the_total_limit(17, Err(HeadViolation::HeaderTooLarge))]
    fn a_header_section_is_refused_only_past_the_total_limit(
        #[case] total: usize,
        #[case] expected: Result<bool, HeadViolation>,
    ) {
        // "GET / HTTP/1.1\r\n\r\n" is 18 bytes, the blank line included.
        assert_eq!(
            scan_in_chunks(b"GET / HTTP/1.1\r\n\r\n", 1, limits(100, total)),
            expected
        );
    }

    #[test]
    fn blank_lines_before_the_request_line_do_not_end_the_header() {
        let mut scanner = HeadScanner::new(limits(100, 100));
        assert_eq!(scanner.feed(b"\r\n\r\n"), Ok(false));
        assert_eq!(scanner.feed(b"GET / HTTP/1.1\r\n"), Ok(false));
        assert_eq!(scanner.feed(b"\r\n"), Ok(true));
    }
}
