//! Tokens of the configuration language.
//!
//! A word is a run of characters that is not whitespace, `;`, `{` or `}`.
//! Quoted segments are part of the word they touch, so `"a""b"` and `a"b"`
//! each form one word. `#` starts a comment only at the start of a token.

/// A token and the line it starts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Token {
    /// What the token is.
    pub(crate) kind: Kind,
    /// One-based line number.
    pub(crate) line: usize,
}

/// The kind of a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Kind {
    /// A word, with quotes removed and escapes applied.
    Word(String),
    /// `;`, which ends a directive.
    Semicolon,
    /// `{`, which opens a block.
    OpenBrace,
    /// `}`, which closes a block.
    CloseBrace,
}

/// A lexing error with the line it was found on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LexError {
    /// One-based line number.
    pub(crate) line: usize,
    /// What is wrong.
    pub(crate) message: String,
}

/// Splits `source` into tokens.
///
/// # Errors
///
/// Returns a [`LexError`] for an unterminated quoted string.
pub(crate) fn tokenize(source: &str) -> Result<Vec<Token>, LexError> {
    let chars: Vec<char> = source.chars().collect();
    let mut tokens = Vec::new();
    let mut index = 0;
    let mut line = 1;
    while let Some(&c) = chars.get(index) {
        match c {
            '\n' => {
                line += 1;
                index += 1;
            }
            c if c.is_whitespace() => index += 1,
            '#' => {
                while chars.get(index).is_some_and(|&c| c != '\n') {
                    index += 1;
                }
            }
            ';' => {
                tokens.push(Token {
                    kind: Kind::Semicolon,
                    line,
                });
                index += 1;
            }
            '{' => {
                tokens.push(Token {
                    kind: Kind::OpenBrace,
                    line,
                });
                index += 1;
            }
            '}' => {
                tokens.push(Token {
                    kind: Kind::CloseBrace,
                    line,
                });
                index += 1;
            }
            _ => {
                let start_line = line;
                let (word, next, next_line) = read_word(&chars, index, line)?;
                tokens.push(Token {
                    kind: Kind::Word(word),
                    line: start_line,
                });
                index = next;
                line = next_line;
            }
        }
    }
    Ok(tokens)
}

/// Reads one word starting at `start`. Returns the word, the index after it and the line after it.
fn read_word(
    chars: &[char],
    start: usize,
    start_line: usize,
) -> Result<(String, usize, usize), LexError> {
    let mut word = String::new();
    let mut index = start;
    let mut line = start_line;
    while let Some(&c) = chars.get(index) {
        match c {
            c if c.is_whitespace() || c == ';' || c == '{' || c == '}' => break,
            '"' | '\'' => {
                let (text, next, next_line) = read_quoted(chars, index, line)?;
                word.push_str(&text);
                index = next;
                line = next_line;
            }
            _ => {
                word.push(c);
                index += 1;
            }
        }
    }
    Ok((word, index, line))
}

/// Reads a quoted segment starting at the opening quote at `start`.
///
/// Recognized escapes are `\"`, `\'`, `\\`, `\n`, `\t` and `\r`. Any other
/// backslash is kept as written, so a Windows path or a regular expression
/// survives unchanged.
fn read_quoted(
    chars: &[char],
    start: usize,
    start_line: usize,
) -> Result<(String, usize, usize), LexError> {
    let Some(&quote) = chars.get(start) else {
        return Err(LexError {
            line: start_line,
            message: "missing opening quote".to_owned(),
        });
    };
    let mut text = String::new();
    let mut index = start + 1;
    let mut line = start_line;
    while let Some(&c) = chars.get(index) {
        if c == quote {
            return Ok((text, index + 1, line));
        }
        if c == '\n' {
            line += 1;
        }
        if c == '\\' {
            match chars.get(index + 1).copied() {
                Some('"') => text.push('"'),
                Some('\'') => text.push('\''),
                Some('\\') => text.push('\\'),
                Some('n') => text.push('\n'),
                Some('t') => text.push('\t'),
                Some('r') => text.push('\r'),
                Some(other) => {
                    text.push('\\');
                    text.push(other);
                    if other == '\n' {
                        line += 1;
                    }
                }
                None => break,
            }
            index += 2;
            continue;
        }
        text.push(c);
        index += 1;
    }
    Err(LexError {
        line: start_line,
        message: format!("unterminated quoted string starting with {quote}"),
    })
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    fn words(source: &str) -> Vec<String> {
        tokenize(source)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|token| match token.kind {
                Kind::Word(text) => Some(text),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn words_are_separated_by_whitespace_and_punctuation() {
        let tokens = tokenize("listen 0.0.0.0:80;").unwrap_or_default();
        let kinds: Vec<Kind> = tokens.into_iter().map(|token| token.kind).collect();
        assert_eq!(
            kinds,
            vec![
                Kind::Word("listen".into()),
                Kind::Word("0.0.0.0:80".into()),
                Kind::Semicolon
            ]
        );
    }

    #[test]
    fn comments_run_to_the_end_of_the_line() {
        assert_eq!(words("a b # c d\ne"), ["a", "b", "e"]);
    }

    #[test]
    fn a_hash_inside_a_word_is_part_of_the_word() {
        assert_eq!(words("a#b"), ["a#b"]);
    }

    #[rstest]
    #[case::double_quoted(r#""hello world""#, "hello world")]
    #[case::single_quoted("'hello world'", "hello world")]
    #[case::escaped_double_quote(r#""say \"hi\"""#, "say \"hi\"")]
    #[case::escaped_single_quote(r"'it\'s'", "it's")]
    #[case::escaped_backslash(r#""a\\b""#, "a\\b")]
    #[case::newline_and_tab(r#""a\nb\tc""#, "a\nb\tc")]
    #[case::unknown_escape_kept(r#""C:\path""#, "C:\\path")]
    #[case::adjacent_segments_join(r#""ab""cd""#, "abcd")]
    #[case::quote_touching_a_word(r#"x"y z""#, "xy z")]
    #[case::empty_quoted(r#""""#, "")]
    fn quoted_segments_are_read(#[case] source: &str, #[case] expected: &str) {
        assert_eq!(words(source), [expected]);
    }

    #[test]
    fn a_quote_inside_a_double_quoted_string_does_not_end_it() {
        assert_eq!(words(r#""it's""#), ["it's"]);
    }

    #[test]
    fn a_trailing_backslash_in_a_string_is_an_error() {
        assert!(tokenize(r#""abc\"#).is_err());
    }

    #[test]
    fn unterminated_string_reports_its_starting_line() {
        let error = tokenize("a\nb \"open\n\nmore").err();
        assert_eq!(error.map(|e| e.line), Some(2));
    }

    #[test]
    fn line_numbers_track_newlines_inside_strings() {
        let tokens = tokenize("\"a\nb\"\nc").unwrap_or_default();
        assert_eq!(tokens.first().map(|t| t.line), Some(1));
        assert_eq!(tokens.last().map(|t| t.line), Some(3));
    }

    #[test]
    fn a_backslash_newline_inside_a_string_counts_one_line() {
        let tokens = tokenize("\"a\\\nb\"\nc").unwrap_or_default();
        assert_eq!(tokens.last().map(|t| t.line), Some(3));
    }

    #[test]
    fn other_escapes_inside_a_string_do_not_count_lines() {
        let tokens = tokenize("\"C:\\path\"\nc").unwrap_or_default();
        assert_eq!(tokens.last().map(|t| t.line), Some(2));
    }

    #[test]
    fn braces_end_a_word_without_whitespace() {
        assert_eq!(words("a}b"), ["a", "b"]);
        assert_eq!(words("a{b"), ["a", "b"]);
    }

    proptest::proptest! {
        #[test]
        fn lexing_never_panics(source in "\\PC{0,200}") {
            let _ = tokenize(&source);
        }
    }
}
