//! Builds the directive tree from tokens.
//!
//! A directive is `name arg ... ;`, or `name arg ... { ... }` for a block. The
//! parser knows nothing about which names are valid: that is decided by the
//! configuration builder, which reports the file and line of each directive.

use std::sync::Arc;

use super::lexer::{Kind, Token};

/// Blocks may be nested this deep at most.
const MAX_DEPTH: usize = 32;

/// One directive, with the position it was read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Directive {
    /// The directive name.
    pub(crate) name: String,
    /// The arguments, in order.
    pub(crate) args: Vec<String>,
    /// The body of a block, or `None` for a simple directive.
    pub(crate) children: Option<Vec<Directive>>,
    /// The file the directive came from, as the user named it.
    pub(crate) file: Arc<str>,
    /// One-based line of the directive name.
    pub(crate) line: usize,
}

/// A syntax error with its position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SyntaxError {
    /// One-based line number.
    pub(crate) line: usize,
    /// What is wrong.
    pub(crate) message: String,
}

/// Parses a token list into directives.
///
/// # Errors
///
/// Returns a [`SyntaxError`] for a misplaced token, a missing `;` or `}`, or
/// blocks nested deeper than the limit.
pub(crate) fn parse(tokens: &[Token], file: &Arc<str>) -> Result<Vec<Directive>, SyntaxError> {
    let mut position = 0;
    let directives = parse_block(tokens, &mut position, file, 0, false)?;
    Ok(directives)
}

fn parse_block(
    tokens: &[Token],
    position: &mut usize,
    file: &Arc<str>,
    depth: usize,
    inside_braces: bool,
) -> Result<Vec<Directive>, SyntaxError> {
    if depth > MAX_DEPTH {
        return Err(SyntaxError {
            line: current_line(tokens, *position),
            message: format!("blocks are nested deeper than {MAX_DEPTH} levels"),
        });
    }
    let mut directives = Vec::new();
    loop {
        let Some(token) = tokens.get(*position) else {
            if inside_braces {
                return Err(SyntaxError {
                    line: current_line(tokens, *position),
                    message: "unexpected end of file, expecting \"}\"".to_owned(),
                });
            }
            return Ok(directives);
        };
        match &token.kind {
            Kind::CloseBrace => {
                if inside_braces {
                    *position += 1;
                    return Ok(directives);
                }
                return Err(SyntaxError {
                    line: token.line,
                    message: "unexpected \"}\"".to_owned(),
                });
            }
            Kind::Semicolon | Kind::OpenBrace => {
                return Err(SyntaxError {
                    line: token.line,
                    message: "directive name expected".to_owned(),
                });
            }
            Kind::Word(name) => {
                let name = name.clone();
                let line = token.line;
                *position += 1;
                directives.push(parse_directive(tokens, position, file, depth, name, line)?);
            }
        }
    }
}

fn parse_directive(
    tokens: &[Token],
    position: &mut usize,
    file: &Arc<str>,
    depth: usize,
    name: String,
    line: usize,
) -> Result<Directive, SyntaxError> {
    let mut args = Vec::new();
    loop {
        let Some(token) = tokens.get(*position) else {
            return Err(SyntaxError {
                line,
                message: format!(
                    "unexpected end of file, expecting \";\" or \"{{\" after \"{name}\""
                ),
            });
        };
        match &token.kind {
            Kind::Word(word) => {
                args.push(word.clone());
                *position += 1;
            }
            Kind::Semicolon => {
                *position += 1;
                return Ok(Directive {
                    name,
                    args,
                    children: None,
                    file: Arc::clone(file),
                    line,
                });
            }
            Kind::OpenBrace => {
                *position += 1;
                let children = parse_block(tokens, position, file, depth + 1, true)?;
                return Ok(Directive {
                    name,
                    args,
                    children: Some(children),
                    file: Arc::clone(file),
                    line,
                });
            }
            Kind::CloseBrace => {
                return Err(SyntaxError {
                    line: token.line,
                    message: format!("directive \"{name}\" is not terminated by \";\""),
                });
            }
        }
    }
}

/// The line of the token at `position`, or of the last token when `position` is past the end.
fn current_line(tokens: &[Token], position: usize) -> usize {
    tokens
        .get(position)
        .or_else(|| tokens.last())
        .map_or(1, |token| token.line)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::super::lexer::tokenize;
    use super::*;

    fn parse_str(source: &str) -> Result<Vec<Directive>, SyntaxError> {
        let file: Arc<str> = Arc::from("test.conf");
        let tokens = tokenize(source).map_err(|e| SyntaxError {
            line: e.line,
            message: e.message,
        })?;
        parse(&tokens, &file)
    }

    #[test]
    fn simple_directive_collects_its_arguments() -> Result<(), SyntaxError> {
        let directives = parse_str("listen 0.0.0.0:80 extra;")?;
        assert_eq!(directives.first().map(|d| d.args.len()), Some(2));
        assert_eq!(directives.first().map(|d| d.name.as_str()), Some("listen"));
        Ok(())
    }

    #[test]
    fn block_holds_its_children() -> Result<(), SyntaxError> {
        let directives = parse_str("decision {\n  backend http;\n}\n")?;
        let children = directives.first().and_then(|d| d.children.as_ref());
        assert_eq!(children.map(Vec::len), Some(1));
        Ok(())
    }

    #[test]
    fn directives_keep_the_line_they_start_on() -> Result<(), SyntaxError> {
        let directives = parse_str("a 1;\n\nb 2;")?;
        assert_eq!(
            directives.iter().map(|d| d.line).collect::<Vec<_>>(),
            [1, 3]
        );
        Ok(())
    }

    #[rstest]
    #[case::missing_semicolon_at_end("listen 80", 1)]
    #[case::stray_close_brace("listen 80;\n}", 2)]
    #[case::stray_semicolon(";", 1)]
    // End of file is reported at the last line of the input.
    #[case::unclosed_block("decision {\n backend http;\n", 2)]
    #[case::close_brace_ends_simple_directive("listen 80 }", 1)]
    fn malformed_input_is_a_syntax_error(#[case] source: &str, #[case] line: usize) {
        let error = parse_str(source).err();
        assert_eq!(error.map(|e| e.line), Some(line));
    }

    #[test]
    fn nesting_beyond_the_limit_is_an_error_not_a_stack_overflow() {
        let source = format!("{}{}", "a {".repeat(200), "}".repeat(200));
        assert!(parse_str(&source).is_err());
    }

    #[test]
    fn blocks_nested_to_the_documented_limit_are_accepted() {
        let source = format!("{}{}", "a {".repeat(MAX_DEPTH), "}".repeat(MAX_DEPTH));
        assert!(parse_str(&source).is_ok());
    }

    #[test]
    fn one_block_past_the_documented_limit_is_an_error() {
        let source = format!(
            "{}{}",
            "a {".repeat(MAX_DEPTH + 1),
            "}".repeat(MAX_DEPTH + 1)
        );
        assert!(parse_str(&source).is_err());
    }

    proptest::proptest! {
        #[test]
        fn parsing_never_panics(source in "[a-z0-9 ;{}\"'#\\\\\n]{0,200}") {
            let _ = parse_str(&source);
        }
    }
}
