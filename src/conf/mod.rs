//! The configuration language: lexer, parser and file includes.
//!
//! The syntax follows nginx: `name arg ...;` directives, `name arg ... { ... }`
//! blocks, `#` comments, and `include` at the top level. [`load_file`] reads a
//! file and expands its includes. [`parse_source`] does the same for text that
//! is not in a file; its includes are relative to the current directory.

mod lexer;
mod parser;

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(crate) use parser::Directive;

use crate::error::ConfigError;

/// Includes may be nested this deep at most.
const MAX_INCLUDE_DEPTH: usize = 8;

/// Reads `path` and returns its directives with all top-level includes expanded.
///
/// # Errors
///
/// Returns [`ConfigError::Read`] when a file cannot be read, and
/// [`ConfigError::Syntax`] or [`ConfigError::Include`] for a bad file or include.
pub(crate) fn load_file(path: &Path) -> Result<Vec<Directive>, ConfigError> {
    let mut stack = Vec::new();
    load_recursive(path, 0, &mut stack)
}

/// Parses `source`, named `origin` in error messages, and expands its includes.
///
/// # Errors
///
/// Returns the same errors as [`load_file`].
pub(crate) fn parse_source(source: &str, origin: &str) -> Result<Vec<Directive>, ConfigError> {
    let base = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut stack = Vec::new();
    let directives = parse_text(source, origin)?;
    expand_includes(directives, &base, 0, &mut stack)
}

/// Returns the text of `path` with each top-level include replaced by the text of
/// the files it names, as `nginx -T` prints it. Included lines are kept as comments.
///
/// # Errors
///
/// Returns the same errors as [`load_file`], and [`ConfigError::Include`] for an
/// include that is not alone on one line, since its line is replaced as a whole.
pub(crate) fn dump_file(path: &Path) -> Result<String, ConfigError> {
    let mut stack = Vec::new();
    let mut out = String::new();
    dump_recursive(path, 0, &mut stack, &mut out)?;
    Ok(out)
}

fn dump_recursive(
    path: &Path,
    depth: usize,
    stack: &mut Vec<PathBuf>,
    out: &mut String,
) -> Result<(), ConfigError> {
    let source = fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let directives = parse_text(&source, &path.display().to_string())?;
    let canonical = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if stack.contains(&canonical) {
        return Err(ConfigError::Include {
            file: path.display().to_string(),
            line: 1,
            message: "include cycle".to_owned(),
        });
    }
    stack.push(canonical);
    let base = path
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let includes: Vec<&Directive> = directives
        .iter()
        .filter(|directive| directive.name == "include")
        .collect();
    let _ = writeln!(out, "# configuration file {}:", path.display());
    for (index, text) in source.lines().enumerate() {
        let line = index + 1;
        let Some(include) = includes.iter().find(|directive| directive.line == line) else {
            let _ = writeln!(out, "{text}");
            continue;
        };
        let include_error = |message: String| ConfigError::Include {
            file: include.file.to_string(),
            line,
            message,
        };
        if !text.trim_end().ends_with(';') || text.trim_start().starts_with('#') {
            return Err(include_error(
                "for -T, an include must be written alone on one line".to_owned(),
            ));
        }
        let [pattern] = include.args.as_slice() else {
            return Err(include_error(
                "include takes exactly one path or glob".to_owned(),
            ));
        };
        if depth + 1 > MAX_INCLUDE_DEPTH {
            return Err(include_error(format!(
                "includes are nested deeper than {MAX_INCLUDE_DEPTH} levels"
            )));
        }
        let target = if Path::new(pattern).is_absolute() {
            PathBuf::from(pattern)
        } else {
            base.join(pattern)
        };
        let _ = writeln!(out, "# {}", text.trim());
        for included in resolve_include(&target, pattern).map_err(include_error)? {
            dump_recursive(&included, depth + 1, stack, out)?;
        }
    }
    stack.pop();
    Ok(())
}

fn load_recursive(
    path: &Path,
    depth: usize,
    stack: &mut Vec<PathBuf>,
) -> Result<Vec<Directive>, ConfigError> {
    let source = fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let directives = parse_text(&source, &path.display().to_string())?;
    let canonical = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if stack.contains(&canonical) {
        return Err(ConfigError::Include {
            file: path.display().to_string(),
            line: 1,
            message: "include cycle".to_owned(),
        });
    }
    stack.push(canonical);
    let base = path
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let expanded = expand_includes(directives, &base, depth, stack);
    stack.pop();
    expanded
}

fn parse_text(source: &str, origin: &str) -> Result<Vec<Directive>, ConfigError> {
    let file: Arc<str> = Arc::from(origin);
    let tokens = lexer::tokenize(source).map_err(|error| ConfigError::Syntax {
        file: origin.to_owned(),
        line: error.line,
        message: error.message,
    })?;
    parser::parse(&tokens, &file).map_err(|error| ConfigError::Syntax {
        file: origin.to_owned(),
        line: error.line,
        message: error.message,
    })
}

/// Replaces each top-level `include` with the directives of the files it names.
fn expand_includes(
    directives: Vec<Directive>,
    base: &Path,
    depth: usize,
    stack: &mut Vec<PathBuf>,
) -> Result<Vec<Directive>, ConfigError> {
    let mut expanded = Vec::new();
    for directive in directives {
        if directive.name != "include" {
            expanded.push(directive);
            continue;
        }
        let include_error = |message: String| ConfigError::Include {
            file: directive.file.to_string(),
            line: directive.line,
            message,
        };
        let [pattern] = directive.args.as_slice() else {
            return Err(include_error(
                "include takes exactly one path or glob".to_owned(),
            ));
        };
        if depth + 1 > MAX_INCLUDE_DEPTH {
            return Err(include_error(format!(
                "includes are nested deeper than {MAX_INCLUDE_DEPTH} levels"
            )));
        }
        let target = if Path::new(pattern).is_absolute() {
            PathBuf::from(pattern)
        } else {
            base.join(pattern)
        };
        for path in resolve_include(&target, pattern).map_err(include_error)? {
            let loaded = load_recursive(&path, depth + 1, stack)?;
            expanded.extend(loaded);
        }
    }
    Ok(expanded)
}

/// Returns the files an include names. A glob may match nothing; a plain path must exist.
fn resolve_include(target: &Path, pattern: &str) -> Result<Vec<PathBuf>, String> {
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    if !name.contains('*') && !name.contains('?') {
        if target.is_file() {
            return Ok(vec![target.to_path_buf()]);
        }
        return Err(format!("include file not found: {pattern}"));
    }
    let dir = target
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let Ok(entries) = fs::read_dir(&dir) else {
        return Ok(Vec::new());
    };
    let mut matches: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| wildcard_matches(name, n))
        })
        .collect();
    matches.sort();
    Ok(matches)
}

/// Matches `text` against a pattern where `*` is any run of characters and `?` is one character.
fn wildcard_matches(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let (mut p, mut t) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    loop {
        match (pattern.get(p), text.get(t)) {
            (Some('*'), _) => {
                star = Some((p, t));
                p += 1;
            }
            (Some(&pc), Some(&tc)) if pc == '?' || pc == tc => {
                p += 1;
                t += 1;
            }
            (None, None) => return true,
            _ => match star {
                Some((sp, st)) if st < text.len() => {
                    star = Some((sp, st + 1));
                    p = sp + 1;
                    t = st + 1;
                }
                _ => return false,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::exact("a.conf", "a.conf", true)]
    #[case::star_suffix("*.conf", "site.conf", true)]
    #[case::star_matches_empty("a*", "a", true)]
    #[case::question_mark("a?.conf", "ab.conf", true)]
    #[case::question_mark_needs_a_character("a?.conf", "a.conf", false)]
    #[case::wrong_extension("*.conf", "site.txt", false)]
    #[case::middle_star("s*e.conf", "site.conf", true)]
    fn wildcards_match_like_shell_globs(
        #[case] pattern: &str,
        #[case] text: &str,
        #[case] expected: bool,
    ) {
        assert_eq!(wildcard_matches(pattern, text), expected);
    }

    #[test]
    fn a_glob_with_no_match_is_allowed() {
        let dir = std::env::temp_dir().join("vh-glob-empty-test");
        let _ = fs::create_dir_all(&dir);
        assert_eq!(
            resolve_include(&dir.join("*.none"), "*.none").map(|v| v.len()),
            Ok(0)
        );
    }

    #[test]
    fn a_plain_include_that_does_not_exist_is_an_error() {
        let dir = std::env::temp_dir();
        assert!(
            resolve_include(
                &dir.join("vh-missing-file-x.conf"),
                "vh-missing-file-x.conf"
            )
            .is_err()
        );
    }

    #[test]
    fn a_nested_include_beyond_the_depth_limit_is_an_error() {
        let directives = parse_text("include x.conf;", "top.conf").unwrap_or_default();
        let mut stack = Vec::new();
        let result = expand_includes(directives, Path::new("."), MAX_INCLUDE_DEPTH, &mut stack);
        assert!(matches!(result, Err(ConfigError::Include { .. })));
    }

    proptest::proptest! {
        #[test]
        fn wildcard_matching_never_panics(pattern in "[a-z*?]{0,12}", text in "[a-z]{0,12}") {
            let _ = wildcard_matches(&pattern, &text);
        }
    }

    /// Writes `levels` files, each including the next, and returns the first one's path.
    fn include_chain(name: &str, levels: usize) -> std::io::Result<PathBuf> {
        let dir = std::env::temp_dir().join(format!("vh-chain-{name}-{}", std::process::id()));
        fs::create_dir_all(&dir)?;
        for level in 0..levels {
            let text = if level + 1 < levels {
                format!("include level{}.conf;\n", level + 1)
            } else {
                "marker end;\n".to_owned()
            };
            fs::write(dir.join(format!("level{level}.conf")), text)?;
        }
        Ok(dir.join("level0.conf"))
    }

    #[test]
    fn includes_nested_to_the_depth_limit_are_loaded() -> std::io::Result<()> {
        // Eight include levels below the top file is the most that is allowed.
        let path = include_chain("depth-allowed", MAX_INCLUDE_DEPTH + 1)?;
        assert!(load_file(&path).is_ok());
        assert!(dump_file(&path).is_ok());
        Ok(())
    }

    #[test]
    fn includes_one_level_past_the_depth_limit_are_refused() -> std::io::Result<()> {
        let path = include_chain("depth-refused", MAX_INCLUDE_DEPTH + 2)?;
        let is_depth_error = |error: Option<ConfigError>| {
            matches!(
                error,
                Some(ConfigError::Include { ref message, .. })
                    if message.contains("nested deeper than 8 levels")
            )
        };
        assert!(is_depth_error(load_file(&path).err()));
        assert!(is_depth_error(dump_file(&path).err()));
        Ok(())
    }

    #[test]
    fn a_glob_include_names_the_matching_files_in_order() -> std::io::Result<()> {
        let dir = std::env::temp_dir().join(format!("vh-glob-order-{}", std::process::id()));
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("b.conf"), "")?;
        fs::write(dir.join("a.conf"), "")?;
        fs::write(dir.join("skipped.txt"), "")?;
        let names = resolve_include(&dir.join("*.conf"), "*.conf").map(|paths| {
            paths
                .iter()
                .filter_map(|path| path.file_name())
                .map(|name| name.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        });
        assert_eq!(names, Ok(vec!["a.conf".to_owned(), "b.conf".to_owned()]));
        Ok(())
    }

    /// The textbook matcher: `*` tries every split, `?` takes one character.
    fn reference_match(pattern: &[char], text: &[char]) -> bool {
        match pattern.split_first() {
            None => text.is_empty(),
            Some((&'*', rest)) => (0..=text.len())
                .any(|split| reference_match(rest, text.get(split..).unwrap_or_default())),
            Some((&'?', rest)) => {
                !text.is_empty() && reference_match(rest, text.get(1..).unwrap_or_default())
            }
            Some((literal, rest)) => {
                text.first() == Some(literal)
                    && reference_match(rest, text.get(1..).unwrap_or_default())
            }
        }
    }

    proptest::proptest! {
        #[test]
        fn wildcard_matching_agrees_with_the_reference_matcher(
            pattern in "[ab*?]{0,8}",
            text in "[ab]{0,8}",
        ) {
            let pattern_chars: Vec<char> = pattern.chars().collect();
            let text_chars: Vec<char> = text.chars().collect();
            assert_eq!(
                wildcard_matches(&pattern, &text),
                reference_match(&pattern_chars, &text_chars)
            );
        }
    }
}
