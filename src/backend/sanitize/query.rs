//! Query strings: redaction of sensitive parameters, and the shape of a query.

use super::REDACTED;
use super::keys::is_redacted_key;

/// The query that the access log shows for a blocked request (`$block_query`).
///
/// It is the same text that [`super::build_event`] sends to the backend, so the log and the
/// backend see the same redaction. Returns `None` when the request has no query.
pub(crate) fn block_query(query: Option<&str>, redact_fields: &[String]) -> Option<String> {
    query.map(|query| redact_query(query, redact_fields))
}

/// Redacts the values of sensitive parameters in a query string.
///
/// Both `&` and `;` separate parameters, because some upstreams split on `;` too. A
/// parameter is redacted by the same rule as a body field, applied to its decoded
/// name. The other parameters and the separators are copied as they were sent, so
/// their order and encoding are kept. A parameter without `=` has no value and is
/// copied as it is.
pub(crate) fn redact_query(query: &str, redact_fields: &[String]) -> String {
    let mut redacted = String::with_capacity(query.len());
    let mut parameter = String::new();
    for c in query.chars() {
        if is_parameter_separator(c) {
            redacted.push_str(&redact_parameter(&parameter, redact_fields));
            redacted.push(c);
            parameter.clear();
        } else {
            parameter.push(c);
        }
    }
    redacted.push_str(&redact_parameter(&parameter, redact_fields));
    redacted
}

/// Whether a character separates two query parameters.
fn is_parameter_separator(c: char) -> bool {
    c == '&' || c == ';'
}

/// Redacts the value of one query parameter when its name is sensitive.
fn redact_parameter(parameter: &str, redact_fields: &[String]) -> String {
    match parameter.split_once('=') {
        Some((name, _)) if is_redacted_key(&decode_name(name), redact_fields) => {
            format!("{name}={REDACTED}")
        }
        _ => parameter.to_owned(),
    }
}

/// Decodes a parameter name the way form data does (`+` is a space, `%XX` is a byte).
fn decode_name(raw: &str) -> String {
    form_urlencoded::parse(raw.as_bytes())
        .map(|(name, _)| name.into_owned())
        .collect()
}

/// Describes the shape of a query string for the `$query_shape` log variable.
///
/// The output keeps the parameter names and the class of each value, and never
/// the value text: `p=42&s=secret+words` becomes `p=<num>&s=<text>`. Parameters
/// are separated by `&` or `;` as in [`redact_query`], and empty pieces are
/// skipped. At most 16 parameters are shown, then `<more>`. Returns `None` when
/// the query has no parameter at all.
pub(crate) fn query_shape(query: &str) -> Option<String> {
    const MAX_PARAMETERS: usize = 16;
    let mut parameters = query
        .split(is_parameter_separator)
        .filter(|piece| !piece.is_empty());
    let mut shapes: Vec<String> = parameters
        .by_ref()
        .take(MAX_PARAMETERS)
        .map(parameter_shape)
        .collect();
    if parameters.next().is_some() {
        shapes.push("<more>".to_owned());
    }
    (!shapes.is_empty()).then(|| shapes.join("&"))
}

/// Describes one non-empty query parameter as `name=<class>`, or `<bare>` when it has no `=`.
fn parameter_shape(parameter: &str) -> String {
    match parameter.split_once('=') {
        None => "<bare>".to_owned(),
        Some((raw_name, raw_value)) => {
            let name = decode_name(raw_name);
            let name = if is_plain_name(&name) {
                name
            } else {
                "<name>".to_owned()
            };
            format!("{name}={}", value_class(raw_value))
        }
    }
}

/// Whether a decoded parameter name is a plain identifier: an ASCII letter or `_`
/// first, then up to 31 ASCII letters, digits, `_`, `.`, `-`, `[` or `]`.
fn is_plain_name(name: &str) -> bool {
    let mut chars = name.chars();
    let starts_well = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    starts_well
        && name.len() <= 32
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | '[' | ']'))
}

/// The class of a raw parameter value, taken after form decoding: `<empty>`,
/// `<num>` (1 to 20 digits), `<word>` (1 to 64 letters, digits, `_` or `-`) or `<text>`.
fn value_class(raw_value: &str) -> &'static str {
    let value = decode_value(raw_value);
    if value.is_empty() {
        "<empty>"
    } else if value.len() <= 20 && value.bytes().all(|b| b.is_ascii_digit()) {
        "<num>"
    } else if value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        "<word>"
    } else {
        "<text>"
    }
}

/// Decodes a parameter value the way form data does. The value is placed after a
/// dummy name so that the form parser decodes it; the raw value holds no `&` or `;`.
fn decode_value(raw: &str) -> String {
    form_urlencoded::parse(format!("v={raw}").as_bytes())
        .map(|(_, value)| value.into_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::plain("a=1&b=two", "a=1&b=two")]
    #[case::sensitive_value("token=abc&c=3", "token=[REDACTED]&c=3")]
    #[case::keeps_order_and_encoding(
        "z=1&password=%26x+y&a=b%20c",
        "z=1&password=[REDACTED]&a=b%20c"
    )]
    #[case::encoded_name("pass%77ord=x&q=y", "pass%77ord=[REDACTED]&q=y")]
    #[case::name_without_value("token&flag", "token&flag")]
    #[case::empty_value_is_redacted("api_key=", "api_key=[REDACTED]")]
    #[case::ordinary_names_are_kept("pinned_note=1&shipping=2", "pinned_note=1&shipping=2")]
    #[case::semicolon_separates_parameters("password=x;id=1", "password=[REDACTED];id=1")]
    #[case::semicolon_hides_no_payload(
        "a=1;token=t&class_name=<p>",
        "a=1;token=[REDACTED]&class_name=<p>"
    )]
    #[case::semicolon_keeps_ordinary_names(
        "class_name=1;business_name=2",
        "class_name=1;business_name=2"
    )]
    #[case::trailing_separators_are_kept("token=t;&", "token=[REDACTED];&")]
    fn sensitive_query_parameters_are_redacted(#[case] query: &str, #[case] expected: &str) {
        assert_eq!(redact_query(query, &[]), expected);
    }

    #[rstest]
    #[case::empty_query_is_none("", None)]
    #[case::only_separators_is_none("&", None)]
    #[case::empty_pieces_are_none("&&;", None)]
    #[case::number_value_is_num("p=123", Some("p=<num>"))]
    #[case::word_value_is_word("feed=rss2", Some("feed=<word>"))]
    #[case::plus_makes_text("s=hello+world", Some("s=<text>"))]
    #[case::dash_and_underscore_are_word_characters("q=new-item_2", Some("q=<word>"))]
    #[case::empty_value_is_empty("q=", Some("q=<empty>"))]
    #[case::piece_without_equals_is_bare("abc", Some("<bare>"))]
    #[case::semicolon_separates("a=1;b=x", Some("a=<num>&b=<word>"))]
    #[case::percent_encoded_name_is_decoded("%70=1", Some("p=<num>"))]
    #[case::name_with_space_is_not_plain("a+b=1", Some("<name>=<num>"))]
    #[case::thirty_three_char_name_is_not_plain(
        "abcdefghijklmnopqrstuvwxyzabcdefg=1",
        Some("<name>=<num>")
    )]
    #[case::thirty_two_char_name_is_plain(
        "abcdefghijklmnopqrstuvwxyzabcdef=1",
        Some("abcdefghijklmnopqrstuvwxyzabcdef=<num>")
    )]
    #[case::twenty_one_digits_is_word("n=123456789012345678901", Some("n=<word>"))]
    #[case::twenty_digits_is_num("n=12345678901234567890", Some("n=<num>"))]
    #[case::sixty_five_chars_is_text(
        "v=abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmno",
        Some("v=<text>")
    )]
    #[case::sixty_four_chars_is_word(
        "v=abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl",
        Some("v=<word>")
    )]
    #[case::seventeen_parameters_show_sixteen_then_more(
        "a=1&b=1&c=1&d=1&e=1&f=1&g=1&h=1&i=1&j=1&k=1&l=1&m=1&n=1&o=1&p=1&q=1",
        Some(
            "a=<num>&b=<num>&c=<num>&d=<num>&e=<num>&f=<num>&g=<num>&h=<num>&i=<num>&j=<num>&k=<num>&l=<num>&m=<num>&n=<num>&o=<num>&p=<num>&<more>"
        )
    )]
    #[case::sixteen_parameters_have_no_more(
        "a=1&b=1&c=1&d=1&e=1&f=1&g=1&h=1&i=1&j=1&k=1&l=1&m=1&n=1&o=1&p=1",
        Some(
            "a=<num>&b=<num>&c=<num>&d=<num>&e=<num>&f=<num>&g=<num>&h=<num>&i=<num>&j=<num>&k=<num>&l=<num>&m=<num>&n=<num>&o=<num>&p=<num>"
        )
    )]
    fn query_shape_describes_names_and_value_classes(
        #[case] query: &str,
        #[case] expected: Option<&str>,
    ) {
        assert_eq!(query_shape(query).as_deref(), expected);
    }

    #[test]
    fn query_shape_never_contains_value_text() {
        let shape = query_shape("token=Secr3tValue&email=a%40b.example");
        assert_eq!(shape.as_deref(), Some("token=<word>&email=<text>"));
        let shape = shape.unwrap_or_default();
        assert!(!shape.contains("Secr3tValue"));
        assert!(!shape.contains("b.example"));
    }

    proptest! {
        #[test]
        fn query_shape_output_uses_only_shape_characters(query in "\\PC{0,128}") {
            let shape = query_shape(&query).unwrap_or_default();
            prop_assert!(shape.chars().all(|c| c.is_ascii_alphanumeric()
                || matches!(c, '_' | '.' | '-' | '[' | ']' | '<' | '>' | '=' | '&')));
        }
    }

    #[test]
    fn redact_field_names_also_redact_query_parameters() {
        let fields = ["lang".to_owned()];
        assert_eq!(redact_query("lang=ja&q=x", &fields), "lang=[REDACTED]&q=x");
    }

    #[test]
    fn block_query_redacts_names_from_redact_field() {
        let fields = ["ticket_ref".to_owned()];
        assert_eq!(
            block_query(Some("ticket_ref=T-1&q=x"), &fields).as_deref(),
            Some("ticket_ref=[REDACTED]&q=x")
        );
    }

    #[test]
    fn block_query_is_none_when_the_request_has_no_query() {
        assert_eq!(block_query(None, &[]), None);
    }

    #[test]
    fn block_query_keeps_a_long_query_whole() {
        let query = format!("q={}", "a".repeat(4000));
        assert_eq!(
            block_query(Some(&query), &[]).as_deref(),
            Some(query.as_str())
        );
    }

    #[test]
    fn block_query_keeps_ordinary_names_and_bare_values_as_received() {
        // Redaction works by parameter name, so a secret under an ordinary name or with no
        // `=` is logged as it was sent.
        let query = "code=123456&key=abc&s3cr3tbare";
        assert_eq!(block_query(Some(query), &[]).as_deref(), Some(query));
    }
}
