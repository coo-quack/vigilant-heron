//! The `decision` block: the backend, its endpoint and token, and the limits on calls to it.

use std::collections::HashSet;
use std::time::Duration;

use http::Uri;

use super::names::DECISION_DIRECTIVES;
use super::value::{
    block, invalid, once, one_arg, parse_bool, parse_number, parse_size, parse_time,
};
use super::{BackendConfig, DecisionConfig};
use crate::conf::Directive;
use crate::error::ConfigError;
use crate::system_one::{ApiToken, ClefModel};

/// Default number of concurrent decision-backend calls.
const DEFAULT_MAX_CONCURRENCY: usize = 64;
/// Default `max_concurrency_per_client`, capped at `max_concurrency` when that is smaller.
const DEFAULT_MAX_CONCURRENCY_PER_CLIENT: usize = 8;
/// Default decision timeout.
const DEFAULT_TIMEOUT: Duration = Duration::from_millis(2000);

/// Default inspected body size.
const DEFAULT_INSPECT_BODY: usize = 8 * 1024;

/// The Jev endpoint used when `url` is omitted.
const JEV_URL: &str = "https://api.typesafe.ai/v1/systemone";
/// The Jev model used when `model` is omitted.
const JEV_MODEL: &str = "jev-latest";
/// The variable read for the Jev token when `api_token_env` is omitted.
const JEV_TOKEN_ENV: &str = "TYPESAFE_API_KEY";
/// The model used when `model` is omitted with backend strands.
const STRANDS_MODEL: &str = "strands-decider";

pub(crate) fn parse_absolute_uri(text: &str, schemes: &[&str]) -> Option<Uri> {
    let uri = text.parse::<Uri>().ok()?;
    let scheme_ok = uri
        .scheme_str()
        .is_some_and(|scheme| schemes.contains(&scheme));
    (scheme_ok && uri.authority().is_some()).then_some(uri)
}

/// Returns true for a model identifier of 1 to 100 characters from `[A-Za-z0-9._-]`.
fn is_valid_model_id(value: &str) -> bool {
    (1..=100).contains(&value.len())
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

#[expect(
    clippy::too_many_lines,
    reason = "one arm per directive keeps each name and its check together"
)]
pub(crate) fn parse_decision<F>(
    directive: &Directive,
    lookup: &F,
) -> Result<DecisionConfig, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let mut seen = HashSet::new();
    let mut backend_name = "jev";
    let mut url_text = None;
    let mut model = None;
    let mut token_env = None;
    let mut timeout = DEFAULT_TIMEOUT;
    let mut queue_timeout = Duration::ZERO;
    let mut max_concurrency = DEFAULT_MAX_CONCURRENCY;
    let mut max_concurrency_per_client: Option<usize> = None;
    let mut inspect_body = DEFAULT_INSPECT_BODY;
    let mut redact_headers = Vec::new();
    let mut redact_fields = Vec::new();
    let mut redact_file_parts = true;
    let mut backend_line = directive;
    let mut token_line = directive;
    let mut model_line = directive;

    for child in block(directive)? {
        if !DECISION_DIRECTIVES.contains(&child.name.as_str()) {
            return Err(invalid(
                child,
                format!("unknown directive \"{}\" in decision", child.name),
            ));
        }
        match child.name.as_str() {
            "backend" => {
                once(&mut seen, child)?;
                backend_line = child;
                backend_name = match one_arg(child)? {
                    name @ ("jev" | "clef" | "strands" | "http") => name,
                    other => {
                        return Err(invalid(
                            child,
                            format!("\"backend\" must be jev, clef, strands or http, got {other}"),
                        ));
                    }
                };
            }
            "url" => {
                once(&mut seen, child)?;
                url_text = Some((one_arg(child)?.to_owned(), child));
            }
            "model" => {
                once(&mut seen, child)?;
                model_line = child;
                model = Some(one_arg(child)?.to_owned());
            }
            "api_token_env" => {
                once(&mut seen, child)?;
                token_line = child;
                token_env = Some(one_arg(child)?.to_owned());
            }
            "timeout" => {
                once(&mut seen, child)?;
                timeout = parse_time(child, one_arg(child)?)?;
            }
            "queue_timeout" => {
                once(&mut seen, child)?;
                queue_timeout = parse_time(child, one_arg(child)?)?;
            }
            "max_concurrency" => {
                once(&mut seen, child)?;
                max_concurrency = parse_number::<usize>(child, one_arg(child)?)?;
            }
            "max_concurrency_per_client" => {
                once(&mut seen, child)?;
                max_concurrency_per_client = Some(parse_number::<usize>(child, one_arg(child)?)?);
            }
            "inspect_body" => {
                once(&mut seen, child)?;
                inspect_body = parse_size(child, one_arg(child)?)?;
            }
            "max_body" => {
                return Err(invalid(
                    child,
                    "\"max_body\" was replaced by \"client_max_body_size\", which is set at the top level",
                ));
            }
            "redact_header" => {
                if child.args.is_empty() {
                    return Err(invalid(
                        child,
                        "\"redact_header\" needs at least one header name",
                    ));
                }
                redact_headers.extend(child.args.iter().map(|h| h.to_ascii_lowercase()));
            }
            "redact_field" => {
                if child.args.is_empty() {
                    return Err(invalid(
                        child,
                        "\"redact_field\" needs at least one field name",
                    ));
                }
                redact_fields.extend(child.args.iter().map(|f| f.to_ascii_lowercase()));
            }
            "redact_file_parts" => {
                once(&mut seen, child)?;
                redact_file_parts = parse_bool(child, one_arg(child)?)?;
            }
            other => {
                return Err(invalid(
                    child,
                    format!("unknown directive \"{other}\" in decision"),
                ));
            }
        }
    }

    if timeout.is_zero() {
        return Err(invalid(directive, "\"timeout\" must be greater than 0"));
    }
    if queue_timeout > timeout {
        return Err(invalid(
            directive,
            "\"queue_timeout\" must not exceed \"timeout\"".to_owned(),
        ));
    }
    if max_concurrency == 0 {
        return Err(invalid(directive, "\"max_concurrency\" must be at least 1"));
    }
    let max_concurrency_per_client = match max_concurrency_per_client {
        Some(0) => {
            return Err(invalid(
                directive,
                "\"max_concurrency_per_client\" must be at least 1",
            ));
        }
        Some(per_client) if per_client > max_concurrency => {
            return Err(invalid(
                directive,
                "\"max_concurrency_per_client\" must not exceed \"max_concurrency\"",
            ));
        }
        Some(per_client) => per_client,
        None => DEFAULT_MAX_CONCURRENCY_PER_CLIENT.min(max_concurrency),
    };

    let (url_text, url_line) = match url_text {
        Some((text, line)) => (text, line),
        None if backend_name == "jev" => (JEV_URL.to_owned(), directive),
        None => {
            return Err(invalid(
                backend_line,
                format!("\"url\" is required with backend {backend_name}"),
            ));
        }
    };
    let url = parse_absolute_uri(&url_text, &["http", "https"]).ok_or_else(|| {
        invalid(
            url_line,
            format!("\"url\" must be an absolute http:// or https:// URI, got {url_text}"),
        )
    })?;

    let backend = match backend_name {
        "http" => {
            if model.is_some() {
                return Err(invalid(
                    model_line,
                    "\"model\" is not valid with backend http",
                ));
            }
            if token_env.is_some() {
                return Err(invalid(
                    token_line,
                    "\"api_token_env\" is not valid with backend http",
                ));
            }
            BackendConfig::Http
        }
        "clef" => {
            let model_text = model
                .ok_or_else(|| invalid(backend_line, "\"model\" is required with backend clef"))?;
            let model = ClefModel::from_name(&model_text).ok_or_else(|| {
                invalid(
                    model_line,
                    format!(
                        "\"model\" must be clef-flash or clef for backend clef, got {model_text}"
                    ),
                )
            })?;
            let env_name = token_env.ok_or_else(|| {
                invalid(
                    backend_line,
                    "\"api_token_env\" is required with backend clef",
                )
            })?;
            BackendConfig::Clef {
                model,
                token: read_token(token_line, &env_name, lookup)?,
            }
        }
        "strands" => {
            let model_text = model.unwrap_or_else(|| STRANDS_MODEL.to_owned());
            if !is_valid_model_id(&model_text) {
                return Err(invalid(
                    model_line,
                    format!(
                        "\"model\" must be 1 to 100 characters from [A-Za-z0-9._-], got {model_text}"
                    ),
                ));
            }
            let token = token_env
                .map(|env_name| read_token(token_line, &env_name, lookup))
                .transpose()?;
            BackendConfig::Strands {
                model: model_text,
                token,
            }
        }
        _ => {
            let model_text = model.unwrap_or_else(|| JEV_MODEL.to_owned());
            if !is_valid_model_id(&model_text) {
                return Err(invalid(
                    model_line,
                    format!(
                        "\"model\" must be 1 to 100 characters from [A-Za-z0-9._-], got {model_text}"
                    ),
                ));
            }
            let env_name = token_env.unwrap_or_else(|| JEV_TOKEN_ENV.to_owned());
            BackendConfig::Jev {
                model: model_text,
                token: read_token(token_line, &env_name, lookup)?,
            }
        }
    };

    Ok(DecisionConfig {
        url,
        backend,
        timeout,
        queue_timeout,
        max_concurrency,
        max_concurrency_per_client,
        inspect_body_bytes: inspect_body,
        redact_headers,
        redact_fields,
        redact_file_parts,
    })
}

/// Reads the token from the variable `name`. A missing or blank value is an error at `directive`.
fn read_token<F>(directive: &Directive, name: &str, lookup: &F) -> Result<ApiToken, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let value = lookup(name).ok_or_else(|| {
        invalid(
            directive,
            format!("environment variable {name} (api_token_env) is not set"),
        )
    })?;
    let token = value.trim();
    if token.is_empty() {
        return Err(invalid(
            directive,
            format!("environment variable {name} (api_token_env) is empty"),
        ));
    }
    Ok(ApiToken::new(token.to_owned()))
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::config::Config;
    use crate::config::test_helpers::connection_limit::{SITE, parse_plain};
    use crate::config::test_helpers::{message, parse, with_decision};

    #[test]
    fn a_decision_without_a_backend_is_jev_and_needs_its_token() {
        let text = "listen 127.0.0.1:8080;\ndecision {\n    url https://api.typesafe.ai/v1/systemone;\n}\n\
                    site example.com {\n    upstream http://upstream:80;\n}\n";
        let result = Config::parse_str_with_lookup(text, "test.conf", |_| None);
        assert!(message(result).contains("test.conf:2:"));
    }

    #[test]
    fn jev_defaults_apply_when_only_the_token_is_given() -> Result<(), ConfigError> {
        let text = "listen 127.0.0.1:8080;\ndecision {\n    api_token_env TEST_TOKEN;\n}\n\
                    site example.com {\n    upstream http://upstream:80;\n}\n";
        let config = parse(text)?;
        assert!(matches!(
            &config.decision.backend,
            BackendConfig::Jev { model, token } if model == "jev-latest" && token.expose() == "tok-123"
        ));
        assert_eq!(
            config.decision.url.to_string(),
            "https://api.typesafe.ai/v1/systemone"
        );
        Ok(())
    }

    #[test]
    fn jev_defaults_read_the_default_token_variable() {
        let text = "listen 127.0.0.1:8080;\ndecision {\n}\n\
                    site example.com {\n    upstream http://upstream:80;\n}\n";
        let result = Config::parse_str_with_lookup(text, "test.conf", |name| {
            (name == "TYPESAFE_API_KEY").then(|| "jev-token".to_owned())
        });
        assert!(result.is_ok());
    }

    #[test]
    fn a_token_variable_that_is_not_set_names_it_and_its_line() {
        let text = "listen 127.0.0.1:8080;\ndecision {\n    api_token_env ABSENT;\n}\n\
                    site example.com {\n    upstream http://upstream:80;\n}\n";
        let result = parse(text);
        assert!(message(result).contains("test.conf:3: environment variable ABSENT"));
    }

    #[test]
    fn a_blank_token_is_rejected() {
        let text = "listen 127.0.0.1:8080;\ndecision {\n    api_token_env BLANK;\n}\n\
                    site example.com {\n    upstream http://upstream:80;\n}\n";
        let result = Config::parse_str_with_lookup(text, "test.conf", |_| Some("   ".to_owned()));
        assert!(message(result).contains("is empty"));
    }

    #[rstest]
    #[case::clef_flash("clef-flash")]
    #[case::clef("clef")]
    fn clef_accepts_its_two_models(#[case] model: &str) {
        let text = with_decision(&format!(
            "    backend clef;\n    model {model};\n    api_token_env TEST_TOKEN;\n"
        ));
        assert!(parse(&text).is_ok());
    }

    #[test]
    fn clef_rejects_other_models_with_the_directive_line() {
        let text = with_decision(
            "    backend clef;\n    model jev-latest;\n    api_token_env TEST_TOKEN;\n",
        );
        // Line 1 listen, 2 decision, 3 url, 4 backend, 5 model.
        assert!(message(parse(&text)).contains("test.conf:5:"));
    }

    #[test]
    fn clef_requires_a_model_and_a_token_variable() {
        let no_model = with_decision("    backend clef;\n    api_token_env TEST_TOKEN;\n");
        assert!(message(parse(&no_model)).contains("\"model\" is required with backend clef"));
        let no_token = with_decision("    backend clef;\n    model clef;\n");
        assert!(
            message(parse(&no_token)).contains("\"api_token_env\" is required with backend clef")
        );
    }

    #[test]
    fn http_rejects_model_and_token_variable() {
        let model = with_decision("    backend http;\n    model clef;\n");
        assert!(message(parse(&model)).contains("\"model\" is not valid with backend http"));
        let token = with_decision("    backend http;\n    api_token_env TEST_TOKEN;\n");
        assert!(
            message(parse(&token)).contains("\"api_token_env\" is not valid with backend http")
        );
    }

    #[test]
    fn a_jev_model_must_be_a_safe_identifier() {
        let text = with_decision(
            "    backend jev;\n    model \"jev latest\";\n    api_token_env TEST_TOKEN;\n",
        );
        assert!(message(parse(&text)).contains("1 to 100 characters"));
    }

    #[test]
    fn strands_requires_a_url() {
        let text = "listen 127.0.0.1:8080;\ndecision {\n    backend strands;\n}\n\
                    site example.com {\n    upstream http://upstream:80;\n}\n";
        assert!(message(parse(text)).contains("\"url\" is required with backend strands"));
    }

    #[test]
    fn strands_model_defaults_to_strands_decider() -> Result<(), ConfigError> {
        let config = parse(&with_decision("    backend strands;\n"))?;
        assert!(matches!(
            &config.decision.backend,
            BackendConfig::Strands { model, .. } if model == "strands-decider"
        ));
        Ok(())
    }

    #[test]
    fn strands_keeps_a_custom_valid_model() -> Result<(), ConfigError> {
        let config = parse(&with_decision(
            "    backend strands;\n    model my-decider.2B_v1;\n",
        ))?;
        assert!(matches!(
            &config.decision.backend,
            BackendConfig::Strands { model, .. } if model == "my-decider.2B_v1"
        ));
        Ok(())
    }

    #[test]
    fn strands_rejects_an_invalid_model_with_the_model_line() {
        let text = with_decision("    backend strands;\n    model \"strands decider\";\n");
        // Line 1 listen, 2 decision, 3 url, 4 backend, 5 model.
        let error = message(parse(&text));
        assert!(error.contains("test.conf:5:"));
        assert!(error.contains("1 to 100 characters"));
    }

    #[test]
    fn strands_without_api_token_env_sends_no_token() -> Result<(), ConfigError> {
        let config = parse(&with_decision("    backend strands;\n"))?;
        assert!(matches!(
            &config.decision.backend,
            BackendConfig::Strands { token: None, .. }
        ));
        Ok(())
    }

    #[test]
    fn strands_with_api_token_env_reads_the_token() -> Result<(), ConfigError> {
        let config = parse(&with_decision(
            "    backend strands;\n    api_token_env TEST_TOKEN;\n",
        ))?;
        assert!(matches!(
            &config.decision.backend,
            BackendConfig::Strands { token: Some(token), .. } if token.expose() == "tok-123"
        ));
        Ok(())
    }

    #[test]
    fn strands_names_a_token_variable_that_is_not_set() {
        let text = with_decision("    backend strands;\n    api_token_env ABSENT;\n");
        let result = Config::parse_str_with_lookup(&text, "test.conf", |_| None);
        assert!(message(result).contains("environment variable ABSENT"));
    }

    #[test]
    fn the_backend_error_lists_strands() {
        let text = with_decision("    backend bogus;\n");
        assert!(
            message(parse(&text))
                .contains("\"backend\" must be jev, clef, strands or http, got bogus")
        );
    }

    #[test]
    fn timeout_zero_queue_longer_than_timeout_and_zero_concurrency_are_rejected() {
        assert!(
            message(parse(&with_decision("    backend http;\n    timeout 0;\n")))
                .contains("\"timeout\" must be greater than 0")
        );
        assert!(
            message(parse(&with_decision(
                "    backend http;\n    timeout 100ms;\n    queue_timeout 200ms;\n"
            )))
            .contains("must not exceed")
        );
        assert!(
            message(parse(&with_decision(
                "    backend http;\n    max_concurrency 0;\n"
            )))
            .contains("at least 1")
        );
    }

    #[test]
    fn max_body_in_decision_is_replaced_by_client_max_body_size() {
        let text = with_decision("    backend http;\n    max_body 1m;\n");
        assert!(message(parse(&text)).contains("replaced by \"client_max_body_size\""));
    }

    #[test]
    fn redact_field_names_are_read_lowercased_in_the_decision_block() -> Result<(), ConfigError> {
        let config = parse(&with_decision(
            "    backend http;\n    redact_field Ticket_Ref Internal-Note;\n    redact_field trace;\n",
        ))?;
        assert_eq!(
            config.decision.redact_fields,
            ["ticket_ref", "internal-note", "trace"]
        );
        Ok(())
    }

    #[test]
    fn max_concurrency_per_client_defaults_to_eight_capped_at_the_global_cap()
    -> Result<(), ConfigError> {
        let config = parse(&with_decision("    backend http;\n"))?;
        assert_eq!(config.decision.max_concurrency_per_client, 8);
        let small = parse(&with_decision(
            "    backend http;\n    max_concurrency 3;\n",
        ))?;
        assert_eq!(small.decision.max_concurrency_per_client, 3);
        Ok(())
    }

    #[test]
    fn max_concurrency_per_client_must_be_between_one_and_the_global_cap() -> Result<(), ConfigError>
    {
        let set = parse(&with_decision(
            "    backend http;\n    max_concurrency 10;\n    max_concurrency_per_client 4;\n",
        ))?;
        assert_eq!(set.decision.max_concurrency_per_client, 4);
        assert!(
            message(parse(&with_decision(
                "    backend http;\n    max_concurrency_per_client 0;\n"
            )))
            .contains("\"max_concurrency_per_client\" must be at least 1")
        );
        assert!(
            message(parse(&with_decision(
                "    backend http;\n    max_concurrency 4;\n    max_concurrency_per_client 5;\n",
            )))
            .contains("\"max_concurrency_per_client\" must not exceed \"max_concurrency\"")
        );
        Ok(())
    }

    #[test]
    fn redact_field_needs_a_name() {
        let text = with_decision("    backend http;\n    redact_field;\n");
        assert!(message(parse(&text)).contains("\"redact_field\" needs at least one field name"));
    }

    #[test]
    fn redact_file_parts_defaults_to_on() -> Result<(), ConfigError> {
        let config = parse(&with_decision("    backend http;\n"))?;
        assert!(config.decision.redact_file_parts);
        Ok(())
    }

    #[rstest]
    #[case::on("on", true)]
    #[case::off("off", false)]
    fn redact_file_parts_reads_on_and_off(
        #[case] value: &str,
        #[case] expected: bool,
    ) -> Result<(), ConfigError> {
        let text = with_decision(&format!(
            "    backend http;\n    redact_file_parts {value};\n"
        ));
        assert_eq!(parse(&text)?.decision.redact_file_parts, expected);
        Ok(())
    }

    #[test]
    fn redact_file_parts_rejects_other_values() {
        let text = with_decision("    backend http;\n    redact_file_parts yes;\n");
        assert!(message(parse(&text)).contains("\"redact_file_parts\" must be \"on\" or \"off\""));
    }

    #[test]
    fn redact_file_parts_is_set_once() {
        let text = with_decision(
            "    backend http;\n    redact_file_parts on;\n    redact_file_parts off;\n",
        );
        assert!(message(parse(&text)).contains("duplicate directive \"redact_file_parts\""));
    }

    #[test]
    fn max_body_is_replaced_by_client_max_body_size() {
        let text = message(Config::parse_str_with_lookup(
            &format!(
                "listen 127.0.0.1:8080;\ndecision {{\n    backend http;\n    url http://stub:9000/decide;\n    max_body 1m;\n}}\n{SITE}"
            ),
            "test.conf",
            |_| None,
        ));
        assert!(
            text.contains("replaced by \"client_max_body_size\""),
            "{text}"
        );
        assert!(text.contains("test.conf:5:"), "{text}");
    }

    #[test]
    fn a_per_client_share_equal_to_the_global_cap_is_allowed() -> Result<(), ConfigError> {
        let config = parse_plain(
            "listen 127.0.0.1:8080;\ndecision {\n    backend http;\n    url http://stub-decider:9000/decide;\n    max_concurrency 10;\n    max_concurrency_per_client 10;\n}\nsite example.com {\n    upstream http://upstream:80;\n}\n",
        )?;
        assert_eq!(config.decision.max_concurrency_per_client, 10);
        Ok(())
    }
}
