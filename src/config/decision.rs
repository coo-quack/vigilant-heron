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

/// Parses one `decision { ... }` directive.
pub(crate) fn parse_decision<F>(
    directive: &Directive,
    lookup: &F,
) -> Result<DecisionConfig, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let children = block(directive)?;
    let mut draft = DecisionDraft::new(directive);
    for child in children {
        draft.apply(child)?;
    }
    draft.finish(lookup)
}

/// A `decision` block while it is read: the settings read so far, which become the fields of
/// [`DecisionConfig`] and [`BackendConfig`], and the places the errors point at. Without a
/// directive of its own, `backend_line`, `token_line` and `model_line` stay at the `decision`
/// directive, as does the line of a default `url`.
struct DecisionDraft<'a> {
    /// The `decision` directive, which the cross-checks point at.
    directive: &'a Directive,
    /// The names of the single-use directives seen so far.
    seen: HashSet<String>,
    backend_name: &'a str,
    /// The text of `url` and the directive that wrote it.
    url_text: Option<(String, &'a Directive)>,
    model: Option<String>,
    token_env: Option<String>,
    timeout: Duration,
    queue_timeout: Duration,
    max_concurrency: usize,
    max_concurrency_per_client: Option<usize>,
    inspect_body: usize,
    redact_headers: Vec<String>,
    redact_fields: Vec<String>,
    redact_file_parts: bool,
    /// The `backend` directive, or the `decision` directive when there is none.
    backend_line: &'a Directive,
    /// The `api_token_env` directive, or the `decision` directive when there is none.
    token_line: &'a Directive,
    /// The `model` directive, or the `decision` directive when there is none.
    model_line: &'a Directive,
}

impl<'a> DecisionDraft<'a> {
    /// A draft of the `decision` block `directive` with the defaults.
    fn new(directive: &'a Directive) -> Self {
        Self {
            directive,
            seen: HashSet::new(),
            backend_name: "jev",
            url_text: None,
            model: None,
            token_env: None,
            timeout: DEFAULT_TIMEOUT,
            queue_timeout: Duration::ZERO,
            max_concurrency: DEFAULT_MAX_CONCURRENCY,
            max_concurrency_per_client: None,
            inspect_body: DEFAULT_INSPECT_BODY,
            redact_headers: Vec::new(),
            redact_fields: Vec::new(),
            redact_file_parts: true,
            backend_line: directive,
            token_line: directive,
            model_line: directive,
        }
    }

    /// Applies one directive of the block. Every directive may appear once, except
    /// `redact_header` and `redact_field`, whose lines add up, and `max_body`, which is
    /// always refused. A repeated directive fails before its value is read.
    fn apply(&mut self, child: &'a Directive) -> Result<(), ConfigError> {
        let name = child.name.as_str();
        if !DECISION_DIRECTIVES.contains(&name) {
            return Err(invalid(
                child,
                format!("unknown directive \"{name}\" in decision"),
            ));
        }
        if !matches!(name, "max_body" | "redact_header" | "redact_field") {
            once(&mut self.seen, child)?;
        }
        match name {
            "backend" => {
                self.backend_line = child;
                self.backend_name = known_backend(child)?;
            }
            "url" => self.url_text = Some((one_arg(child)?.to_owned(), child)),
            "model" => {
                self.model_line = child;
                self.model = Some(one_arg(child)?.to_owned());
            }
            "api_token_env" => {
                self.token_line = child;
                self.token_env = Some(one_arg(child)?.to_owned());
            }
            "timeout" => self.timeout = parse_time(child, one_arg(child)?)?,
            "queue_timeout" => self.queue_timeout = parse_time(child, one_arg(child)?)?,
            "max_concurrency" => self.max_concurrency = parse_number(child, one_arg(child)?)?,
            "max_concurrency_per_client" => {
                self.max_concurrency_per_client = Some(parse_number(child, one_arg(child)?)?);
            }
            "inspect_body" => self.inspect_body = parse_size(child, one_arg(child)?)?,
            "max_body" => {
                return Err(invalid(
                    child,
                    "\"max_body\" was replaced by \"client_max_body_size\", which is set at the top level",
                ));
            }
            "redact_header" => self.redact_headers.extend(lowercased_args(
                child,
                "\"redact_header\" needs at least one header name",
            )?),
            "redact_field" => self.redact_fields.extend(lowercased_args(
                child,
                "\"redact_field\" needs at least one field name",
            )?),
            "redact_file_parts" => self.redact_file_parts = parse_bool(child, one_arg(child)?)?,
            other => {
                return Err(invalid(
                    child,
                    format!("unknown directive \"{other}\" in decision"),
                ));
            }
        }
        Ok(())
    }

    /// Checks the settings against each other, then resolves the URL and the backend,
    /// whose token is read with `lookup`, and builds the result.
    fn finish<F>(self, lookup: &F) -> Result<DecisionConfig, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        check_timeouts(self.directive, self.timeout, self.queue_timeout)?;
        let max_concurrency_per_client = per_client_limit(
            self.directive,
            self.max_concurrency,
            self.max_concurrency_per_client,
        )?;
        let url = self.endpoint_url()?;
        let backend = self.select_backend(lookup)?;
        Ok(DecisionConfig {
            url,
            backend,
            timeout: self.timeout,
            queue_timeout: self.queue_timeout,
            max_concurrency: self.max_concurrency,
            max_concurrency_per_client,
            inspect_body_bytes: self.inspect_body,
            redact_headers: self.redact_headers,
            redact_fields: self.redact_fields,
            redact_file_parts: self.redact_file_parts,
        })
    }

    /// The `url` as a URI. Only backend jev has a default, so the others need one.
    fn endpoint_url(&self) -> Result<Uri, ConfigError> {
        let (text, line) = match &self.url_text {
            Some((text, line)) => (text.as_str(), *line),
            None if self.backend_name == "jev" => (JEV_URL, self.directive),
            None => {
                return Err(invalid(
                    self.backend_line,
                    format!("\"url\" is required with backend {}", self.backend_name),
                ));
            }
        };
        parse_absolute_uri(text, &["http", "https"]).ok_or_else(|| {
            invalid(
                line,
                format!("\"url\" must be an absolute http:// or https:// URI, got {text}"),
            )
        })
    }

    /// The backend the settings name, with the model and token it needs.
    fn select_backend<F>(&self, lookup: &F) -> Result<BackendConfig, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        match self.backend_name {
            "http" => self.http_backend(),
            "clef" => self.clef_backend(lookup),
            "strands" => self.strands_backend(lookup),
            _ => self.jev_backend(lookup),
        }
    }

    /// Backend http speaks its own protocol, which has neither a model nor a token.
    fn http_backend(&self) -> Result<BackendConfig, ConfigError> {
        if self.model.is_some() {
            return Err(invalid(
                self.model_line,
                "\"model\" is not valid with backend http",
            ));
        }
        if self.token_env.is_some() {
            return Err(invalid(
                self.token_line,
                "\"api_token_env\" is not valid with backend http",
            ));
        }
        Ok(BackendConfig::Http)
    }

    /// Backend clef: one of its two models and a token are both required.
    fn clef_backend<F>(&self, lookup: &F) -> Result<BackendConfig, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let model_text = self
            .model
            .as_deref()
            .ok_or_else(|| invalid(self.backend_line, "\"model\" is required with backend clef"))?;
        let model = ClefModel::from_name(model_text).ok_or_else(|| {
            invalid(
                self.model_line,
                format!("\"model\" must be clef-flash or clef for backend clef, got {model_text}"),
            )
        })?;
        let env_name = self.token_env.as_deref().ok_or_else(|| {
            invalid(
                self.backend_line,
                "\"api_token_env\" is required with backend clef",
            )
        })?;
        Ok(BackendConfig::Clef {
            model,
            token: read_token(self.token_line, env_name, lookup)?,
        })
    }

    /// Backend strands: the model has a default, and the token is optional.
    fn strands_backend<F>(&self, lookup: &F) -> Result<BackendConfig, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let model = self.model_id(STRANDS_MODEL)?;
        let token = self
            .token_env
            .as_deref()
            .map(|env_name| read_token(self.token_line, env_name, lookup))
            .transpose()?;
        Ok(BackendConfig::Strands { model, token })
    }

    /// Backend jev: the model and the token variable both have defaults.
    fn jev_backend<F>(&self, lookup: &F) -> Result<BackendConfig, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let model = self.model_id(JEV_MODEL)?;
        let env_name = self.token_env.as_deref().unwrap_or(JEV_TOKEN_ENV);
        Ok(BackendConfig::Jev {
            model,
            token: read_token(self.token_line, env_name, lookup)?,
        })
    }

    /// The `model` text, or `default` when there is none, if it is a safe identifier.
    fn model_id(&self, default: &str) -> Result<String, ConfigError> {
        let model = self.model.as_deref().unwrap_or(default);
        if !is_valid_model_id(model) {
            return Err(invalid(
                self.model_line,
                format!("\"model\" must be 1 to 100 characters from [A-Za-z0-9._-], got {model}"),
            ));
        }
        Ok(model.to_owned())
    }
}

/// `backend jev`, `clef`, `strands` or `http`. Returns the name.
fn known_backend(directive: &Directive) -> Result<&str, ConfigError> {
    match one_arg(directive)? {
        name @ ("jev" | "clef" | "strands" | "http") => Ok(name),
        other => Err(invalid(
            directive,
            format!("\"backend\" must be jev, clef, strands or http, got {other}"),
        )),
    }
}

/// The arguments of `redact_header` or `redact_field`, lowercased. With none, the error is
/// `when_empty`.
fn lowercased_args(directive: &Directive, when_empty: &str) -> Result<Vec<String>, ConfigError> {
    if directive.args.is_empty() {
        return Err(invalid(directive, when_empty));
    }
    Ok(directive
        .args
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect())
}

/// Checks `timeout` and `queue_timeout`; the errors point at the `decision` directive.
fn check_timeouts(
    directive: &Directive,
    timeout: Duration,
    queue_timeout: Duration,
) -> Result<(), ConfigError> {
    if timeout.is_zero() {
        return Err(invalid(directive, "\"timeout\" must be greater than 0"));
    }
    if queue_timeout > timeout {
        return Err(invalid(
            directive,
            "\"queue_timeout\" must not exceed \"timeout\"",
        ));
    }
    Ok(())
}

/// The per-client limit, after `max_concurrency` and `max_concurrency_per_client` are checked.
/// When it is not set, it is the default, capped at `max_concurrency`. The errors point at the
/// `decision` directive.
fn per_client_limit(
    directive: &Directive,
    max_concurrency: usize,
    per_client: Option<usize>,
) -> Result<usize, ConfigError> {
    if max_concurrency == 0 {
        return Err(invalid(directive, "\"max_concurrency\" must be at least 1"));
    }
    match per_client {
        Some(0) => Err(invalid(
            directive,
            "\"max_concurrency_per_client\" must be at least 1",
        )),
        Some(per_client) if per_client > max_concurrency => Err(invalid(
            directive,
            "\"max_concurrency_per_client\" must not exceed \"max_concurrency\"",
        )),
        Some(per_client) => Ok(per_client),
        None => Ok(DEFAULT_MAX_CONCURRENCY_PER_CLIENT.min(max_concurrency)),
    }
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
    fn redact_header_needs_a_name() {
        let text = with_decision("    backend http;\n    redact_header;\n");
        assert!(message(parse(&text)).contains("\"redact_header\" needs at least one header name"));
    }

    #[test]
    fn redact_header_lines_add_up() -> Result<(), ConfigError> {
        let config = parse(&with_decision(
            "    backend http;\n    redact_header X-A;\n    redact_header X-B;\n",
        ))?;
        assert_eq!(config.decision.redact_headers, ["x-a", "x-b"]);
        Ok(())
    }

    #[test]
    fn a_missing_url_is_reported_at_the_backend_line() {
        let text = message(parse(
            "listen 127.0.0.1:8080;\ndecision {\n    backend strands;\n}\n\
             site example.com {\n    upstream http://upstream:80;\n}\n",
        ));
        assert!(text.starts_with("test.conf:3:"), "{text}");
        assert!(
            text.contains("\"url\" is required with backend strands"),
            "{text}"
        );
    }

    #[test]
    fn a_model_with_backend_http_is_reported_at_the_model_line() {
        let text = message(parse(&with_decision(
            "    backend http;\n    model jev-latest;\n",
        )));
        assert!(text.starts_with("test.conf:5:"), "{text}");
        assert!(
            text.contains("\"model\" is not valid with backend http"),
            "{text}"
        );
    }

    #[test]
    fn an_unknown_directive_in_decision_is_named() {
        let text = message(parse(&with_decision(
            "    backend http;\n    upstream http://upstream:80;\n",
        )));
        assert!(
            text.contains("unknown directive \"upstream\" in decision"),
            "{text}"
        );
    }

    #[test]
    fn a_queue_timeout_equal_to_the_timeout_is_allowed() -> Result<(), ConfigError> {
        let config = parse(&with_decision(
            "    backend http;\n    timeout 100ms;\n    queue_timeout 100ms;\n",
        ))?;
        assert_eq!(config.decision.queue_timeout, Duration::from_millis(100));
        Ok(())
    }

    #[test]
    fn a_decision_url_that_is_not_an_absolute_http_uri_is_rejected_at_its_line() {
        let text = message(parse(
            "listen 127.0.0.1:8080;\ndecision {\n    backend http;\n    url stub-decider/decide;\n}\n\
             site example.com {\n    upstream http://upstream:80;\n}\n",
        ));
        assert!(text.starts_with("test.conf:4:"), "{text}");
        assert!(
            text.contains(
                "\"url\" must be an absolute http:// or https:// URI, got stub-decider/decide"
            ),
            "{text}"
        );
    }

    #[rstest]
    #[case::backend("    backend http;\n    backend http;\n", "backend")]
    #[case::url("    backend http;\n    url http://stub-decider:9000/other;\n", "url")]
    #[case::model("    model a;\n    model b;\n", "model")]
    #[case::api_token_env("    api_token_env A;\n    api_token_env B;\n", "api_token_env")]
    #[case::timeout("    backend http;\n    timeout 1s;\n    timeout 2s;\n", "timeout")]
    #[case::queue_timeout(
        "    backend http;\n    queue_timeout 1ms;\n    queue_timeout 2ms;\n",
        "queue_timeout"
    )]
    #[case::max_concurrency(
        "    backend http;\n    max_concurrency 2;\n    max_concurrency 3;\n",
        "max_concurrency"
    )]
    #[case::max_concurrency_per_client(
        "    backend http;\n    max_concurrency_per_client 1;\n    max_concurrency_per_client 2;\n",
        "max_concurrency_per_client"
    )]
    #[case::inspect_body(
        "    backend http;\n    inspect_body 1k;\n    inspect_body 2k;\n",
        "inspect_body"
    )]
    fn a_single_use_decision_directive_is_rejected_the_second_time(
        #[case] lines: &str,
        #[case] name: &str,
    ) {
        let text = message(parse(&with_decision(lines)));
        assert!(
            text.contains(&format!("duplicate directive \"{name}\"")),
            "{text}"
        );
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
