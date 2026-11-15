//! The `proxy_set_header` directive: its config syntax, the variables a value may use,
//! and how a value is rendered for one request.

use http::header::{HeaderMap, HeaderName, HeaderValue};

use super::HOP_BY_HOP;
use crate::conf::{Directive, invalid};
use crate::error::ConfigError;

/// One `proxy_set_header` directive: a header name and the value template it is set to.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct HeaderOp {
    /// The header that is set or removed.
    pub(crate) name: HeaderName,
    /// The value, as literal text and variables.
    template: Vec<Part>,
}

/// One piece of a `proxy_set_header` value.
#[derive(Debug, Clone, PartialEq)]
enum Part {
    /// Text copied as written.
    Text(String),
    /// A variable, replaced with its value for each request.
    Var(Var),
}

/// The variables a `proxy_set_header` value may use.
#[derive(Debug, Clone, PartialEq)]
enum Var {
    /// The client address chosen by the realip settings.
    ClientIp,
    /// The address of the TCP peer.
    RemoteAddr,
    /// The normalized `Host` of the request.
    Host,
    /// The first host name of the site that serves the request.
    Site,
    /// The request method.
    Method,
    /// The request path, as received.
    Path,
    /// The request id, or an empty string when there is none.
    RequestId,
    /// A request header, `$http_<name>`, with underscores read as hyphens.
    Header(HeaderName),
}

/// The values of one request that `proxy_set_header` values can use.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HeaderContext<'a> {
    /// The client address chosen by the realip settings.
    pub(crate) client_ip: &'a str,
    /// The address of the TCP peer.
    pub(crate) remote_addr: &'a str,
    /// The normalized `Host` of the request.
    pub(crate) host: &'a str,
    /// The site name, or an empty string.
    pub(crate) site: &'a str,
    /// The request method.
    pub(crate) method: &'a str,
    /// The request path, as received.
    pub(crate) path: &'a str,
    /// The request id, or an empty string.
    pub(crate) request_id: &'a str,
    /// The headers the client sent.
    pub(crate) headers: &'a HeaderMap,
}

impl HeaderOp {
    /// Parses `proxy_set_header <name> <value>;`. An empty value removes the header.
    ///
    /// # Errors
    ///
    /// Returns an error when the directive has no name, names a hop-by-hop
    /// header, uses an unknown variable, or has text that is not a valid header value.
    pub(crate) fn parse(directive: &Directive) -> Result<Self, ConfigError> {
        let [name, value] = directive.args.as_slice() else {
            return Err(invalid(
                directive,
                "\"proxy_set_header\" takes a header name and a value; use \"\" to remove a header",
            ));
        };
        let header = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
            invalid(
                directive,
                format!("\"proxy_set_header\" is not a header name: {name}"),
            )
        })?;
        if HOP_BY_HOP.contains(&header.as_str()) {
            return Err(invalid(
                directive,
                format!("\"proxy_set_header\" cannot set the hop-by-hop header {name}"),
            ));
        }
        let template = parse_template(directive, value)?;
        Ok(Self {
            name: header,
            template,
        })
    }

    /// The value for one request.
    pub(crate) fn render(&self, ctx: &HeaderContext<'_>) -> String {
        let mut value = String::new();
        for part in &self.template {
            match part {
                Part::Text(text) => value.push_str(text),
                Part::Var(var) => value.push_str(var_value(var, ctx)),
            }
        }
        value
    }
}

/// Splits a value into text and `$variable` or `${variable}` parts, and checks each variable.
fn parse_template(directive: &Directive, value: &str) -> Result<Vec<Part>, ConfigError> {
    let mut parts = Vec::new();
    let mut text = String::new();
    let mut rest = value;
    while let Some(position) = rest.find('$') {
        text.push_str(rest.get(..position).unwrap_or_default());
        let after = rest.get(position + 1..).unwrap_or_default();
        let (name, consumed) = if let Some(braced) = after.strip_prefix('{') {
            let end = braced.find('}').ok_or_else(|| {
                invalid(
                    directive,
                    "\"proxy_set_header\" has a \"${\" without a closing brace",
                )
            })?;
            (braced.get(..end).unwrap_or_default(), end + 3)
        } else {
            let length = after
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(after.len());
            (after.get(..length).unwrap_or_default(), length + 1)
        };
        if !text.is_empty() {
            parts.push(Part::Text(std::mem::take(&mut text)));
        }
        parts.push(Part::Var(variable(directive, name)?));
        rest = rest.get(position + consumed..).unwrap_or_default();
    }
    text.push_str(rest);
    if !text.is_empty() {
        parts.push(Part::Text(text));
    }
    for part in &parts {
        if let Part::Text(literal) = part
            && HeaderValue::from_str(literal).is_err()
        {
            return Err(invalid(
                directive,
                "\"proxy_set_header\" value is not a valid header value",
            ));
        }
    }
    Ok(parts)
}

/// Reads the name of one variable.
fn variable(directive: &Directive, name: &str) -> Result<Var, ConfigError> {
    let known = match name {
        "client_ip" => Some(Var::ClientIp),
        "remote_addr" => Some(Var::RemoteAddr),
        "host" => Some(Var::Host),
        "site" => Some(Var::Site),
        "method" => Some(Var::Method),
        "path" => Some(Var::Path),
        "request_id" => Some(Var::RequestId),
        _ => None,
    };
    if let Some(var) = known {
        return Ok(var);
    }
    if let Some(header) = name.strip_prefix("http_").filter(|rest| !rest.is_empty()) {
        let header_name = header.replace('_', "-");
        return HeaderName::from_bytes(header_name.as_bytes())
            .map(Var::Header)
            .map_err(|_| {
                invalid(
                    directive,
                    format!("\"proxy_set_header\" variable ${name} is not a header name"),
                )
            });
    }
    Err(invalid(
        directive,
        format!("\"proxy_set_header\" has an unknown variable ${name}"),
    ))
}

/// The text a variable stands for in one request.
fn var_value<'a>(var: &Var, ctx: &HeaderContext<'a>) -> &'a str {
    match var {
        Var::ClientIp => ctx.client_ip,
        Var::RemoteAddr => ctx.remote_addr,
        Var::Host => ctx.host,
        Var::Site => ctx.site,
        Var::Method => ctx.method,
        Var::Path => ctx.path,
        Var::RequestId => ctx.request_id,
        Var::Header(name) => ctx
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use crate::error::ConfigError;
    use crate::proxy::test_helpers::op;

    #[rstest]
    #[case::plain("X-Real-IP $client_ip")]
    #[case::braced("X-Proto \"${http_x_forwarded_proto}\"")]
    #[case::text_around_variable("X-Note id-$request_id-end")]
    #[case::remove("X-Remove \"\"")]
    #[case::every_variable("X-All \"$remote_addr $host $site $method $path $request_id\"")]
    fn valid_set_header_lines_parse(#[case] line: &str) {
        assert!(op(&format!("proxy_set_header {line};")).is_ok());
    }

    #[rstest]
    #[case::connection("Connection close")]
    #[case::upgrade("Upgrade websocket")]
    #[case::keep_alive("Keep-Alive timeout=5")]
    #[case::transfer_encoding("Transfer-Encoding chunked")]
    #[case::te("TE trailers")]
    fn hop_by_hop_headers_cannot_be_set(#[case] line: &str) {
        let result = op(&format!("proxy_set_header {line};"));
        assert!(
            matches!(&result, Err(ConfigError::Invalid { message, .. }) if message.contains("hop-by-hop")),
            "{result:?}"
        );
    }

    #[rstest]
    #[case::unknown_variable("X-A $nope")]
    #[case::empty_variable("X-A $")]
    #[case::empty_braces("X-A ${}")]
    #[case::unclosed_braces("X-A ${client_ip")]
    #[case::cookie_variable_is_not_a_variable("X-A $http_")]
    #[case::bad_header_name("X Name value")]
    #[case::no_value("X-Only")]
    #[case::control_character_in_text("X-A bad\u{1}value")]
    fn bad_set_header_lines_are_rejected(#[case] line: &str) {
        assert!(op(&format!("proxy_set_header {line};")).is_err());
    }
}
