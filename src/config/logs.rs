//! The log directives: `error_log`, `log_format` and `access_log`.

use super::value::invalid;
use super::{AccessLogConfig, Destination, ErrorLogConfig, LogLevel};
use crate::accesslog::{Escape, LogFormat};
use crate::conf::Directive;
use crate::error::ConfigError;

pub(crate) fn parse_error_log(directive: &Directive) -> Result<ErrorLogConfig, ConfigError> {
    let (destination_text, level_text) = match directive.args.as_slice() {
        [destination] => (destination.as_str(), None),
        [destination, level] => (destination.as_str(), Some(level.as_str())),
        _ => {
            return Err(invalid(
                directive,
                "\"error_log\" takes a destination and an optional level",
            ));
        }
    };
    let destination = match destination_text {
        "stderr" => Destination::Stderr,
        "stdout" => Destination::Stdout,
        text if text.starts_with("syslog:") => {
            return Err(invalid(
                directive,
                "\"error_log\" cannot write to syslog; use stderr, stdout or a file",
            ));
        }
        path => Destination::File(path.into()),
    };
    let level = match level_text.unwrap_or("info") {
        "error" => LogLevel::Error,
        "warn" => LogLevel::Warn,
        "info" => LogLevel::Info,
        "debug" => LogLevel::Debug,
        other => {
            return Err(invalid(
                directive,
                format!("\"error_log\" level must be error, warn, info or debug, got {other}"),
            ));
        }
    };
    Ok(ErrorLogConfig { destination, level })
}

/// A `log_format` directive before its variables are checked.
pub(crate) struct RawFormat<'a> {
    name: &'a str,
    escape: Escape,
    // nginx concatenates the strings of a log_format, so a long format can be
    // split over several lines.
    text: String,
    directive: &'a Directive,
}

pub(crate) fn collect_formats<'a>(
    directives: &[&'a Directive],
) -> Result<Vec<RawFormat<'a>>, ConfigError> {
    let mut formats: Vec<RawFormat<'a>> = Vec::new();
    for directive in directives {
        let (name, rest) = match directive.args.split_first() {
            Some((name, rest)) => (name.as_str(), rest),
            None => {
                return Err(invalid(
                    directive,
                    "\"log_format\" needs a name and a format string",
                ));
            }
        };
        if name == "json" || name == "main" {
            return Err(invalid(
                directive,
                format!("\"{name}\" is a built-in log format and cannot be redefined"),
            ));
        }
        if formats.iter().any(|f| f.name == name) {
            return Err(invalid(
                directive,
                format!("duplicate log_format \"{name}\""),
            ));
        }
        let (escape, strings) = match rest {
            [option, strings @ ..] if option.starts_with("escape=") => (
                parse_escape(directive, option.get(7..).unwrap_or_default())?,
                strings,
            ),
            strings => (Escape::Default, strings),
        };
        if strings.is_empty() {
            return Err(invalid(
                directive,
                "\"log_format\" takes a name, an optional escape=default|json, and one or more quoted format strings",
            ));
        }
        let text = strings.concat();
        formats.push(RawFormat {
            name,
            escape,
            text,
            directive,
        });
    }
    Ok(formats)
}

fn parse_escape(directive: &Directive, text: &str) -> Result<Escape, ConfigError> {
    match text {
        "default" => Ok(Escape::Default),
        "json" => Ok(Escape::Json),
        other => Err(invalid(
            directive,
            format!("log escape must be default or json, got {other}"),
        )),
    }
}

/// Compiled named formats, looked up by name.
pub(crate) struct Formats {
    named: Vec<LogFormat>,
}

pub(crate) fn compile_formats(
    raw: Vec<RawFormat<'_>>,
    redact: &[String],
) -> Result<Formats, ConfigError> {
    let mut named = Vec::new();
    for format in raw {
        let compiled = LogFormat::compile(format.name, format.escape, &format.text, redact)
            .map_err(|message| invalid(format.directive, message))?;
        named.push(compiled);
    }
    Ok(Formats { named })
}

impl Formats {
    fn find(&self, name: &str) -> Option<LogFormat> {
        match name {
            "json" => Some(LogFormat::json()),
            "main" => Some(LogFormat::main()),
            other => self.named.iter().find(|f| f.name == other).cloned(),
        }
    }
}

/// Parses the destination and optional format of an `access_log` directive.
/// Returns `None` for `access_log off`.
pub(crate) fn parse_access(
    directive: &Directive,
    formats: &Formats,
) -> Result<Option<AccessLogConfig>, ConfigError> {
    let (destination_text, format_name) = match directive.args.as_slice() {
        [destination] => (destination.as_str(), None),
        [destination, format] => (destination.as_str(), Some(format.as_str())),
        _ => {
            return Err(invalid(
                directive,
                "\"access_log\" takes a destination and an optional format",
            ));
        }
    };
    if destination_text == "off" {
        if format_name.is_some() {
            return Err(invalid(directive, "\"access_log off\" takes no format"));
        }
        return Ok(None);
    }
    let destination = parse_destination(directive, destination_text)?;
    let format = match format_name {
        None => LogFormat::json(),
        Some(name) => formats
            .find(name)
            .ok_or_else(|| invalid(directive, format!("unknown log format \"{name}\"")))?,
    };
    Ok(Some(AccessLogConfig {
        destination,
        format,
    }))
}

fn parse_destination(directive: &Directive, text: &str) -> Result<Destination, ConfigError> {
    match text {
        "stdout" => Ok(Destination::Stdout),
        "stderr" => Ok(Destination::Stderr),
        _ => {
            if let Some(rest) = text.strip_prefix("syslog:") {
                let mut server = None;
                let mut tag = "vigilant-heron".to_owned();
                for option in rest.split(',') {
                    match option.split_once('=') {
                        Some(("server", value)) => server = Some(value.to_owned()),
                        Some(("tag", value)) if !value.is_empty() => value.clone_into(&mut tag),
                        _ => {
                            return Err(invalid(
                                directive,
                                format!("invalid syslog option \"{option}\""),
                            ));
                        }
                    }
                }
                let server =
                    server.ok_or_else(|| invalid(directive, "syslog needs server=<host:port>"))?;
                if !server.contains(':') {
                    return Err(invalid(
                        directive,
                        format!("syslog server needs a port: {server}"),
                    ));
                }
                return Ok(Destination::Syslog { server, tag });
            }
            if text.is_empty() {
                return Err(invalid(directive, "\"access_log\" needs a destination"));
            }
            Ok(Destination::File(text.into()))
        }
    }
}

/// Resolves the top-level `access_log` directives. With none, `stdout json` is the default.
pub(crate) fn resolve_top_access(
    directives: &[&Directive],
    formats: &Formats,
) -> Result<Vec<AccessLogConfig>, ConfigError> {
    if directives.is_empty() {
        return Ok(vec![AccessLogConfig {
            destination: Destination::Stdout,
            format: LogFormat::json(),
        }]);
    }
    let mut logs = Vec::new();
    let mut off = false;
    for directive in directives {
        match parse_access(directive, formats)? {
            Some(log) => logs.push(log),
            None => off = true,
        }
    }
    if let Some(first) = directives.first().filter(|_| off && !logs.is_empty()) {
        return Err(invalid(
            first,
            "\"access_log off\" cannot be combined with other access_log directives",
        ));
    }
    Ok(logs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_helpers::connection_limit::{PLAIN_BASE, parse_plain};
    use crate::config::test_helpers::{BASE, first_site, message, parse, with_decision, with_site};

    #[test]
    fn error_log_takes_a_destination_and_a_level() -> Result<(), ConfigError> {
        let config = parse(&format!("error_log /var/log/vh/error.log warn;\n{BASE}"))?;
        assert_eq!(
            config.error_log.destination,
            Destination::File("/var/log/vh/error.log".into())
        );
        assert_eq!(config.error_log.level, LogLevel::Warn);
        assert!(
            message(parse(&format!("error_log syslog:server=h:514;\n{BASE}")))
                .contains("cannot write to syslog")
        );
        assert!(
            message(parse(&format!("error_log stderr loud;\n{BASE}"))).contains("level must be")
        );
        Ok(())
    }

    #[test]
    fn access_log_default_is_stdout_json() -> Result<(), ConfigError> {
        let config = parse(BASE)?;
        assert_eq!(
            config.access_logs.first().map(|l| l.destination.clone()),
            Some(Destination::Stdout)
        );
        assert_eq!(
            config.access_logs.first().map(|l| l.format.name.clone()),
            Some("json".to_owned())
        );
        Ok(())
    }

    #[test]
    fn access_log_accepts_stdout_and_stderr_as_destinations() -> Result<(), ConfigError> {
        let out = parse(&format!("access_log stdout;\n{BASE}"))?;
        assert_eq!(
            out.access_logs.first().map(|l| l.destination.clone()),
            Some(Destination::Stdout)
        );
        let err = parse(&format!("access_log stderr;\n{BASE}"))?;
        assert_eq!(
            err.access_logs.first().map(|l| l.destination.clone()),
            Some(Destination::Stderr)
        );
        Ok(())
    }

    #[test]
    fn top_level_access_log_off_leaves_no_default_writer() -> Result<(), ConfigError> {
        let config = parse(&format!("access_log off;\n{BASE}"))?;
        assert_eq!(config.access_logs.len(), 0);
        Ok(())
    }

    #[test]
    fn a_site_access_log_replaces_the_inherited_ones() -> Result<(), ConfigError> {
        let config = parse(&format!(
            "access_log /var/log/vh/all.log;\n{}",
            with_site("    access_log /var/log/vh/site.log main;\n")
        ))?;
        assert_eq!(config.access_logs.len(), 1);
        let site = first_site(&config)?;
        let own = site.access_logs.as_deref().unwrap_or_default();
        assert_eq!(own.len(), 1);
        assert_eq!(
            own.first().map(|l| l.destination.clone()),
            Some(Destination::File("/var/log/vh/site.log".into()))
        );
        Ok(())
    }

    #[test]
    fn site_access_log_off_disables_inherited_logs() -> Result<(), ConfigError> {
        let config = parse(&with_site("    access_log off;\n"))?;
        assert_eq!(first_site(&config)?.access_logs, Some(Vec::new()));
        Ok(())
    }

    #[test]
    fn access_log_off_cannot_be_combined_with_a_destination() {
        let text = with_site("    access_log off;\n    access_log stdout;\n");
        assert!(message(parse(&text)).contains("cannot be combined"));
    }

    #[test]
    fn syslog_destinations_need_a_server_and_accept_a_tag() -> Result<(), ConfigError> {
        let config = parse(&format!(
            "access_log syslog:server=192.0.2.10:514,tag=router;\n{BASE}"
        ))?;
        assert_eq!(
            config.access_logs.first().map(|l| l.destination.clone()),
            Some(Destination::Syslog {
                server: "192.0.2.10:514".to_owned(),
                tag: "router".to_owned()
            })
        );
        assert!(
            message(parse(&format!("access_log syslog:tag=x;\n{BASE}")))
                .contains("syslog needs server")
        );
        assert!(
            message(parse(&format!("access_log syslog:server=nohost;\n{BASE}")))
                .contains("needs a port")
        );
        Ok(())
    }

    #[test]
    fn named_log_formats_are_used_by_access_log_and_may_come_later() -> Result<(), ConfigError> {
        let config = parse(&format!(
            "access_log stdout short;\nlog_format short \"$client_ip $status\";\n{BASE}"
        ))?;
        assert_eq!(
            config.access_logs.first().map(|l| l.format.name.clone()),
            Some("short".to_owned())
        );
        Ok(())
    }

    #[test]
    fn an_unknown_log_format_name_is_rejected() {
        let text = format!("access_log stdout nosuch;\n{BASE}");
        assert!(message(parse(&text)).contains("unknown log format \"nosuch\""));
    }

    #[test]
    fn log_format_checks_its_variables_and_headers() {
        assert!(
            message(parse(&format!("log_format bad \"$nosuch\";\n{BASE}")))
                .contains("unknown variable $nosuch")
        );
        assert!(
            message(parse(&format!("log_format bad \"$http_cookie\";\n{BASE}")))
                .contains("never logged")
        );
        let redact = format!(
            "log_format bad \"$http_x_session\";\n{}",
            with_decision("    backend http;\n    redact_header X-Session;\n")
        );
        assert!(message(parse(&redact)).contains("never logged"));
    }

    #[test]
    fn log_format_names_must_be_unique_and_not_built_in() {
        assert!(
            message(parse(&format!("log_format json \"$client_ip\";\n{BASE}")))
                .contains("built-in")
        );
        let duplicate = format!("log_format x \"$client_ip\";\nlog_format x \"$site\";\n{BASE}");
        assert!(message(parse(&duplicate)).contains("duplicate log_format"));
    }

    #[test]
    fn log_format_escape_option_is_checked() -> Result<(), ConfigError> {
        parse(&format!("log_format j escape=json \"$client_ip\";\n{BASE}"))?;
        assert!(
            message(parse(&format!(
                "log_format j escape=none \"$client_ip\";\n{BASE}"
            )))
            .contains("escape must be default or json")
        );
        Ok(())
    }

    #[test]
    fn log_format_concatenates_several_strings() -> Result<(), ConfigError> {
        parse(&format!(
            "log_format split escape=json '{{\"ip\":\"$client_ip\",' '\"site\":\"$site\"}}';\n{BASE}"
        ))?;
        parse(&format!("log_format plain '$client_ip ' '$site';\n{BASE}"))?;
        Ok(())
    }

    #[test]
    fn log_format_without_a_string_is_an_error() {
        assert!(
            message(parse(&format!("log_format empty escape=json;\n{BASE}")))
                .contains("one or more quoted format strings")
        );
    }

    #[test]
    fn a_syslog_tag_must_not_be_empty() {
        let text = message(parse_plain(&format!(
            "access_log syslog:server=192.0.2.10:514,tag=;\n{PLAIN_BASE}"
        )));
        assert!(text.contains("invalid syslog option \"tag=\""), "{text}");
    }

    #[test]
    fn error_log_can_write_to_stdout_or_stderr_by_name() -> Result<(), ConfigError> {
        let out = parse_plain(&format!("error_log stdout;\n{PLAIN_BASE}"))?;
        assert_eq!(out.error_log.destination, Destination::Stdout);
        let err = parse_plain(&format!("error_log stderr;\n{PLAIN_BASE}"))?;
        assert_eq!(err.error_log.destination, Destination::Stderr);
        Ok(())
    }
}
