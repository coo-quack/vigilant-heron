# Logging

The router writes one access line per request, and operational messages to the
error log. Access lines go to the destinations named by `access_log`. Each
destination has its own bounded queue, so a slow disk or syslog server never
delays a request. When a queue is full, the new line is dropped and counted, and
the drop count is reported in the error log.

## Access log

```nginx
access_log stdout json;                          # the default when none is given
access_log /var/log/vigilant-heron/access.log main;
access_log syslog:server=192.0.2.10:514,tag=vigilant-heron main;
access_log off;                                  # disables access logs; alone only
```

- The destinations are `stdout`, `stderr`, a file, or `syslog:server=HOST:PORT[,tag=TAG]`.
  Syslog uses UDP and RFC 3164, the `local7` facility, and the `info` severity.
- The format is `json` (the default), `main`, or a name defined with `log_format`.
- `access_log` may repeat. A `site` with its own `access_log` lines replaces the
  top-level ones.
- Files are reopened on `SIGUSR1`, so logrotate can move them away.

### The built-in formats

`json` writes one JSON object per line, with every value as a string. It has
these keys in this order: `time`, `request_id`, `client_ip`, `site`, `host`,
`method`, `path`, `status`, `action`, `reason`, `rule_id`, `would_have`, `attack`,
`ai_instruction`, `category`, `decision_error`, `retry_after`, `input_tokens` and
`latency_ms`.

`main` writes a text line that starts with the time, the client address, the site
and the request line, followed by `status`, `action`, `reason`, `would_have`,
the scores, `category`, `decision_error`, `retry_after`, `input_tokens`,
`latency_ms` and `request_id`, as `name=value` pairs. `category`, `retry_after` and
`request_id` are quoted, so a value with spaces or `=` cannot add a field. A missing
value is `-` in `main` and an empty string in `json`.

## Log formats

A named format is defined at the top level:

```nginx
log_format main-ip escape=default "$time_iso8601 $client_ip $site \"$method $path\" $status $action $reason";
```

The syntax is `log_format <name> [escape=default|json] "<template>";`.

- `escape default` (the default) escapes quotes, backslashes, and every byte
  outside `0x20` to `0x7e`. A value therefore cannot split a line.
- `escape json` writes JSON string escapes. Every control character (C0, DEL and
  the C1 range `0x80` to `0x9f`) and U+2028 and U+2029 are written as `\uXXXX`.
  Printable non-ASCII text, such as Japanese, is kept as it is.
- A missing value is `-` with `escape default`, and an empty string with
  `escape json`.

## Variables

Each variable is a value of the request or of its decision. A variable may be
written as `$name` or `${name}`.

| Variable | Value |
|---|---|
| `$time_iso8601` | Time of the request, ISO 8601 with offset |
| `$time_local` | Time of the request, in the `dd/Mon/yyyy:hh:mm:ss +0000` form. The router uses UTC, since it has no timezone database |
| `$msec` | Unix time of the request, with milliseconds |
| `$request_id` | Value of the `request_id_header`, or empty |
| `$rule_id` | Id of the rule that decided the request, or empty |
| `$client_ip` | Client address after realip selection |
| `$remote_addr` | TCP peer address |
| `$site` | First host of the matched site, or empty when no site matched |
| `$host` | Normalized host of the request |
| `$method` | Request method |
| `$path` | Request path |
| `$status` | Status sent to the client |
| `$action` | `allow`, `block`, `redirect` or `reject`, the last for a request refused by a limit |
| `$reason` | Why the decision was made, see below |
| `$would_have` | In shadow mode, the action that would have been taken |
| `$attack` | Attack score from the backend |
| `$ai_instruction` | AI-instruction score from the backend |
| `$category` | Category from the backend, when it gives one |
| `$decision_error` | Cause of a failed decision, see below |
| `$retry_after` | `Retry-After` value of the backend's rate-limit answer, when it sent one |
| `$input_tokens` | Input tokens sent to the backend, for backends that count them |
| `$upstream_status` | Status the upstream answered with, or `-` |
| `$upstream_error` | Why the upstream gave no response: `connect_timeout`, `connect_failed`, `read_timeout`, `send_timeout` or `upstream_failed` |
| `$latency_ms` | Time the router took for the request, in milliseconds |
| `$limit_req_status` | Outcome of `limit_req`, see [Limits](/limits#what-happens-to-a-limited-request) |
| `$limit_conn_status` | Outcome of `limit_conn`, see [Limits](/limits#what-happens-to-a-limited-request) |
| `$http_<name>` | A request header, with `_` for `-` |

The `$reason` values are `model`, `below_threshold`, `rule`, `skip`, `skip_rule`,
`access_denied`, `fail_closed_path`, `rate_limited_allowed`,
`rate_limited_blocked`, `decision_error_allowed`, `decision_error_blocked`, and the
limit and timer reasons such as `limit_req`, `limit_conn`, `header_timeout`,
`body_timeout`, `body_too_large`, `unreadable_body` and `uri_too_long`.

The `$decision_error` values are `rate_limited`, `backend_busy`, `timeout`,
`http_status` and `parse`.

`$http_<name>` cannot name a credential. `cookie`, `authorization`,
`proxy-authorization`, `x-api-key`, `x-auth-token` and every name in
`redact_header` are refused when the configuration loads, so a log line never
contains them.

## Error log

```nginx
error_log /var/log/vigilant-heron/error.log warn;
```

The destination is `stderr`, `stdout` or a file, and the level is `error`, `warn`,
`info` (the default) or `debug`. Syslog is not available for the error log. The
error log is reopened on `SIGUSR1` and on `SIGHUP`. A limit event carries
`limit_error=zone_exhausted` when a zone had no free state.
