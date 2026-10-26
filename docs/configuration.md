# Configuration

The configuration uses nginx syntax. A directive is a name, its arguments and a
semicolon. A block holds more directives. `#` starts a comment that runs to the
end of the line, and arguments that contain spaces are quoted with `"` or `'`.

```nginx
listen 0.0.0.0:8080;            # a simple directive ends with a semicolon

decision {                      # a block holds more directives
    backend jev;
}

site example.com {
    upstream http://app:8080;
}
```

Every error names the file and line, for example
`vigilant-heron.conf:12: "block_threshold" must be between 0 and 1`. The
complete commented sample is
[`examples/vigilant-heron.conf`](https://github.com/coo-quack/vigilant-heron/blob/develop/examples/vigilant-heron.conf).

Each section below lists a directive with its syntax, its default, the contexts
where it is allowed and what it does. A context is the top level, the
`decision` block, a `site` block or a `location` block. A `location` inherits
from its `site`, and a `site` inherits from the top level, unless a level sets
the directive itself.

## Units

- **Times** take `ms`, `s`, `m` or `h`. A bare number is seconds, as in nginx.
  `0` is accepted only where a zero time is documented.
- **Sizes** take `k`, `m` or `g`. A bare number is bytes.
- **Booleans** are `on` and `off`.

## Top level

These directives are written outside any block.

### `listen`

- **Syntax:** `listen <address>;`
- **Default:** none, required.
- **Context:** top level.

Socket address that the router binds, such as `0.0.0.0:8080`.

### `pid`

- **Syntax:** `pid <path>;`
- **Default:** `/run/vigilant-heron.pid`.
- **Context:** top level.

File where the router writes its process id once it is listening, and removes
when it exits. `vigilant-heron -s reload|reopen|stop|quit` reads the id from this
file. The write replaces any file already there, through a temporary file in the
same directory. If the file cannot be written, the router logs a warning and keeps
running, and `-s` then reports the missing file. Read at startup only: a reload
does not move the file. The `-s` command reads the same path from the file it is
given, so change it in the file before restarting. Put the pid file in a directory that only the router's user can write: the commands refuse a pid file that another user owns inside a shared directory such as `/tmp`.

The default directory must be writable by the user that runs the router. The
Docker image runs as `nonroot`, which cannot write to `/run`, so set a path in
`/tmp` in the configuration mounted into the image:

```nginx
pid /tmp/vigilant-heron.pid;
```

### `worker_threads`

- **Syntax:** `worker_threads <number>;`
- **Default:** one per CPU core.
- **Context:** top level.

Runtime worker threads that run the proxy. At least 1 when set. Read at startup only.

### `worker_shutdown_timeout`

- **Syntax:** `worker_shutdown_timeout <time>;`
- **Default:** none (wait until every connection has closed).
- **Context:** top level.

On `SIGINT`, `SIGTERM` (`-s stop`) or `SIGQUIT` (`-s quit`) the router stops accepting connections and waits for
requests in flight, open WebSocket tunnels and lingering closes to finish. When
this time is set and expires, every remaining connection and tunnel is closed and
the process exits, as nginx's directive of the same name does. Without it a
WebSocket client that never disconnects keeps the router from exiting, so set it
when `proxy_websocket` is on. Read at startup only.

### `max_connections`

- **Syntax:** `max_connections <number>;`
- **Default:** `1024`.
- **Context:** top level.

Most client connections served at the same time. At least 1. Read at startup only.

### `default_status`

- **Syntax:** `default_status <code>;`
- **Default:** `421`.
- **Context:** top level.

Status for a request whose `Host` matches no site. Must be a 4xx or 5xx code.

### `request_id_header`

- **Syntax:** `request_id_header <name>;`
- **Default:** none.
- **Context:** top level.

Request header whose value is logged as `$request_id`. The value is not sent to the decision backend.

### `real_ip_from`

- **Syntax:** `real_ip_from <address|CIDR> ...;`
- **Default:** none. Without a trusted peer, the client is the TCP peer.
- **Context:** top level.

Peers whose real-IP header is believed. Repeatable.

### `real_ip_header`

- **Syntax:** `real_ip_header <name>;`
- **Default:** `X-Real-IP`.
- **Context:** top level.

Header that holds the client address when the peer is in `real_ip_from`. When the
header comes in several lines, all of them are read in the order received and
joined with commas, as nginx does. A proxy that appends its own line is therefore
seen last. If any line is not valid text, the header is ignored and the peer is
the client.

### `real_ip_recursive`

- **Syntax:** `real_ip_recursive on | off;`
- **Default:** `off`.
- **Context:** top level.

With `on`, the header is read from the right, skipping trusted hops, as nginx does.

### `decision`

- **Syntax:** `decision { ... }`
- **Default:** none, required.
- **Context:** top level, once.

The decision backend. Its directives are listed in [Decision block](#decision-block).

### `client_header_timeout`

- **Syntax:** `client_header_timeout <time>;`
- **Default:** `60s`.
- **Context:** top level.

Time to receive a whole request header, counted from its first byte.

### `keepalive_timeout`

- **Syntax:** `keepalive_timeout <time>;`
- **Default:** `75s`.
- **Context:** top level.

Idle time between two requests on one connection. `0` disables keep-alive.

### `keepalive_requests`

- **Syntax:** `keepalive_requests <number>;`
- **Default:** `1000`.
- **Context:** top level.

Requests served on one connection. The last one is answered with `Connection: close`.

### `send_timeout`

- **Syntax:** `send_timeout <time>;`
- **Default:** `60s`.
- **Context:** top level.

Longest wait between two writes to the client.

### `large_client_header_buffers`

- **Syntax:** `large_client_header_buffers <count> <size>;`
- **Default:** `4 8k`.
- **Context:** top level.

The request line may be up to `size` long (414 otherwise), each header field up to `size` (400), and the header section up to `count` times `size`.

### `lingering_close`

- **Syntax:** `lingering_close on | always | off;`
- **Default:** `on`.
- **Context:** top level.

When a connection lingers after a response. `on` lingers only when request data was left unread, `always` after every response to a request, and `off` never.

### `lingering_time`

- **Syntax:** `lingering_time <time>;`
- **Default:** `30s`.
- **Context:** top level.

Longest total time of one lingering close.

### `lingering_timeout`

- **Syntax:** `lingering_timeout <time>;`
- **Default:** `5s`.
- **Context:** top level.

Longest silence, with no data from the client, that one lingering close waits for.

### `client_body_timeout`

- **Syntax:** `client_body_timeout <time>;`
- **Default:** `60s`.
- **Context:** top level, site.

Time between two successive reads of the request body from the client. Expiry gives 408.

### `client_max_body_size`

- **Syntax:** `client_max_body_size <size>;`
- **Default:** `1m`.
- **Context:** top level, site.

Largest request body. `0` removes the limit. A larger body gets 413, before it is read when `Content-Length` shows the size.

### `proxy_connect_timeout`

- **Syntax:** `proxy_connect_timeout <time>;`
- **Default:** `60s`.
- **Context:** top level, site.

Time to connect to the upstream. Expiry gives 504.

### `proxy_read_timeout`

- **Syntax:** `proxy_read_timeout <time>;`
- **Default:** `60s`.
- **Context:** top level, site.

Wait for the response head, and between two successive reads of the response. Expiry gives 504 before the head, and closes the connection after it.

### `proxy_send_timeout`

- **Syntax:** `proxy_send_timeout <time>;`
- **Default:** `60s`.
- **Context:** top level, site.

Longest wait between two writes to the upstream. Expiry gives 504 before the response head.

### `max_body`

- **Syntax:** none. Removed.
- **Context:** top level, `decision`.

The parser rejects `max_body` and names its replacement, `client_max_body_size`, which is set at the top level. The decision default was 10m as `max_body`, so uploads of 1 to 10 MB need `client_max_body_size 10m;`.

### `allow` and `deny`

- **Syntax:** `allow <address|CIDR|all>;` and `deny <address|CIDR|all>;`
- **Default:** none. Every client is allowed.
- **Context:** top level, site.

Access list by client address. The entries are checked in order, and the first entry that covers the client decides. A denied client gets 403 before the body is read. On a site in [shadow mode](/how-it-works#shadow-mode), a denied client is forwarded and the denial is recorded as `would_have=block`, as for every other check. A site that has any `allow` or `deny` line replaces the top-level list. See [Rules](/rules#access-list).

### `proxy_set_header`

- **Syntax:** `proxy_set_header <name> <value>;`
- **Default:** none. The defaults are `Host` kept and `X-Forwarded-For` appended.
- **Context:** top level, site, location.

Sets a header sent to the upstream. An empty value removes the header. A level with any `proxy_set_header` replaces the list it inherits. Variables are listed in [Logging](/logging#variables).

### `block_status`

- **Syntax:** `block_status <code>;`
- **Default:** `403`.
- **Context:** top level, site, location.

Status for a blocked request: any 4xx or 5xx code, or `444`, which closes the connection without a response. An access-list denial stays 403.

### `block_page`

- **Syntax:** `block_page <file>;`
- **Default:** none. The body is `Forbidden`.
- **Context:** top level, site, location.

HTML served for blocked requests, with `Content-Type: text/html; charset=utf-8`. The file is read when the configuration loads and must be at most 64 KiB. A relative path is relative to the file that holds the directive.

### `builtin_rules`

- **Syntax:** `builtin_rules on | off;`
- **Default:** `on`.
- **Context:** top level, site.

Turns the built-in rules on or off. A site setting replaces the top-level one. See [Built-in rules](/builtin-rules).

### `disable_rule`

- **Syntax:** `disable_rule <id> ...;`
- **Default:** none.
- **Context:** top level, site.

Turns off built-in rules by id. Repeatable. The top-level list is extended by a site's own list. An unknown id is a configuration error.

A site's `disable_rule` turns off a rule that the top level enabled with `enable_rule`. The order between the two is described under `enable_rule`.

### `enable_rule`

- **Syntax:** `enable_rule <id> ...;`
- **Default:** none.
- **Context:** top level, site.

Turns on built-in rules by id that are off by default (a rule with `default off;` in `builtin.conf`). Repeatable. An unknown id is a configuration error. Enabling a rule that is on by default is allowed and does nothing. The shipped rules that are off are the [opt-in CVE rules](/builtin-rules#opt-in-rules).

For each rule id, the nearest level that names the id decides, in this order:

1. the site's `disable_rule`, then the site's `enable_rule`;
2. the top-level `disable_rule`, then the top-level `enable_rule`.

Inside one level, `disable_rule` wins over `enable_rule`. A rule that no list names runs when `builtin_rules` is on at the site and the rule is on by default. So a rule that the site enables runs even when `builtin_rules off;` applies to the site, and a site's `enable_rule` overrides a top-level `disable_rule` for the same id.

```nginx
enable_rule vh-cve-2026-9103;   # top level: every site runs it

site langflow.example.com {
    upstream http://langflow:7860;
    enable_rule vh-cve-2026-8481;   # this site only, in addition to the top level
}
```

### `rule`

- **Syntax:** `rule <id> { ... }`
- **Default:** none.
- **Context:** top level, site.

A block rule or skip rule. Its conditions and its `site` directive are described in [Rules](/rules).

### `site`

- **Syntax:** `site <host> ... { ... }`
- **Default:** none. At least one site is required.
- **Context:** top level.

A virtual host. It is chosen by the request's `Host`. Its directives are listed in [Site block](#site-block). Host forms are described in [Rules](/rules).

### `error_log`

- **Syntax:** `error_log <stderr|stdout|file> [error|warn|info|debug];`
- **Default:** `stderr info`.
- **Context:** top level.

Destination and level of operational messages. A `SIGHUP` reload applies a new destination and level; if the new destination cannot be opened, the reload fails and the old configuration, error log included, stays. `SIGUSR1` reopens the file. Syslog is not available for the error log.

### `access_log`

- **Syntax:** `access_log <destination> [format];` or `access_log off;`
- **Default:** `access_log stdout json;` when none is given.
- **Context:** top level, site. Repeatable.

Access log destination: `stdout`, `stderr`, a file, or `syslog:server=HOST:PORT[,tag=TAG]` (UDP, RFC 3164). The format is `json`, `main`, or a name from `log_format`. `access_log off;` disables logging and cannot be combined with other `access_log` lines. See [Logging](/logging).

### `log_format`

- **Syntax:** `log_format <name> [escape=default|json] "<template>";`
- **Default:** none. The built-in formats are `json` and `main`.
- **Context:** top level.

Defines a named log format from [variables](/logging#variables). `escape=default` is the default.

### `include`

- **Syntax:** `include <path-or-glob>;`
- **Default:** none.
- **Context:** top level.

Reads other files in place. A relative path is relative to the directory of the file that holds the `include`. A glob may match nothing. Includes may nest up to eight levels, and a cycle is an error.

### `limit_req_zone`

- **Syntax:** `limit_req_zone <key> zone=<name>:<size> rate=<N>r/s|r/m;`
- **Default:** none.
- **Context:** top level only.

A leaky bucket per key. `rate` is the drain rate. The key is built from variables known before the body is read: `$client_ip`, `$remote_addr`, `$site`, `$host`, `$method`, `$path` and `$http_<name>`. Credential headers are refused. A zone of `<size>` holds `size / 128` states.

### `limit_conn_zone`

- **Syntax:** `limit_conn_zone <key> zone=<name>:<size>;`
- **Default:** none.
- **Context:** top level only.

Counts requests in progress per key. A zone of `<size>` holds `size / 64` states. Key rules are the same as for `limit_req_zone`. See [Limits](/limits).

### `limit_req`

- **Syntax:** `limit_req zone=<name> [burst=<n>] [nodelay | delay=<n>];`
- **Default:** none. Limits are not applied.
- **Context:** top level, site, location. Repeatable.

Applies a request-rate zone. See [Limits](/limits#directives).

### `limit_conn`

- **Syntax:** `limit_conn <zone> <number>;`
- **Default:** none.
- **Context:** top level, site, location. Repeatable.

Allows at most `number` requests in progress per key. See [Limits](/limits#directives).

### `limit_req_status`

- **Syntax:** `limit_req_status <code>;`
- **Default:** `503`.
- **Context:** top level, site, location.

Status of a request refused by `limit_req`. A 4xx or 5xx code.

### `limit_conn_status`

- **Syntax:** `limit_conn_status <code>;`
- **Default:** `503`.
- **Context:** top level, site, location.

Status of a request refused by `limit_conn`. A 4xx or 5xx code.

### `limit_req_dry_run`

- **Syntax:** `limit_req_dry_run on | off;`
- **Default:** `off`.
- **Context:** top level, site, location.

With `on`, `limit_req` only counts. Nothing is rejected or delayed.

### `limit_conn_dry_run`

- **Syntax:** `limit_conn_dry_run on | off;`
- **Default:** `off`.
- **Context:** top level, site, location.

With `on`, `limit_conn` only counts. Nothing is rejected.

### `limit_req_log_level`

- **Syntax:** `limit_req_log_level info | notice | warn | error;`
- **Default:** `error`.
- **Context:** top level, site, location.

Severity of a `limit_req` event in the error log. The router's error log has no notice level, so `notice` is written at info.

### `limit_conn_log_level`

- **Syntax:** `limit_conn_log_level info | notice | warn | error;`
- **Default:** `error`.
- **Context:** top level, site, location.

Severity of a `limit_conn` event in the error log. `notice` is written at info.

## Decision block

The `decision` block selects and configures the backend. It is required.

### `backend`

- **Syntax:** `backend jev | clef | strands | http;`
- **Default:** `jev`.
- **Context:** decision.

The protocol. `jev` calls TypeSafe Jev, `clef` calls Cloudflare Clef on Workers AI, `strands` calls a self-hosted Strands Decider server (see [Decision backends](/decision-backends#strands-decider-self-hosted)), and `http` posts the JSON protocol described in [Decision backends](/decision-backends#http-protocol).

### `url`

- **Syntax:** `url <http or https URI>;`
- **Default:** `https://api.typesafe.ai/v1/systemone` with `jev`. Required with `clef`, `strands` and `http`.
- **Context:** decision.

Absolute URI of the backend.

### `model`

- **Syntax:** `model <name>;`
- **Default:** `jev-latest` with `jev`, `strands-decider` with `strands`. Required with `clef`.
- **Context:** decision.

With `clef`, `clef-flash` or `clef`. With `jev` and `strands`, a model identifier of 1 to 100 characters from `A-Za-z0-9._-`. Not valid with `http`.

### `api_token_env`

- **Syntax:** `api_token_env <variable name>;`
- **Default:** `TYPESAFE_API_KEY` with `jev`. Required with `clef`. Optional with `strands`: when omitted, no `Authorization` header is sent.
- **Context:** decision.

Name of the environment variable that holds the bearer token. The token itself is never written in the file. The process fails to start when the variable is unset or blank. Not valid with `http`.

### `timeout`

- **Syntax:** `timeout <time>;`
- **Default:** `300ms`.
- **Context:** decision.

Time allowed for one decision, including any wait for a slot. Must be greater than 0.

### `queue_timeout`

- **Syntax:** `queue_timeout <time>;`
- **Default:** `0`, no queueing.
- **Context:** decision.

Longest wait for a free concurrency slot. A request that finds no slot in that time is `backend_busy`. Must not exceed `timeout`.

### `max_concurrency`

- **Syntax:** `max_concurrency <number>;`
- **Default:** `64`.
- **Context:** decision.

Most backend calls in flight at the same time. At least 1.

### `max_concurrency_per_client`

- **Syntax:** `max_concurrency_per_client <number>;`
- **Default:** `8`, or `max_concurrency` when that is smaller.
- **Context:** decision.

Most backend calls in flight for one client address, keyed by the client address that the realip settings choose. A request from a client that already holds its share is not queued. It is refused for that client alone (`decision_error=client_busy`), and the site's `on_client_busy` decides what happens to it: by default it gets 429, so other clients keep getting the model. It must be at least 1 and at most `max_concurrency`. This limits a denial-of-service (DoS) attack from one address, but not one from many addresses.

Behind a shared address, such as an office or school NAT, or a proxy whose real client address is not set up with `real_ip_from`, many legitimate users look like one client. If they hit the 429, raise this value, or set `on_client_busy allow` so that the excess skips the model (rules still apply). See [How it works](/how-it-works#failure-behavior).

### `inspect_body`

- **Syntax:** `inspect_body <size>;`
- **Default:** `8k`.
- **Context:** decision.

Bytes of the request body sent to the backend. The rest of the body is streamed to the upstream after the decision and is not buffered.

### `max_body`

- **Syntax:** none. Removed.
- **Context:** decision.

Rejected with an error that names `client_max_body_size`, which is set at the top level. See [Top level](#max-body).

### `redact_header`

- **Syntax:** `redact_header <name> ...;`
- **Default:** none. `cookie`, `authorization`, `proxy-authorization`, `x-api-key` and `x-auth-token` are always removed. So is any header with a credential-like name (such as `x-csrf-token`, `x-hub-signature-256` or `x-functions-key`). See [How it works](/how-it-works) for the full rule.
- **Context:** decision.

Extra header names removed before the event is sent to the backend. Repeatable. Each name is compared case-insensitively with the whole header name. Use this for a header the default rules keep but that your site treats as secret. They cannot be logged either.

### `redact_field`

- **Syntax:** `redact_field <name> ...;`
- **Default:** none. Field names with password-, token-, signature-, card-number-like or other sensitive parts and words are redacted already (see [How it works](/how-it-works)).
- **Context:** decision.

Extra field names whose values are replaced by `[REDACTED]` before the event is sent to the backend. This applies to form, JSON, multipart and XML bodies, and to the query string. A name matches a whole field name, compared case-insensitively: `ticket_ref` redacts `Ticket_Ref` but not `my_ticket_ref`. For a multipart part, the name is the `name` in its `Content-Disposition`. For an XML element, it is the local name without the prefix, so `ticket_ref` also redacts `<ns:ticket_ref>`. Repeatable.

## Site block

A `site` names the hosts it serves after the keyword. It is required to have at
least one host and one `upstream`.

Host names can be exact (`example.com`), a leading wildcard (`*.example.com`), a
trailing wildcard (`example.*`), `.example.com` (the name and its subdomains) or a
regular expression, quoted, such as `"~^(www\.)?example\.(com|jp)$"`. A name may
belong to one site only.

### `upstream`

- **Syntax:** `upstream <http URI>;`
- **Default:** none, required.
- **Context:** site.

Absolute `http://` URI that receives the allowed requests.

### `mode`

- **Syntax:** `mode enforce | shadow;`
- **Default:** `enforce`.
- **Context:** site.

`enforce` applies the verdict. `shadow` forwards every request and records what would have happened. See [How it works](/how-it-works#shadow-mode).

### `action`

- **Syntax:** `action block;` or `action redirect <url>;`
- **Default:** `block`.
- **Context:** site.

What a blocked request gets: the `block_status` response, or a 302 to the given location.

### `block_threshold`

- **Syntax:** `block_threshold <number>;`
- **Default:** `0.87`.
- **Context:** site.

Attack score, from 0 to 1, at or above which a request is blocked.

### `instruction_threshold`

- **Syntax:** `instruction_threshold <number>;`
- **Default:** `0.8`.
- **Context:** site.

AI-instruction score, from 0 to 1, at or above which a request is blocked.

### `on_client_busy`

- **Syntax:** `on_client_busy allow | block;`
- **Default:** `block`.
- **Context:** site.

What happens when a client already holds its `max_concurrency_per_client` share of backend calls (`decision_error=client_busy`). The default `block` answers 429 with an empty body and does not call the backend. `allow` forwards the request without the model, and rules still apply. The setting is separate from `on_rate_limit`, so changing that does not change this. Earlier versions let such a request through, because it followed `on_rate_limit`, which defaults to `allow`. See [the changelog](/changelog).

### `on_rate_limit`

- **Syntax:** `on_rate_limit allow | block;`
- **Default:** `allow`.
- **Context:** site.

What happens when the backend answers HTTP 429, or when no slot is free within `queue_timeout` (`backend_busy`). A client over its `max_concurrency_per_client` share is governed by `on_client_busy` instead. Rules are not affected. A denial-of-service (DoS) attack against the backend can use this to make requests skip the model, so a site that prefers safety over availability should set `block`, and limit each client with `limit_req` and `limit_conn`. See [How it works](/how-it-works#failure-behavior).

### `on_decision_error`

- **Syntax:** `on_decision_error allow | block;`
- **Default:** `allow`.
- **Context:** site.

What happens when the backend fails in any other way: a timeout, a connection error, a non-2xx status or an unusable answer. The default allows; a site that prefers blocking while the backend is down sets `block`.

### `deny_path`

- **Syntax:** `deny_path <prefix> ...;`
- **Default:** none.
- **Context:** site.

Path prefixes that are always blocked without calling the backend. A prefix matches when it starts any [reading of the path](/how-it-works#path-readings), lowercased, so `/wp-config.php` also covers `/wp-config.php.bak`, and `/manager` also covers `/;/manager/html` and `/x/..;/manager/html`. Repeatable.

### `fail_closed_path`

- **Syntax:** `fail_closed_path <prefix> ...;`
- **Default:** none.
- **Context:** site.

Path prefixes that are blocked whenever the decision fails, whatever `on_rate_limit` and `on_decision_error` say. They match the path readings in the same way as `deny_path`, and a matching path is never a static skip.

### `static_extensions`

- **Syntax:** `static_extensions <extension> ...;`
- **Default:** `css js png jpg jpeg gif svg webp ico woff woff2 ttf map`.
- **Context:** site.

File extensions of plain GET or HEAD requests with no query and no body that skip the backend. When given, the list replaces the defaults. Repeatable. A path is skipped only when every [path reading](/how-it-works#path-readings) ends in one of these extensions with no earlier script extension (`php`, `phtml`, `jsp`, `jspx`, `asp`, `aspx`, `cgi`, `pl`, `py`, `rb`), so `/index.php/x.css` and `/x;.css` are inspected.

### `static_location`

- **Syntax:** `static_location <prefix> ...;`
- **Default:** none. The static skip applies under any path.
- **Context:** site.

Path prefixes under which the static skip (`static_extensions`) may apply. Every path reading must start with one of them, so `/static/..;/img/a.css` is inspected. Compared lowercased. Repeatable; each prefix must start with `/`. Set it when the static files live in known directories, so that a static extension elsewhere is always inspected.

### `debug_headers`

- **Syntax:** `debug_headers on | off;`
- **Default:** `off`.
- **Context:** site.

With `on`, responses carry `x-vigilant-heron` with `action`, `reason` and `would_have`.

### `proxy_websocket`

- **Syntax:** `proxy_websocket on | off;`
- **Default:** `off`.
- **Context:** site, location.

Tunnels HTTP/1.1 `Upgrade` requests after the handshake has been screened. Frames are not inspected. Only the handshake is judged. The upgrade headers are forwarded only when this is `on`.

### `default_server`

- **Syntax:** `default_server;`
- **Default:** none.
- **Context:** site.

This site takes the requests whose `Host` matches no site. At most one site may have it. It takes no arguments.

### `location`

- **Syntax:** `location [=|~|~*|^~] <path> { ... }`
- **Default:** none.
- **Context:** site.

Limits and block settings for one path. The matching rules are in [Limits](/limits#location-blocks). Inside a location only the limit directives, `block_status`, `block_page`, `proxy_websocket` and `proxy_set_header` are allowed.

### `client_body_timeout`, `client_max_body_size`, `proxy_connect_timeout`, `proxy_read_timeout`, `proxy_send_timeout`

These are the top-level timers described above. A site can override them. Their
syntax and defaults are the same, and see [Timeouts and limits](/timeouts) for the
table of what each one bounds.

### `block_status`, `block_page`, `allow`, `deny`, `builtin_rules`, `disable_rule`, `enable_rule`, `rule`, `access_log`, `proxy_set_header`

These are the same directives as at the top level. A site setting replaces the
inherited one, as described in each entry above. The `access_log` of a site
replaces the top-level ones.

### `limit_req`, `limit_conn`, `limit_req_status`, `limit_conn_status`, `limit_req_dry_run`, `limit_conn_dry_run`, `limit_req_log_level`, `limit_conn_log_level`

Limit directives may be written in a site as well as at the top level. They
inherit as described in [Limits](/limits#inheritance).

### Top-level only directives

The parser rejects the following inside a site, with the message that names the
level. They apply before the `Host` selects a site.

- `client_header_timeout`, `keepalive_timeout`, `keepalive_requests`,
  `send_timeout`, `large_client_header_buffers`, `lingering_close`,
  `lingering_time` and `lingering_timeout`.
- `limit_req_zone` and `limit_conn_zone`. Zones are shared by every site.

## Location block

A `location` may contain only the directives below. Any other directive is an
error at its line.

- `limit_req`, `limit_conn`, `limit_req_status`, `limit_conn_status`,
  `limit_req_dry_run`, `limit_conn_dry_run`, `limit_req_log_level` and
  `limit_conn_log_level`.
- `block_status` and `block_page`.
- `proxy_websocket` and `proxy_set_header`.

## Reload and log reopen

- **`SIGHUP`** reloads the configuration, as `nginx -s reload` does. The whole file
  with its includes is read and validated again. A valid file replaces the
  configuration for every request that starts after the reload. An invalid file
  is logged at error level with its file and line, and the previous configuration
  keeps serving. The `error_log` destination and level follow the new file. Zones keep their counts
  when a zone with the same name and size exists in the new file.
- **`SIGUSR1`** reopens the file destinations of the access logs and the error log,
  so logrotate can move them away without a reload.
- **`SIGTERM`** and **`SIGQUIT`** stop the router gracefully, as `-s stop` and
  `-s quit` send them. Both wait for requests in flight, as described for
  `worker_shutdown_timeout`. This version has no fast shutdown.

The `-s` command sends these signals to the process named in the `pid` file. See
[Command line](/cli).

These settings take effect at startup only. A reload that changes one of them
logs a warning, and the change applies at the next restart: `listen`,
`pid`, `worker_threads`, `worker_shutdown_timeout`, `max_connections`, and the
connection timers and header limits.

## Checking the configuration

`vigilant-heron -t [--config <path>]` reads the file, its includes, rules, block
pages and token variables, validates everything and exits. It never binds the
listen address. `-T` does the same check and then prints the configuration with
every include expanded. The output and exit codes are shown in
[Getting started](/getting-started#check-the-configuration-with-t) and in
[Command line](/cli).

## Migrating from earlier versions

### From `max_body`

The body limit is the top-level `client_max_body_size`, which defaults to 1m. It
was 10m as `decision.max_body`, so uploads between 1 and 10 MB need
`client_max_body_size 10m;`. A `max_body` line is an error that names its
replacement.

### From the TOML configuration

There is no automatic converter. Each `[[sites]]` table becomes a `site` block,
`timeout_ms = 150` becomes `timeout 150ms;`, and `deny_paths = [...]` becomes
`deny_path ...;`. The other keys keep their names unless the tables above say
otherwise.
