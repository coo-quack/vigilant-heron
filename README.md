# vigilant-heron

A reverse-proxy router that checks each web request with a typed decision
model and blocks it, redirects it, or forwards it to the site's upstream.

> Status: early development. Run new sites in `shadow` mode first.

## How it works

```
client ── nginx / Cloudflare ── vigilant-heron ──► upstream (allowed requests)
                                     │
                                     └── decision backend (Clef, Jev, …)
```

For every request, the router:

1. Selects a site by `Host`. Unknown hosts get the configured status (421).
   The access list runs first, on the client address: a denied client gets 403.
2. Applies deterministic rules, in the order given in
   [Access list and rules](#access-list-and-rules): `deny_path` entries and
   block rules (built-in and user) are blocked without calling the backend,
   skip rules and plain GET/HEAD requests for static assets skip it.
3. Sends a sanitized copy of the request to the decision backend: credential
   headers are dropped, password- and token-like fields are redacted, only the
   first `inspect_body` bytes of the body are sent, and all client data sits
   under an `untrusted` field.
4. Applies the site's policy to the returned scores (`attack`,
   `ai_instruction`): block (403), redirect (302), or forward. When the
   backend fails, the failure settings decide (see [Failure behavior](#failure-behavior)).
5. Forwards the request, with the rest of its body streamed as it arrives.
   The upstream gets the whole body; the backend never sees more than
   `inspect_body`.
6. Logs one access line per request.

Every deterministic rule runs in step 2, before the backend is called, and no
failure setting changes its result: a rule block stays a block when the backend
rate-limits, errors, is unreachable or is saturated. New rule types must follow
the same rule. In `shadow` mode every request is forwarded, rules included, and
the log and optional debug header record what would have happened.

## Access list and rules

Two deterministic mechanisms run before the decision backend: an access list by
client address, and rules that match the request. Both are configured with
nginx syntax, and both can be set at the top level and inside a `site`.

### Access list

```
allow <address|CIDR|all>;
deny  <address|CIDR|all>;
```

The entries are checked in order and the first one that covers the client
decides, as in nginx's `ngx_http_access_module`. A client that no entry covers
is allowed. A site with any `allow` or `deny` line replaces the top-level list;
a site without one inherits it. The client address is the one chosen by the
realip settings (`real_ip_from`, `real_ip_header`).

A denied client on an `enforce` site gets 403 with reason `access_denied`. The
request body is not read and the backend is not called. The site's `action` does
not apply, as in nginx. On a `shadow` site the request is forwarded, and the log
and debug header record `would_have=block`, as for every other decision. A
refusal with no site (an unknown host) is always 403.

### Rules

A rule is a block with an id:

```
rule <id> {
    description "<text>";       # required
    action block|skip;          # required
    site <host> ...;            # top-level rules only
    method <METHOD> ...;
    path <value>;               # prefix; or: path = <value>, path ^~ <value>, path ~ <regex>, path ~* <regex>
    query <~|~*> <regex>;
    header <name> <~|~*> <regex>;
    body <~|~*> <regex>;
    any <~|~*> <regex>;         # path, query, every header value, or the body prefix
    client <address|CIDR> ...;
}
```

A rule matches when every condition it lists matches, and it must list at least
one condition. `method`, `path` and `client` may appear once; `query`,
`header`, `body` and `any` may repeat, and each repetition must match. `path`
uses nginx's location modifiers: no modifier is a prefix, `=` is exact, `^~` is
a prefix, `~` is a case-sensitive regex and `~*` is a case-insensitive one.

- A rule at the top level applies to every site, unless it has a `site`
  directive that names the sites it applies to. The host names must be sites of
  the configuration.
- A rule inside a `site` block applies to that site only, and cannot have a
  `site` directive.
- `action block` is decided like `deny_path`: the site's `action` applies, and
  shadow mode forwards the request and records it in `would_have`. `action skip`
  forwards the request without calling the backend, and `reason` is `skip_rule`.
- Rule ids are unique across all files. The error names both places. Ids that
  start with `vh-` are reserved for built-in rules.

Matching uses the normalized request and never changes what is forwarded:

- Path: one percent-decode, dot segments resolved, NUL bytes removed. The case
  is kept, so `path` and `path ~` are case-sensitive, as in nginx.
- Query and form body: `+` becomes a space, the percent-decoding is applied at
  most twice (so a double-encoded escape is undone), and NUL bytes are removed.
- Header values: the same decoding as the query, except that `+` is literal.
- Body: only the first `inspect_body` bytes, decoded as the query. A body
  condition cannot see later bytes, and the multipart structure is not parsed.
- `client`: the realip address.

Regexes use the `regex` crate. Matching takes time linear in the input and never
backtracks, so no pattern can make a request slow in proportion to a bad input
(no look-around or back-references are available). A regex may be 512 bytes at
most, and its compiled form is limited to 1 MiB. The configuration holds at most
1000 rules, built-in ones included. Each limit violation is a configuration
error that names its file and line.

### Built-in rules

The rules in [`src/rules/builtin.conf`](src/rules/builtin.conf) ship with the
binary, parsed with the same parser as user rules. They cover high-confidence
signatures of these classes, with ids `vh-<category>-<nnn>`:

| Category | Ids | What they match |
|---|---|---|
| SQL injection | `vh-sqli-001` to `004` | `UNION SELECT` in a query; a quote, a tautology and a comment terminator; a quote and a stacked `drop` or `shutdown`; time-based functions after a quote |
| XSS | `vh-xss-001` to `003` | a `<script>` tag in a query; a `javascript:` URL in a query; an inline event handler in markup in a query |
| Path traversal | `vh-traversal-001` to `003` | a `../` sequence in a query; `etc/passwd`, `win.ini` and similar in a query; the same files in the path |
| Command injection | `vh-cmdi-001` to `003` | a shell separator, `$(` or a backtick followed by a common command, in a query |
| File inclusion | `vh-lfi-001` to `004` | `php://` wrappers; a base64 data URI in a query; `expect://`; a remote URL in a `file`, `page` or `include` parameter |
| SSRF | `vh-ssrf-001`, `002` | the cloud metadata address `169.254.169.254`; `file`, `gopher`, `dict`, `ldap` or `tftp` URLs in a query |
| Template and expression | `vh-expr-001` to `003` | the JNDI lookup `${jndi:`; the `{{7*7}}` probe; the Spring class loader path |
| XML external entities | `vh-xxe-001` | an entity declared with `SYSTEM` in a body |
| Scanners | `vh-scanner-001` | the user agent of a known scanner (sqlmap, nikto, nuclei, masscan, zgrab and others) |

The built-in rules are kept to patterns that do not occur in ordinary text. A
pattern that could appear in a code paste, a post about SQL or HTML, a base64
blob or Japanese text is left out, and such traffic goes to the decision model
or to a user rule. [SECURITY.md](SECURITY.md) lists what they do not cover.

```
builtin_rules on;           # top level or site; default on. off turns the set off
disable_rule vh-scanner-001 vh-xss-003;   # top level or site; only built-in ids
```

A `site` setting replaces the top-level `builtin_rules`. `disable_rule` adds to
the top-level list for that site. An unknown id is a configuration error.

### Order of evaluation

For each request, in this order:

1. The access list. A denied client gets 403 (`reason access_denied`).
2. `deny_path` entries of the site. A match is a rule block (`reason rule`, no
   `$rule_id`).
3. Block rules: the built-in rules that are on, then the top-level block rules
   in the order of the file, then the site's block rules. The first match blocks.
4. Skip rules: the top-level skip rules, then the site's. The first match
   forwards the request without calling the backend (`reason skip_rule`).
5. The static asset skip (`static_extensions`), which also forwards.
6. The decision model. The thresholds and failure settings apply here only.

Block rules are always checked before skip rules, so a skip rule never lets
through a request that a block rule matches. No failure setting changes steps 1
to 5: a rule decision holds when the backend rate-limits, errors or is slow.

### Logs

`$rule_id` is the id of the rule that decided the request, and it is empty when
no rule did. The built-in `json` format logs it as `rule_id`; a `log_format`
can include `$rule_id` as well. The `reason` values for these decisions are:

- `access_denied`: refused by the access list (`action` is `block` on an
  enforce site, and `allow` with `would_have=block` on a shadow site)
- `rule`: blocked by a block rule (also `deny_path`, which has no `$rule_id`)
- `skip_rule`: forwarded by a skip rule

## Failure behavior

A decision fails when the backend answers HTTP 429, when no concurrency slot is
free within `timeout`, or when it fails in any other way. The two groups have
their own site settings, both `"allow"` by default:

- `on_rate_limit`: the 429 and "no slot in time" group
- `on_decision_error`: timeouts, connection errors, other non-2xx statuses,
  malformed or out-of-range answers. A timeout that happens after a slot was
  obtained is in this group.

Saturation is always in the rate-limit group: a request that gets no
concurrency slot within `decision` `queue_timeout` is `backend_busy`, and that
never falls under `on_decision_error`.

`fail_closed_paths` wins over both: a failure on such a path is always blocked.
A blocked failure uses the site's `action`. The decision log records the
outcome in `reason` (`rate_limited_allowed`, `decision_error_blocked`,
`fail_closed_path`, ...) and the specific cause in `decision_error` (`rate_limited`,
`backend_busy`, `timeout`, `http_status`, `parse`, ...).

## Concurrency

| Setting | Limits | Default |
|---|---|---|
| `max_connections` | client connections open at the same time | 1024 |
| `worker_threads` | runtime threads that run the proxy | one per CPU core |
| `decision` `max_concurrency` | decision-backend calls in flight at the same time | 64 |
| `decision` `queue_timeout` | how long a call may wait for one of those slots; no slot in that time is `backend_busy` | 0 (no queueing) |

Waiting for a slot is bounded by `queue_timeout` only. A call that gets a
slot then has the rest of `timeout`. Saturation is therefore always a rate
limit, and it follows `on_rate_limit`, never `on_decision_error`.

The defaults are: `backend jev` (its URL, model and token variable
are set by default too), `timeout 300ms`, `block_threshold 0.87`,
`instruction_threshold 0.8`, and both failure settings `"allow"`. Configs that
want the JSON protocol must set `backend http;`.

## Timeouts and limits

The directives use nginx's names, units and defaults, and mean what they mean
in nginx unless the table or the notes below say otherwise. `keepalive_timeout 0`
disables keep-alive, and `client_max_body_size 0` removes the body limit.

| Directive | Default | Set in | Bounds | When it expires |
|---|---|---|---|---|
| `client_header_timeout` | 60s | top level | the whole request header, counted from its first byte (from accept, for the first request) | 408 when part of the header arrived, otherwise the connection closes |
| `keepalive_timeout` | 75s | top level | idle time between two requests on a connection | the connection closes |
| `keepalive_requests` | 1000 | top level | requests served on one connection | the last one answers `Connection: close` |
| `send_timeout` | 60s | top level | time between two successive writes to the client | the connection closes |
| `large_client_header_buffers` | 4 8k | top level | request line up to 8k, each header field up to 8k, the header section up to 4 × 8k | 414 for a long request line, 400 for a long field or section |
| `lingering_close` | on | top level | when a connection lingers after its response: `on` only when request data was left unread, `always` after every response to a request, `off` never | the connection closes; see the note on lingering below |
| `lingering_time` | 30s | top level | total time of one lingering close | the connection closes |
| `lingering_timeout` | 5s | top level | silence, with no client data, that one lingering close waits for | the connection closes |
| `client_body_timeout` | 60s | top level, site | time between two successive reads of the request body | 408 |
| `client_max_body_size` | 1m | top level, site | the request body | 413, before the body is read when `Content-Length` says so |
| `proxy_connect_timeout` | 60s | top level, site | connecting to the upstream | 504 |
| `proxy_read_timeout` | 60s | top level, site | the wait for the response head, and between two successive response reads | 504 before the head; after it, the connection closes |
| `proxy_send_timeout` | 60s | top level, site | time between two successive writes to the upstream | 504 before the response head |

An upstream that cannot be reached, or that resets the connection, still gets
502. Expired timers and oversized requests are visible in the access log: the
`$status` is the status sent, `$reason` names the cause (`header_timeout`,
`body_timeout`, `body_too_large`, `unreadable_body`, `uri_too_long`,
`header_too_large`), and
`$upstream_error` names the upstream failure.

Notes on where the limits differ from nginx:

- The connection timers and header limits (`client_header_timeout`,
  `keepalive_timeout`, `keepalive_requests`, `send_timeout`,
  `large_client_header_buffers` and the lingering directives) are top-level
  only. They apply before the `Host` selects a site, and a `site` block that
  sets one is a configuration error.
- The `proxy_read_timeout` clock starts when the request is handed to the
  upstream client, so it includes connecting. `proxy_connect_timeout` bounds
  the connect on its own.
- A zero time is rejected for every timer except `keepalive_timeout`.
- A connection whose `client_header_timeout` expires before it sent any byte
  of a request is closed without a response. The first request's clock starts
  when the connection is accepted.
- Lingering is nginx's `lingering_close`, with the same names and defaults. The
  router writes its answer in full, half-closes the connection, then reads and
  discards what the client still sends. The discard buffer is 4 KiB. A lingering
  close ends when the client closes, after `lingering_timeout` without data, or
  after `lingering_time` in total, so no connection is held longer than
  `lingering_time` after the close is decided. Connections that have not sent a
  request byte, and idle keep-alive connections that time out, close at once in
  every mode. A graceful shutdown waits for lingering closes that are in progress.

Where each limit is enforced. The header limits and the connection timers
apply to the bytes before hyper parses them, in the socket wrapper
(`src/transport.rs`). The body timer and `client_max_body_size` apply while the
body is read (`src/body.rs`). The upstream timers apply in the upstream client
(`src/proxy.rs`).

Request bodies are streamed. The router reads the first `inspect_body` bytes
for the decision and forwards the rest as the upstream reads it. A body over
`client_max_body_size` is refused with 413 when the `Content-Length` shows it
before anything is read. A chunked body that grows past the limit is cut off:
the upstream request is aborted and the client gets 413, unless the upstream
has already answered, in which case the connection closes. Memory per request
is bounded by `inspect_body` and a few buffers, not by the body size.

The header limits are checked on the first bytes of each request, so a
request pipelined behind another on the same connection is not checked by
them, only by hyper's own buffer limit. hyper's limit of 100 header fields is
unchanged.

## Evaluation

The first measurement of Clef-flash and Jev on the labelled dataset is in
[`eval/reports/2026-10-25-clef-flash-vs-jev.md`](eval/reports/2026-10-25-clef-flash-vs-jev.md).
The harness is described in [`eval/README.md`](eval/README.md). The built-in
rules are measured on the same dataset, with their combination with the model,
in [`eval/reports/2026-10-25-builtin-rules.md`](eval/reports/2026-10-25-builtin-rules.md).

## Configuration

The configuration uses nginx syntax: `directive arguments;` and blocks such as
`decision { ... }` and `site example.com { ... }`, with `#` comments and
`include` for splitting files. See
[`examples/vigilant-heron.conf`](examples/vigilant-heron.conf) for every
directive with comments.

Times take `ms`, `s`, `m` or `h` (a bare number is seconds, as in nginx). Sizes
take `k`, `m` or `g`. Every error names the file and line, for example
`vigilant-heron.conf:12: "block_threshold" must be between 0 and 1`.

Access logs are written per request, one line each, to the destinations named by
`access_log` (`stdout`, `stderr`, a file, or `syslog:server=HOST:PORT`). The
default is `access_log stdout json;`. Formats are defined with `log_format`
from the variables listed in the example file. `error_log` controls the
operational messages. A file destination is reopened on SIGUSR1, so logrotate
can move it away.

Migration from `max_body`: the body limit is now the top-level
`client_max_body_size`, which defaults to 1m. It was 10m as `decision.max_body`,
so uploads between 1 and 10 MB need `client_max_body_size 10m;`, and a
`max_body` line is an error that names its replacement.

Migration from the earlier TOML configuration: there is no automatic converter.
Each `[[sites]]` table becomes a `site` block, `timeout_ms = 150` becomes
`timeout 150ms;`, and `deny_paths = [...]` becomes `deny_path ...;`. The keys
keep their names unless the table above says otherwise.

## Running

```bash
TYPESAFE_API_KEY=... cargo run --release -- --config examples/vigilant-heron.conf
```

The example uses the default backend, Jev, so the token variable it names must
be set or the router refuses to start.

The config path can also come from `VIGILANT_HERON_CONFIG`; the default is
`/etc/vigilant-heron/vigilant-heron.conf`.

With Docker, use the published image (`linux/amd64` and `linux/arm64`). The
package is private while the repository is private, so log in to `ghcr.io`
first:

```bash
docker run --rm -p 8080:8080 \
  -v "$PWD/vigilant-heron.conf:/etc/vigilant-heron/vigilant-heron.conf:ro" \
  ghcr.io/coo-quack/vigilant-heron:<version>
```

Replace `<version>` with a release from the
[GitHub Releases](https://github.com/coo-quack/vigilant-heron/releases) page,
or use `latest`. To build the image yourself:

```bash
docker build --target runtime -t vigilant-heron .
```

## Decision backends

`backend` in the `decision` block selects the protocol. The default is `jev`.
`clef` calls Cloudflare Clef on Workers AI, `jev` calls TypeSafe Jev, and `http`
is the JSON protocol below. Both use the same System One request and answer shapes, so they
share one implementation.

### Clef (Cloudflare Workers AI)

```
decision {
    backend clef;
    model clef-flash;           # or clef (64K context)
    url https://api.cloudflare.com/client/v4/accounts/<ACCOUNT_ID>/ai/run/@cf/cloudflare/clef-flash;
    api_token_env CLOUDFLARE_AI_TOKEN;
}
```

The token is read from the environment variable named by `api_token_env` when
the configuration loads. It is never written in the config file and is printed
as `[REDACTED]` in logs and errors. The router asks three questions about each
sanitized event: whether it is an attack (`attack`), whether it addresses an AI
(`ai_instruction`), and which category of attack it is (`category`, logged
only). The question wording lives in [`src/system_one.rs`](src/system_one.rs).

Clef sends the sanitized event to Cloudflare. Read [SECURITY.md](SECURITY.md)
before enabling it.

### Jev (TypeSafe)

```
decision {
    backend jev;
    model jev-latest;           # any identifier of 1 to 100 characters from A-Za-z0-9._-
    url https://api.typesafe.ai/v1/systemone;
    api_token_env TYPESAFE_API_KEY;
}
```

The token handling is the same as for Clef. The request is the System One shape
described above, and the answer is the bare result (no envelope). The router
does not request TypeSafe's long-context mode. Jev receives the sanitized event;
see [SECURITY.md](SECURITY.md).

### HTTP protocol

With `backend http;`, the router posts JSON to the decision `url`:

```json
{"event": {
  "untrusted": {"method": "POST", "path": "/login", "query": null,
                "headers": [["user-agent", "…"]], "body": "user=alice&password=[REDACTED]"},
  "meta": {"host": "example.com", "client_ip": "203.0.113.7", "body_truncated": false}
}}
```

and expects `{"attack": 0.02, "ai_instruction": 0.01}`, both in `0..=1`. A
`"category"` string is optional and is logged when present.

## Security

See [SECURITY.md](SECURITY.md) for what is sent to the backend and how the
router limits the effect of a misled model.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT
