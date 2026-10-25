# Security

## Reporting

Report vulnerabilities privately to the maintainers of the coo-quack
organization. Do not open a public issue.

## Data Disclosure

For every request that is not skipped or blocked by a rule, the router sends
the request line, headers and up to `inspect_body_bytes` of the body to the
configured decision backend. It drops `Cookie`, `Authorization`,
`Proxy-Authorization`, `X-Api-Key`, `X-Auth-Token` and any header listed in
`redact_headers`, and replaces the values of password-, token- and card-like
form and JSON fields with `[REDACTED]` before sending. Multipart
(`multipart/form-data`) bodies are only lexically redacted, so a sensitive field
inside one can still reach the backend in some layouts. Everything else, which
can include personal data typed into forms, reaches the backend. Point the
router at a backend you may disclose that data to, or run the decision model
yourself.

With `backend = "clef"`, the same sanitized event is sent to Cloudflare Workers
AI (`api.cloudflare.com`), a third party, as the `state` of a Clef request. The
bearer token is sent in the `Authorization` header to that endpoint only. Use
an account whose Workers AI data handling you have accepted, and keep the token
in the environment, not in the config file. The router never logs the token.

Access logs contain the client address, the method, the path, the status and
the decision fields, but never a request body, a query string or a credential
header. A `$http_*` variable that names a credential or a redacted header is
rejected when the configuration loads. Every logged value is escaped, so a
request cannot inject a line break or a control character into the log.

With `backend = "jev"`, the same sanitized event is sent to TypeSafe
(`api.typesafe.ai`), a third party, in the same System One request shape. The
bearer token goes only to that endpoint, and the router never logs it. The
router does not enable TypeSafe's long-context mode, so events are sent in the
standard form.

## Slow clients and memory

Each limit below is an nginx directive of the same name. The defaults are
nginx's, and the table in the README lists them all.

- A client that sends its header a byte at a time is cut off by
  `client_header_timeout`. A client that holds an idle connection is closed by
  `keepalive_timeout`, and `keepalive_requests` closes a connection after a fixed
  number of requests.
- A client that stops reading the response is cut off by `send_timeout`, so a
  stalled response cannot hold a connection open forever. A client that sends
  its body slowly is cut off by `client_body_timeout`.
- `large_client_header_buffers` bounds the request line and the header section
  before they are parsed: a long request line gets 414, and a long field or a
  header section over its total gets 400.
- `client_max_body_size` (1m by default) refuses a body larger than the limit
  with 413. A `Content-Length` over the limit is refused before any body byte is
  read; a chunked body is cut off once it grows past the limit.
- A request body is not held in memory. The first `inspect_body` bytes (8k by
  default) are read for the decision, and the rest is streamed to the upstream.
  Memory per request is therefore bounded by `inspect_body`, one read frame, and
  hyper's buffers, not by the body size. Before this, up to 10 MB of each body
  was buffered.
- Each connection still costs hyper's read buffer, which is about 408 KiB at
  most, and the number of connections is capped by `max_connections`. The timers
  above limit how long a connection can hold that memory, not how much of it is
  used. Request rate is not limited, and an upstream or backend that is slow
  holds its request for at most the matching timer.

The header limits check the bytes of each request as they are read. A request
pipelined behind another on the same connection is not checked by them.

A response sent before the request body is read (413, 403 for a rule block, 408
or 400) is followed by a lingering close, as nginx does. The router reads and
discards the client's remaining bytes, in a 4 KiB buffer, so a client that is
still sending receives the response instead of a reset. Lingering is bounded:
it ends when the client closes, after `lingering_timeout` without data, or after
`lingering_time` in total, so it cannot hold a connection longer than
`lingering_time`. The total is 30s by default and the silence is 5s. An
attacker can still keep one connection open for `lingering_time` after each
rejected request, so `max_connections` and the memory per connection still
bound the load. `lingering_close off` removes this cost and gives up the
orderly response to such clients.

## Access list and rules

The access list, the `deny_path` entries and the rules are decided before the
decision model, in the order the README gives. They never send data anywhere.

- A model answer cannot turn an access-list refusal, a `deny_path` match or a
  block rule into an allow. A skip rule cannot let through a request that a block
  rule matches, because every block rule is checked first.
- The access list uses the client address chosen by the realip settings. That
  address is believed only from a peer listed in `real_ip_from`, so a client
  that is not a trusted proxy cannot pick its own address with a header.
- Rules match the normalized request: the path is percent-decoded once, the
  query and bodies are decoded at most twice, and NUL bytes are removed. A third
  level of encoding is not decoded, so an input encoded three times is not seen
  as the attack it encodes. The request is forwarded unchanged.
- A body rule sees only the first `inspect_body` bytes. Anything later in the
  body is not matched, and a multipart body is not parsed.
- Regexes use the `regex` crate, which matches in time linear in the input and
  never backtracks, so a pattern cannot be made to take exponential time by a
  crafted request. Each regex is limited to 512 bytes of source and 1 MiB of
  compiled program, and a configuration holds at most 1000 rules.

The built-in rules are signatures, and they are intentionally narrow. They do
not cover:

- SQL injection in form bodies or JSON, except tautologies with a comment
  terminator, stacked destructive statements and time-based functions, which
  are matched anywhere in the inspected input. `UNION SELECT` is matched in
  query strings only.
- SQL keywords split by comments or inserted characters (`UN/**/ION`), other
  SQL dialects, and stored or second-order injection, which no single request
  shows.
- XSS in bodies, headers and paths, and the script or `javascript:` forms in
  bodies. Only query strings carry `<script>`, `javascript:` and inline event
  handlers, because those forms also occur in code pastes and posts about HTML.
  DOM-based XSS never reaches the server.
- Deserialization gadgets, template injection beyond the probes listed, and
  command injection that has no shell separator in a query string.
- Payloads with any encoding beyond two levels, or in another transport
  encoding such as base64 inside a parameter.
- Credential stuffing, bursts and anything that only shows across requests.

Each rule is an opinion about attack syntax, not a proof. Use a rule-based WAF
in front of the router as well, and disable a built-in rule with `disable_rule`
when it blocks traffic you need.

## Limits of the decision model

The model judges text written by the attacker. Payloads can try to steer it,
and it can miss attacks or flag legitimate requests. The router limits what a
steered model can do:

- Attacker-controlled data is sent under a separate `untrusted` field.
- Rule blocks (`deny_path` and block rules) are decided before the model is
  called, so a model answer can never turn a rule block into an allow.
- Requests whose content addresses an AI model are a block signal of their own
  (`instruction_threshold`).

Keep a rule-based WAF in front of the router, start each site in `shadow`
mode, and switch to `enforce` only after measuring missed attacks and false
positives on real traffic.

## Password guessing and request floods

The decision model judges one request at a time, so it cannot tell that the same
client has tried a hundred passwords. Throttling that is the job of
`limit_req` on the path, for example on `/wp-login.php` (see README, "Limits").
A limit is a rate, not a verdict: the model's scores do not change it.

Zones live in the router process. When a zone has no free state, the request is
treated as a rejection: it gets the configured status (503 unless
`limit_req_status` or `limit_conn_status` says otherwise), and in dry run it goes
on. The error log marks such events with `limit_error=zone_exhausted`, so a flood
of distinct keys is visible to operators. Size the zones for the number of
distinct keys (`$client_ip`) you expect; a larger zone holds more states, at
128 bytes (`limit_req`) or 64 bytes (`limit_conn`) per state.

## Upgraded connections and 444

`proxy_websocket on;` tunnels an HTTP `Upgrade` after its handshake is
screened. The handshake goes through the same checks as any request, and a
blocked handshake gets no upgrade. After a `101`, the frames are not inspected:
the router copies the bytes both ways without parsing them. A payload that
attacks the upstream after the handshake passes unseen, and only the handshake
is judged. A tunnel closes when either side closes, or when neither side moves
a byte for `proxy_read_timeout`. It holds its `limit_conn` permits while open.

`block_status 444;` closes the connection without writing a response, as
nginx does. A client that sent a body may then see a reset instead of a status.
The request is still logged with status 444.

## Reload

`SIGHUP` validates the whole configuration before it applies it. A file that
fails validation is rejected: the error is logged with its file and line, and
the configuration that was running keeps serving. Requests in flight during a
reload finish with the configuration they started with. The listen address and
the connection-level settings do not change until a restart, and a reload that
changes them logs a warning. The error log follows the reloaded file: its level
and destination apply at once. A destination that cannot be opened fails the
reload, and the failure is logged to the destination still in use.

## Failure behavior

When the decision backend cannot judge a request, the outcome depends on the
failure and on the site settings:

- A decision fails in one of two groups. `rate_limited` covers HTTP 429 and
  saturation: no concurrency slot obtained within `decision.queue_timeout_ms`
  (`backend_busy`). Saturation is always this group, so it follows
  `on_rate_limit` and never `on_decision_error`. `error` covers timeouts (also
  after a slot was obtained), connection failures, other non-2xx statuses,
  `success: false`, and malformed or out-of-range answers.
- `on_rate_limit` and `on_decision_error` set the outcome for each group:
  `"allow"` (the default) forwards the request, `"block"` applies the site's
  `action`.
- `fail_closed_paths` always blocks a failure on a matching path, whatever the
  group or setting.
- Deterministic rules (the access list, `deny_path` and block rules) are decided
  before the backend is called. The failure settings do not affect them, so a
  rule block stays a block when the backend rate-limits, errors, is unreachable or
  is saturated. Shadow mode still forwards every request, rules included.

The defaults allow requests when the backend fails. A site that depends on the
backend to block attacks should set `on_decision_error = "block"` and, for
paths that must never open, `fail_closed_paths`. Each setting is a trade-off:
blocking on errors turns a provider outage into a block of legitimate traffic.
