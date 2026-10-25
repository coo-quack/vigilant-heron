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

## Limits of the decision model

The model judges text written by the attacker. Payloads can try to steer it,
and it can miss attacks or flag legitimate requests. The router limits what a
steered model can do:

- Attacker-controlled data is sent under a separate `untrusted` field.
- Rule blocks (`deny_paths`) are decided before the model is called, so a
  model answer can never turn a rule block into an allow.
- Requests whose content addresses an AI model are a block signal of their own
  (`instruction_threshold`).

Keep a rule-based WAF in front of the router, start each site in `shadow`
mode, and switch to `enforce` only after measuring missed attacks and false
positives on real traffic.

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
- Deterministic rules (`deny_paths`) are decided before the backend is called.
  The failure settings do not affect them, so a rule block stays a block when the
  backend rate-limits, errors, is unreachable or is saturated. Shadow mode still
  forwards every request, rules included.

The defaults allow requests when the backend fails. A site that depends on the
backend to block attacks should set `on_decision_error = "block"` and, for
paths that must never open, `fail_closed_paths`. Each setting is a trade-off:
blocking on errors turns a provider outage into a block of legitimate traffic.
