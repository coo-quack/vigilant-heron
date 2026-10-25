# How it works

For each request, vigilant-heron selects a site by its `Host`, checks the request
against limits, an access list and rules, asks the decision backend only when
none of those decide, and then applies the site's policy. A request that a
deterministic check blocks never reaches the backend, and no backend answer can
turn a block into an allow.

## Evaluation order

Each request goes through these steps, in this order. The first step that
decides the request ends the evaluation.

0. **Limits.** `limit_req` and `limit_conn` run first, before the access list and
   before the body is read. A request over a limit gets the limit's status
   (503 by default) and is never forwarded. In a shadow site it is forwarded and
   recorded with `would_have=reject`.
1. **Host.** A `Host` header that is not a hostname, an IPv4 address or a bracketed
   IPv6 literal, with an optional `:port`, gets 400 (reason `invalid_host`) before the
   access list. A request without a `Host` header is routed as before.
2. **Access list.** The `allow` and `deny` entries are checked in order by the
   client address. A denied client gets 403 with reason `access_denied`. The
   site's `action` does not apply.
3. **`deny_path`.** A path prefix of the site that matches the normalized request
   is a block (reason `rule`, no rule id).
4. **Block rules.** The built-in rules that are on, then the top-level block
   rules in file order, then the site's block rules. The first match blocks.
5. **Skip rules.** The top-level skip rules, then the site's. The first match
   forwards the request without calling the backend (reason `skip_rule`).
6. **Static assets.** A plain GET or HEAD for a path with a static extension and
   no query and no body is forwarded without calling the backend (reason `skip`).
   It is skipped only when every [path reading](#path-readings) ends in a static
   extension with no earlier script extension, the raw path has no `;`, `\`, `%2F`,
   `%5C` or `%3B`, and no `fail_closed_path` matches. A `static_location` restricts
   it to some prefixes.
7. **Decision model.** The request is sent to the backend, and the policy
   compares the returned scores with `block_threshold` and
   `instruction_threshold`. The outcome is `model` when a threshold is reached and
   `below_threshold` otherwise.

Steps 2 to 5 are the deterministic checks. Every one of them runs before the
backend is called, so the backend's health, its rate limits and the failure
settings have no effect on them. A rule block stays a block when the backend is
down, slow or saturated. Block rules are always checked before skip rules, so a
skip rule never lets through a request that a block rule matches.

The normalized request is used for matching only. What reaches the upstream is
the request as the client sent it, apart from the headers changed by
`proxy_set_header`.

### Path readings

The request path is read in six ways, because upstreams resolve the same bytes
differently. Each reading is percent-decoded once, or resolved on the raw path, as
described below, and dot segments are resolved on `/`:

1. The decoded path.
2. As 1, with each segment cut at its first `;`. Tomcat, Jetty and Spring drop
   these path parameters.
3. As 1, with `\` read as `/`. IIS and ASP.NET do this.
4. As 2 and 3 together.
5. The raw path, with `%2F` and `%5C` kept inside their segments, then
   percent-decoded once. Express matches the raw path this way.
6. As 5, with `;` parameters cut and `\` read as `/`.

NUL bytes are removed from each reading. A reading that equals another is counted
once. The forwarded request is never changed.

A block rule, `deny_path`, `fail_closed_path` and a block rule's `path` condition
match when any reading matches. A skip rule's `path` condition must match every
reading. Limits apply to every `location` that any reading selects. The block
response and the location headers come from the location of the decoded path.

## Block, redirect or forward

A blocked request gets the site's `action`: `block` (the `block_status`, 403 by
default, with the `block_page` if one is set) or `redirect <url>` (302 to the
given location). An allowed request is forwarded to the upstream. The upstream
receives the whole body; the router reads only the first `inspect_body` bytes
for the decision and streams the rest as the upstream reads it.

## Failure behavior

A decision can fail in two ways, and each has its own site setting. Both default
to `block` (fail closed).

- **`on_rate_limit`** covers the backend's HTTP 429 and a request that finds no
  free concurrency slot within `queue_timeout` (`backend_busy`).
- **`on_decision_error`** covers timeouts, connection errors, other non-2xx
  statuses, and answers that cannot be parsed or are out of range.

Set each to `allow` or `block`. A saturated backend is always in the rate-limit
group, so `on_decision_error` never applies to it.

Attackers can try a denial-of-service (DoS) attack against the decision backend: they keep many requests in flight so that the concurrency slots stay full, and the requests of other clients then fail in the rate-limit group. With `on_rate_limit allow`, a DoS attack of this kind makes requests skip the model. The router limits it per client with `decision` `max_concurrency_per_client` (default 8, and at most `max_concurrency`): a client that already has its share of calls in flight is refused at once with `decision_error=client_busy`, which is in the rate-limit group, so only that client follows `on_rate_limit`, and other clients keep being judged. This cap does not prevent a DoS attack from many addresses. For a site that prefers safety over availability, set `on_rate_limit block`, and limit each client with `limit_req` and `limit_conn`.

Two more rules apply to failures:

- A failure on a `fail_closed_path` prefix is always blocked, whatever the two
  settings say.
- A rule decision is not affected by any of these settings.

The decision log records the outcome in `reason`, one of `rate_limited_allowed`,
`rate_limited_blocked`, `decision_error_allowed`, `decision_error_blocked` or
`fail_closed_path`. The cause is in `decision_error`: `rate_limited`,
`backend_busy`, `timeout`, `http_status` or `parse`.

```nginx
site example.com {
    upstream http://app:8080;
    on_rate_limit allow;
    on_decision_error block;
    fail_closed_path /wp-login.php /wp-admin;
}
```

With these settings, a rate-limited decision is allowed, except on the login
paths, which are blocked whatever the failure. Any other decision error blocks
the request.

## Shadow mode

`mode shadow;` turns every enforcement into a record. The request is forwarded,
whatever the verdict, and the access log and the optional debug header show what
would have happened:

- `would_have` is `block` or `redirect` for a decision by the rules, the access
  list or the model, and `reject` for a limit. It is empty when the request would
  have been forwarded anyway.
- `action` and `reason` show the decision that was made.

Rules, the access list and the limits are included. In shadow mode a limit is a
dry run and a denial is recorded, not enforced. Use shadow mode to measure what a
rule or a threshold would do on real traffic before you enforce it.

`debug_headers on;` adds an `x-vigilant-heron` response header with `action`,
`reason` and `would_have`. Turn it off on a public site, because it tells a
client which rule or threshold blocked it.

## What the backend receives

Only a sanitized copy of the request goes to the decision backend. Before it is
sent:

- Credential headers are removed. `cookie`, `authorization`,
  `proxy-authorization`, `x-api-key` and `x-auth-token` are always dropped, and
  each name in `redact_header` is dropped too.
- Form and JSON bodies are scanned for sensitive fields. A field is sensitive
  when its name contains one of `password`, `passwd`, `pwd`, `secret`, `token`,
  `apikey`, `card`, `cvv`, `ssn`, `passphrase`, `passcode`, `credential`,
  `private_key` or `access_key` (case and `_`, `-`, `.` ignored), or when one of
  its words is `pass`, `pin`, `otp`, `auth`, `session`, `cookie` or `jwt`. A word
  is a run of letters and digits, split at other characters and at a lowercase to
  uppercase change, so `author`, `shipping` and `passenger` are not sensitive. The
  value is replaced by `[REDACTED]`. A field named in `redact_field` is also
  replaced, when its name equals that name, case-insensitively. Text that is
  neither form data nor valid JSON is scanned for `key=value` pairs and
  `"key": value` pairs with the same rules.
- Only the first `inspect_body` bytes of the body are sent, cut on a UTF-8 boundary.
  `body_truncated` is set when the body was longer.

All of the client's data sits under `untrusted`, so the backend is told to read
it as data and not as instructions. The event has this shape:

```json
{"event": {
  "untrusted": {"method": "POST", "path": "/login", "query": null,
                "headers": [["user-agent", "…"]], "body": "user=alice&password=[REDACTED]"},
  "meta": {"host": "example.com", "client_ip": "203.0.113.7", "body_truncated": false}
}}
```

`meta.host` is the name of the site the request matched: the first name of the
`site` block, or its pattern for a wildcard or regex site. It is not the client's
`Host`, so a client cannot choose it. The client's `Host` is still sent, as one of
the `untrusted` headers.

The `path` and `query` are the raw values. Normalization applies to matching only.
The `meta` fields are set by the router, not by the client.

Redaction is a best effort on names. A secret stored under a name without one of
the listed words is sent as it is. Read [Security](/security) for what this means
in practice, and for what the decision model can and cannot see.

## Where to go next

- [Rules](/rules) describes the rule syntax and the access list.
- [Limits](/limits) describes the request-rate and connection limits.
- [Decision backends](/decision-backends) describes the thresholds and the protocols.
