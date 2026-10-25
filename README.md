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
2. Applies deterministic rules on the normalized path: `deny_paths` are
   blocked without calling the backend; plain GET/HEAD requests for static
   assets skip it.
3. Sends a sanitized copy of the request to the decision backend: credential
   headers are dropped, password- and token-like fields are redacted, the body
   is truncated, and all client data sits under an `untrusted` field.
4. Applies the site's policy to the returned scores (`attack`,
   `ai_instruction`): block (403), redirect (302), or forward. When the
   backend fails, the failure settings decide (see [Failure behavior](#failure-behavior)).
5. Logs one `vigilant_heron::decision` event per request.

Every deterministic rule runs in step 2, before the backend is called, and no
failure setting changes its result: a rule block stays a block when the backend
rate-limits, errors, is unreachable or is saturated. New rule types must follow
the same rule. In `shadow` mode every request is forwarded, rules included, and
the log and optional debug header record what would have happened.

## Failure behavior

A decision fails when the backend answers HTTP 429, when no concurrency slot is
free within `timeout_ms`, or when it fails in any other way. The two groups have
their own site settings, both `"allow"` by default:

- `on_rate_limit`: the 429 and "no slot in time" group
- `on_decision_error`: timeouts, connection errors, other non-2xx statuses,
  malformed or out-of-range answers. A timeout that happens after a slot was
  obtained is in this group.

Saturation is always in the rate-limit group: a request that gets no
concurrency slot within `decision.queue_timeout_ms` is `backend_busy`, and that
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
| `decision.max_concurrency` | decision-backend calls in flight at the same time | 64 |
| `decision.queue_timeout_ms` | how long a call may wait for one of those slots; no slot in that time is `backend_busy` | 0 (no queueing) |

Waiting for a slot is bounded by `queue_timeout_ms` only. A call that gets a
slot then has the rest of `timeout_ms`. Saturation is therefore always a rate
limit, and it follows `on_rate_limit`, never `on_decision_error`.

The defaults are: `decision.backend = "jev"` (its URL, model and token variable
are set by default too), `timeout_ms = 300`, `block_threshold = 0.87`,
`instruction_threshold = 0.8`, and both failure settings `"allow"`. Configs that
want the JSON protocol must set `backend = "http"`.

## Evaluation

The first measurement of Clef-flash and Jev on the labelled dataset is in
[`eval/reports/2026-10-25-clef-flash-vs-jev.md`](eval/reports/2026-10-25-clef-flash-vs-jev.md).
The harness is described in [`eval/README.md`](eval/README.md).

## Configuration

See [`examples/config.toml`](examples/config.toml) for every key with
comments. Sites are listed under `[[sites]]`, each with its own hosts,
upstream, mode, action and thresholds.

## Running

```bash
cargo run --release -- --config examples/config.toml
```

The config path can also come from `VIGILANT_HERON_CONFIG`; the default is
`/etc/vigilant-heron/config.toml`.

With Docker, use the published image (`linux/amd64` and `linux/arm64`). The
package is private while the repository is private, so log in to `ghcr.io`
first:

```bash
docker run --rm -p 8080:8080 \
  -v "$PWD/config.toml:/etc/vigilant-heron/config.toml:ro" \
  ghcr.io/coo-quack/vigilant-heron:<version>
```

Replace `<version>` with a release from the
[GitHub Releases](https://github.com/coo-quack/vigilant-heron/releases) page,
or use `latest`. To build the image yourself:

```bash
docker build --target runtime -t vigilant-heron .
```

## Decision backends

`decision.backend` selects the protocol. The default, `"http"`, is the JSON
protocol below. `"clef"` calls Cloudflare Clef on Workers AI, and `"jev"` calls
TypeSafe Jev. Both use the same System One request and answer shapes, so they
share one implementation.

### Clef (Cloudflare Workers AI)

```toml
[decision]
backend = "clef"
model = "clef-flash"        # or "clef" (64K context)
url = "https://api.cloudflare.com/client/v4/accounts/<ACCOUNT_ID>/ai/run/@cf/cloudflare/clef-flash"
api_token_env = "CLOUDFLARE_AI_TOKEN"
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

```toml
[decision]
backend = "jev"
model = "jev-latest"        # any identifier of 1 to 100 characters from [A-Za-z0-9._-]
url = "https://api.typesafe.ai/v1/systemone"
api_token_env = "TYPESAFE_API_KEY"
```

The token handling is the same as for Clef. The request is the System One shape
described above, and the answer is the bare result (no envelope). The router
does not request TypeSafe's long-context mode. Jev receives the sanitized event;
see [SECURITY.md](SECURITY.md).

### HTTP protocol

With `backend = "http"`, the router posts JSON to `decision.url`:

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
