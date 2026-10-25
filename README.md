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
   blocked without calling the model; plain GET/HEAD requests for static
   assets skip it.
3. Sends a sanitized copy of the request to the decision backend: credential
   headers are dropped, password- and token-like fields are redacted, the body
   is truncated, and all client data sits under an `untrusted` field.
4. Applies the site's policy to the returned scores (`attack`,
   `ai_instruction`): block (403), redirect (302), or forward. When the
   backend fails, `fail_closed_paths` are blocked and other paths are
   forwarded.
5. Logs one `vigilant_heron::decision` event per request.

In `shadow` mode every request is forwarded, and the log and optional debug
header record what would have happened.

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

With Docker:

```bash
docker build --target runtime -t vigilant-heron .
docker run --rm -p 8080:8080 \
  -v "$PWD/config.toml:/etc/vigilant-heron/config.toml:ro" vigilant-heron
```

## Decision backends

`decision.backend` selects the protocol. The default, `"http"`, is the JSON
protocol below. `"clef"` calls Cloudflare Clef on Workers AI, or any server that
implements the same API.

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
only). The question wording lives in [`src/clef.rs`](src/clef.rs).

Clef sends the sanitized event to Cloudflare. Read [SECURITY.md](SECURITY.md)
before enabling it.

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
