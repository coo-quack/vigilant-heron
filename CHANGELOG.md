# Changelog

## Unreleased

- **Breaking:** `decision.max_body` is replaced by the top-level
  `client_max_body_size`, which takes nginx's units and defaults to `1m`
  (`max_body` defaulted to 10m). `client_max_body_size 0` is unlimited. A body
  over the limit gets 413, before it is read when `Content-Length` shows it.
  Uploads between 1 and 10 MB need `client_max_body_size 10m;`. `max_body` is
  now a configuration error that names its replacement.
- **Breaking:** request bodies are streamed. Only the first `inspect_body` bytes
  are read for the decision, and the rest is forwarded as it arrives, so memory
  per request no longer grows with the body (up to 10 MB before).
- Connection timers with nginx's names and defaults: `client_header_timeout`,
  `client_body_timeout`, `send_timeout`, `keepalive_timeout` (0 disables
  keep-alive) and `keepalive_requests`. The connection timers and header limits
  are top-level only; the body timer and `client_max_body_size` can be set per
  site.
- `large_client_header_buffers`: a request line over one buffer gets 414, a
  header field or a header section over its limit gets 400. A request header
  that stops arriving gets 408; a silent connection is closed.
- Upstream timers with nginx's names and defaults, per site: `proxy_connect_timeout`,
  `proxy_read_timeout` and `proxy_send_timeout`. A connect, read or send timeout
  before the response gets 504; a connection failure keeps 502.
- Access log variables `$upstream_status` and `$upstream_error`. A timer or
  limit that answers the client is logged with its status and `$reason`.
- **Breaking:** the configuration is nginx-style (`vigilant-heron.conf`), not
  TOML. Each TOML key has a directive, times and sizes take units, and
  `include` splits files. The default path is `/etc/vigilant-heron/vigilant-heron.conf`.
  There is no automatic converter; see the README for the mapping.
- **Breaking:** the `vigilant_heron::decision` tracing event is replaced by
  access logs: one line per request to the destinations named by `access_log`,
  with `log_format` and the built-in `json` and `main` formats. `error_log`
  controls operational messages. Default: `access_log stdout json;`.
- `client_ip_header` is replaced by `real_ip_from`, `real_ip_header` and
  `real_ip_recursive`, with nginx semantics: the header is believed only from a
  trusted proxy.
- Defaults: `decision.backend` is `"jev"` (with its URL, model and token
  variable), `timeout_ms` is 300, site thresholds are 0.87 and 0.8. Configs that
  used the JSON protocol must set `backend = "http"`.
- Failure settings per site: `on_rate_limit` (HTTP 429 and "no slot in time")
  and `on_decision_error` (everything else), each `"allow"` or `"block"`. The
  decision log reports `reason` and `decision_error`. `fail_closed_paths` wins
  over both.
- Concurrency: `max_connections`, `worker_threads` and `decision.max_concurrency`
  bound client connections, runtime threads and decision-backend calls.
  `decision.queue_timeout_ms` (default 0) bounds the wait for a slot; a request
  that does not get one in that window is always `backend_busy`, a rate limit.
- `request_id_header` logs a request id with each decision event.
- The example config ships a list of commonly probed deny paths.
- Evaluation harness (`eval/`), a load tool, and the first Clef-flash and Jev
  measurement.
- Host-based router with deny rules, static skip, a decision backend over
  HTTP, block/redirect/shadow policy and fail-open/fail-closed paths
- Docker image (`runtime` target) and Compose-based e2e suite
- Cloudflare Clef decision backend (`decision.backend = "clef"`), with the
  API token read from an environment variable and https support
