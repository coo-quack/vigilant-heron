# Changelog

## Unreleased

- Defaults: `decision.backend` is `"jev"` (with its URL, model and token
  variable), `timeout_ms` is 300, site thresholds are 0.87 and 0.8. Configs that
  used the JSON protocol must set `backend = "http"`.
- Failure settings per site: `on_rate_limit` (HTTP 429 and "no slot in time")
  and `on_decision_error` (everything else), each `"allow"` or `"block"`. The
  decision log reports `reason` and `decision_error`. `fail_closed_paths` wins
  over both.
- Concurrency: `max_connections`, `worker_threads` and `decision.max_concurrency`
  bound client connections, runtime threads and decision-backend calls.
- `request_id_header` logs a request id with each decision event.
- The example config ships a list of commonly probed deny paths.
- Evaluation harness (`eval/`), a load tool, and the first Clef-flash and Jev
  measurement.
- Host-based router with deny rules, static skip, a decision backend over
  HTTP, block/redirect/shadow policy and fail-open/fail-closed paths
- Docker image (`runtime` target) and Compose-based e2e suite
- Cloudflare Clef decision backend (`decision.backend = "clef"`), with the
  API token read from an environment variable and https support
