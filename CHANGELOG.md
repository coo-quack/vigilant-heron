# Changelog

## Unreleased

- Command line, as nginx's: `-h`/`--help` and `-v`/`--version`, `-c <path>` as a
  short form of `--config`, `-T` (test, then print the configuration with every
  include expanded under its `# configuration file <path>:` header), and
  `-s reload|reopen|stop|quit`. `-s` sends SIGHUP, SIGUSR1, SIGTERM or SIGQUIT to
  the pid in the file the `pid` directive names. An unknown option prints the
  usage and exits 1. `stop` and `quit` are both graceful in this version.
- `pid <path>;` directive (default `/run/vigilant-heron.pid`). The router writes its
  process id there once it is listening and removes it on exit. A write failure is
  logged and the router keeps running. SIGQUIT now shuts down gracefully, like
  SIGTERM and SIGINT.
- `docs/cli.md` describes the command line, and `pid` is documented in
  `docs/configuration.md`. The migration notes from the README moved to
  `docs/configuration.md`.
- README rewritten as a short introduction with install, a quick start, the
  command line, the order of checks, and links to the documentation. The
  reference stays in `docs/`.
- Removed `rustfmt.toml`, which only repeated `edition = "2024"` from `Cargo.toml`.
  `cargo fmt` output is unchanged.

- Command line, as nginx's: `-h`/`--help` and `-v`/`--version`, `-c <path>` as a
  short form of `--config`, `-T` (test, then print the configuration with every
  include expanded under its `# configuration file <path>:` header), and
  `-s reload|reopen|stop|quit`. `-s` sends SIGHUP, SIGUSR1, SIGTERM or SIGQUIT to
  the pid in the file the `pid` directive names. An unknown option prints the
  usage and exits 1. `stop` and `quit` are both graceful in this version.
- `pid <path>;` directive (default `/run/vigilant-heron.pid`). The router writes its
  process id there once it is listening and removes it on exit. A write failure is
  logged and the router keeps running. SIGQUIT now shuts down gracefully, like
  SIGTERM and SIGINT.
- `docs/cli.md` describes the command line, and `pid` is documented in
  `docs/configuration.md`. The migration notes from the README moved to
  `docs/configuration.md`.
- README rewritten as a short introduction with install, a quick start, the
  command line, the order of checks, and links to the documentation. The
  reference stays in `docs/`.
- Removed `rustfmt.toml`, which only repeated `edition = "2024"` from `Cargo.toml`.
  `cargo fmt` output is unchanged.

- Host matching as in nginx `server_name`: exact names, `*.example.com`,
  `example.*`, `.example.com` and `~regex` names in a `site`, with exact, then
  leading wildcard, then trailing wildcard, then regex precedence. `default_server;`
  marks the one site that takes hosts matching no site (at most one per
  configuration). A name claimed by two sites is still a configuration error.
- `proxy_set_header <name> <value>;` at the top level, in a `site` and in a
  `location`, with nginx's replace-per-level and empty-removes rules. Values take
  `$client_ip`, `$remote_addr`, `$host`, `$site`, `$method`, `$path`,
  `$request_id` and `$http_<name>`. The default headers (Host kept,
  `X-Forwarded-For` appended) are unchanged. Hop-by-hop headers cannot be set.
- `SIGHUP` reloads the configuration like `nginx -s reload`. A valid file is
  applied to new requests, while requests in flight finish with the old one. A
  broken file is logged at error level with its file and line, and the old
  configuration keeps serving. Zones keep their counts when the name and size
  match. Listen address, `worker_threads`, `max_connections` and connection timers
  apply only at startup (a warning is logged). The `error_log` level and
  destination follow a reload: a destination that cannot be opened fails the
  reload. `SIGUSR1` still reopens the log files.
- `vigilant-heron -t [--config <path>]` checks the configuration like `nginx -t`:
  it validates the whole file (includes, rules, block pages, token variables),
  reports the result on stderr and exits 0 or 1. It never binds or serves.
- `worker_shutdown_timeout <time>;` (top level, startup only, unset by default).
  A shutdown now waits for open WebSocket tunnels as well as in-flight requests.
  Without the directive it waits indefinitely, as nginx does; with it, every
  connection and tunnel still open is closed when the time expires.
- `proxy_websocket on|off;` in a `site` and a `location` (default off). With `on`,
  an HTTP/1.1 Upgrade handshake is screened like any request, then forwarded; a
  `101` from the upstream is spliced into a bidirectional tunnel that closes after
  `proxy_read_timeout` of inactivity, and counts against `limit_conn`. Only the
  handshake is judged, not the frames.
- `block_status <code>;` (4xx or 5xx, or 444 to close the connection without a
  response) and `block_page <file>;` (HTML, at most 64 KiB, read at load time) for
  blocked requests, at the top level, in a `site` and in a `location`. Limit
  refusals and access-list denials (403) keep their statuses.
- Request-rate and connection limits, with nginx's `limit_req` and `limit_conn`
  semantics: `limit_req_zone` and `limit_conn_zone` at the top level, `limit_req`,
  `limit_conn`, their status, dry-run and log-level directives at the top level,
  in a `site` and in a `location`. Limits run before the access list, and a
  refused request gets its status (default 503) without reaching the backend.
  New access-log variables `$limit_req_status` and `$limit_conn_status`.
  `location` blocks inside `site` select a path with nginx's matching rules.
- **Breaking:** the access list and the rules run before the decision backend,
  and a rule block now also comes from the built-in set. Existing configurations
  keep their behavior except for requests the built-in rules match, which are
  now blocked without a backend call. Turn them off with `builtin_rules off;`,
  or disable single ids with `disable_rule`.
- Access list, as in nginx: `allow` and `deny` with an address, a CIDR network or
  `all`, at the top level and in a `site` (a site's list replaces the top-level
  one). The first match decides, and the client address comes from the realip
  settings. A denied client gets 403 with reason `access_denied`, before the body
  is read; on a shadow site it is forwarded and recorded with `would_have=block`.
- Rules in nginx syntax: `rule <id> { description; action block|skip; ... }` at
  the top level (all sites, or the sites named by `site`) and inside a `site`.
  Conditions: `method`, `path` (prefix, `=`, `^~`, `~`, `~*`), `query`, `header`,
  `body` (the inspected prefix), `any` and `client`. Regexes use the `regex`
  crate (linear time), with a 512-byte source and 1 MiB compiled size limit, and
  at most 1000 rules per configuration. Ids are unique across files and `vh-`
  is reserved.
- Built-in rules (`src/rules/builtin.conf`, ids `vh-<category>-<nnn>`) for SQL
  injection, XSS, path traversal, command injection, file inclusion, SSRF,
  template injection, XXE and known scanner user agents. They are written to miss
  an attack rather than block code pastes, prose about SQL or HTML, base64 blobs
  or Japanese text. `builtin_rules` and `disable_rule` control them, at the top
  level and per site.
- Logs: `$rule_id` is the id of the rule that decided the request. The reasons
  `access_denied`, `rule` and `skip_rule` are new. The built-in `json` format
  has a `rule_id` field.
- `eval/rules.py` measures the built-in rules on the labelled dataset and the
  combined pipeline with the saved model results. `eval/run.py` runs with the
  built-in rules off, so it still measures the model alone.

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
- Lingering close, as nginx's `lingering_close`: after an early response (413,
  403, 408, 400, 414) the router half-closes and discards the client's remaining
  bytes, so a client that is still sending reads the response instead of a
  reset. `lingering_close on|always|off` (default `on`), `lingering_time` (30s)
  and `lingering_timeout` (5s) are top-level only. Lingering is bounded by both
  times.
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
