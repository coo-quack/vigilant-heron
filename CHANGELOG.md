# Changelog

## Unreleased

- Added: `check_request_with`, the library form of `check_request` that takes an
  already loaded `Config`, so a caller that checks many requests loads the
  configuration once.
- Added: the `$query_shape` log variable and a `query_shape` field in the built-in
  `json` format. It records the names of the query parameters and the kind of each
  value (`p=<num>&s=<text>`), never the values, so a log shows which kinds of
  requests a site receives. See [Logging](/logging#query-shape).
- Added: `vigilant-heron suggest-skip-rules <access-log>` reads a `json` access log
  and suggests skip rules for request shapes that the model judged harmless many
  times, from many clients, over several days, and never blocked. It only prints the
  rules for review. See
  [Learn skip rules from the access log](/cli#learn-skip-rules-from-the-access-log).
- Added: each GitHub Release has Linux binaries for x86_64 and aarch64 (glibc 2.39
  or newer) and a `SHA256SUMS` file. See
  [Download a release binary](/install#download-a-release-binary).
- Fixed: `docker build -t vigilant-heron .` without `--target` built the e2e stub
  decision backend instead of the router. The router is now the Dockerfile's last
  stage.

## v0.1.0 (2026-10-26)

- Added: `vigilant-heron test-request <file> [--client <address>]` reports what the
  router would do with one raw HTTP/1.1 request before deployment: the site, the access
  list, `deny_path`, the rules that match, and whether the request would go to the
  decision backend. It runs the server's own checks, never calls the upstream or the
  backend, and does not simulate `limit_req` or `limit_conn` counts. See
  [Check a request with test-request](/cli#check-a-request-with-test-request).
- Fixed: a stale pid file could make `-s`, `stop`, `restart` and `start` act on an
  unrelated process. When a router died without removing its pid file and the OS
  gave its pid to another process, `-s stop` or `stop` signalled that process, and
  `start` refused with "already running". A running router now holds an exclusive
  lock on `<pid file>.lock`, and those commands treat a pid file as running only
  while the lock is held. A stale file is never signalled. Also, two routers with
  the same `pid` path no longer overwrite each other's pid file: the second exits
  with `another router is using the pid file <path>`.
- Changed: releases now run the tests and the advisory check (`cargo deny` and
  `pnpm audit`) in a job without write access, and the publishing job keeps no
  credential in its checkout. The version tag is created through the REST API.
- Fixed: the opt-in virtual patches `vh-cve-2026-9103` (`/api/v1/login/auto_login`)
  and `vh-cve-2026-8481` (`/api/v1/validate/code`) compared the path case-sensitively,
  so a request such as `/API/V1/LOGIN/AUTO_LOGIN` got past them. Both rules now match
  the path in any letter case. Which requests they block is otherwise unchanged.
- Security: more credentials are kept out of the decision backend. Headers named
  with `signature` (for example `x-hub-signature-256`, `svix-signature` and
  `x-slack-signature`), with `ticket` or `authentication` as a word, or ending in
  `key`, `authkey` or `sessionkey` (for example `x-functions-key`, `x-master-key`
  and `x-admin-key`) are now dropped. Body fields with `signature` in their name are
  redacted. The rules for `ticket`, `authentication`
  and the `key` suffix apply to header names only, so an ordinary `key` or `ticket`
  body or query field is still sent. Multipart parts whose `name` is sensitive have
  their values replaced, and XML elements such as `<password>` and `<wsse:Password>`
  have their text replaced. Form bodies split on `;` as well as `&`, so
  `a=1;password=x` hides the password. A file part is redacted by its field name
  only. Its content is not scanned.
- Fixed: a `proxy_websocket` tunnel was read as if it were HTTP requests. After the
  `101 Switching Protocols`, a tunnelled chunk of more than 8 KiB without a line
  break (a binary WebSocket frame, for example) was answered with 414 and the
  connection was closed, and a tunnel open longer than `client_header_timeout`
  (60s by default) received a 408 while it was still active. Tunnelled bytes are
  now copied as they arrive, with no header limits and no header timer.
- Fixed: a zone keyed on a long client-chosen value, such as a request header,
  could use far more memory than its declared size, because each state stored the
  whole key. States now store a fixed-size digest of the key, so the declared size
  bounds the memory again.
- Added: decision backend `strands` (`decision.backend strands;`) for a self-hosted
  Strands Decider server, which speaks the System One protocol. `model` defaults to
  `strands-decider`, `url` is required, and `api_token_env` is optional: without it,
  no `Authorization` header is sent.
- Behaviour change: a client that holds its `max_concurrency_per_client` share of
  decision calls is now answered 429 with an empty body, and the backend is not
  called. Before, that excess followed `on_rate_limit`, which defaults to `allow`,
  so it was forwarded without the model. The new site directive `on_client_busy
  allow|block;` (default `block`) controls it, and `on_rate_limit` no longer
  affects it. Set `on_client_busy allow` to keep the old forwarding. Shadow mode
  records the 429 as the would-have action. The decision log `reason` is
  `client_busy_allowed` or `client_busy_blocked`.
- The query string sent to the decision backend is redacted. A parameter whose
  decoded name is sensitive, by the same rule as body fields, or named in
  `redact_field`, has its value replaced by `[REDACTED]`. Other parameters are sent
  as the client sent them. `;` separates parameters as `&` does, so
  `password=x;id=1` hides the password and sends `id=1`.
- Security (F2): short sensitive parts no longer match inside ordinary names.
  `ssn`, `card`, `cvv` and `pwd` now match only as whole words, so `class_name`,
  `business_name`, `process_name`, `address_number` and `discard` are sent to the
  decision backend unredacted. `card_id`, `user_ssn`, `userSSN`, `cvv` and `new_pwd`
  are still redacted. `creditcard` and `cardnumber` match as parts of a name.
- Security (F1): the commands that signal the router (`-s`, `start`, `stop` and
  `restart`) refuse a pid file in a directory that other users can write, such as
  `/tmp`, when another user owns the file. A pid that is not a positive decimal
  number, such as `0` or `-1`, is refused with an error. Before, `-1` could signal
  every process of the user. The host guide now writes the pid file to a relative
  path, `pid vigilant-heron.pid;`, which is resolved from the directory the command
  runs in.
- Headers with a credential-like name are no longer sent to the decision backend,
  for example `x-csrf-token`, `x-xsrf-token`, `x-amz-security-token`,
  `x-access-token` and `x-session-id`. `host`, `user-agent`, `accept`, `referer`,
  `origin`, `x-forwarded-for` and the other headers the model uses are still sent.
- A configuration reload keeps the decision slots. Calls admitted before a reload
  still count against `max_concurrency` and `max_concurrency_per_client`, which a
  reload used to exceed. The slots are reused while their limit is unchanged. A
  changed limit gets new slots, and calls in flight keep the slots they hold.
- `start` no longer signals a process it has already reaped when the router exits
  while starting. The pid of a reaped process can belong to another process.
- The pid file's temporary file and the startup log are created exclusively. A file
  planted at those paths, such as a symlink in a shared directory like `/tmp`, is
  no longer written through.
- The docs said that a request whose `Host` matches no site is always 403. It gets
  `default_status` (421 by default) with reason `unknown_host`, unless the top-level
  access list denies it. The docs now say so. The security notes also used the
  wrong name `fail_closed_paths`; the directive is `fail_closed_path`.
- `stop` waits `worker_shutdown_timeout` plus 5 seconds, or 35 seconds when the
  directive is not set. The docs now give that figure.
- `start`, `stop` and `restart` run the router in the background on a host. `start`
  checks the file first, refuses when a router already runs, and prints
  `started (pid N)`. `stop` sends the graceful shutdown and waits until the process
  has exited, and prints `not running` when none runs. `restart` checks the file
  first, so an invalid file leaves the running router alone. Under Docker or
  systemd, run the router in the foreground, as before.
- The shutdown signals (SIGINT, SIGTERM, SIGQUIT) are registered before the pid
  file is written. A stop sent right after the pid file appears now runs the
  cleanup that removes it, where it used to end the process without that cleanup.
- `docs/install.md` builds from source and from the Dockerfile. It no longer
  mentions a published image, and it has a systemd unit example.
- `SECURITY.md` lists the reporting channels: email and a GitHub security advisory.

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

- `enable_rule <id> ...;` at the top level and in a `site` turns on built-in rules
  that are off by default. A built-in rule written with `default off;` runs only
  where it is enabled. The nearest level that names a rule decides, a site's lists
  before the top level's, and `disable_rule` wins over `enable_rule` within one level.
  `default off;` is valid only in the built-in rules.
- Opt-in virtual patches `vh-cve-2026-9103` (IBM Langflow OSS
  `/api/v1/login/auto_login`, CVE-2026-9103) and `vh-cve-2026-8481` (IBM Langflow OSS
  `POST /api/v1/validate/code`, CVE-2026-8481). Both are off by default. IBM's fix
  for CVE-2026-9103 is Langflow 1.10.1; for CVE-2026-8481, upgrade past 1.10.0 and
  check the bulletin. The docs page "From CVE advisories to rules" describes how
  to write, roll out and remove such rules, and the policy for shipped ones.
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
  decision log reports `reason` and `decision_error`. `fail_closed_path` wins
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
- Security (F10, F11): `escape json` now writes every control character (C0,
  DEL and the C1 range) and U+2028/U+2029 as `\uXXXX`, so a log line cannot
  carry terminal control sequences or be split by a Unicode line separator. The
  built-in `main` format quotes `category`, `retry_after` and `request_id`, so a
  client-chosen request id with spaces and `=` cannot add fields. Log lines in the
  `main` format change for those three values (their values are now quoted).
- Security (F3): every line of `real_ip_header` is read, in order, and the lines are
  joined with commas before the right-to-left choice. Previously only the first
  line was read, so a trusted proxy that appended its own line (HAProxy's
  `option forwardfor`) could not stop a client from choosing its address. A
  malformed line makes the whole header ignored, as before.
- Security (F6): a denial-of-service (DoS) attack against the decision backend,
  which keeps the concurrency slots full, could make requests skip the model. The
  defaults of `on_rate_limit` and `on_decision_error` stay `allow`; an earlier
  change that made them `block` is reverted. The new `decision`
  `max_concurrency_per_client` directive (default 8, at most `max_concurrency`)
  limits the calls in flight for one client address, keyed by the realip address.
  A client beyond its share is refused at once with `decision_error=client_busy`,
  in the rate-limit group, so only that client follows `on_rate_limit`, and other
  clients keep being judged. A DoS attack from many addresses is not prevented.
  Sites that prefer safety over availability can set `on_rate_limit block`.
- Security (F8): the lexical redaction of JSON-like bodies computed the end of
  every value, including the end of an unclosed container, for every key. A body
  of `"":{` repeated filled the inspected prefix and took time quadratic in its
  length. The end is now computed only for a value that is replaced or copied, so
  the scan is linear. The output is unchanged; a property test compares it with
  the previous implementation.
- Security (F2): the sensitive field names now include `pass`, `passphrase`,
  `passcode`, `pin`, `otp`, `credential`, `auth`, `session`, `private_key`,
  `access_key`, `secret_key`, `jwt` and `cookie`. A Drupal login
  (`name=alice&pass=...`) no longer sends its password to the decision backend.
  Short words (`pass`, `pin`, `otp`, `auth`, `session`, `cookie`, `jwt`) match a
  whole word of the field name, so `author`, `shipping` and `passenger` are not
  redacted. The known names now also match with `_`, `-` or `.` removed
  (`api_key`, `API-KEY`). New `redact_field <name> ...;` directive in the
  `decision` block adds field names, matched exactly and case-insensitively.
  The expectation `session=1` in the lexical test became `session=[REDACTED]`,
  because the list now includes `session` (the previous expectation encoded the
  shorter list).
- Security (F7): the decision event's `meta.host` is the name of the matched
  site (its first name, or the pattern of a wildcard or regex site), never the
  client's `Host`. The client's `Host` stays in the `untrusted` headers only. A
  `Host` whose name has characters other than letters, digits, `.`, `-` and `_`
  (and is not a bracketed IPv6 literal, with an optional digits-only port) now gets
  400 with reason `invalid_host`, before the access list. Underscores are allowed,
  since real deployments use them. A request with no `Host` header is routed as before.
- Security (F1, F4, F5, F9): the security checks read the request path in six
  ways (decoded; with `;` parameters cut per segment; with `\` as `/`; both; and
  the raw path with `%2F` and `%5C` kept inside their segments, plain and with
  the first two). `deny_path`, `fail_closed_path` and a block rule's `path`
  condition match when any reading matches. A skip rule's `path` condition matches
  only when every reading does. Limits apply to every `location` any reading
  selects. A static skip needs every reading to end in a static extension with no
  earlier script extension, the raw path free of `;`, `\`, `%2F`, `%5C` and `%3B`,
  and no `fail_closed_path` match. The request is still forwarded unchanged.
  New directive `static_location <prefix> ...;` in a `site` restricts the static
  skip to some prefixes.
- Built-in rule `vh-cmdi-001` no longer matches a query parameter whose name starts
  with a command name followed by `-` (such as `&id-from=3`, `&cat-name=x` or
  `&nc-mode=1`). The command must now be followed by whitespace, the end of the
  value, or a shell separator. The positive examples still match.
