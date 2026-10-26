# Project Rules

## Overview

Reverse-proxy router that sits behind nginx or Cloudflare. For each site
selected by `Host`, it screens a request with deterministic rules, sends a
sanitized copy to a decision backend (a typed decision model such as Clef or
Jev), and blocks (403), redirects (302) or forwards it to the site's upstream.
Shadow mode records what it would have done without blocking.

## Tech Stack

- Rust (toolchain pinned in `rust-toolchain.toml`, edition 2024)
- tokio, hyper 1, hyper-util (server and pooled client)
- serde, toml, serde_json; thiserror in the library, anyhow only in the binary (`main.rs` and its modules `cli.rs` and `lifecycle.rs`)
- Tests: built-in harness, rstest, proptest; e2e with Docker Compose

## Commands

- `cargo fmt --all` — format
- `cargo clippy --workspace --all-targets --locked -- -D warnings` — lint
- `cargo test --workspace --locked` — unit and integration tests
- `cargo llvm-cov --workspace --locked --fail-under-lines 90` — the tests with line coverage; CI fails below 90%
- `bash scripts/e2e.sh` — e2e suite against the Compose stack in `e2e/`
- `cargo deny --locked check` — advisories, licenses, sources
- `cargo machete` — unused dependencies

## Project Structure

```
src/
  main.rs        # Entry point: runtime built from worker_threads, SIGHUP reload, SIGUSR1 reopen, SIGTERM/SIGINT/SIGQUIT graceful stop, signal handlers registered before the pid file
  cli.rs         # Options (-h -v -c -t -T -s, start/stop/restart words), usage text, -s signals through rustix via the pid file
  lifecycle.rs   # start/stop/restart: detached child (own process group), pid-file readiness, bounded waits, no SIGKILL
  pidfile.rs     # PID file: written after bind (atomic rename), removed on drop
  lib.rs         # Public API: Config, ConfigError, serve, install_error_log
  conf/          # Configuration language: lexer, parser, includes (globs, depth, cycles)
  config.rs      # Directive tree -> validated Config; every error names file:line
  realip.rs      # Client address from real_ip_from / real_ip_header / real_ip_recursive
  accesslog.rs   # log_format compiler, variables, escaping, built-in json and main formats
  logsink.rs     # Access-log destinations: bounded queues, drop counts, SIGUSR1 reopen, syslog; error log with reloadable level and destination
  router.rs      # Host normalization and site lookup: exact, leading and trailing wildcards, ~regex, default_server
  block.rs       # block_status (4xx/5xx or 444) and block_page (HTML, 64 KiB, read at load), per level
  access.rs      # Access list: allow/deny by client address, checked in order (nginx semantics)
  limits.rs      # limit_req / limit_conn zones, leaky bucket, connection counts, location selection; runs first
  rules/         # Rules: rule block parser, built-in rules (builtin.conf), matching and normalization
  prefilter.rs   # Screening order: deny_path, block rules, skip rules, static skip
  request_check.rs # test-request: parses a raw request file and reports the server's checks for it, without the backend
  skip_suggest.rs  # suggest-skip-rules: learns skip-rule candidates from a json access log under fixed thresholds
  sanitize.rs    # Backend event: header drop, body redaction, truncation
  decision.rs    # DecisionBackend trait, shared HTTPS transport and limits, HTTP backend, backend enum
  system_one.rs  # System One backends (Clef, Jev): questions, request, response parsing, API token type
  policy.rs      # Pure decision table (rules, thresholds, failure settings, shadow)
  proxy.rs       # Forwarding to upstreams (per-site client, connect and send timers), hop-by-hop headers, proxy_set_header
  tunnel.rs      # proxy_websocket: splices the client and upstream after a 101, idle timeout, holds limit_conn permits; shutdown waits for tunnels and force-closes them at worker_shutdown_timeout
  transport.rs   # Client socket: header, keep-alive and send timers, header limits (414/400); upstream send timer
  body.rs        # Request body: sniff of inspect_body, replay, client_max_body_size, frame timers, keep-alive marker
  server.rs      # Accept loop, reload (watch channel of the state), shutdown drain, per-request pipeline, access records
  error.rs       # Error types
  test_support.rs # Builds sites and configurations for the unit tests
tests/
  router.rs      # In-process integration tests with stub upstream and backend
  clef.rs        # In-process tests of the Clef backend against a fake endpoint
  jev.rs         # In-process tests of the Jev backend against a fake endpoint
  failures.rs    # Failure settings, rule-first guarantee, queued requests with one slot
  limits.rs      # Timers, header limits, body limit and upstream timeouts, with short timers
  logging.rs     # Access-log lines: fields, request id, causes, formats, access_log off
  rules.rs       # Access list and rule decisions in-process: order, shadow mode, logging, backend failures
  clef_live.rs   # Ignored; calls Cloudflare Workers AI, never run in CI
  block.rs       # block_status and block_page responses, including 444 and location overrides
  docs.rs        # Keeps docs/ in step with the parser's directive lists
  error_log.rs   # The error log across SIGHUP and SIGUSR1, with the real binary
  rate_limits.rs # limit_req and limit_conn: locations, log variables, dry run and shadow, gated upstream
  common/        # Shared helpers: in-process upstream, stub and gated decision backends, client, fake System One endpoint
  cli.rs         # The binary: -h, -v, -t and -T, -s signals (reload, reopen, stop, quit), start, stop and restart, the startup log
  headers.rs     # proxy_set_header: variables, removal, inheritance, location replacement
  websocket.rs   # proxy_websocket tunnels against an in-process echo upstream
  reload.rs      # serve_reloadable: valid, broken, zone state kept or reset, in-flight requests finish
  request_check.rs # test-request agrees with the running router on outcome, reason and rule id
  skip_suggest.rs # suggest-skip-rules: learns skip-rule candidates from a json access log under fixed thresholds
  e2e.rs         # Ignored by default; run by scripts/e2e.sh
e2e/
  stub-decider/  # Deterministic decision backend used by the e2e stack
  vigilant-heron.conf # Router for the http backend, with nine sites, one per e2e check (enforce, redirect, shadow, rate limits, path limits, WebSocket, uploads, Langflow patches, access list)
  config-clef.conf    # Second router that uses backend clef against the stub
  config-jev.conf     # Third router that uses backend jev against the stub
  rules.d/       # Rule file included by vigilant-heron.conf (e2e only)
  compose.yaml   # nginx edge, three routers, stub decider, upstream
scripts/
  e2e.sh         # The whole e2e suite, run by the CI job e2e: binary phase, then the Compose stack
  e2e-cli.sh     # Binary phase: the release binary run as docs/getting-started.md shows
  e2e-image.sh   # Image phase: the Compose-built image with the e2e configuration
eval/
  run.py         # Labelled-dataset evaluation (stdlib only, python3 -I)
  load.py        # Load test against the stub decider (offline only)
  rules.py       # Built-in rules on dev and holdout, and the combined pipeline (stdlib only)
  dataset/       # Labelled dev and holdout sets (JSON lines)
  config.template.conf # Router configuration template; run.py fills the @PLACEHOLDERS@
  README.md      # The Clef-flash evaluation: what it measures and how to run it
  reports/       # Written reports of each measurement
examples/
  vigilant-heron.conf # Fully commented sample configuration
  rules.d/local.conf  # Commented sample rules, for an include
```

Top-level and documentation files:

```
docs/            # Reference and guides for the VitePress site (docs.yml); changelog.md is a symlink to CHANGELOG.md
.github/         # CODEOWNERS and the CI workflows (ci.yml, docs.yml, backport.yml, release.yml)
Dockerfile       # Container image build
package.json     # VitePress for docs/ (docs:dev, docs:build, docs:preview)
Cargo.toml       # Workspace, lints and dependencies; Cargo.lock is pinned with --locked
deny.toml        # cargo-deny policy: advisories, licenses, sources
clippy.toml      # Clippy settings (allow the lints in tests)
rust-toolchain.toml # Toolchain pin
README.md, CHANGELOG.md, CONTRIBUTING.md, SECURITY.md # Project documents
```

## Key Constraints

- The router handles attacker-controlled input. Lints forbid `unsafe`, and
  non-test code may not unwrap, expect, panic, index or slice by position.
  Never weaken `[workspace.lints]`; silence a lint only with
  `#[expect(lint, reason = "...")]`.
- Matching (`deny_path`, `fail_closed_path`, static skip, rules) uses the
  normalized request described in the README; forwarding uses the raw request
  unchanged.
- A model verdict can only add blocks: rule blocks are decided before the
  backend is called, and nothing turns a rule block into an allow.
- The access list runs first, before the body is read. A skip rule never
  lets through a request that a block rule matches. Built-in rules are rules.
- Every deterministic rule runs before the decision backend and is unaffected
  by `on_rate_limit` and `on_decision_error`. New rule types must follow this
  rule, and shadow mode still forwards everything, rules included.
- Client data goes to the backend only under `event.untrusted`, after
  credential headers are dropped and sensitive fields are redacted. Access logs
  never contain a credential header (`$http_cookie`, `$http_authorization`, and
  the others are rejected at load), and every value is escaped so a log line
  cannot be split.
- Limits (`limit_req`, `limit_conn`) run first, before the access list and the
  body is read. Their key uses only variables known before the body, and a
  limited request never reaches the rules or the backend. In shadow mode they are
  dry runs.
- Comments and documentation are in English.
- CI job names (`audit`, `lint`, `fmt`, `test`, `e2e`, `deadcode`) are
  registered as required checks in coo-quack/iac; do not rename them.
- Test expectations are never edited to match what the code happens to do.
