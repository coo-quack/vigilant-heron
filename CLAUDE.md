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
- serde, toml, serde_json; thiserror in the library, anyhow only in `main.rs`
- Tests: built-in harness, rstest, proptest; e2e with Docker Compose

## Commands

- `cargo fmt --all` — format
- `cargo clippy --workspace --all-targets --locked -- -D warnings` — lint
- `cargo test --workspace --locked` — unit and integration tests
- `bash scripts/e2e.sh` — e2e suite against the Compose stack in `e2e/`
- `cargo deny --locked check` — advisories, licenses, sources
- `cargo machete` — unused dependencies

## Project Structure

```
src/
  main.rs        # CLI: --config, tracing setup, signal handling
  lib.rs         # Public API: Config, ConfigError, serve
  config.rs      # TOML schema and validation
  router.rs      # Host normalization and site lookup
  prefilter.rs   # Path normalization, deny rules, static skip
  sanitize.rs    # Backend event: header drop, body redaction, truncation
  decision.rs    # DecisionBackend trait, shared HTTPS transport, HTTP backend, backend enum, Probability, Verdict
  system_one.rs  # System One backends (Clef, Jev): questions, request, response parsing, API token type
  policy.rs      # Pure decision table (rules, thresholds, fail-open/closed, shadow)
  proxy.rs       # Forwarding to upstreams, hop-by-hop headers
  server.rs      # Accept loop and per-request pipeline, decision log
  error.rs       # Error types
tests/
  router.rs      # In-process integration tests with stub upstream and backend
  clef.rs        # In-process tests of the Clef backend against a fake endpoint
  jev.rs         # In-process tests of the Jev backend against a fake endpoint
  clef_live.rs   # Ignored; calls Cloudflare Workers AI, never run in CI
  e2e.rs         # Ignored by default; run by scripts/e2e.sh
e2e/
  stub-decider/  # Deterministic decision backend used by the e2e stack
  config-clef.toml # Second router that uses backend = "clef" against the stub
  config-jev.toml  # Third router that uses backend = "jev" against the stub
  compose.yaml   # nginx edge, three routers, stub decider, upstream
```

## Key Constraints

- The router handles attacker-controlled input. Lints forbid `unsafe`, and
  non-test code may not unwrap, expect, panic, index or slice by position.
  Never weaken `[workspace.lints]`; silence a lint only with
  `#[expect(lint, reason = "...")]`.
- Matching (`deny_paths`, `fail_closed_paths`, static skip) uses the
  normalized path; forwarding uses the raw path unchanged.
- A model verdict can only add blocks: rule blocks are decided before the
  backend is called, and nothing turns a rule block into an allow.
- Client data goes to the backend only under `event.untrusted`, after
  credential headers are dropped and sensitive fields are redacted.
- Comments and documentation are in English.
- CI job names (`audit`, `lint`, `fmt`, `test`, `e2e`, `deadcode`) are
  registered as required checks in coo-quack/iac; do not rename them.
- Test expectations are never edited to match what the code happens to do.
