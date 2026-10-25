# Changelog

## Unreleased

- Host-based router with deny rules, static skip, a decision backend over
  HTTP, block/redirect/shadow policy and fail-open/fail-closed paths
- Docker image (`runtime` target) and Compose-based e2e suite
- Cloudflare Clef decision backend (`decision.backend = "clef"`), with the
  API token read from an environment variable and https support
