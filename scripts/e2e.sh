#!/usr/bin/env bash
# The whole e2e suite, run by the CI job `e2e` and by hand:
#   1. the binary phase (scripts/e2e-cli.sh): the release binary, run as docs/getting-started.md shows
#   2. the Compose stack: the image phase (scripts/e2e-image.sh), then the ignored e2e tests
# The first broken check fails the script, and cleanup runs on every exit.
set -euo pipefail

cd "$(dirname "$0")/.."

compose=(docker compose -f e2e/compose.yaml)
base="${VH_E2E_BASE:-http://127.0.0.1:18080}"
# Under target/, not the system temp directory: Colima shares only the repository and home with its VM.
mkdir -p "$(pwd)/target"
ROUTER_DIR="$(mktemp -d "$(pwd)/target/vh-e2e-router.XXXXXX")"
# mktemp creates the directory as 0700; the router container runs as nonroot and must read it.
chmod 755 "$ROUTER_DIR"

cleanup() {
  local status=$?
  "${compose[@]}" down -v >/dev/null 2>&1 || true
  docker rm -f vh-e2e-nopid >/dev/null 2>&1 || true
  rm -rf "$ROUTER_DIR"
  exit "$status"
}
trap cleanup EXIT

bash scripts/e2e-cli.sh

# The router reads a writable copy of the e2e configuration, so the image phase can change it.
cp e2e/vigilant-heron.conf "$ROUTER_DIR/"
cp -R e2e/rules.d "$ROUTER_DIR/rules.d"
chmod -R a+rX "$ROUTER_DIR"
export VH_E2E_ROUTER_DIR="$ROUTER_DIR"

"${compose[@]}" up -d --build

# The edge answers 421 for an unknown host only once vigilant-heron is serving.
code=""
for _ in $(seq 1 60); do
  code="$(curl -s -o /dev/null -w '%{http_code}' "$base/" || true)"
  if [ "$code" = "421" ]; then
    break
  fi
  sleep 1
done
if [ "$code" != "421" ]; then
  echo "e2e stack did not become ready within 60 seconds (last HTTP code: ${code:-none})" >&2
  "${compose[@]}" ps -a >&2 || true
  "${compose[@]}" logs --no-color --tail 40 >&2 || true
  exit 1
fi

bash scripts/e2e-image.sh "$ROUTER_DIR"

VH_E2E_BASE="$base" cargo test --test e2e -- --ignored --test-threads=1
