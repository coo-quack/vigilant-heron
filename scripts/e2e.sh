#!/usr/bin/env bash
# Starts the e2e compose stack, runs the ignored e2e tests, then tears the stack down.
set -euo pipefail

cd "$(dirname "$0")/.."

compose=(docker compose -f e2e/compose.yaml)
base="${VH_E2E_BASE:-http://127.0.0.1:18080}"

cleanup() {
  "${compose[@]}" down -v
}
trap cleanup EXIT

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
  exit 1
fi

VH_E2E_BASE="$base" cargo test --test e2e -- --ignored --test-threads=1
