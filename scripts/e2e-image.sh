#!/usr/bin/env bash
# Image phase of the e2e suite. It runs after `docker compose up` in scripts/e2e.sh and uses the
# image that Compose built (vigilant-heron:e2e). Usage: scripts/e2e-image.sh <router-dir>
# where <router-dir> is a writable copy of e2e/ holding vigilant-heron.conf and rules.d/.
set -euo pipefail

cd "$(dirname "$0")/.."

ROUTER_DIR="${1:?usage: e2e-image.sh <router-dir>}"
COMPOSE=(docker compose -f e2e/compose.yaml)
IMAGE="vigilant-heron:e2e"
BASE="${VH_E2E_BASE:-http://127.0.0.1:18080}"
CONF_IN_IMAGE="/etc/vigilant-heron/vigilant-heron.conf"
BIN_IN_IMAGE="/usr/local/bin/vigilant-heron"
NOPID_NAME="vh-e2e-nopid"
NOPID_PORT="${VH_E2E_NOPID_PORT:-18090}"
# Under target/: Docker mounts these directories into containers, and Colima shares only the repository and home.
mkdir -p "$(pwd)/target"
TMP="$(mktemp -d "$(pwd)/target/vh-e2e-image.XXXXXX")"
# mktemp creates the directory as 0700; containers run as nonroot and must read what is mounted from it.
chmod 755 "$TMP"

cleanup() {
  local status=$?
  docker rm -f "$NOPID_NAME" >/dev/null 2>&1 || true
  docker image rm -f vigilant-heron:e2e-default >/dev/null 2>&1 || true
  if [ "$status" -ne 0 ]; then
    echo "----- $NOPID_NAME logs (tail) -----" >&2
    docker logs --tail 40 "$NOPID_NAME" >&2 2>&1 || true
  fi
  rm -rf "$TMP"
  exit "$status"
}
trap cleanup EXIT

fail() {
  echo "e2e-image: FAIL: $*" >&2
  exit 1
}

# Runs a command that must exit with the given code. Output goes to $TMP/last.out and last.err.
expect_exit() {
  local want="$1"
  shift
  local got=0
  "$@" >"$TMP/last.out" 2>"$TMP/last.err" || got=$?
  if [ "$got" -ne "$want" ]; then
    echo "--- stdout" >&2
    cat "$TMP/last.out" >&2
    echo "--- stderr" >&2
    cat "$TMP/last.err" >&2
    fail "\"$*\" exited $got, expected $want"
  fi
}

require_contains() {
  grep -qF -- "$2" "$1" || {
    cat "$1" >&2
    fail "output does not contain \"$2\""
  }
}

# The HTTP status of a GET through the edge with the given Host header.
edge_status() {
  curl -s -o /dev/null -w '%{http_code}' -H "Host: $1" "$BASE$2" || true
}

wait_for_edge() {
  local host="$1" path="$2" want="$3" code="" i
  for i in $(seq 1 50); do
    code="$(edge_status "$host" "$path")"
    if [ "$code" = "$want" ]; then
      return 0
    fi
    sleep 0.2
  done
  fail "GET $path (Host $host) through the edge gave $code, expected $want"
}

echo "e2e-image: the image answers -v and -h"
expect_exit 0 docker run --rm "$IMAGE" -v
require_contains "$TMP/last.out" "vigilant-heron version"
expect_exit 0 docker run --rm "$IMAGE" -h
require_contains "$TMP/last.out" "Usage:"

echo "e2e-image: a build without --target is the router"
expect_exit 0 docker build -q -t vigilant-heron:e2e-default .
expect_exit 0 docker run --rm vigilant-heron:e2e-default -v
require_contains "$TMP/last.out" "vigilant-heron version"

echo "e2e-image: -t on the mounted configuration"
expect_exit 0 docker run --rm -v "$ROUTER_DIR:/etc/vigilant-heron:ro" "$IMAGE" -t
require_contains "$TMP/last.err" "test is successful"

mkdir -p "$TMP/broken"
cp "$ROUTER_DIR/vigilant-heron.conf" "$TMP/broken/"
cp -R "$ROUTER_DIR/rules.d" "$TMP/broken/rules.d"
echo "unknown_directive 1;" >>"$TMP/broken/vigilant-heron.conf"
chmod -R a+rX "$TMP/broken"
expect_exit 1 docker run --rm -v "$TMP/broken:/etc/vigilant-heron:ro" "$IMAGE" -t
require_contains "$TMP/last.err" "test failed"
# The failure must come from the bad directive, not from a file the container cannot read.
require_contains "$TMP/last.err" 'unknown directive "unknown_directive"'

echo "e2e-image: reload and reopen through compose exec"
ROUTER_ID="$("${COMPOSE[@]}" ps -q vigilant-heron)"
[ -n "$ROUTER_ID" ] || fail "the vigilant-heron container is not running"
ORIGINAL="$TMP/original.conf"
cp "$ROUTER_DIR/vigilant-heron.conf" "$ORIGINAL"
# A change that only an unknown host sees: its status moves from 421 to 404.
python3 -I -c 'import sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
assert text.count("default_status 421;") == 1
open(path, "w", encoding="utf-8").write(text.replace("default_status 421;", "default_status 404;"))' "$ROUTER_DIR/vigilant-heron.conf"
expect_exit 0 "${COMPOSE[@]}" exec -T vigilant-heron "$BIN_IN_IMAGE" -s reload -c "$CONF_IN_IMAGE"
wait_for_edge unknown.test / 404
echo "e2e-image: the reloaded status is 404 through the edge"

cp "$ORIGINAL" "$ROUTER_DIR/vigilant-heron.conf"
expect_exit 0 "${COMPOSE[@]}" exec -T vigilant-heron "$BIN_IN_IMAGE" -s reload -c "$CONF_IN_IMAGE"
wait_for_edge unknown.test / 421
expect_exit 0 "${COMPOSE[@]}" exec -T vigilant-heron "$BIN_IN_IMAGE" -s reopen -c "$CONF_IN_IMAGE"

echo "e2e-image: -s quit stops the container with exit code 0"
expect_exit 0 "${COMPOSE[@]}" exec -T vigilant-heron "$BIN_IN_IMAGE" -s quit -c "$CONF_IN_IMAGE"
state=""
for i in $(seq 1 50); do
  state="$(docker inspect -f '{{.State.Status}}' "$ROUTER_ID")"
  if [ "$state" = "exited" ]; then
    break
  fi
  sleep 0.2
done
[ "$state" = "exited" ] || fail "the container is still $state after -s quit"
code="$(docker inspect -f '{{.State.ExitCode}}' "$ROUTER_ID")"
[ "$code" = "0" ] || fail "the container exited with $code after -s quit"
echo "e2e-image: container exit code is $code"

# Bring the router back for the ignored e2e tests. The edge is restarted too, because nginx
# resolved the router's address when it started.
"${COMPOSE[@]}" start vigilant-heron >/dev/null
"${COMPOSE[@]}" restart edge >/dev/null
wait_for_edge unknown.test / 421

echo "e2e-image: a container without a pid directive still serves"
ROUTER_CID="$("${COMPOSE[@]}" ps -q vigilant-heron)"
NET="$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}' "$ROUTER_CID")"
[ -n "$NET" ] || fail "cannot find the compose network"
mkdir -p "$TMP/nopid"
cat >"$TMP/nopid/vigilant-heron.conf" <<'CONF'
listen 0.0.0.0:8080;
default_status 421;

decision {
    backend http;
    url http://stub-decider:9000/decide;
    timeout 300ms;
}

site enforce.test {
    upstream http://upstream:80;
    mode enforce;
}
CONF
chmod -R a+rX "$TMP/nopid"
docker rm -f "$NOPID_NAME" >/dev/null 2>&1 || true
docker run -d --name "$NOPID_NAME" --network "$NET" -p "127.0.0.1:$NOPID_PORT:8080" \
  -v "$TMP/nopid:/etc/vigilant-heron:ro" "$IMAGE" >/dev/null
nopid_code=""
for i in $(seq 1 50); do
  nopid_code="$(curl -s -o /dev/null -w '%{http_code}' -H "Host: enforce.test" "http://127.0.0.1:$NOPID_PORT/" || true)"
  if [ "$nopid_code" = "200" ]; then
    break
  fi
  sleep 0.2
done
[ "$nopid_code" = "200" ] || fail "the container without a pid directive gave $nopid_code, expected 200"
running="$(docker inspect -f '{{.State.Running}}' "$NOPID_NAME")"
[ "$running" = "true" ] || fail "the container without a pid directive stopped"
if docker logs "$NOPID_NAME" 2>&1 | grep -q "cannot write the pid file"; then
  echo "e2e-image: /run is NOT writable for the nonroot user (the pid write warned and the container kept serving)"
else
  echo "e2e-image: /run is writable for the nonroot user (no pid warning)"
fi

echo "e2e-image: all image checks passed"
