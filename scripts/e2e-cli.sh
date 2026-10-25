#!/usr/bin/env bash
# Binary phase of the e2e suite. It runs the release binary the way docs/getting-started.md
# describes, so the guide itself is tested. Called by scripts/e2e.sh; it can also run alone.
#
# The configuration is the first nginx block of docs/getting-started.md. Only these are changed:
# the ports (free local ports, so nothing clashes with the compose stack), the pid path (a temp
# directory), the upstream URL of the decision model (the stub decider), and an access log file
# appended at the end so the script can read the log.
set -euo pipefail

cd "$(dirname "$0")/.."

ROOT="$(pwd)"
GUIDE="$ROOT/docs/getting-started.md"
VH="$ROOT/target/release/vigilant-heron"
STUB="$ROOT/target/release/stub-decider"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/vh-e2e-cli.XXXXXX")"
CONF="$TMP/vigilant-heron.conf"
ACCESS="$TMP/access.log"
TOKEN="e2e-cli-token"
PIDS=""
ROUTER_PID=""

# Prints the logs of the processes that ran, so a failing CI run shows why.
dump_logs() {
  local name
  for name in router stub upstream; do
    if [ -s "$TMP/$name.log" ]; then
      echo "----- $name.log (tail) -----" >&2
      tail -n 60 "$TMP/$name.log" >&2 || true
    fi
  done
  if [ -s "$ACCESS" ]; then
    echo "----- access.log (tail) -----" >&2
    tail -n 20 "$ACCESS" >&2 || true
  fi
}

cleanup() {
  local status=$?
  local pid
  for pid in $PIDS; do
    kill "$pid" 2>/dev/null || true
  done
  if [ "$status" -ne 0 ]; then
    dump_logs
  fi
  rm -rf "$TMP"
  exit "$status"
}
trap cleanup EXIT

fail() {
  echo "e2e-cli: FAIL: $*" >&2
  exit 1
}

# A free TCP port on 127.0.0.1.
free_port() {
  python3 -I -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()'
}

# Starts a background process and remembers its pid for the cleanup.
start() {
  "$@" &
  PIDS="$PIDS $!"
}

# Prints the HTTP status of a GET through the router. Port 0 gives 000 when nothing listens.
status_of() {
  local host="$1" path="$2"
  curl -s -o /dev/null -w '%{http_code}' -H "Host: $host" "http://127.0.0.1:$VH_PORT$path" || true
}

# Polls `status_of` until it gives the expected code, for up to ten seconds.
wait_for_status() {
  local host="$1" path="$2" want="$3" code="" i
  for i in $(seq 1 50); do
    code="$(status_of "$host" "$path")"
    if [ "$code" = "$want" ]; then
      return 0
    fi
    sleep 0.2
  done
  fail "GET $path (Host $host) gave $code, expected $want"
}

# Polls until the file contains the text, for up to ten seconds.
wait_for_text() {
  local file="$1" text="$2" i
  for i in $(seq 1 50); do
    if [ -f "$file" ] && grep -qF -- "$text" "$file"; then
      return 0
    fi
    sleep 0.2
  done
  fail "$file does not contain \"$text\""
}

# Runs a command that must exit with the given code, and captures its output in $TMP/last.out and last.err.
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
  local file="$1" text="$2"
  grep -qF -- "$text" "$file" || {
    cat "$file" >&2
    fail "output does not contain \"$text\""
  }
}

echo "e2e-cli: building the release binaries"
cargo build --release --locked -p vigilant-heron -p stub-decider

VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)"
[ -n "$VERSION" ] || fail "cannot read the version from Cargo.toml"

echo "e2e-cli: command line options"
for option in -h --help; do
  expect_exit 0 "$VH" "$option"
  for listed in -h --help -v --version -c --config -t -T -s; do
    require_contains "$TMP/last.out" "$listed"
  done
done
expect_exit 0 "$VH" -v
require_contains "$TMP/last.out" "vigilant-heron version $VERSION"
expect_exit 1 "$VH" --no-such-option
require_contains "$TMP/last.err" "Usage:"

echo "e2e-cli: test upstream and decision stub"
STUB_PORT="$(free_port)"
UP_PORT="$(free_port)"
VH_PORT="$(free_port)"
mkdir -p "$TMP/site"
echo "hello from the upstream" >"$TMP/site/index.html"
start env STUB_LISTEN="127.0.0.1:$STUB_PORT" "$STUB" >"$TMP/stub.log" 2>&1
start python3 -I -m http.server "$UP_PORT" --bind 127.0.0.1 --directory "$TMP/site" >"$TMP/upstream.log" 2>&1
for i in $(seq 1 50); do
  stub_code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$STUB_PORT/v1/systemone" || true)"
  up_code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$UP_PORT/" || true)"
  if [ "$stub_code" != "000" ] && [ "$up_code" = "200" ]; then
    break
  fi
  sleep 0.2
done
[ "$up_code" = "200" ] || fail "the test upstream did not answer on port $UP_PORT"
[ "$stub_code" != "000" ] || fail "the decision stub did not answer on port $STUB_PORT"

echo "e2e-cli: the configuration from the guide"
python3 -I - "$GUIDE" "$CONF" "$TMP/vigilant-heron.pid" "$VH_PORT" "$UP_PORT" "$STUB_PORT" "$ACCESS" <<'PY'
import re
import sys

guide, out, pid, vh_port, up_port, stub_port, access = sys.argv[1:]
text = open(guide, encoding="utf-8").read()
match = re.search(r"^```nginx\n(.*?)^```$", text, re.S | re.M)
if match is None:
    sys.exit("no nginx block in docs/getting-started.md")
config = match.group(1)
replacements = [
    ("listen 127.0.0.1:8080;", "listen 127.0.0.1:%s;" % vh_port),
    ("pid /tmp/vigilant-heron.pid;", "pid %s;" % pid),
    ("upstream http://127.0.0.1:3000;", "upstream http://127.0.0.1:%s;" % up_port),
    ("backend jev;", "backend jev;\n    url http://127.0.0.1:%s/v1/systemone;" % stub_port),
]
for old, new in replacements:
    if config.count(old) != 1:
        sys.exit("expected exactly one %r in the guide's configuration" % old)
    config = config.replace(old, new)
config += "\n# Test only: the access log goes to a file the script can read.\naccess_log %s json;\n" % access
open(out, "w", encoding="utf-8").write(config)
PY
export TYPESAFE_API_KEY="$TOKEN"

echo "e2e-cli: check the file"
expect_exit 0 "$VH" -t -c "$CONF"
require_contains "$TMP/last.err" "test is successful"

sed 's/mode shadow;/mode shadw;/' "$CONF" >"$TMP/broken.conf"
expect_exit 1 "$VH" -t -c "$TMP/broken.conf"
require_contains "$TMP/last.err" "$TMP/broken.conf:"
require_contains "$TMP/last.err" "test failed"

expect_exit 0 "$VH" -T -c "$CONF"
require_contains "$TMP/last.out" "# configuration file $CONF:"
require_contains "$TMP/last.out" "listen 127.0.0.1:$VH_PORT;"
if grep -qF -- "$TOKEN" "$TMP/last.out"; then
  fail "-T printed the token value"
fi

echo "e2e-cli: start the router and send requests (shadow mode)"
"$VH" -c "$CONF" >"$TMP/router.log" 2>&1 &
ROUTER_PID=$!
PIDS="$PIDS $ROUTER_PID"
wait_for_status example.com / 200
body="$(curl -s -H "Host: example.com" "http://127.0.0.1:$VH_PORT/")"
case "$body" in
  *"hello from the upstream"*) ;;
  *) fail "a normal request did not return the upstream page: $body" ;;
esac
attack="/?id=1%20UNION%20SELECT%20password%20FROM%20users"
wait_for_status example.com "$attack" 200
wait_for_text "$ACCESS" '"would_have":"block"'
wait_for_text "$ACCESS" '"rule_id":"vh-sqli-001"'

echo "e2e-cli: enforce mode and a reload"
python3 -I -c 'import sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
assert text.count("mode shadow;") == 1
open(path, "w", encoding="utf-8").write(text.replace("mode shadow;", "mode enforce;"))' "$CONF"
expect_exit 0 "$VH" -s reload -c "$CONF"
wait_for_status example.com "$attack" 403
wait_for_status example.com / 200

printf 'block_status 418;\n' >>"$CONF"
expect_exit 0 "$VH" -s reload -c "$CONF"
wait_for_status example.com "$attack" 418

echo "e2e-cli: reopen the access log"
mv "$ACCESS" "$ACCESS.1"
expect_exit 0 "$VH" -s reopen -c "$CONF"
# -s reopen returns once the signal is sent, and the router reopens the file
# asynchronously: a request served before that is logged to the old file, so
# keep sending requests until one reaches the new file.
reopened=0
for i in $(seq 1 50); do
  curl -s -o /dev/null -H "Host: example.com" "http://127.0.0.1:$VH_PORT/reopen-check"
  if [ -f "$ACCESS" ] && grep -qF -- "/reopen-check" "$ACCESS"; then
    reopened=1
    break
  fi
  sleep 0.2
done
[ "$reopened" = 1 ] || fail "$ACCESS does not contain \"/reopen-check\" after -s reopen"

echo "e2e-cli: quit"
expect_exit 0 "$VH" -s quit -c "$CONF"
exited=0
for i in $(seq 1 50); do
  if ! kill -0 "$ROUTER_PID" 2>/dev/null; then
    exited=1
    break
  fi
  sleep 0.1
done
[ "$exited" = 1 ] || fail "the router did not exit within five seconds of -s quit"
router_code=0
wait "$ROUTER_PID" || router_code=$?
[ "$router_code" -eq 0 ] || fail "the router exited with $router_code after -s quit"
[ ! -e "$TMP/vigilant-heron.pid" ] || fail "the pid file was not removed on exit"

echo "e2e-cli: reload with no running router"
expect_exit 1 "$VH" -s reload -c "$CONF"
require_contains "$TMP/last.err" "cannot read the pid file"

echo "e2e-cli: start, start again, restart and stop in the background"
expect_exit 0 "$VH" start -c "$CONF"
require_contains "$TMP/last.out" "started (pid "
first_pid="$(sed -n 's/^started (pid \([0-9]*\))$/\1/p' "$TMP/last.out")"
[ -n "$first_pid" ] || fail "start did not print the pid"
wait_for_status example.com / 200
expect_exit 1 "$VH" start -c "$CONF"
require_contains "$TMP/last.err" "already running (pid $first_pid)"
wait_for_status example.com / 200
expect_exit 0 "$VH" restart -c "$CONF"
second_pid="$(sed -n 's/^started (pid \([0-9]*\))$/\1/p' "$TMP/last.out")"
[ -n "$second_pid" ] && [ "$second_pid" != "$first_pid" ] || fail "restart did not start a new process"
wait_for_status example.com / 200
expect_exit 0 "$VH" stop -c "$CONF"
require_contains "$TMP/last.out" "stopped (pid $second_pid)"
[ ! -e "$TMP/vigilant-heron.pid" ] || fail "the pid file remains after stop"
expect_exit 0 "$VH" stop -c "$CONF"
require_contains "$TMP/last.out" "not running"

echo "e2e-cli: all binary checks passed"
