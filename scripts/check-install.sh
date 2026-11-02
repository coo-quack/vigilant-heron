#!/bin/sh
# Checks packaging/install.sh on the real paths, without --root: the user and its group,
# the owners and the modes, the files, and a second run that overwrites nothing. The
# tests in tests/packaging.rs cannot reach these steps, because they need root.
#
# The script writes to /etc, /usr/local, /var/log and the account database, so run it
# only on a throwaway Linux machine, as root. The ci.yml release-build job runs it with
# the x86_64 binary that the Docker build exports.
# Usage: sudo sh scripts/check-install.sh <binary>
set -eu

BIN="${1:?usage: check-install.sh <binary>}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() {
  echo "check-install: FAIL: $*" >&2
  exit 1
}

step() {
  echo "check-install: $*"
}

# Checks that a path has the expected mode and owner, such as "640 root:vigilant-heron".
expect_stat() {
  got="$(stat -c '%a %U:%G' "$1")"
  [ "$got" = "$2" ] || fail "$1 is '$got', expected '$2'"
  echo "check-install: ok: $1 $got"
}

[ "$(id -u)" -eq 0 ] || fail "run as root"
if id vigilant-heron >/dev/null 2>&1; then
  fail "the user vigilant-heron already exists; run this on a fresh machine"
fi

step "a user whose primary group is not vigilant-heron stops the install before any write"
useradd --system --gid nogroup vigilant-heron
if sh "$REPO/packaging/install.sh" --binary "$BIN" >"$WORK/wrong-group.out" 2>&1; then
  fail "the install ran although the user has the wrong primary group"
fi
grep -q 'primary group' "$WORK/wrong-group.out" || {
  cat "$WORK/wrong-group.out" >&2
  fail "the refusal does not name the primary group"
}
[ ! -e /usr/local/bin/vigilant-heron ] || fail "the install wrote the binary before it stopped"
[ ! -e /etc/vigilant-heron ] || fail "the install created /etc/vigilant-heron before it stopped"
userdel vigilant-heron

step "first run"
sh "$REPO/packaging/install.sh" --binary "$BIN" >"$WORK/first.out"
id vigilant-heron
[ "$(getent passwd vigilant-heron | cut -d: -f6,7)" = "/nonexistent:/usr/sbin/nologin" ] ||
  fail "the user has the wrong home or shell"
[ "$(id -gn vigilant-heron)" = vigilant-heron ] || fail "the user's primary group is not vigilant-heron"
expect_stat /usr/local/bin/vigilant-heron "755 root:root"
expect_stat /etc/vigilant-heron "750 root:vigilant-heron"
expect_stat /etc/vigilant-heron/env "600 root:root"
expect_stat /etc/vigilant-heron/vigilant-heron.conf "640 root:vigilant-heron"
expect_stat /var/log/vigilant-heron "750 vigilant-heron:adm"
expect_stat /etc/systemd/system/vigilant-heron.service "644 root:root"
expect_stat /etc/logrotate.d/vigilant-heron "644 root:root"
cmp "$BIN" /usr/local/bin/vigilant-heron || fail "the installed binary differs from the input"
cmp "$REPO/packaging/systemd/vigilant-heron.service" /etc/systemd/system/vigilant-heron.service ||
  fail "the installed unit differs from packaging/systemd/vigilant-heron.service"
cmp "$REPO/packaging/logrotate/vigilant-heron" /etc/logrotate.d/vigilant-heron ||
  fail "the installed logrotate file differs from packaging/logrotate/vigilant-heron"
cmp "$REPO/examples/vigilant-heron.conf" /etc/vigilant-heron/vigilant-heron.conf ||
  fail "the installed configuration differs from examples/vigilant-heron.conf"

step "second run: edited files must survive"
printf '# marker written by check-install\n' >>/etc/vigilant-heron/vigilant-heron.conf
printf 'TYPESAFE_API_KEY=marker-by-check-install\n' >>/etc/vigilant-heron/env
cp /etc/vigilant-heron/vigilant-heron.conf "$WORK/conf.before"
cp /etc/vigilant-heron/env "$WORK/env.before"
sh "$REPO/packaging/install.sh" --binary "$BIN" >"$WORK/second.out"
cmp "$WORK/conf.before" /etc/vigilant-heron/vigilant-heron.conf || fail "the second run changed the configuration"
cmp "$WORK/env.before" /etc/vigilant-heron/env || fail "the second run changed the token file"
grep -q 'kept /etc/vigilant-heron/env' "$WORK/second.out" || fail "the second run did not report keeping the token file"
grep -q 'systemctl restart vigilant-heron' "$WORK/second.out" || fail "the second run did not ask for a restart"
expect_stat /etc/vigilant-heron/env "600 root:root"
expect_stat /etc/vigilant-heron "750 root:vigilant-heron"
id vigilant-heron >/dev/null || fail "the second run removed the user"

echo "check-install: all real-path checks passed"
