#!/bin/sh
# Installs vigilant-heron as a systemd service. Run it as root from the extracted
# release archive: sudo sh packaging/install.sh
#
# Usage: install.sh [--root DIR] [--binary PATH]
#   --root DIR     install under DIR instead of /. The root check, the user and group,
#                  and the ownership changes are skipped. "/" and "" mean no root.
#   --binary PATH  the router binary. Default: ../vigilant-heron, as the archive lays it out.
#
# It checks everything it needs before it writes anything: the files in the archive,
# the paths it writes (none may be a symbolic link), the adm group, and the vigilant-heron
# user. It installs the binary, the unit and the logrotate file. It creates the
# configuration and log directories, and it copies the sample configuration and a token
# template only when those files are absent. An existing configuration or token file is
# never overwritten. The service is not started; the script prints the next steps.
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT=""
ROOT_GIVEN=0
BINARY=""

die() {
  echo "install.sh: $*" >&2
  exit 1
}

usage() {
  cat <<'USAGE'
Usage: install.sh [--root DIR] [--binary PATH]
  --root DIR     install under DIR instead of / (skips the root check, the user and
                 group, and the ownership changes). "/" and "" mean no root.
  --binary PATH  the vigilant-heron binary (default: ../vigilant-heron)
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --root)
      [ "$#" -ge 2 ] || die "--root needs a directory"
      ROOT="$2"
      # Trailing slashes go, so "/" and "//" leave an empty root, which is the real system.
      while [ "${ROOT%/}" != "$ROOT" ]; do
        ROOT="${ROOT%/}"
      done
      ROOT_GIVEN=0
      if [ -n "$ROOT" ]; then
        ROOT_GIVEN=1
      fi
      shift 2
      ;;
    --binary)
      [ "$#" -ge 2 ] && [ -n "$2" ] || die "--binary needs a path"
      BINARY="$2"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1 (see --help)"
      ;;
  esac
done

if [ "$ROOT_GIVEN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
  die "run as root, for example sudo sh $0, or pass --root DIR to install under another directory"
fi

UNIT_SRC="$HERE/systemd/vigilant-heron.service"
LOGROTATE_SRC="$HERE/logrotate/vigilant-heron"
CONF_SRC="$HERE/../examples/vigilant-heron.conf"
[ -n "$BINARY" ] || BINARY="$HERE/../vigilant-heron"
for source in "$BINARY" "$UNIT_SRC" "$LOGROTATE_SRC" "$CONF_SRC"; do
  [ -f "$source" ] || die "missing file: $source (pass the binary with --binary PATH)"
done

ETC="$ROOT/etc/vigilant-heron"
ENV_FILE="$ETC/env"
CONF_FILE="$ETC/vigilant-heron.conf"
LOG_DIR="$ROOT/var/log/vigilant-heron"
BIN_DST="$ROOT/usr/local/bin/vigilant-heron"
UNIT_DST="$ROOT/etc/systemd/system/vigilant-heron.service"
LOGROTATE_DST="$ROOT/etc/logrotate.d/vigilant-heron"

# Every path the script creates or keeps, from the top down. A symbolic link at one of
# them would send a write somewhere else, so the script stops before it writes anything.
for path in \
  "$ROOT/usr" "$ROOT/usr/local" "$BIN_DST" \
  "$ROOT/etc" "$ETC" "$ENV_FILE" "$CONF_FILE" \
  "$ROOT/etc/systemd" "$ROOT/etc/systemd/system" "$UNIT_DST" \
  "$ROOT/etc/logrotate.d" "$LOGROTATE_DST" \
  "$ROOT/var" "$ROOT/var/log" "$LOG_DIR"; do
  if [ -L "$path" ]; then
    die "refusing to write through a symbolic link: $path"
  fi
done

# True when the path exists, including a dangling symbolic link.
exists() {
  [ -e "$1" ] || [ -L "$1" ]
}

# Sets the owner of a path. Skipped under --root.
own() {
  if [ "$ROOT_GIVEN" -eq 0 ]; then
    chown "$1" "$2"
  fi
}

if [ "$ROOT_GIVEN" -eq 0 ]; then
  # The log directory and the log files belong to vigilant-heron:adm.
  getent group adm >/dev/null 2>&1 || die "the group adm does not exist; create it, then run again"
  if id -u vigilant-heron >/dev/null 2>&1; then
    primary="$(id -gn vigilant-heron)"
    [ "$primary" = vigilant-heron ] || die "user vigilant-heron has the primary group $primary, not vigilant-heron. Fix it (for example usermod -g vigilant-heron vigilant-heron), then run again"
  fi
fi

if [ "$ROOT_GIVEN" -eq 1 ]; then
  echo "--root given: skipping the user and group, and the ownership changes"
elif id -u vigilant-heron >/dev/null 2>&1; then
  echo "user vigilant-heron exists"
else
  getent group vigilant-heron >/dev/null 2>&1 || groupadd --system vigilant-heron
  useradd --system --gid vigilant-heron --home-dir /nonexistent --no-create-home \
    --shell /usr/sbin/nologin vigilant-heron
  echo "created the system user and group vigilant-heron"
fi

BIN_REPLACED=0
if exists "$BIN_DST"; then
  BIN_REPLACED=1
fi
mkdir -p "$ROOT/usr/local/bin"
install -m 755 "$BINARY" "$BIN_DST"

mkdir -p "$ETC"
chmod 750 "$ETC"
own root:vigilant-heron "$ETC"

if exists "$ENV_FILE"; then
  echo "kept $ENV_FILE"
else
  (
    umask 077
    cat >"$ENV_FILE" <<'ENV'
# Secrets for vigilant-heron: one KEY=value per line. systemd reads this file as root
# when the service starts. Uncomment the line for the decision backend you use.
# TYPESAFE_API_KEY=
# CLOUDFLARE_AI_TOKEN=
ENV
  )
  chmod 600 "$ENV_FILE"
  own root:root "$ENV_FILE"
  echo "created $ENV_FILE"
fi

if exists "$CONF_FILE"; then
  echo "kept $CONF_FILE"
else
  install -m 640 "$CONF_SRC" "$CONF_FILE"
  own root:vigilant-heron "$CONF_FILE"
  echo "created $CONF_FILE from the sample"
fi

mkdir -p "$LOG_DIR"
chmod 750 "$LOG_DIR"
own vigilant-heron:adm "$LOG_DIR"

mkdir -p "$ROOT/etc/systemd/system"
install -m 644 "$UNIT_SRC" "$UNIT_DST"
mkdir -p "$ROOT/etc/logrotate.d"
install -m 644 "$LOGROTATE_SRC" "$LOGROTATE_DST"

cat <<NEXT

installed vigilant-heron. The service is not started.

Next steps:
  1. Edit $CONF_FILE. Add the pid line that the unit expects, a JSON access log
     (the guide's tools, shadow-report and suggest-skip-rules, read the json
     format), and your sites:
       pid /run/vigilant-heron/vigilant-heron.pid;
       access_log /var/log/vigilant-heron/access.json json;
  2. Put the API token in $ENV_FILE, for example TYPESAFE_API_KEY=...
  3. sudo systemctl daemon-reload
  4. sudo systemctl enable --now vigilant-heron
NEXT

if [ "$BIN_REPLACED" -eq 1 ]; then
  cat <<'RESTART'

The binary was replaced. A running service keeps the old program until it restarts,
and a reload does not load a new program. Restart it:
  sudo systemctl restart vigilant-heron
RESTART
fi
