#!/bin/sh
# Installs vigilant-heron as a systemd service. Run it as root from the extracted
# release archive: sudo sh packaging/install.sh
#
# Usage: install.sh [--root DIR] [--binary PATH]
#   --root DIR     install under DIR instead of /. The root check, the user and group,
#                  and the ownership changes are skipped.
#   --binary PATH  the router binary. Default: ../vigilant-heron, as the archive lays it out.
#
# It installs the binary, the unit and the logrotate file. It creates the configuration
# and log directories, and it copies the sample configuration and a token template only
# when those files are absent. An existing configuration or token file is never
# overwritten. The service is not started; the script prints the next steps.
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
                 group, and the ownership changes)
  --binary PATH  the vigilant-heron binary (default: ../vigilant-heron)
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --root)
      [ "$#" -ge 2 ] && [ -n "$2" ] || die "--root needs a directory"
      ROOT="$2"
      ROOT_GIVEN=1
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
# Check every source before anything is written.
for source in "$BINARY" "$UNIT_SRC" "$LOGROTATE_SRC" "$CONF_SRC"; do
  [ -f "$source" ] || die "missing file: $source (pass the binary with --binary PATH)"
done

ETC="$ROOT/etc/vigilant-heron"
ENV_FILE="$ETC/env"
CONF_FILE="$ETC/vigilant-heron.conf"
LOG_DIR="$ROOT/var/log/vigilant-heron"

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

mkdir -p "$ROOT/usr/local/bin"
install -m 755 "$BINARY" "$ROOT/usr/local/bin/vigilant-heron"

mkdir -p "$ETC"
chmod 750 "$ETC"
own root:vigilant-heron "$ETC"

if exists "$ENV_FILE"; then
  echo "kept $ENV_FILE"
else
  (
    umask 027
    cat >"$ENV_FILE" <<'ENV'
# Secrets for vigilant-heron: one KEY=value per line, read by systemd when the service starts.
# Uncomment the line for the decision backend you use, and fill in its token.
# TYPESAFE_API_KEY=
# CLOUDFLARE_AI_TOKEN=
ENV
  )
  chmod 640 "$ENV_FILE"
  own root:vigilant-heron "$ENV_FILE"
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
install -m 644 "$UNIT_SRC" "$ROOT/etc/systemd/system/vigilant-heron.service"
mkdir -p "$ROOT/etc/logrotate.d"
install -m 644 "$LOGROTATE_SRC" "$ROOT/etc/logrotate.d/vigilant-heron"

cat <<NEXT

installed vigilant-heron. The service is not started.

Next steps:
  1. Edit $CONF_FILE. Add the pid line that the unit expects, a log file for
     rotation, and your sites:
       pid /run/vigilant-heron/vigilant-heron.pid;
       access_log /var/log/vigilant-heron/access.log main;
  2. Put the API token in $ENV_FILE, for example TYPESAFE_API_KEY=...
  3. sudo systemctl daemon-reload
  4. sudo systemctl enable --now vigilant-heron
NEXT
