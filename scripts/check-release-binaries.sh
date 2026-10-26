#!/usr/bin/env bash
# Checks the release binaries that the Dockerfile's `binaries` stage exports.
# Usage: scripts/check-release-binaries.sh <dist-dir> <version>
# <dist-dir> holds linux_amd64/vigilant-heron and linux_arm64/vigilant-heron, as
# `docker buildx build --output type=local` writes them for two platforms.
# Each binary must need glibc 2.39 or older (docs/install.md promises Ubuntu 24.04
# and Debian 13), and the x86_64 one must report <version>.
set -euo pipefail

DIST="${1:?usage: check-release-binaries.sh <dist-dir> <version>}"
VERSION="${2:?usage: check-release-binaries.sh <dist-dir> <version>}"
GLIBC_FLOOR=2.39

for arch in amd64 arm64; do
  bin="$DIST/linux_$arch/vigilant-heron"
  [ -x "$bin" ] || { echo "missing binary: $bin" >&2; exit 1; }
  need=$(readelf --dyn-syms -W "$bin" | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sed 's/^GLIBC_//' | sort -V | tail -n 1)
  if [ "$(printf '%s\n' "$need" "$GLIBC_FLOOR" | sort -V | tail -n 1)" != "$GLIBC_FLOOR" ]; then
    echo "$bin needs glibc $need, newer than the documented $GLIBC_FLOOR" >&2
    exit 1
  fi
  echo "$bin: glibc $need"
done
"$DIST/linux_amd64/vigilant-heron" -v | grep -qx "vigilant-heron version $VERSION" || {
  echo "the x86_64 binary does not report version $VERSION" >&2
  exit 1
}
echo "both binaries pass; the x86_64 binary reports $VERSION"
