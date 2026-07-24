#!/usr/bin/env bash
#
# Build a distributable BackupMGR release for the scriptgain.com download.
# Produces  dist/guard-mgr-<version>.tar.gz  containing a clean source tree
# (installer runs composer/npm on the target), the prebuilt scan agent
# binaries the Manager serves to hosts, and a VERSION stamp.
#
# Usage:   deploy/build-release.sh 1.2.0
#          deploy/build-release.sh            # reads ./VERSION
#
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="${1:-$(cat VERSION 2>/dev/null || true)}"
[ -n "$VERSION" ] || { echo "Set a version: deploy/build-release.sh <version>  (or create ./VERSION)"; exit 1; }
VERSION="${VERSION#v}"

NAME="guard-mgr-${VERSION}"
OUT="$ROOT/dist"
STAGE="$OUT/$NAME"
rm -rf "$STAGE"; mkdir -p "$STAGE"

echo "==> Staging source tree ($NAME)"
# Ship source; the installer builds vendor/assets on the target. Exclude dev,
# secrets, local state, and the giant node_modules/vendor.
rsync -a \
  --exclude='.git' --exclude='.env' --exclude='.env.*' \
  --exclude='node_modules' --exclude='vendor' \
  --exclude='dist' --exclude='tests' \
  --exclude='storage/logs/*' \
  --exclude='storage/framework/cache/*' --exclude='storage/framework/sessions/*' --exclude='storage/framework/views/*' \
  --exclude='storage/app/backups/*' \
  --exclude='agent/bin/*' \
  ./ "$STAGE/"

echo "==> Bundling the scan agent binary"
mkdir -p "$STAGE/public/downloads"
if [ -f agent/bin/guard-agent ]; then
  cp agent/bin/guard-agent "$STAGE/public/downloads/agent"
  cp deploy/agent-install.sh "$STAGE/public/downloads/agent-install.sh"
  chmod +x "$STAGE/public/downloads/agent"
else
  echo "!! agent/bin/guard-agent missing — build the agent first (cd agent && ./build.sh)."; exit 1
fi

echo "==> Writing VERSION + manifest"
printf '%s\n' "$VERSION" > "$STAGE/VERSION"
cat > "$STAGE/RELEASE.txt" <<TXT
GuardMGR ${VERSION}
Self-hosted backup platform by scriptgain.com

Install (fresh Debian/Ubuntu server, as root):
  DOMAIN=backup.example.com ./deploy/install-master.sh
  # add SSL=1 EMAIL=you@example.com for a Let's Encrypt cert

License:
  After install, set your key:  php artisan guard:license <YOUR-KEY>
  Buy / manage at https://scriptgain.com/products/backup-manager
TXT

echo "==> Packaging (gzipped tarball, files at root for tar xzf -C)"
mkdir -p "$OUT"
rm -f "$OUT/$NAME.tar.gz"
# Files sit at the tarball root (not under $NAME/) so the self-updater can
# `tar xzf <file> -C <app-root>` with no --strip-components.
tar czf "$OUT/$NAME.tar.gz" -C "$STAGE" .
rm -rf "$STAGE"

SIZE=$(du -h "$OUT/$NAME.tar.gz" | cut -f1)
echo "==> Built $OUT/$NAME.tar.gz ($SIZE)"
echo "    sha256: $(sha256sum "$OUT/$NAME.tar.gz" | cut -d' ' -f1)"
