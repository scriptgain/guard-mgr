#!/usr/bin/env bash
#
# GuardMGR agent installer. Run on the host you want to scan:
#
#   curl -fsSL https://MASTER/downloads/agent-install.sh | sudo bash -s -- https://MASTER <enroll-token>
#
# Downloads the agent from the master, enrolls this host, and — as part of
# enrollment — installs an always-on systemd service that polls for scan jobs
# every ~30s. One command in, a set-and-forget worker out. Linux x86_64.
set -euo pipefail

MASTER="${1:?usage: agent-install.sh <master-url> <enroll-token>}"
TOKEN="${2:?usage: agent-install.sh <master-url> <enroll-token>}"
MASTER="${MASTER%/}"
BIN="/usr/local/bin/guard-agent"

[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)."; exit 1; }
command -v curl >/dev/null || { echo "curl is required."; exit 1; }

echo "==> Downloading agent from ${MASTER}/downloads/agent"
curl -fsSL "${MASTER}/downloads/agent" -o "$BIN"
chmod +x "$BIN"

echo "==> Enrolling with the master (this also installs + starts the systemd service)"
"$BIN" enroll -master "$MASTER" -token "$TOKEN"

# Belt-and-suspenders: ensure the service is installed even if enrollment ran in
# an environment where the auto-install was skipped. Idempotent.
"$BIN" install >/dev/null 2>&1 || true

echo "==> Done. guard-agent is enrolled and running:"
systemctl --no-pager status guard-agent | head -n 5 || true
