#!/usr/bin/env bash
# Node.js (pinned, checksum-verified) and uWebSockets.js from its git tag, pinned by commit (npm
# records the resolved commit in package-lock.json).
. "$(dirname "$0")/../lib.sh"
ensure_node
apt_install git
(cd "$COMP/uws" && npm install --no-audit --no-fund --ignore-scripts >/dev/null)
