#!/usr/bin/env bash
# ZecX-HPot one-command installer
# Usage examples:
#   ./install.sh --ingest-url http://your-backend:5000 --ingest-token SECRET
#   ./install.sh                       # falls back to direct Firestore mode if creds are available
# Flags are forwarded to agent/install.sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="$SCRIPT_DIR/agent"
exec "$AGENT_DIR/install.sh" "$@"
