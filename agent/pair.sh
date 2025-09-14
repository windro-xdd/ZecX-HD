#!/usr/bin/env bash
# ZecX-HPot — One-command pairing code generator
# - Prints the pairing code to the terminal
# - Saves it securely to a file for later reference
# - Works on any Linux with Go installed
# - Never prints or stores service account secrets

set -euo pipefail

# Resolve repo paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

INFO() { printf "\033[1;34m[INFO]\033[0m %s\n" "$*"; }
WARN() { printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
ERR()  { printf "\033[1;31m[ERR ]\033[0m %s\n" "$*"; }

# 1) Check dependencies
if ! command -v go >/dev/null 2>&1; then
  ERR "Go toolchain is required. Please install Go (https://go.dev/dl) and retry."
  exit 2
fi

# 2) Determine Firebase project ID
PROJECT_ID="${FIREBASE_PROJECT_ID:-}"
if [[ -z "$PROJECT_ID" ]]; then
  if command -v jq >/dev/null 2>&1 && [[ -f "$REPO_ROOT/backend/.firebaserc" ]]; then
    PROJECT_ID="$(jq -r '.projects.default // empty' "$REPO_ROOT/backend/.firebaserc")"
  fi
fi
if [[ -z "$PROJECT_ID" && -f "$REPO_ROOT/backend/.firebaserc" ]]; then
  # Fallback parse without jq
  PROJECT_ID="$(grep -oE '"default"\s*:\s*"[^"]+"' "$REPO_ROOT/backend/.firebaserc" | sed -E 's/.*"default"\s*:\s*"([^"]+)".*/\1/' || true)"
fi
if [[ -z "$PROJECT_ID" ]]; then
  PROJECT_ID="zecx-hpot"
  WARN "FIREBASE_PROJECT_ID not set; defaulting to '$PROJECT_ID'. Override by exporting FIREBASE_PROJECT_ID."
fi

# 3) Locate service account credentials securely
CREDS="${GOOGLE_APPLICATION_CREDENTIALS:-}"
if [[ -n "${CREDS:-}" && -r "$CREDS" ]]; then
  : # use provided
elif [[ -r /etc/zecx-hpot/serviceAccountKey.json ]]; then
  CREDS="/etc/zecx-hpot/serviceAccountKey.json"
elif [[ -r "$SCRIPT_DIR/serviceAccountKey.json" ]]; then
  CREDS="$SCRIPT_DIR/serviceAccountKey.json"
else
  ERR "Service account key not found. Place it at /etc/zecx-hpot/serviceAccountKey.json or set GOOGLE_APPLICATION_CREDENTIALS to a readable file."
  exit 3
fi
export GOOGLE_APPLICATION_CREDENTIALS="$CREDS"

INFO "Using Firebase project: $PROJECT_ID"

# 3a) Determine agent UUID
AGENT_UUID="${AGENT_UUID:-}"
CONF_FILE="/etc/zecx-hpot/agent.conf"
if [[ -z "$AGENT_UUID" && -r "$CONF_FILE" ]]; then
  AGENT_UUID="$(grep -oE '^agent_uuid=[^ ]+' "$CONF_FILE" | sed 's/agent_uuid=//')"
fi
if [[ -z "$AGENT_UUID" && -n "${1:-}" ]]; then
  if [[ "$1" == "--agent" && -n "${2:-}" ]]; then
    AGENT_UUID="$2"
    shift 2 || true
  fi
fi
if [[ -z "$AGENT_UUID" ]]; then
  ERR "Agent UUID not found. Provide via --agent <uuid> or set /etc/zecx-hpot/agent.conf with agent_uuid=<uuid>."
  exit 7
fi
INFO "Target agent: $AGENT_UUID"

# 4) Generate pairing code using the Go tool
umask 077
TMP_OUT="$(mktemp -t zecx_pair_code.XXXXXX)"
cleanup() { rm -f "$TMP_OUT" 2>/dev/null || true; }
trap cleanup EXIT

GENPAIR_DIR="$SCRIPT_DIR/cmd/genpair"
if [[ ! -d "$GENPAIR_DIR" ]]; then
  ERR "Missing directory: $GENPAIR_DIR"
  exit 4
fi

INFO "Generating pairing code..."
pushd "$SCRIPT_DIR" >/dev/null
if ! FIREBASE_PROJECT_ID="$PROJECT_ID" go run ./cmd/genpair >"$TMP_OUT"; then
  popd >/dev/null || true
  ERR "Pairing code generation failed. See messages above."
  exit 5
fi
popd >/dev/null || true

CODE="$(tr -d '\r\n' < "$TMP_OUT")"
if [[ -z "$CODE" ]]; then
  ERR "Empty code produced — aborting."
  exit 6
fi

# 5) Persist code securely for later reference
SAVE_DIR="/etc/zecx-hpot"
SAVE_FALLBACK="$HOME/.config/zecx-hpot"
DEST_DIR=""
if [[ -w "$SAVE_DIR" || ( -d "$SAVE_DIR" && -w "$SAVE_DIR" ) ]]; then
  DEST_DIR="$SAVE_DIR"
else
  DEST_DIR="$SAVE_FALLBACK"
fi
mkdir -p "$DEST_DIR"
chmod 700 "$DEST_DIR" || true

OUT_FILE="$DEST_DIR/pairing_code_${AGENT_UUID}.txt"
{
  printf 'pairing_code=%s\n' "$CODE"
  printf 'project_id=%s\n' "$PROJECT_ID"
  printf 'agent_uuid=%s\n' "$AGENT_UUID"
  printf 'generated_at=%s\n' "$(date -Iseconds)"
} > "$OUT_FILE"
chmod 600 "$OUT_FILE" || true

# 6) Final output
printf '\n\033[1;32mPairing code:\033[0m %s\n' "$CODE"
INFO "Saved to: $OUT_FILE"
INFO "Keep this file private. It contains only the pairing code and metadata (no credentials)."
