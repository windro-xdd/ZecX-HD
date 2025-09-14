#!/usr/bin/env bash
set -euo pipefail

BIN_NAME="network-dispatcher"
SERVICE_NAME="network-dispatcher.service"
INSTALL_DIR="/usr/local/bin"
CONF_DIR="/etc/zecx-hpot"
UNIT_PATH="/etc/systemd/system/$SERVICE_NAME"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

INFO(){ printf "\033[1;34m[INFO]\033[0m %s\n" "$*"; }
WARN(){ printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
ERR(){  printf "\033[1;31m[ERR ]\033[0m %s\n" "$*"; }

PROJECT_ID="${FIREBASE_PROJECT_ID:-}"
CREDS_IN="${GOOGLE_APPLICATION_CREDENTIALS:-}"
INGEST_URL="${ZECX_INGEST_URL:-}"
INGEST_TOKEN="${ZECX_INGEST_TOKEN:-}"

# Ensure root; re-exec via sudo if needed
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  INFO "Elevating privileges with sudo"
  exec sudo -E bash "$0" "$@"
fi

# Load default ingest settings from repo root if present
if [[ -f "$REPO_ROOT/.ingest.env" ]]; then
  INFO "Loading defaults from $REPO_ROOT/.ingest.env"
  set +u
  # shellcheck disable=SC1090
  source "$REPO_ROOT/.ingest.env"
  set -u
  if [[ -z "$INGEST_URL" && -n "${ZECX_INGEST_URL:-}" ]]; then INGEST_URL="$ZECX_INGEST_URL"; fi
  if [[ -z "$INGEST_TOKEN" && -n "${ZECX_INGEST_TOKEN:-}" ]]; then INGEST_TOKEN="$ZECX_INGEST_TOKEN"; fi
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project) PROJECT_ID="${2:-}"; shift 2;;
    --creds)   CREDS_IN="${2:-}"; shift 2;;
    --ingest-url)   INGEST_URL="${2:-}"; shift 2;;
    --ingest-token) INGEST_TOKEN="${2:-}"; shift 2;;
    --use-prebuilt) USE_PREBUILT=1; shift;;
    --reseed) RESEED=1; shift;;
    --no-start) NO_START=1; shift;;
    --no-restart) NO_RESTART=1; shift;;
    *) WARN "Unknown flag: $1"; shift;;
  esac
done

GO_AVAILABLE=1
if ! command -v go >/dev/null 2>&1; then GO_AVAILABLE=0; fi

if [[ -z "${USE_PREBUILT:-}" ]]; then
  if [[ "$GO_AVAILABLE" -eq 0 ]]; then
    if [[ -x "$SCRIPT_DIR/$BIN_NAME" ]]; then
      WARN "Go toolchain not found; using prebuilt binary at $SCRIPT_DIR/$BIN_NAME"
      USE_PREBUILT=1
    else
      ERR "Go is required to build. Install from https://go.dev/dl or provide a prebuilt $BIN_NAME and pass --use-prebuilt"
      exit 1
    fi
  fi
fi

mkdir -p "$CONF_DIR"
chmod 700 "$CONF_DIR" || true

USE_INGEST=false
if [[ -n "$INGEST_URL" ]]; then
  USE_INGEST=true
  INFO "Using HTTP ingest mode (no service account required)"
else
  # Determine Firebase Project ID
  if [[ -z "$PROJECT_ID" ]]; then
    if command -v jq >/dev/null 2>&1 && [[ -f "$REPO_ROOT/backend/.firebaserc" ]]; then
      PROJECT_ID="$(jq -r '.projects.default // empty' "$REPO_ROOT/backend/.firebaserc")"
    elif [[ -f "$REPO_ROOT/backend/.firebaserc" ]]; then
      PROJECT_ID="$(grep -oE '"default"\s*:\s*"[^"]+"' "$REPO_ROOT/backend/.firebaserc" | sed -E 's/.*"default"\s*:\s*"([^"]+)".*/\1/')"
    fi
  fi
  if [[ -z "$PROJECT_ID" ]]; then
    PROJECT_ID="zecx-hpot"
    WARN "FIREBASE_PROJECT_ID not set; defaulting to '$PROJECT_ID'"
  fi
  INFO "Firebase project: $PROJECT_ID"
fi

CREDS_DST="$CONF_DIR/serviceAccountKey.json"
if [[ "$USE_INGEST" == true ]]; then
  INFO "Skipping service account credential setup (ingest mode)"
else
  # Locate service account credentials
  if [[ -n "$CREDS_IN" && -r "$CREDS_IN" ]]; then
    install -m 0600 "$CREDS_IN" "$CREDS_DST"
  elif [[ -r "$CREDS_DST" ]]; then
    :
  elif [[ -r "$SCRIPT_DIR/serviceAccountKey.json" ]]; then
    install -m 0600 "$SCRIPT_DIR/serviceAccountKey.json" "$CREDS_DST"
  elif [[ -r "$REPO_ROOT/serviceAccountKey.json" ]]; then
    install -m 0600 "$REPO_ROOT/serviceAccountKey.json" "$CREDS_DST"
  else
    ERR "Service account key not found. For easiest setup, set ZECX_INGEST_URL and re-run. Or provide --creds <path> or place it at $CREDS_DST"
    exit 2
  fi

  # If no project was specified, try to detect from credentials
  if [[ -z "$PROJECT_ID" && -r "$CREDS_DST" ]]; then
    if command -v jq >/dev/null 2>&1; then
      PROJECT_ID="$(jq -r '.project_id // empty' "$CREDS_DST")"
    else
      PROJECT_ID="$(grep -oE '"project_id"\s*:\s*"[^"]+"' "$CREDS_DST" | sed -E 's/.*"project_id"\s*:\s*"([^"]+)".*/\1/' | head -n1)"
    fi
    if [[ -n "$PROJECT_ID" ]]; then
      INFO "Detected Firebase project from credentials: $PROJECT_ID"
    fi
  fi
fi

# Build binary for host architecture (CGO disabled for portability)
if [[ -n "${USE_PREBUILT:-}" ]]; then
  INFO "Installing prebuilt agent binary"
  install -m 0755 "$SCRIPT_DIR/$BIN_NAME" "$INSTALL_DIR/$BIN_NAME"
else
  INFO "Building agent binary"
  pushd "$SCRIPT_DIR" >/dev/null
  CGO_ENABLED=0 go build -o "$BIN_NAME" ./cmd
  popd >/dev/null
  install -m 0755 "$SCRIPT_DIR/$BIN_NAME" "$INSTALL_DIR/$BIN_NAME"
fi

# Build and install unpair helper so uninstall can revoke pairing without Go
if [[ -n "${USE_PREBUILT:-}" || "$GO_AVAILABLE" -eq 0 ]]; then
  if [[ -x "$SCRIPT_DIR/zecx-unpair" ]]; then
    INFO "Installing prebuilt unpair helper"
    install -m 0755 "$SCRIPT_DIR/zecx-unpair" "$INSTALL_DIR/zecx-unpair"
  else
    if [[ "$GO_AVAILABLE" -eq 0 ]]; then
      ERR "Unpair helper prebuilt missing and Go not available. Provide $SCRIPT_DIR/zecx-unpair or install Go."
      exit 1
    else
      INFO "Go available; building unpair helper"
      pushd "$SCRIPT_DIR" >/dev/null
      CGO_ENABLED=0 go build -o zecx-unpair ./cmd/unpair
      popd >/dev/null
      install -m 0755 "$SCRIPT_DIR/zecx-unpair" "$INSTALL_DIR/zecx-unpair"
    fi
  fi
else
  INFO "Building unpair helper"
  pushd "$SCRIPT_DIR" >/dev/null
  CGO_ENABLED=0 go build -o zecx-unpair ./cmd/unpair
  popd >/dev/null
  install -m 0755 "$SCRIPT_DIR/zecx-unpair" "$INSTALL_DIR/zecx-unpair"
fi

# Allow binding to low ports without root
if command -v setcap >/dev/null 2>&1; then
  setcap 'cap_net_bind_service=+ep' "$INSTALL_DIR/$BIN_NAME" || true
fi

INSTALLED=0
if [[ -f "$UNIT_PATH" ]] || systemctl status "$SERVICE_NAME" >/dev/null 2>&1; then
  INSTALLED=1
fi

# Export runtime envs for potential seed and for service env
if [[ "$USE_INGEST" == true ]]; then
  export ZECX_INGEST_URL="$INGEST_URL"
  export ZECX_INGEST_TOKEN="$INGEST_TOKEN"
else
  export FIREBASE_PROJECT_ID="$PROJECT_ID"
  export GOOGLE_APPLICATION_CREDENTIALS="$CREDS_DST"
fi

PAIR_CODE=""
AGENT_CONF="$CONF_DIR/agent.conf"
AGENT_UUID=""
DO_SEED=1
if [[ $INSTALLED -eq 1 && -z "${RESEED:-}" ]]; then
  DO_SEED=0
fi

if [[ $DO_SEED -eq 1 ]]; then
  INFO "Seeding agent and generating pairing code (this may take a few seconds)"
  PAIR_TMP="$(mktemp -t zecx_pair_seed.XXXXXX)"
  if command -v timeout >/dev/null 2>&1; then
    timeout 10s "$INSTALL_DIR/$BIN_NAME" >"$PAIR_TMP" 2>/dev/null || true
  else
    "$INSTALL_DIR/$BIN_NAME" >"$PAIR_TMP" 2>/dev/null &
    PID=$!; sleep 8; kill -INT "$PID" 2>/dev/null || true; wait "$PID" || true
  fi
  PAIR_CODE="$(grep -oE '^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$' "$PAIR_TMP" | tail -n1 || true)"
  rm -f "$PAIR_TMP" || true
  if [[ -z "$PAIR_CODE" ]]; then
    WARN "Did not capture pairing code during seed run. The service will print it to journal on first start."
  fi
fi

if [[ -r "$AGENT_CONF" ]]; then
  AGENT_UUID="$(grep -oE '^agent_uuid=[^ ]+' "$AGENT_CONF" | sed 's/agent_uuid=//')"
fi

if [[ -n "$PAIR_CODE" ]]; then
  OUT_FILE="$CONF_DIR/pairing_code_${AGENT_UUID:-unknown}.txt"
  umask 077
  {
    printf 'pairing_code=%s\n' "$PAIR_CODE"
    printf 'project_id=%s\n' "${PROJECT_ID:-}"
    printf 'agent_uuid=%s\n' "${AGENT_UUID:-}"
    printf 'generated_at=%s\n' "$(date -Iseconds)"
  } > "$OUT_FILE"
  chmod 600 "$OUT_FILE" || true
fi

# Create systemd unit
INFO "Installing systemd unit $SERVICE_NAME"
if [[ "$USE_INGEST" == true ]]; then
  cat >"$UNIT_PATH" <<EOF
[Unit]
Description=ZecX network dispatcher (ingest mode)
After=network.target

[Service]
ExecStart=$INSTALL_DIR/$BIN_NAME
Restart=always
RestartSec=5
Environment=ZECX_INGEST_URL=$INGEST_URL
Environment=ZECX_INGEST_TOKEN=$INGEST_TOKEN
WorkingDirectory=/

[Install]
WantedBy=multi-user.target
EOF
else
  cat >"$UNIT_PATH" <<EOF
[Unit]
Description=ZecX network dispatcher (firestore mode)
After=network.target

[Service]
ExecStart=$INSTALL_DIR/$BIN_NAME
Restart=always
RestartSec=5
Environment=FIREBASE_PROJECT_ID=$PROJECT_ID
Environment=GOOGLE_APPLICATION_CREDENTIALS=$CREDS_DST
WorkingDirectory=/

[Install]
WantedBy=multi-user.target
EOF
fi

systemctl daemon-reload
if [[ -z "${NO_START:-}" ]]; then
  if [[ $INSTALLED -eq 1 ]]; then
    if [[ -z "${NO_RESTART:-}" ]]; then
      systemctl restart "$SERVICE_NAME"
      INFO "Service restarted: $SERVICE_NAME"
    else
      INFO "Service is installed; skipping restart (--no-restart used)"
    fi
  else
    systemctl enable --now "$SERVICE_NAME"
    INFO "Service started: $SERVICE_NAME"
  fi
else
  INFO "Service installed but not started (--no-start used)"
fi

if [[ -n "$PAIR_CODE" ]]; then
  printf '\n\033[1;32mPairing code:\033[0m %s\n' "$PAIR_CODE"
  INFO "Saved to: $OUT_FILE"
  INFO "Use this code in the dashboard within 10 minutes."
else
  if [[ $INSTALLED -eq 1 ]]; then
    INFO "Existing install detected. No reseed by default. To generate a new code: systemctl restart $SERVICE_NAME and check journalctl. Or rerun with --reseed."
  else
    INFO "Pairing code will be available via: journalctl -u $SERVICE_NAME --since \"5 minutes ago\""
  fi
fi

INFO "Installed $BIN_NAME as $SERVICE_NAME"
