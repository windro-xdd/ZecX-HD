#!/usr/bin/env bash
set -euo pipefail

BIN_NAME="network-dispatcher"
UNPAIR_BIN="zecx-unpair"
SERVICE_NAME="network-dispatcher.service"
INSTALL_DIR="/usr/local/bin"
CONF_DIR="/etc/zecx-hpot"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

INFO(){ printf "\033[1;34m[INFO]\033[0m %s\n" "$*"; }
WARN(){ printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
ERR(){  printf "\033[1;31m[ERR ]\033[0m %s\n" "$*"; }

PURGE_CONF=false
if [[ "${1:-}" == "--purge" ]]; then
  PURGE_CONF=true
fi

if command -v systemctl >/dev/null 2>&1; then
  if systemctl is-active --quiet "$SERVICE_NAME"; then
    INFO "Stopping service $SERVICE_NAME"
    systemctl stop "$SERVICE_NAME" || true
  fi
  if systemctl is-enabled --quiet "$SERVICE_NAME"; then
    INFO "Disabling service $SERVICE_NAME"
    systemctl disable "$SERVICE_NAME" || true
  fi
  if [[ -f "/etc/systemd/system/$SERVICE_NAME" ]]; then
    INFO "Removing unit file /etc/systemd/system/$SERVICE_NAME"
    rm -f "/etc/systemd/system/$SERVICE_NAME"
    systemctl daemon-reload || true
  fi
else
  WARN "systemctl not found; skipping service operations"
fi

# Attempt to unpair from account prior to removing credentials
PROJ_ID_ENV="${FIREBASE_PROJECT_ID:-}"
if [[ -z "$PROJ_ID_ENV" ]]; then
  # Try to parse from systemd unit if present
  if [[ -f "/etc/systemd/system/$SERVICE_NAME" ]]; then
    PROJ_ID_ENV="$(grep -oE 'Environment=FIREBASE_PROJECT_ID=[^ ]+' "/etc/systemd/system/$SERVICE_NAME" | sed 's/.*FIREBASE_PROJECT_ID=//')"
  fi
fi
if [[ -z "$PROJ_ID_ENV" && -f "$REPO_ROOT/backend/.firebaserc" ]]; then
  if command -v jq >/dev/null 2>&1; then
    PROJ_ID_ENV="$(jq -r '.projects.default // empty' "$REPO_ROOT/backend/.firebaserc")"
  else
    PROJ_ID_ENV="$(grep -oE '"default"\s*:\s*"[^"]+"' "$REPO_ROOT/backend/.firebaserc" | sed -E 's/.*"default"\s*:\s*"([^"]+)".*/\1/')"
  fi
fi
if [[ -z "$PROJ_ID_ENV" ]]; then
  PROJ_ID_ENV="zecx-hpot"
fi

CREDS_PATH="$CONF_DIR/serviceAccountKey.json"
if [[ -r "$CREDS_PATH" ]]; then
  INFO "Unpairing agent from project '$PROJ_ID_ENV' before uninstall"
  if command -v "$INSTALL_DIR/$UNPAIR_BIN" >/dev/null 2>&1; then
    FIREBASE_PROJECT_ID="$PROJ_ID_ENV" GOOGLE_APPLICATION_CREDENTIALS="$CREDS_PATH" "$INSTALL_DIR/$UNPAIR_BIN" || WARN "Unpair helper returned non-zero; continuing"
  elif command -v "$UNPAIR_BIN" >/dev/null 2>&1; then
    FIREBASE_PROJECT_ID="$PROJ_ID_ENV" GOOGLE_APPLICATION_CREDENTIALS="$CREDS_PATH" "$UNPAIR_BIN" || WARN "Unpair helper returned non-zero; continuing"
  elif command -v go >/dev/null 2>&1 && [[ -d "$SCRIPT_DIR/cmd/unpair" ]]; then
    ( cd "$SCRIPT_DIR" && FIREBASE_PROJECT_ID="$PROJ_ID_ENV" GOOGLE_APPLICATION_CREDENTIALS="$CREDS_PATH" go run ./cmd/unpair ) || WARN "go run unpair failed; continuing"
  else
    WARN "Unpair helper not available; skipping cloud unpair"
  fi
else
  WARN "Credentials not found at $CREDS_PATH; skipping cloud unpair"
fi

# Remove any saved pairing code files to avoid confusion (codes are revoked above)
if [[ -d "$CONF_DIR" ]]; then
  rm -f "$CONF_DIR"/pairing_code_*.txt 2>/dev/null || true
fi

if [[ -f "$INSTALL_DIR/$BIN_NAME" ]]; then
  INFO "Removing binary $INSTALL_DIR/$BIN_NAME"
  rm -f "$INSTALL_DIR/$BIN_NAME"
fi

if [[ -f "$INSTALL_DIR/$UNPAIR_BIN" ]]; then
  INFO "Removing helper $INSTALL_DIR/$UNPAIR_BIN"
  rm -f "$INSTALL_DIR/$UNPAIR_BIN"
fi

if [[ "$PURGE_CONF" == true ]]; then
  if [[ -d "$CONF_DIR" ]]; then
    INFO "Purging config dir $CONF_DIR (service account, agent.conf, saved pairing codes)"
    rm -rf "$CONF_DIR"
  fi
else
  INFO "Keeping config in $CONF_DIR (use --purge to remove)"
fi

INFO "Uninstall complete. System restored to pre-install state."
