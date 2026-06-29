#!/usr/bin/env bash
#
# uninstall.sh — remove the mayfly-agent deployment artifacts. By default it
# PRESERVES runtime state (machine identity under /etc/mayfly-agent and persisted
# sync state under /var/lib/mayfly) so a re-install does not re-enroll.
#
# Uninstall ORDER: remove the agent first, then the helper (from the
# mayfly-helper repository). The shared mayfly user/group are removed here only
# with --purge.
#
# Usage:
#   sudo ./uninstall.sh             # remove agent service/binary, keep state
#   sudo ./uninstall.sh --purge     # ALSO remove config, identity, state, user/group
set -euo pipefail

readonly MAYFLY_USER="mayfly"
readonly MAYFLY_GROUP="mayfly"
readonly AGENT_BIN_DEST="${MAYFLY_AGENT_BIN_DEST:-/usr/local/bin/mayfly-agent}"
readonly CONFIG_DIR="/etc/mayfly-agent"
readonly STATE_DIR="/var/lib/mayfly"
readonly UNIT_DIR="/etc/systemd/system"

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

log() { printf '[uninstall-agent] %s\n' "$*" >&2; }
die() { printf '[uninstall-agent] ERROR: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root"

stop_service() {
  if systemctl list-unit-files mayfly-agent.service >/dev/null 2>&1; then
    log "stopping and disabling mayfly-agent.service"
    systemctl disable --now mayfly-agent.service 2>/dev/null || true
  fi
}

remove_unit() {
  rm -f "$UNIT_DIR/mayfly-agent.service"
  systemctl daemon-reload
}

remove_binary() {
  rm -f "$AGENT_BIN_DEST"
}

purge_state() {
  # Note: the SSH trust files and helper token are owned by the helper; remove
  # them with the helper's uninstall --purge. Here we remove agent state.
  log "purging config, identity, and state"
  rm -rf "$CONFIG_DIR" "$STATE_DIR"
  if getent passwd "$MAYFLY_USER" >/dev/null 2>&1; then
    userdel "$MAYFLY_USER" 2>/dev/null || true
  fi
  if getent group "$MAYFLY_GROUP" >/dev/null 2>&1; then
    groupdel "$MAYFLY_GROUP" 2>/dev/null || true
  fi
}

main() {
  stop_service
  remove_unit
  remove_binary
  if [ "$PURGE" -eq 1 ]; then
    purge_state
  else
    log "preserving runtime state under $CONFIG_DIR and $STATE_DIR (use --purge to remove)"
  fi
  log "agent uninstall complete"
}

main "$@"
