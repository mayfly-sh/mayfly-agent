#!/usr/bin/env bash
#
# uninstall.sh — remove mayfly deployment artifacts. By default it PRESERVES
# runtime state (the machine identity under /etc/mayfly-agent and persisted sync
# state under /var/lib/mayfly) so a re-install does not re-enroll.
#
# Usage:
#   sudo ./uninstall.sh                # remove services/binaries/drop-in, keep state
#   sudo ./uninstall.sh --purge        # ALSO remove config, identity, token, state, user/group
set -euo pipefail

readonly MAYFLY_USER="mayfly"
readonly MAYFLY_GROUP="mayfly"
readonly AGENT_BIN_DEST="${MAYFLY_AGENT_BIN_DEST:-/usr/local/bin/mayfly-agent}"
readonly HELPER_BIN_DEST="${MAYFLY_HELPER_BIN_DEST:-/usr/local/sbin/mayfly-helper}"
readonly CONFIG_DIR="/etc/mayfly-agent"
readonly STATE_DIR="/var/lib/mayfly"
readonly SSH_CA_DIR="/etc/ssh/mayfly"
readonly DROPIN_FILE="/etc/ssh/sshd_config.d/90-mayfly.conf"
readonly UNIT_DIR="/etc/systemd/system"

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

log() { printf '[uninstall] %s\n' "$*" >&2; }
die() { printf '[uninstall] ERROR: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root"

stop_services() {
  for unit in mayfly-agent.service mayfly-helper.service; do
    if systemctl list-unit-files "$unit" >/dev/null 2>&1; then
      log "stopping and disabling $unit"
      systemctl disable --now "$unit" 2>/dev/null || true
    fi
  done
}

remove_units() {
  rm -f "$UNIT_DIR/mayfly-agent.service" "$UNIT_DIR/mayfly-helper.service"
  systemctl daemon-reload
}

remove_binaries() {
  rm -f "$AGENT_BIN_DEST" "$HELPER_BIN_DEST"
}

remove_dropin() {
  # Removing the drop-in stops new cert logins via the Mayfly CA; reload sshd so
  # the change takes effect. We never touch the main sshd_config.
  if [ -f "$DROPIN_FILE" ]; then
    log "removing sshd drop-in and reloading sshd"
    rm -f "$DROPIN_FILE"
    if command -v sshd >/dev/null 2>&1 && sshd -t 2>/dev/null; then
      systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
    fi
  fi
}

purge_state() {
  log "purging config, identity, token, and state"
  rm -rf "$CONFIG_DIR" "$STATE_DIR" "$SSH_CA_DIR"
  if getent passwd "$MAYFLY_USER" >/dev/null 2>&1; then
    userdel "$MAYFLY_USER" 2>/dev/null || true
  fi
  if getent group "$MAYFLY_GROUP" >/dev/null 2>&1; then
    groupdel "$MAYFLY_GROUP" 2>/dev/null || true
  fi
}

main() {
  stop_services
  remove_units
  remove_binaries
  remove_dropin
  if [ "$PURGE" -eq 1 ]; then
    purge_state
  else
    log "preserving runtime state under $CONFIG_DIR and $STATE_DIR (use --purge to remove)"
  fi
  log "uninstall complete"
}

main "$@"
