#!/usr/bin/env bash
#
# systemctl-shim.sh — a minimal `systemctl` stand-in for containers without a
# real init system. The helper's SshdControl only ever calls `reload <svc>` and
# `is-active <svc>`; this maps those to direct sshd signals/checks so the full
# safe-reload workflow can run in a plain (non-systemd) container during e2e.
#
# Point the helper at it with MAYFLY_HELPER_SYSTEMCTL_BINARY=/usr/local/bin/systemctl-shim.sh
set -euo pipefail

action="${1:-}"

sshd_pid() { pgrep -x sshd | head -n1; }

case "$action" in
  reload)
    pid="$(sshd_pid || true)"
    [ -n "$pid" ] || { echo "sshd not running" >&2; exit 1; }
    kill -HUP "$pid"
    ;;
  is-active)
    if sshd_pid >/dev/null; then echo active; else echo inactive; exit 3; fi
    ;;
  *)
    echo "systemctl-shim: unsupported action: $action" >&2
    exit 64
    ;;
esac
