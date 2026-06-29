#!/usr/bin/env bash
#
# run-integration.sh — drive the Docker-first integration suite for milestone 007
# from the CI host. Brings up the topology and asserts the privilege-separated
# apply path end to end.
#
# Phases:
#   1. topology up; server healthy; host sshd + helper socket up         [now]
#   2. host sshd config is valid (sshd -t) with the drop-in Included     [now]
#   3. server bootstrap: seed enrollment token + register a CA           [007b]
#   4. agent enrolls, syncs; helper updates TrustedUserCAKeys            [007b]
#   5. SSH certificate login to host succeeds                            [007b]
#   6. rollback: an invalid bundle is rejected; previous file restored   [007b]
#
# Phases 3–6 require the server's test-mode token seeding (no interactive GitHub
# OAuth), wired in increment 007b. They run only when MAYFLY_E2E_FULL=1.
#
# Run on a Linux host with Docker:
#   ./deploy/docker/run-integration.sh
set -euo pipefail

readonly HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly COMPOSE=(docker compose -f "$HERE/docker-compose.yml")
readonly FULL="${MAYFLY_E2E_FULL:-0}"

log()  { printf '[e2e] %s\n' "$*" >&2; }
fail() { printf '[e2e] FAIL: %s\n' "$*" >&2; exit 1; }

cleanup() { "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT

retry() {
  local tries="$1"; shift
  local i
  for ((i = 0; i < tries; i++)); do
    if "$@"; then return 0; fi
    sleep 1
  done
  return 1
}

host_exec() { "${COMPOSE[@]}" exec -T host "$@"; }

phase_up() {
  log "phase 1: bringing up topology"
  "${COMPOSE[@]}" up --build -d
  retry 60 "${COMPOSE[@]}" exec -T host test -S /run/mayfly/helper.sock \
    || fail "helper socket did not appear"
  retry 60 host_exec sh -c 'pgrep -x sshd >/dev/null' || fail "sshd not running on host"
  log "phase 1 ok: helper socket + sshd up"
}

phase_sshd_valid() {
  log "phase 2: sshd config validity"
  host_exec sh -c 'grep -Eqs "^\s*[Ii]nclude\s+.*sshd_config\.d" /etc/ssh/sshd_config' \
    || fail "sshd_config does not Include the drop-in directory"
  host_exec /usr/sbin/sshd -t || fail "sshd -t rejected the effective configuration"
  log "phase 2 ok: sshd -t passes, drop-in dir Included"
}

bootstrap_server() {
  # TODO(007b): using the server's test-mode admin token, register a CA and mint
  # an enrollment token; export ENROLL_TOKEN and CA material for later phases.
  log "phase 3: server bootstrap (enrollment token + CA) — finalised in 007b"
}

phase_apply() {
  # TODO(007b): wait for the agent to enroll + sync, then assert the host's
  # /etc/ssh/mayfly/trusted_user_ca_keys contains the registered CA and is
  # root-owned 0644.
  log "phase 4: TrustedUserCAKeys update via helper — finalised in 007b"
}

phase_ssh_login() {
  # TODO(007b): ssh -i user_cert ... into host; expect success via the Mayfly CA.
  log "phase 5: SSH certificate login — finalised in 007b"
}

phase_rollback() {
  # TODO(007b): present a bundle that fails `sshd -t`; assert the helper rolls
  # back and the previous TrustedUserCAKeys is restored unchanged.
  log "phase 6: rollback on invalid bundle — finalised in 007b"
}

main() {
  phase_up
  phase_sshd_valid
  if [ "$FULL" = "1" ]; then
    bootstrap_server
    phase_apply
    phase_ssh_login
    phase_rollback
  else
    log "MAYFLY_E2E_FULL!=1: ran host-side phases only (server-bootstrap phases pending 007b)"
  fi
  log "integration run complete"
}

main "$@"
