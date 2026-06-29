#!/usr/bin/env bash
#
# host-entrypoint.sh — bring up a managed "host" container that runs sshd plus
# the privilege-separated Mayfly pair (mayfly-helper as root, mayfly-agent as the
# unprivileged mayfly user), all sharing the local helper socket. This models a
# real deployment target: agent + helper + sshd co-locate on the host they
# protect (the helper manages that host's sshd and the agent talks to it over a
# local Unix socket).
set -euo pipefail

log() { printf '[host] %s\n' "$*" >&2; }

# 1. Host keys + ensure the drop-in directory is Included.
[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A
mkdir -p /etc/ssh/sshd_config.d /etc/ssh/mayfly /run/sshd
if ! grep -Eqs '^\s*[Ii]nclude\s+.*sshd_config\.d' /etc/ssh/sshd_config; then
  echo "Include /etc/ssh/sshd_config.d/*.conf" >> /etc/ssh/sshd_config
fi

# 2. Mayfly user/group + directories + capability token.
getent group mayfly  >/dev/null 2>&1 || groupadd --system mayfly
getent passwd mayfly >/dev/null 2>&1 || useradd --system --gid mayfly \
  --home-dir /var/lib/mayfly --no-create-home --shell /usr/sbin/nologin mayfly
install -d -o root  -g mayfly -m 0750 /etc/mayfly-agent
install -d -o mayfly -g mayfly -m 0750 /var/lib/mayfly
install -d -o root  -g mayfly -m 2750 /run/mayfly
if [ ! -s /etc/mayfly-agent/helper.token ]; then
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > /etc/mayfly-agent/helper.token
fi
chown root:mayfly /etc/mayfly-agent/helper.token
chmod 0640 /etc/mayfly-agent/helper.token

# 3. Agent config (server URL supplied via env).
: "${MAYFLY_SERVER_URL:?MAYFLY_SERVER_URL is required}"
cat > /etc/mayfly-agent/config.toml <<EOF
server_url = "${MAYFLY_SERVER_URL}"
machine_id = "${MAYFLY_MACHINE_ID:-docker-host}"
allow_insecure_tls = ${MAYFLY_ALLOW_INSECURE_TLS:-true}
EOF
chown root:mayfly /etc/mayfly-agent/config.toml
chmod 0640 /etc/mayfly-agent/config.toml

# 4. Start sshd (foreground child), then the helper (root), then the agent.
log "starting sshd"
/usr/sbin/sshd -e

mayfly_gid="$(getent group mayfly | cut -d: -f3)"
log "starting mayfly-helper (root)"
MAYFLY_HELPER_SYSTEMCTL_BINARY=/usr/local/bin/systemctl-shim.sh \
MAYFLY_HELPER_SERVICE_NAME=ssh \
MAYFLY_HELPER_SOCKET_GID="$mayfly_gid" \
/usr/local/sbin/mayfly-helper &
helper_pid=$!

# Wait for the socket before launching the agent.
for _ in $(seq 1 50); do [ -S /run/mayfly/helper.sock ] && break; sleep 0.1; done

log "starting mayfly-agent (mayfly user)"
setpriv --reuid mayfly --regid mayfly --init-groups \
  env MAYFLY_AGENT_CONFIG=/etc/mayfly-agent/config.toml \
  /usr/local/bin/mayfly-agent &
agent_pid=$!

trap 'kill "$helper_pid" "$agent_pid" 2>/dev/null || true' TERM INT
wait -n "$helper_pid" "$agent_pid"
