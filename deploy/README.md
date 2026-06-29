# Mayfly agent — deployment

Production deployment of `mayfly-agent` with privilege separation, OpenSSH
integration, and systemd. See ADR-0008 for the security model and
`../../.cursor/contracts/helper-socket.json` for the agent↔helper protocol.

## Components

| Component | Runs as | Responsibility |
|-----------|---------|----------------|
| `mayfly-agent` | unprivileged `mayfly` user | enroll, heartbeat, CA sync, scheduling, networking, persistence, talk to helper |
| `mayfly-helper` | `root` | atomically replace `TrustedUserCAKeys`, manage the sshd drop-in, `sshd -t`, reload, verify — and nothing else |

The agent holds **no root capability**. Every privileged action is delegated to
the helper over an authenticated Unix Domain Socket (`/run/mayfly/helper.sock`,
mode `0660` `root:mayfly`). Requests carry a capability token
(`/etc/mayfly-agent/helper.token`, `0640` `root:mayfly`) compared in constant
time, and map 1:1 to an explicit, allow-listed operation. There is no generic
filesystem or command facility.

## Files installed

| Path | Owner / mode | Purpose |
|------|--------------|---------|
| `/usr/local/bin/mayfly-agent` | root 0755 | agent binary |
| `/usr/local/sbin/mayfly-helper` | root 0755 | privileged helper binary |
| `/etc/mayfly-agent/config.toml` | root:mayfly 0640 | agent configuration |
| `/etc/mayfly-agent/helper.token` | root:mayfly 0640 | helper capability token |
| `/var/lib/mayfly/` | mayfly:mayfly 0750 | persisted sync state + identity |
| `/etc/ssh/mayfly/trusted_user_ca_keys` | root 0644 | managed TrustedUserCAKeys |
| `/etc/ssh/sshd_config.d/90-mayfly.conf` | root 0644 | sshd drop-in (TrustedUserCAKeys directive) |
| `/etc/systemd/system/mayfly-{agent,helper}.service` | root 0644 | systemd units |

The main `/etc/ssh/sshd_config` is **never modified**. It must contain
`Include /etc/ssh/sshd_config.d/*.conf` (the modern OpenSSH default); the
installer and the helper both detect and report a missing `Include` rather than
silently producing an inert configuration.

## Install / uninstall

```sh
# Build release binaries (Linux target), then:
sudo MAYFLY_SERVER_URL=https://mayfly.example.com \
     MAYFLY_MACHINE_ID="$(uname -n)" \
     BINDIR=/path/to/binaries \
     ./install.sh

# Remove services/binaries/drop-in, KEEP identity + state:
sudo ./uninstall.sh
# Remove everything including identity, state, user/group:
sudo ./uninstall.sh --purge
```

`install.sh` verifies OS/arch/dependencies, optionally verifies `SHA256SUMS`,
creates the `mayfly` user/group, lays out directories with correct ownership,
installs the binaries/units/drop-in, generates the capability token, reloads
systemd, starts both services, and verifies they are active.

## systemd hardening

Both units apply `NoNewPrivileges`, `ProtectSystem`, `ProtectHome`,
`PrivateTmp`, kernel/cgroup/clock protections, `RestrictAddressFamilies`,
`MemoryDenyWriteExecute`, and a `@system-service` syscall allow-list. The agent
unit drops **all** capabilities (`CapabilityBoundingSet=`) and is network +
local-socket only. The helper unit is `ProtectSystem=full` with
`ReadWritePaths=/etc/ssh /etc/ssh/sshd_config.d`, and uses `Group=mayfly` with a
setgid `RuntimeDirectory=mayfly` so the socket it binds is group-owned by
`mayfly` (no explicit chown needed under systemd). The syscall denylist
deliberately keeps the service-manager reload path working (it does not add
`~@privileged`).

## Safe reload workflow

`ApplyTrustedCaKeys` (helper) runs: validate content → write temp → fsync →
atomic rename → `sshd -t` → reload → verify active → commit. **Any** failure
restores the previous file, reloads, and re-verifies. The host is never left with
an SSH configuration `sshd` rejects.

## Docker-first integration testing

`docker/docker-compose.yml` brings up `server` + `host` (sshd + helper + agent),
driven by `docker/run-integration.sh` from the CI host. Host-side phases
(topology up, helper socket, `sshd -t` validity, drop-in `Include`) run today;
the server-bootstrap phases (enrollment-token seeding, CA registration, SSH
certificate login, rollback-on-invalid-bundle) are gated behind
`MAYFLY_E2E_FULL=1` and finalised in increment **007b**, which wires the server's
test-mode token seeding so the flow runs without interactive GitHub OAuth.

> The container suite is **authored** in 007a and **executed** on a Linux/CI host
> in 007b (the dev environment has no running Docker daemon and no musl linker).
