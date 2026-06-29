# Mayfly agent — deployment

Production deployment of the **unprivileged** `mayfly-agent` with systemd. The
agent holds **no root capability**: every privileged host action is delegated to
the root `mayfly-helper`, which now lives in its **own repository**
(`mayfly-helper`). See ADR-0008/ADR-0009 for the security model and
`../../.cursor/contracts/helper-socket.json` for the agent↔helper protocol.

## Platform layout

```
mayfly-server  ──HTTPS──▶  mayfly-agent (this repo, unprivileged)  ──UDS──▶  mayfly-helper (root)
```

| Component | Repository | Runs as | Responsibility |
|-----------|------------|---------|----------------|
| `mayfly-agent` | this repo | unprivileged `mayfly` user | enroll, heartbeat, CA sync, scheduling, networking, persistence, IPC client |
| `mayfly-helper` | `mayfly-helper` | `root` | atomically replace `TrustedUserCAKeys`, manage the sshd drop-in, `sshd -t`, reload, verify — and nothing else |

The agent talks to the helper over an authenticated Unix Domain Socket
(`/run/mayfly/helper.sock`, mode `0660` `root:mayfly`). Requests carry a
capability token (`/etc/mayfly-agent/helper.token`, `0640` `root:mayfly`)
compared in constant time, and map 1:1 to an explicit, allow-listed operation.

## Install order

Install the **helper first** (from the `mayfly-helper` repo): it creates the
shared `mayfly` user/group, the capability token, and the managed SSH
directories. Then install the agent:

```sh
# 1) in the mayfly-helper repo:  sudo ./deploy/install.sh
# 2) here:
sudo MAYFLY_SERVER_URL=https://mayfly.example.com \
     MAYFLY_MACHINE_ID="$(uname -n)" \
     BINDIR=/path/to/agent/binary \
     ./install.sh
```

## Files installed (by this script)

| Path | Owner / mode | Purpose |
|------|--------------|---------|
| `/usr/local/bin/mayfly-agent` | root 0755 | agent binary |
| `/etc/mayfly-agent/config.toml` | root:mayfly 0640 | agent configuration |
| `/var/lib/mayfly/` | mayfly:mayfly 0750 | persisted sync state + identity |
| `/etc/systemd/system/mayfly-agent.service` | root 0644 | agent systemd unit |

The helper installs `/usr/local/sbin/mayfly-helper`, the helper unit, the
`/etc/mayfly-agent/helper.token`, the `90-mayfly.conf` drop-in, and the
`/etc/ssh/mayfly/` directory. The main `/etc/ssh/sshd_config` is **never**
modified by either component.

## Uninstall

```sh
sudo ./uninstall.sh          # remove agent service/binary, KEEP identity + state
sudo ./uninstall.sh --purge  # also remove config, identity, state, user/group
# then, in the mayfly-helper repo: sudo ./deploy/uninstall.sh [--purge]
```

## systemd hardening

`systemd/mayfly-agent.service` applies `NoNewPrivileges`, `ProtectSystem`,
`ProtectHome`, `PrivateTmp`, kernel/cgroup/clock protections,
`RestrictAddressFamilies`, `MemoryDenyWriteExecute`, and a `@system-service`
syscall allow-list. The agent drops **all** capabilities
(`CapabilityBoundingSet=`) and is network + local-socket only.

## Integration testing

The cross-repo Docker integration harness spans all three repositories
(`mayfly-server` + `mayfly-agent` + `mayfly-helper`). It is **not** part of this
repo after the milestone-008 split (the previous single-crate harness built both
binaries from one crate). A dedicated three-repo integration harness is tracked
as **BL-018** / the next milestone. Helper-side container assets (the
`systemctl` shim) now live in the `mayfly-helper` repo.
