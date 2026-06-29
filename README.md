# mayfly-agent

A minimal, **security-first** Linux daemon whose only responsibility is to
synchronise OpenSSH `TrustedUserCAKeys` from the Mayfly server. It runs
**unprivileged** under systemd and delegates every privileged host operation to
the root `mayfly-helper`.

This is **not** a general-purpose remote-management agent. It does not execute
arbitrary commands, open shells, or expose a control plane.

> **Status — working runtime (milestone 009 / BL-015).** The agent runs as a
> daemon that enrolls over HTTPS, heartbeats, and synchronises the signed CA
> bundle on a jittered schedule, with graceful `SIGINT`/`SIGTERM` shutdown and
> persistent runtime state. The privileged apply (atomic write of
> `TrustedUserCAKeys`, `sshd -t`, reload, verify, rollback) is owned entirely by
> the `mayfly-helper` and reached over an authenticated Unix Domain Socket via
> the `BundleApplier` port (ADR-0012). The agent itself performs **no** privileged
> filesystem writes to host paths and never reloads `sshd`.

## What is implemented

| Module        | Responsibility |
|---------------|----------------|
| `config`      | Strongly typed config with `MAYFLY_AGENT_*` environment overrides and validation. |
| `clock`       | Injectable clock abstraction (`SystemClock` + deterministic `FixedClock`/`MockClock`). |
| `security`    | Reusable hardened FS primitives for the agent's **own** files: `secure_write`, `atomic_replace`, `fsync_dir`, and permission/owner/symlink validation. |
| `errors`      | A single `Error` type whose user-facing messages never contain filesystem paths. |
| `logging`     | Structured `tracing` in JSON or pretty format. |
| `state`       | `AppState` bundling `Config`, the `Clock`, and startup time. |
| `identity`    | Ed25519 machine identity, enrollment service, and the production HTTP enrollment client (`api_client`). |
| `protocol`    | Request signing, the heartbeat client, and the CA-bundle verify/render sync service, which delegates the privileged apply through the `BundleApplier` port. |
| `ipc`         | The `mayfly-helper` client (`HelperClient`) and `HelperBundleApplier`, the production applier that routes the live apply through the helper over the UDS. |
| `platform`    | Read-only Linux/systemd inspections: `validate_root`, `is_systemd`, host facts (`uname`/IP). No privileged service-control; that is owned by the helper. |
| `ssh`         | Read-only `TrustedUserCAKeys` body validation (defence in depth before delegating) and a startup `sshd_config` `Include` check. |
| `service`     | The `Daemon` (startup, enrollment/recovery, poll loop), `Scheduler`, `backoff`, `shutdown`, and persistent `runtime_state`. |

## Security properties

- `#![forbid(unsafe_code)]` at every crate root **and** as a lint — zero unsafe.
- **Pure Rust only**: no OpenSSL, no native-tls, no C TLS stack (verified via
  `cargo tree`).
- Clippy clean under `-D warnings` (including `unwrap_used`/`expect_used` in
  non-test code); `cargo fmt` clean; 100% documented public APIs.
- No `TODO`s, no placeholder code, no `unimplemented!`/`todo!`.
- All time flows through the injected `Clock`; business logic never calls
  `SystemTime::now()` directly.
- Atomic, crash-safe file replacement (write-temp → `fsync` → rename →
  directory `fsync`); permission bits applied before the file is moved into
  place.
- Errors never leak filesystem paths to callers; path context is logged via
  structured `tracing` instead.
- The agent runs **unprivileged** and performs no privileged filesystem writes
  or `sshd` control. Replacing `TrustedUserCAKeys`, validating with `sshd -t`,
  reloading `sshd`, and rolling back on failure are delegated to the root
  `mayfly-helper` over an authenticated Unix Domain Socket (`HelperBundleApplier`).
  If the helper is unreachable a new CA bundle apply fails non-fatally and is
  retried on the next cadence; the agent never advances its generation unless the
  helper confirms a successful apply.
- Enrollment uses a single-use token supplied **only** via the
  `MAYFLY_AGENT_ENROLLMENT_TOKEN` environment variable; it is never written to
  disk. The server-provided bundle signing key is pinned trust-on-first-use.
- TLS is rustls + ring; certificate validation is only ever disabled behind the
  dev-only `allow_insecure_tls` flag, which is logged loudly at startup.
- Synchronous, thread-based runtime (no async executor); shutdown is prompt
  because sleeps are interruptible and check the signal flag in small steps.

## Configuration

Default path: `/etc/mayfly-agent/config.toml`. Each field can be overridden by an
environment variable named `MAYFLY_AGENT_<FIELD>` (uppercase). The config path
itself can be set via `MAYFLY_AGENT_CONFIG`.

| Field                | Type            | Default | Notes |
|----------------------|-----------------|---------|-------|
| `server_url`         | string          | —       | required; must be `https://` unless `allow_insecure_tls` |
| `machine_id`         | string          | —       | required; `[A-Za-z0-9._-]`, ≤128 chars |
| `heartbeat_interval` | integer seconds | `60`    | 1..=86400 |
| `sync_interval`      | integer seconds | `300`   | 1..=86400 (interval comes from enrollment at runtime) |
| `trusted_ca_path`    | path            | `/etc/ssh/mayfly/trusted_user_ca_keys` | must be absolute, no `..` |
| `sshd_config_path`   | path            | `/etc/ssh/sshd_config.d/mayfly.conf` | must be absolute, no `..` |
| `state_dir`          | path            | `/var/lib/mayfly` | runtime state (generation, fingerprint, `runtime_status.json`) |
| `identity_dir`       | path            | `/etc/mayfly-agent` | machine keypair + `machine.json` |
| `bundle_signing_public_key` | string   | — (TOFU) | operator pin; if unset the enrollment key is pinned on first use |
| `poll_jitter_ratio`  | float           | `0.10`  | jitter applied to heartbeat/sync cadence |
| `log_level`          | enum            | `info`  | `trace`/`debug`/`info`/`warn`/`error` |
| `log_format`         | enum            | `json`  | `json`/`pretty` |
| `allow_insecure_tls` | bool            | `false` | development only |

Example `config.toml`:

```toml
server_url = "https://mayfly.example.com"
machine_id = "edge-node-01"
heartbeat_interval = 30
sync_interval = 300
log_level = "info"
log_format = "json"
```

`RUST_LOG`, if set, takes precedence over `log_level` for filtering.

## Project layout

```text
src/
├── main.rs            # binary entry point → Daemon::run
├── lib.rs             # crate root and module graph
├── config.rs          # configuration + env overrides + validation
├── state.rs           # AppState (Config + Clock + startup time)
├── errors.rs          # the single Error type (no path leakage)
├── logging.rs         # tracing setup (JSON + pretty)
├── clock.rs           # injectable Clock abstraction
├── security.rs        # hardened filesystem primitives
├── identity/
│   ├── keypair.rs     # Ed25519 MachineKeypair
│   ├── machine.rs     # MachineIdentity / MachineRecord persistence
│   ├── enrollment.rs  # EnrollmentService + MayflyApiClient trait
│   └── api_client.rs  # production HTTP enrollment client (reqwest + rustls)
├── protocol/
│   ├── signing.rs     # request signing (byte-compatible with the server)
│   ├── heartbeat.rs   # HeartbeatClient + ReqwestTransport
│   ├── ca_bundle.rs   # bundle model + canonicalisation + verification
│   └── ca_sync.rs     # CaSyncService: fetch → verify → render → BundleApplier (helper) → ack
├── ipc/
│   ├── protocol.rs    # helper socket request/response + framing (byte-identical to helper)
│   └── client.rs      # HelperClient + HelperBundleApplier (production BundleApplier)
├── platform/
│   ├── linux.rs       # validate_root, effective_uid, host_facts
│   └── systemd.rs     # is_systemd (read-only); no privileged service-control here
├── ssh/
│   ├── trusted_ca.rs  # TrustedUserCAKeys parsing/validation
│   └── sshd_config.rs # sshd_config Include detection (read-only)
└── service/
    ├── daemon.rs        # startup, enrollment/recovery, the poll loop
    ├── scheduler.rs     # dual-cadence jittered scheduler
    ├── backoff.rs       # cancellable exponential backoff (enrollment)
    ├── shutdown.rs      # signal handlers + interruptible sleeper
    ├── runtime_state.rs # RuntimeStatus + recovery + signing-key pin
    └── agent.rs         # legacy AppState holder (superseded by Daemon)
```

## Running

```bash
# First boot (not yet enrolled): supply the single-use token via the environment.
MAYFLY_AGENT_ENROLLMENT_TOKEN=mf_enroll_... \
  mayfly-agent   # reads /etc/mayfly-agent/config.toml; enrolls, then heartbeats + syncs

# Subsequent boots recover the persisted identity and need no token.
mayfly-agent

# Stop cleanly with SIGINT/SIGTERM (Ctrl-C); a clean-shutdown status is persisted.
```

## Building and testing

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

### Static, multi-architecture Linux builds

Target the musl toolchains for fully static binaries (no glibc, no OpenSSL):

```bash
rustup target add x86_64-unknown-linux-musl
rustup target add aarch64-unknown-linux-musl
rustup target add armv7-unknown-linux-musleabihf
rustup target add arm-unknown-linux-musleabihf    # armv6 / Raspberry Pi Zero W

cargo build --release --target x86_64-unknown-linux-musl
```

## License

See [LICENSE](LICENSE).
