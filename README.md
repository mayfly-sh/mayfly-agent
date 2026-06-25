# mayfly-agent

A minimal, **security-first** Linux daemon whose only responsibility is to
synchronise OpenSSH `TrustedUserCAKeys` from the Mayfly server and maintain the
associated `sshd` configuration safely. It runs as root under systemd.

This is **not** a general-purpose remote-management agent. It does not execute
arbitrary commands, open shells, or expose a control plane.

> **Status — foundation only.** This repository currently contains just the
> internal architecture. The following are intentionally **not** implemented
> yet: networking, enrollment, heartbeats, CA synchronisation, any modification
> of `sshd_config`, and restarting/reloading `sshd`. There are no installation
> scripts.

## What is implemented

| Module        | Responsibility |
|---------------|----------------|
| `config`      | Strongly typed config with `MAYFLY_AGENT_*` environment overrides and validation. |
| `clock`       | Injectable clock abstraction (`SystemClock` + deterministic `FixedClock`/`MockClock`). |
| `security`    | Reusable hardened FS primitives: `secure_write`, `atomic_replace`, `fsync`, and permission/owner/symlink validation. |
| `errors`      | A single `Error` type whose user-facing messages never contain filesystem paths. |
| `logging`     | Structured `tracing` in JSON or pretty format. |
| `state`       | `AppState` bundling `Config`, the `Clock`, and startup time. |
| `platform`    | Architecture-only Linux/systemd wrappers (`validate_root`, `is_systemd`, `reload_sshd`, `restart_sshd`). |
| `ssh`         | Read-only parsing/validation of the `TrustedUserCAKeys` file and the sshd `TrustedUserCAKeys` directive. |
| `service`     | The `Agent` orchestrator skeleton (owns `AppState`). |

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
- The privileged service-control wrappers (`reload_sshd`, `restart_sshd`) are
  architecture-only and deliberately perform **no action** (they return
  `Error::Unsupported`) until wired up in a reviewed, later phase.

## Configuration

Default path: `/etc/mayfly-agent/config.toml`. Each field can be overridden by an
environment variable named `MAYFLY_AGENT_<FIELD>` (uppercase). The config path
itself can be set via `MAYFLY_AGENT_CONFIG`.

| Field                | Type            | Default | Notes |
|----------------------|-----------------|---------|-------|
| `server_url`         | string          | —       | required; must be `https://` unless `allow_insecure_tls` |
| `machine_id`         | string          | —       | required; `[A-Za-z0-9._-]`, ≤128 chars |
| `heartbeat_interval` | integer seconds | `60`    | 1..=86400 |
| `sync_interval`      | integer seconds | `300`   | 1..=86400 |
| `trusted_ca_path`    | path            | `/etc/ssh/mayfly_ca.pub` | must be absolute, no `..` |
| `sshd_config_path`   | path            | `/etc/ssh/sshd_config.d/mayfly.conf` | must be absolute, no `..` |
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
├── main.rs            # binary entry point (foundation wiring only)
├── lib.rs             # crate root and module graph
├── config.rs          # configuration + env overrides + validation
├── state.rs           # AppState (Config + Clock + startup time)
├── errors.rs          # the single Error type (no path leakage)
├── logging.rs         # tracing setup (JSON + pretty)
├── clock.rs           # injectable Clock abstraction
├── security.rs        # hardened filesystem primitives
├── platform/
│   ├── linux.rs       # validate_root, effective_uid
│   └── systemd.rs     # is_systemd, reload_sshd, restart_sshd (architecture only)
├── ssh/
│   ├── trusted_ca.rs  # TrustedUserCAKeys parsing/validation
│   └── sshd_config.rs # TrustedUserCAKeys directive inspect/render (read-only)
└── service/
    └── agent.rs       # Agent orchestrator skeleton
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
