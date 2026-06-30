//! # mayfly-agent
//!
//! A minimal, security-first Linux service whose **only** responsibility is to
//! synchronise OpenSSH `TrustedUserCAKeys` from the Mayfly server and maintain
//! the associated `sshd` configuration safely.
//!
//! This is deliberately **not** a general-purpose remote-management agent. It
//! does not execute arbitrary commands, open shells, or expose a control plane.
//!
//! ## Privilege separation (three repositories)
//!
//! Mayfly is split into three single-responsibility repositories that cooperate:
//!
//! * **`mayfly-server`** — the control plane (enrollment, certificates, bundle
//!   signing, CA lifecycle, audit), reached over HTTPS.
//! * **`mayfly-agent`** (this crate) — runs **unprivileged**. Enrollment,
//!   heartbeat, CA synchronisation, scheduling, networking, persistence, startup
//!   validation, and the **IPC client** to the helper.
//! * **`mayfly-helper`** (a separate repository) — runs as **root** and performs
//!   only the small, explicit set of privileged host operations (atomically
//!   replace `TrustedUserCAKeys`, create directories, install/update the `sshd`
//!   drop-in, validate `sshd -t`, reload, verify the service). The agent reaches
//!   it over an authenticated Unix domain socket.
//!
//! This crate therefore contains **no privileged implementation** — only the
//! [`ipc`] client and protocol it uses to delegate to `mayfly-helper`.
//!
//! ## Modules
//!
//! * [`config`] — strongly typed configuration (env overrides + validation),
//!   including the helper socket/token paths;
//! * [`clock`] — an injectable clock abstraction (no `SystemTime::now()` in
//!   business logic);
//! * [`security`] — reusable, hardened filesystem primitives (atomic, `fsync`-durable
//!   replace, permission/owner/symlink validation) for the agent's own files;
//! * [`errors`] — a single error type that never leaks filesystem paths;
//! * [`logging`] — structured `tracing` (JSON and pretty);
//! * [`state`] — the shared application state;
//! * [`platform`] — Linux host facts + root validation;
//! * [`ssh`] — read-only trusted-CA body parsing/validation and `sshd_config`
//!   `Include`-directive detection (drop-in rendering/writing is the helper's job);
//! * [`identity`] — the Ed25519 machine identity and enrollment flow (keypair,
//!   DTOs, validation, and the production HTTP enrollment client);
//! * [`protocol`] — request signing, heartbeat, and signed CA-bundle
//!   verify/apply orchestration;
//! * [`service`] — the daemon orchestrator, jittered scheduler, and startup
//!   validation;
//! * [`ipc`] — the agent-side client and protocol for delegating privileged host
//!   operations to the root `mayfly-helper` over an authenticated Unix socket.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod clock;
pub mod config;
pub mod errors;
pub mod identity;
pub mod ipc;
pub mod logging;
pub mod platform;
pub mod protocol;
pub mod security;
pub mod service;
pub mod ssh;
pub mod state;
pub mod tls;

#[cfg(test)]
mod golden_vectors;

pub use errors::{Error, Result};
pub use state::AppState;
