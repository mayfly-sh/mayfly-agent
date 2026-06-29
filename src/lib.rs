//! # mayfly-agent
//!
//! A minimal, security-first Linux service whose **only** responsibility is to
//! synchronise OpenSSH `TrustedUserCAKeys` from the Mayfly server and maintain
//! the associated `sshd` configuration safely.
//!
//! This is deliberately **not** a general-purpose remote-management agent. It
//! does not execute arbitrary commands, open shells, or expose a control plane.
//!
//! ## Privilege separation (two binaries)
//!
//! The crate produces two binaries that cooperate over an authenticated Unix
//! domain socket:
//!
//! * **`mayfly-agent`** (`src/main.rs`) — runs **unprivileged**. Enrollment,
//!   heartbeat, CA synchronisation, scheduling, networking, persistence, and
//!   startup validation.
//! * **`mayfly-helper`** (`src/bin/mayfly-helper.rs`) — runs as **root** and
//!   performs only the small, explicit set of privileged operations (atomically
//!   replace `TrustedUserCAKeys`, create required directories, install/update the
//!   `sshd` drop-in, validate `sshd -t`, reload, verify the service). It never
//!   executes arbitrary commands and exposes no generic filesystem API.
//!
//! ## Modules
//!
//! * [`config`] — strongly typed configuration (env overrides + validation),
//!   including the helper socket/token paths;
//! * [`clock`] — an injectable clock abstraction (no `SystemTime::now()` in
//!   business logic);
//! * [`security`] — reusable, hardened filesystem primitives (atomic replace,
//!   `fsync`, permission/owner/symlink validation);
//! * [`errors`] — a single error type that never leaks filesystem paths;
//! * [`logging`] — structured `tracing` (JSON and pretty);
//! * [`state`] — the shared application state;
//! * [`platform`] — Linux host facts + root validation;
//! * [`ssh`] — trusted-CA parsing/validation + `sshd` drop-in rendering and
//!   `Include`-directive detection;
//! * [`identity`] — the Ed25519 machine identity and enrollment flow (keypair,
//!   DTOs, validation, and the production HTTP enrollment client);
//! * [`protocol`] — request signing, heartbeat, and signed CA-bundle
//!   verify/apply orchestration;
//! * [`service`] — the daemon orchestrator, jittered scheduler, and startup
//!   validation;
//! * [`helper`] — the privileged helper: authenticated UDS server, the agent-side
//!   client, the explicit privileged-operation set, and the `sshd` control seam.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod clock;
pub mod config;
pub mod errors;
pub mod helper;
pub mod identity;
pub mod logging;
pub mod platform;
pub mod protocol;
pub mod security;
pub mod service;
pub mod ssh;
pub mod state;

pub use errors::{Error, Result};
pub use state::AppState;
