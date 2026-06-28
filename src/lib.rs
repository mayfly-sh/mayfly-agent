//! # mayfly-agent
//!
//! A minimal, security-first Linux daemon whose **only** responsibility is to
//! synchronise OpenSSH `TrustedUserCAKeys` from the Mayfly server and maintain
//! the associated `sshd` configuration safely. It runs as root under systemd.
//!
//! This is deliberately **not** a general-purpose remote-management agent. It
//! does not execute arbitrary commands, open shells, or expose a control plane.
//!
//! ## Scope of this crate (foundation only)
//!
//! This codebase currently provides only the internal architecture. The
//! following are intentionally **not** implemented yet:
//!
//! * networking, enrollment, heartbeats, and CA synchronisation;
//! * any modification of `sshd_config`;
//! * restarting or reloading `sshd`.
//!
//! What *is* implemented and tested:
//!
//! * [`config`] — strongly typed configuration with environment overrides and
//!   validation;
//! * [`clock`] — an injectable clock abstraction (no `SystemTime::now()` in
//!   business logic);
//! * [`security`] — reusable, hardened filesystem primitives (atomic replace,
//!   `fsync`, permission/owner/symlink validation);
//! * [`errors`] — a single error type that never leaks filesystem paths to
//!   callers;
//! * [`logging`] — structured `tracing` (JSON and pretty);
//! * [`state`] — the shared application state;
//! * [`platform`] — architecture-only wrappers for Linux/systemd operations;
//! * [`ssh`] — parsing/validation models for the trusted-CA file and the sshd
//!   drop-in (read-only; no writes);
//! * [`identity`] — the Ed25519 machine identity and the enrollment flow
//!   (machine keypair, strongly typed DTOs, validation, and a mockable API
//!   client abstraction; **no HTTP implementation and no request signing yet**).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod clock;
pub mod config;
pub mod errors;
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
