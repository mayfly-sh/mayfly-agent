//! Inter-process communication with the privileged `mayfly-helper`.
//!
//! The agent runs **unprivileged** and delegates the one security-critical
//! capability it must not hold — replacing OpenSSH `TrustedUserCAKeys` and
//! reloading `sshd` — to the root `mayfly-helper` (a **separate repository**)
//! over an authenticated Unix Domain Socket. See ADR-0008/ADR-0009 and
//! `contracts/helper-socket.json`.
//!
//! This module is the agent's side of that boundary only:
//!
//! * [`protocol`] — the request/response types, length-prefixed framing, and
//!   constant-time token comparison. This is a **byte-identical copy** of the
//!   canonical protocol owned by `mayfly-helper`, kept in sync pending a shared
//!   crate (ADR-0009, BL-017).
//! * [`client`] — [`HelperClient`], the thin client used to call the helper, and
//!   [`HelperBundleApplier`], the production
//!   [`BundleApplier`](crate::protocol::ca_sync::BundleApplier) that routes the
//!   live CA-bundle apply path through the helper.
//!
//! Everything *below* this boundary (the socket server, the privileged
//! operations, the `sshd` control seam) lives in the `mayfly-helper` repository.

pub mod client;
pub mod protocol;

pub use client::{HelperBundleApplier, HelperClient};
pub use protocol::{Operation, Outcome, Request, Response, MAX_BODY_BYTES, PROTOCOL_VERSION};
