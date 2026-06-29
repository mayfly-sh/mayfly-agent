//! Privilege separation: the `mayfly-helper` root service and its agent client.
//!
//! The agent (`mayfly-agent`) runs as an **unprivileged** user and performs all
//! networking, parsing, and persistence. The single security-critical capability
//! it cannot hold safely — replacing OpenSSH `TrustedUserCAKeys` and reloading
//! `sshd` — is delegated to a tiny **root** service, `mayfly-helper`, over an
//! authenticated Unix Domain Socket. See ADR-0008 and
//! `contracts/helper-socket.json`.
//!
//! Layout:
//!
//! * [`protocol`] — the shared request/response types, length-prefixed framing,
//!   and constant-time token comparison (used by both client and server).
//! * [`sshd_control`] — the `SshdControl` seam: the *only* place that executes
//!   external programs (`sshd -t`, `systemctl`), behind a mockable trait.
//! * [`ops`] — the privileged operations themselves, built on the audited
//!   [`crate::security`] primitives and an injected [`sshd_control::SshdControl`].
//! * [`server`] — the helper's UDS accept loop, authentication, and dispatch.
//! * [`client`] — the agent-side client used to call the helper.
//!
//! Nothing here trusts a request before authenticating it, and no operation is
//! generic: every request maps 1:1 to an explicit, allow-listed action.

pub mod client;
pub mod ops;
pub mod protocol;
pub mod server;
pub mod sshd_control;

pub use client::HelperClient;
pub use ops::{HelperOps, OpsConfig};
pub use protocol::{Operation, Outcome, Request, Response, MAX_BODY_BYTES, PROTOCOL_VERSION};
pub use server::HelperServer;
pub use sshd_control::{SshdControl, SshdControlConfig, SystemSshdControl};
