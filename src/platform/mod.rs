//! Linux platform abstraction.
//!
//! This module groups the read-only host inspections the daemon performs
//! ([`linux::validate_root`], [`linux::host_facts`], [`systemd::is_systemd`]).
//! The agent holds no privileged service-control capability: mutating system
//! state (replacing `TrustedUserCAKeys`, validating/reloading `sshd`) is owned
//! entirely by the root `mayfly-helper` and reached via [`crate::ipc`].

pub mod linux;
pub mod systemd;
