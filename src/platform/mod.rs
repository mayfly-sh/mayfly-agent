//! Linux platform abstraction.
//!
//! This module groups the host-specific operations the daemon will eventually
//! perform. In this foundation phase the wrappers exist to fix the architecture
//! and signatures; the operations that would mutate system state (restarting or
//! reloading `sshd`) deliberately perform **no action** and return
//! [`Error::Unsupported`](crate::errors::Error::Unsupported). The read-only
//! inspections ([`linux::validate_root`], [`systemd::is_systemd`]) are
//! implemented, since they change nothing.

pub mod linux;
pub mod systemd;
