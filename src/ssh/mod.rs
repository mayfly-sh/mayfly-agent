//! SSH-facing data models.
//!
//! This module contains pure, read-only parsing and validation for the two SSH
//! artifacts the daemon manages:
//!
//! * [`trusted_ca`] — the `TrustedUserCAKeys` file (a list of CA public keys);
//! * [`sshd_config`] — inspection and rendering of the `TrustedUserCAKeys`
//!   directive for the sshd drop-in.
//!
//! Nothing here performs I/O against the real system, fetches keys from the
//! network, or modifies `sshd_config`. These are deliberately parsing and
//! rendering routines only.

pub mod sshd_config;
pub mod trusted_ca;
