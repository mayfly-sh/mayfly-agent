//! systemd-specific operations.
//!
//! [`is_systemd`] is a read-only detection and is implemented. [`reload_sshd`]
//! and [`restart_sshd`] are architecture-only in this phase: they intentionally
//! perform **no action** and return [`Error::Unsupported`]. Wiring them to the
//! service manager is deferred to a later phase so that this security-sensitive
//! capability is added deliberately and reviewed in isolation.

use std::path::Path;

use crate::errors::{Error, Result};

/// The marker directory systemd creates when it is the init system.
const SYSTEMD_RUNTIME_MARKER: &str = "/run/systemd/system";

/// Return whether the host is booted with systemd as its init system.
///
/// This mirrors the standard `sd_booted(3)` check: it tests for the presence of
/// systemd's runtime directory. It reads nothing else and changes nothing.
pub fn is_systemd() -> bool {
    Path::new(SYSTEMD_RUNTIME_MARKER).is_dir()
}

/// Reload `sshd` so a new configuration takes effect.
///
/// # Errors
///
/// Always returns [`Error::Unsupported`] in this build: reloading `sshd` is not
/// yet enabled. The wrapper exists to fix the architecture; it performs no
/// action.
pub fn reload_sshd() -> Result<()> {
    tracing::debug!("reload_sshd called but is not enabled in this build");
    Err(Error::Unsupported)
}

/// Restart `sshd`.
///
/// # Errors
///
/// Always returns [`Error::Unsupported`] in this build: restarting `sshd` is not
/// yet enabled. The wrapper exists to fix the architecture; it performs no
/// action.
pub fn restart_sshd() -> Result<()> {
    tracing::debug!("restart_sshd called but is not enabled in this build");
    Err(Error::Unsupported)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn is_systemd_matches_marker_directory() {
        assert_eq!(is_systemd(), Path::new(SYSTEMD_RUNTIME_MARKER).is_dir());
    }

    #[test]
    fn reload_sshd_is_unsupported() {
        assert!(matches!(reload_sshd().unwrap_err(), Error::Unsupported));
    }

    #[test]
    fn restart_sshd_is_unsupported() {
        assert!(matches!(restart_sshd().unwrap_err(), Error::Unsupported));
    }
}
