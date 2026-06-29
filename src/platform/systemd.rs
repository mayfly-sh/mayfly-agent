//! systemd-specific operations.
//!
//! [`is_systemd`] is a read-only init-system detection used for diagnostics and
//! startup validation. The agent holds **no** privileged service-control
//! capability: reloading/validating `sshd` is owned entirely by the root
//! `mayfly-helper` (reached via [`crate::ipc`]), so no `reload_sshd`/`restart`
//! wrappers exist here.

use std::path::Path;

/// The marker directory systemd creates when it is the init system.
const SYSTEMD_RUNTIME_MARKER: &str = "/run/systemd/system";

/// Return whether the host is booted with systemd as its init system.
///
/// This mirrors the standard `sd_booted(3)` check: it tests for the presence of
/// systemd's runtime directory. It reads nothing else and changes nothing.
pub fn is_systemd() -> bool {
    Path::new(SYSTEMD_RUNTIME_MARKER).is_dir()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn is_systemd_matches_marker_directory() {
        assert_eq!(is_systemd(), Path::new(SYSTEMD_RUNTIME_MARKER).is_dir());
    }
}
