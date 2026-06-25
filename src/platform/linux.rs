//! General Linux host operations.
//!
//! These are read-only inspections of the running process and host. They never
//! mutate system state.

use crate::errors::{Error, Result};

/// Return the effective user id of the current process.
pub fn effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// Validate that the process is running as root (effective uid 0).
///
/// # Errors
///
/// Returns [`Error::NotRoot`] if the effective uid is not 0.
pub fn validate_root() -> Result<()> {
    let euid = effective_uid();
    if euid == 0 {
        Ok(())
    } else {
        tracing::warn!(euid, "process is not running as root");
        Err(Error::NotRoot)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn effective_uid_matches_validate_root() {
        let euid = effective_uid();
        let result = validate_root();
        if euid == 0 {
            assert!(result.is_ok());
        } else {
            assert!(matches!(result.unwrap_err(), Error::NotRoot));
        }
    }
}
