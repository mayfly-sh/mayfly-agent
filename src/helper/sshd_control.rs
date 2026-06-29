//! The `sshd` control seam — the one place that executes external programs.
//!
//! Validating and reloading `sshd` cannot be done in pure Rust; it requires
//! running `sshd -t` and a service-manager reload. Per ADR-0008 this is the
//! single sanctioned exception to the project's no-shell-outs rule, and it is
//! confined to the **root helper**. All execution goes through a *fixed
//! allow-list* of absolute binaries with fixed arguments — never `sh -c`, never
//! caller-controlled arguments — and is hidden behind the [`SshdControl`] trait
//! so the privileged [`super::ops`] are fully testable with a mock.

use std::path::PathBuf;
use std::process::Command;

use crate::errors::{Error, Result};

/// Abstraction over validating, reloading, and probing `sshd`.
pub trait SshdControl: Send + Sync {
    /// Validate the effective `sshd` configuration (`sshd -t`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::SshdValidationFailed`] if `sshd` rejects the config or
    /// the validator could not be run.
    fn validate_config(&self) -> Result<()>;

    /// Reload `sshd` so a new configuration takes effect.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SshdInactive`] if the reload command fails.
    fn reload(&self) -> Result<()>;

    /// Verify `sshd` is active.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SshdInactive`] if the service is not active or the query
    /// fails.
    fn is_active(&self) -> Result<()>;
}

/// Configuration for [`SystemSshdControl`]: the absolute binary paths and the
/// service unit name. Defaults match a standard Debian/Ubuntu host; they are
/// configurable so container integration tests can point at the binaries and
/// service present in the test image.
#[derive(Debug, Clone)]
pub struct SshdControlConfig {
    /// Absolute path to the `sshd` binary (used as `<sshd> -t`).
    pub sshd_binary: PathBuf,
    /// Absolute path to `systemctl`.
    pub systemctl_binary: PathBuf,
    /// The `sshd` service/unit name (e.g. `ssh` or `sshd`).
    pub service_name: String,
}

impl Default for SshdControlConfig {
    fn default() -> Self {
        Self {
            sshd_binary: PathBuf::from("/usr/sbin/sshd"),
            systemctl_binary: PathBuf::from("/usr/bin/systemctl"),
            service_name: "ssh".to_string(),
        }
    }
}

impl SshdControlConfig {
    /// Build from `MAYFLY_HELPER_*` environment variables, falling back to
    /// [`Default`]. Used by the `mayfly-helper` binary.
    pub fn from_env<F>(get_env: F) -> Self
    where
        F: Fn(&str) -> Option<String>,
    {
        let mut cfg = Self::default();
        if let Some(v) = get_env("MAYFLY_HELPER_SSHD_BINARY") {
            cfg.sshd_binary = PathBuf::from(v);
        }
        if let Some(v) = get_env("MAYFLY_HELPER_SYSTEMCTL_BINARY") {
            cfg.systemctl_binary = PathBuf::from(v);
        }
        if let Some(v) = get_env("MAYFLY_HELPER_SERVICE_NAME") {
            cfg.service_name = v;
        }
        cfg
    }
}

/// Production [`SshdControl`] backed by `std::process::Command`.
///
/// Each method runs exactly one fixed-shape command and inspects only its exit
/// status. No shell is involved and no argument is caller-controlled.
#[derive(Debug, Clone)]
pub struct SystemSshdControl {
    config: SshdControlConfig,
}

impl SystemSshdControl {
    /// Construct from explicit configuration.
    pub fn new(config: SshdControlConfig) -> Self {
        Self { config }
    }

    /// Run a fixed command and return whether it exited successfully, logging
    /// (but never returning) its captured output for diagnostics.
    fn run(&self, command: &mut Command, what: &str) -> bool {
        match command.output() {
            Ok(output) if output.status.success() => true,
            Ok(output) => {
                tracing::warn!(
                    command = what,
                    code = output.status.code(),
                    stderr = %String::from_utf8_lossy(&output.stderr).trim(),
                    "privileged command reported failure"
                );
                false
            }
            Err(err) => {
                tracing::warn!(command = what, error = %err, "failed to execute privileged command");
                false
            }
        }
    }
}

impl SshdControl for SystemSshdControl {
    fn validate_config(&self) -> Result<()> {
        // `sshd -t` validates the effective configuration, including any
        // drop-ins pulled in via `Include`.
        let mut cmd = Command::new(&self.config.sshd_binary);
        cmd.arg("-t");
        if self.run(&mut cmd, "sshd -t") {
            Ok(())
        } else {
            Err(Error::SshdValidationFailed)
        }
    }

    fn reload(&self) -> Result<()> {
        let mut cmd = Command::new(&self.config.systemctl_binary);
        cmd.arg("reload").arg(&self.config.service_name);
        if self.run(&mut cmd, "systemctl reload") {
            Ok(())
        } else {
            Err(Error::SshdInactive)
        }
    }

    fn is_active(&self) -> Result<()> {
        let mut cmd = Command::new(&self.config.systemctl_binary);
        cmd.arg("is-active").arg(&self.config.service_name);
        if self.run(&mut cmd, "systemctl is-active") {
            Ok(())
        } else {
            Err(Error::SshdInactive)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn control_with_missing_binaries() -> SystemSshdControl {
        SystemSshdControl::new(SshdControlConfig {
            sshd_binary: PathBuf::from("/nonexistent/sshd"),
            systemctl_binary: PathBuf::from("/nonexistent/systemctl"),
            service_name: "ssh".to_string(),
        })
    }

    #[test]
    fn validate_config_fails_when_binary_missing() {
        // Exercises the exec-failure path deterministically without a real sshd.
        assert!(matches!(
            control_with_missing_binaries()
                .validate_config()
                .unwrap_err(),
            Error::SshdValidationFailed
        ));
    }

    #[test]
    fn reload_and_is_active_fail_when_binary_missing() {
        let c = control_with_missing_binaries();
        assert!(matches!(c.reload().unwrap_err(), Error::SshdInactive));
        assert!(matches!(c.is_active().unwrap_err(), Error::SshdInactive));
    }

    #[test]
    fn from_env_overrides_defaults() {
        let cfg = SshdControlConfig::from_env(|k| match k {
            "MAYFLY_HELPER_SERVICE_NAME" => Some("sshd".to_string()),
            "MAYFLY_HELPER_SSHD_BINARY" => Some("/usr/local/sbin/sshd".to_string()),
            _ => None,
        });
        assert_eq!(cfg.service_name, "sshd");
        assert_eq!(cfg.sshd_binary, PathBuf::from("/usr/local/sbin/sshd"));
        assert_eq!(cfg.systemctl_binary, PathBuf::from("/usr/bin/systemctl"));
    }
}
