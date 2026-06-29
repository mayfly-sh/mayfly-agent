//! Startup runtime validation.
//!
//! Before the daemon begins its work it checks its environment and reports
//! actionable, **path-free** diagnostics. Checks are classified:
//!
//! * [`Severity::Fail`] — the agent cannot operate correctly; startup should
//!   abort (via [`ValidationReport::into_result`]).
//! * [`Severity::Warn`] — degraded but survivable (e.g. the helper is not yet
//!   reachable: the agent can still enroll/heartbeat and will retry applies).
//! * [`Severity::Ok`] — the check passed.
//!
//! Everything here is read-only and requires no privileges, so it is fully
//! testable with temporary directories.

use std::path::Path;

use crate::config::Config;
use crate::errors::{Error, Result};
use crate::ipc::HelperClient;
use crate::platform::systemd;
use crate::ssh::sshd_config;

/// The severity of a single validation [`Check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// The check passed.
    Ok,
    /// Degraded but survivable.
    Warn,
    /// Fatal: the agent should not continue.
    Fail,
}

/// A single named validation result with an optional non-sensitive detail.
#[derive(Debug, Clone)]
pub struct Check {
    /// A stable check identifier (e.g. `identity`).
    pub name: &'static str,
    /// The outcome severity.
    pub severity: Severity,
    /// A fixed, non-sensitive description; never a path or secret.
    pub detail: Option<&'static str>,
}

impl Check {
    fn ok(name: &'static str) -> Self {
        Self {
            name,
            severity: Severity::Ok,
            detail: None,
        }
    }
    fn warn(name: &'static str, detail: &'static str) -> Self {
        Self {
            name,
            severity: Severity::Warn,
            detail: Some(detail),
        }
    }
    fn fail(name: &'static str, detail: &'static str) -> Self {
        Self {
            name,
            severity: Severity::Fail,
            detail: Some(detail),
        }
    }
}

/// The aggregate result of [`validate_startup`].
#[derive(Debug, Clone)]
pub struct ValidationReport {
    /// The individual checks, in execution order.
    pub checks: Vec<Check>,
}

impl ValidationReport {
    /// Whether any check is [`Severity::Fail`].
    pub fn has_failures(&self) -> bool {
        self.checks.iter().any(|c| c.severity == Severity::Fail)
    }

    /// Emit each check via structured logging at an appropriate level.
    pub fn log(&self) {
        for check in &self.checks {
            match check.severity {
                Severity::Ok => tracing::info!(check = check.name, "startup check ok"),
                Severity::Warn => {
                    tracing::warn!(
                        check = check.name,
                        detail = check.detail,
                        "startup check degraded"
                    )
                }
                Severity::Fail => {
                    tracing::error!(
                        check = check.name,
                        detail = check.detail,
                        "startup check failed"
                    )
                }
            }
        }
    }

    /// Convert into a [`Result`]: `Err` if any check failed fatally.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigInvalid`] naming the failing checks when any check
    /// is [`Severity::Fail`].
    pub fn into_result(self) -> Result<()> {
        let failed: Vec<&str> = self
            .checks
            .iter()
            .filter(|c| c.severity == Severity::Fail)
            .map(|c| c.name)
            .collect();
        if failed.is_empty() {
            Ok(())
        } else {
            Err(Error::config_invalid(format!(
                "startup validation failed: {}",
                failed.join(", ")
            )))
        }
    }
}

/// Run all startup checks against `config` and return a [`ValidationReport`].
///
/// Attempts a live helper `Ping` (a `Warn` if unreachable). Performs no writes.
pub fn validate_startup(config: &Config) -> ValidationReport {
    let mut checks = Vec::new();

    // 1. Configuration is internally consistent (already validated at load; this
    //    re-affirms and catches programmatic construction).
    checks.push(match config.validate() {
        Ok(()) => Check::ok("configuration"),
        Err(_) => Check::fail("configuration", "configuration is invalid"),
    });

    // 2. Identity directory must exist (holds the machine key/record).
    checks.push(dir_check(
        "identity",
        &config.identity_dir,
        Severity::Fail,
        "identity directory is missing",
    ));

    // 3. State directory should exist (the daemon persists generation/etag here).
    checks.push(dir_check(
        "state_dir",
        &config.state_dir,
        Severity::Warn,
        "state directory is missing",
    ));

    // 4. Helper token file should be present and non-empty (needed to apply).
    checks.push(match read_nonempty(&config.helper_token_path) {
        Ok(true) => Check::ok("helper_token"),
        Ok(false) => Check::warn("helper_token", "helper token file is empty"),
        Err(_) => Check::warn("helper_token", "helper token file is unreadable"),
    });

    // 5. Helper connectivity: try a live Ping.
    checks.push(helper_check(config));

    // 6. systemd presence (informational).
    checks.push(if systemd::is_systemd() {
        Check::ok("systemd")
    } else {
        Check::warn("systemd", "host is not systemd-managed")
    });

    // 7. SSH compatibility: the main sshd_config must Include the drop-in dir.
    checks.push(ssh_compat_check());

    ValidationReport { checks }
}

fn dir_check(name: &'static str, path: &Path, missing: Severity, detail: &'static str) -> Check {
    if path.is_dir() {
        Check::ok(name)
    } else {
        Check {
            name,
            severity: missing,
            detail: Some(detail),
        }
    }
}

fn read_nonempty(path: &Path) -> Result<bool> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(!text.trim().is_empty()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::Io(e)),
    }
}

fn helper_check(config: &Config) -> Check {
    let client = match HelperClient::from_paths(
        config.helper_socket_path.clone(),
        &config.helper_token_path,
    ) {
        Ok(client) => client,
        Err(_) => return Check::warn("helper", "helper token unavailable"),
    };
    match client.ping() {
        Ok(_) => Check::ok("helper"),
        Err(_) => Check::warn("helper", "helper is not reachable"),
    }
}

fn ssh_compat_check() -> Check {
    let main = Path::new("/etc/ssh/sshd_config");
    match std::fs::read_to_string(main) {
        Ok(text) if sshd_config::includes_dropin_dir(&text, sshd_config::DROPIN_DIR) => {
            Check::ok("ssh_compatibility")
        }
        Ok(_) => Check::warn(
            "ssh_compatibility",
            "sshd_config does not Include the drop-in directory",
        ),
        Err(_) => Check::warn("ssh_compatibility", "sshd_config is unreadable"),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn config_with_dirs(identity: &Path, state: &Path, socket: &Path, token: &Path) -> Config {
        let toml = format!(
            "server_url = \"https://x.example.com\"\nmachine_id = \"host-01\"\n\
             identity_dir = \"{}\"\nstate_dir = \"{}\"\n\
             helper_socket_path = \"{}\"\nhelper_token_path = \"{}\"\n",
            identity.display(),
            state.display(),
            socket.display(),
            token.display(),
        );
        Config::from_toml_with_env(&toml, |_| None).unwrap()
    }

    #[test]
    fn report_includes_all_expected_checks() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_with_dirs(
            dir.path(),
            dir.path(),
            &dir.path().join("helper.sock"),
            &dir.path().join("helper.token"),
        );
        let report = validate_startup(&cfg);
        let names: Vec<&str> = report.checks.iter().map(|c| c.name).collect();
        for expected in [
            "configuration",
            "identity",
            "state_dir",
            "helper_token",
            "helper",
            "systemd",
            "ssh_compatibility",
        ] {
            assert!(names.contains(&expected), "missing check {expected}");
        }
    }

    #[test]
    fn missing_identity_dir_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-such-identity");
        let cfg = config_with_dirs(
            &missing,
            dir.path(),
            &dir.path().join("helper.sock"),
            &dir.path().join("helper.token"),
        );
        let report = validate_startup(&cfg);
        assert!(report.has_failures());
        assert!(report.into_result().is_err());
    }

    #[test]
    fn present_dirs_pass_identity_check() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_with_dirs(
            dir.path(),
            dir.path(),
            &dir.path().join("helper.sock"),
            &dir.path().join("helper.token"),
        );
        let report = validate_startup(&cfg);
        let identity = report.checks.iter().find(|c| c.name == "identity").unwrap();
        assert_eq!(identity.severity, Severity::Ok);
        // Helper is unreachable (no server bound) → a warning, not a failure.
        let helper = report.checks.iter().find(|c| c.name == "helper").unwrap();
        assert_eq!(helper.severity, Severity::Warn);
        assert!(!report.has_failures());
    }

    #[test]
    fn empty_token_is_warning() {
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("helper.token");
        std::fs::write(&token, "   \n").unwrap();
        let cfg = config_with_dirs(
            dir.path(),
            dir.path(),
            &dir.path().join("helper.sock"),
            &token,
        );
        let report = validate_startup(&cfg);
        let check = report
            .checks
            .iter()
            .find(|c| c.name == "helper_token")
            .unwrap();
        assert_eq!(check.severity, Severity::Warn);
    }
}
