//! The privileged operations performed by `mayfly-helper`.
//!
//! Each operation is explicit and narrow — there is no generic filesystem or
//! command facility. All file mutation goes through the audited
//! [`crate::security`] primitives (atomic write, `fsync`, symlink rejection,
//! perm/owner validation), and all `sshd` interaction goes through the injected
//! [`SshdControl`] seam, so the whole module is testable without root or a real
//! `sshd`.
//!
//! The headline operation, [`HelperOps::apply_trusted_ca_keys`], implements the
//! rollback-safe reload workflow from ADR-0008:
//!
//! ```text
//! validate content → write temp → fsync → atomic rename → sshd -t → reload
//!   → verify active → commit            (success)
//!   → on ANY failure: restore previous file → reload → verify  (rollback)
//! ```
//!
//! It never leaves the host with an SSH configuration `sshd` rejected.

use std::path::{Path, PathBuf};

use crate::errors::{Error, Result};
use crate::helper::protocol::{Operation, Outcome, Request, Response};
use crate::helper::sshd_control::SshdControl;
use crate::security;
use crate::ssh::sshd_config;
use crate::ssh::trusted_ca::TrustedCaKeys;

/// Mode for the managed `/etc/ssh/mayfly` directory: owner-write, world-read.
const DIR_MODE: u32 = 0o755;

/// Filesystem locations the helper manages. Defaults match the agent's
/// configuration defaults; they are configurable so container tests can relocate
/// them under a writable prefix.
#[derive(Debug, Clone)]
pub struct OpsConfig {
    /// The managed `TrustedUserCAKeys` file (e.g. `/etc/ssh/mayfly/trusted_user_ca_keys`).
    pub trusted_ca_path: PathBuf,
    /// The managed sshd drop-in file (e.g. `/etc/ssh/sshd_config.d/90-mayfly.conf`).
    pub dropin_path: PathBuf,
    /// The main sshd config, read only to detect a missing `Include`.
    pub main_sshd_config: PathBuf,
}

impl Default for OpsConfig {
    fn default() -> Self {
        Self {
            trusted_ca_path: PathBuf::from("/etc/ssh/mayfly/trusted_user_ca_keys"),
            dropin_path: PathBuf::from("/etc/ssh/sshd_config.d/90-mayfly.conf"),
            main_sshd_config: PathBuf::from("/etc/ssh/sshd_config"),
        }
    }
}

impl OpsConfig {
    /// Build from `MAYFLY_HELPER_*` environment variables, falling back to
    /// [`Default`].
    pub fn from_env<F>(get_env: F) -> Self
    where
        F: Fn(&str) -> Option<String>,
    {
        let mut cfg = Self::default();
        if let Some(v) = get_env("MAYFLY_HELPER_TRUSTED_CA_PATH") {
            cfg.trusted_ca_path = PathBuf::from(v);
        }
        if let Some(v) = get_env("MAYFLY_HELPER_DROPIN_PATH") {
            cfg.dropin_path = PathBuf::from(v);
        }
        if let Some(v) = get_env("MAYFLY_HELPER_MAIN_SSHD_CONFIG") {
            cfg.main_sshd_config = PathBuf::from(v);
        }
        cfg
    }
}

/// The privileged operation executor.
pub struct HelperOps<C: SshdControl> {
    config: OpsConfig,
    sshd: C,
}

impl<C: SshdControl> HelperOps<C> {
    /// Construct with explicit configuration and an `sshd` control backend.
    pub fn new(config: OpsConfig, sshd: C) -> Self {
        Self { config, sshd }
    }

    /// Execute a request, returning a [`Response`]. This never returns `Err`:
    /// every failure is mapped to a fixed, non-sensitive [`Response`] so the
    /// server can always reply. Detail strings come from [`Error`]'s `Display`,
    /// which is guaranteed path- and secret-free.
    pub fn dispatch(&self, request: &Request) -> Response {
        match request.op {
            Operation::Ping => Response {
                ok: true,
                outcome: Outcome::Ok,
                helper_version: Some(env!("CARGO_PKG_VERSION").to_string()),
                detail: None,
            },
            Operation::EnsureDirectories => {
                self.to_response(self.ensure_directories(), Outcome::Ok)
            }
            Operation::InstallSshdDropin => match self.install_sshd_dropin() {
                Ok(outcome) => Response::success(outcome),
                Err(err) => Response::failure(Outcome::Unhealthy, err.to_string()),
            },
            Operation::ApplyTrustedCaKeys => match request.content.as_deref() {
                None => Response::failure(Outcome::RolledBack, "missing content"),
                Some(content) => match self.apply_trusted_ca_keys(content) {
                    Ok(outcome) => Response::success(outcome),
                    Err(err) => Response::failure(Outcome::RolledBack, err.to_string()),
                },
            },
            Operation::VerifyState => self.to_response(self.verify_state(), Outcome::Ok),
        }
    }

    fn to_response(&self, result: Result<()>, ok_outcome: Outcome) -> Response {
        match result {
            Ok(()) => Response::success(ok_outcome),
            Err(err) => Response::failure(Outcome::Unhealthy, err.to_string()),
        }
    }

    /// Ensure the managed directories exist with safe ownership/permissions.
    pub fn ensure_directories(&self) -> Result<()> {
        let dirs = [
            self.config.trusted_ca_path.parent(),
            self.config.dropin_path.parent(),
        ];
        for dir in dirs.into_iter().flatten() {
            ensure_directory(dir)?;
        }
        Ok(())
    }

    /// Install or refresh the sshd drop-in, then validate and reload `sshd`.
    ///
    /// Returns [`Outcome::NotModified`] when the on-disk drop-in already matches.
    /// Reports (but does not auto-fix) a missing `Include` of the drop-in
    /// directory: without it, the drop-in would be inert, which we must not
    /// silently accept.
    pub fn install_sshd_dropin(&self) -> Result<Outcome> {
        self.ensure_directories()?;
        self.ensure_include_present()?;

        let desired = sshd_config::render_dropin(&self.config.trusted_ca_path);
        if read_optional_string(&self.config.dropin_path)?.as_deref() == Some(desired.trim_end()) {
            // Already current (ignoring a trailing-newline difference); still
            // confirm sshd is healthy but skip the rewrite/reload.
            return Ok(Outcome::NotModified);
        }

        security::ensure_not_symlink(&self.config.dropin_path)?;
        security::secure_write(
            &self.config.dropin_path,
            desired.as_bytes(),
            security::MODE_PUBLIC,
        )?;
        self.sshd.validate_config()?;
        self.sshd.reload()?;
        self.sshd.is_active()?;
        tracing::info!("installed sshd drop-in and reloaded sshd");
        Ok(Outcome::Ok)
    }

    /// Atomically replace `TrustedUserCAKeys` and reload `sshd`, rolling back to
    /// the previous file on any failure.
    pub fn apply_trusted_ca_keys(&self, content: &str) -> Result<Outcome> {
        // Never write a file we cannot parse back (defence in depth).
        TrustedCaKeys::parse(content)?;
        self.ensure_directories()?;
        security::ensure_not_symlink(&self.config.trusted_ca_path)?;

        let previous = read_optional(&self.config.trusted_ca_path)?;
        if previous.as_deref() == Some(content.as_bytes()) {
            tracing::debug!("trusted CA keys already current; no change");
            return Ok(Outcome::NotModified);
        }

        security::secure_write(
            &self.config.trusted_ca_path,
            content.as_bytes(),
            security::MODE_PUBLIC,
        )?;

        match self.validate_reload_verify() {
            Ok(()) => {
                tracing::info!("applied new TrustedUserCAKeys and reloaded sshd");
                Ok(Outcome::Applied)
            }
            Err(err) => {
                tracing::error!(error = %err, "apply failed; restoring previous TrustedUserCAKeys");
                self.rollback(previous.as_deref());
                Err(err)
            }
        }
    }

    /// Verify the managed files' ownership/permissions and that `sshd` is
    /// healthy.
    pub fn verify_state(&self) -> Result<()> {
        for path in [&self.config.dropin_path, &self.config.trusted_ca_path] {
            if read_optional(path)?.is_some() {
                security::ensure_not_symlink(path)?;
                security::ensure_not_group_or_world_writable(path)?;
            }
        }
        self.sshd.validate_config()?;
        self.sshd.is_active()
    }

    fn validate_reload_verify(&self) -> Result<()> {
        self.sshd.validate_config()?;
        self.sshd.reload()?;
        self.sshd.is_active()
    }

    /// Restore the previous trusted-CA file (or remove it if none existed) and
    /// best-effort reload `sshd`. Failures here are logged; the caller has
    /// already decided the apply failed.
    fn rollback(&self, previous: Option<&[u8]>) {
        let restore = match previous {
            Some(bytes) => {
                security::secure_write(&self.config.trusted_ca_path, bytes, security::MODE_PUBLIC)
            }
            None => remove_optional(&self.config.trusted_ca_path),
        };
        if let Err(err) = restore {
            tracing::error!(error = %err, "failed to restore previous TrustedUserCAKeys during rollback");
            return;
        }
        if let Err(err) = self.validate_reload_verify() {
            tracing::error!(error = %err, "sshd still unhealthy after rollback restore");
        }
    }

    fn ensure_include_present(&self) -> Result<()> {
        match read_optional_string(&self.config.main_sshd_config)? {
            Some(text) if sshd_config::includes_dropin_dir(&text, sshd_config::DROPIN_DIR) => {
                Ok(())
            }
            Some(_) => {
                tracing::error!(
                    "sshd_config does not Include the drop-in directory; drop-in would be inert"
                );
                Err(Error::SshdValidationFailed)
            }
            None => {
                // No main config to inspect: cannot confirm the Include, but do
                // not fabricate one. Treat as a validation failure to surface it.
                tracing::error!("sshd_config is unreadable; cannot confirm drop-in Include");
                Err(Error::SshdValidationFailed)
            }
        }
    }
}

/// Create `dir` (and parents) if absent, then enforce safe perms and reject a
/// symlinked final component.
fn ensure_directory(dir: &Path) -> Result<()> {
    if !dir.exists() {
        std::fs::create_dir_all(dir).map_err(Error::Io)?;
    }
    security::ensure_not_symlink(dir)?;
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(DIR_MODE)).map_err(Error::Io)?;
    Ok(())
}

/// Read a file's bytes, mapping a missing file to `None`.
fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::Io(e)),
    }
}

/// Read a file as a trimmed UTF-8 string, mapping missing to `None`.
fn read_optional_string(path: &Path) -> Result<Option<String>> {
    match read_optional(path)? {
        None => Ok(None),
        Some(bytes) => {
            let text = String::from_utf8(bytes).map_err(|_| Error::HelperProtocol)?;
            Ok(Some(text.trim_end().to_string()))
        }
    }
}

/// Remove a file, treating a missing file as success.
fn remove_optional(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::Io(e)),
    }
}

#[cfg(test)]
#[path = "ops_tests.rs"]
mod tests;
