//! Persistent runtime state and startup recovery helpers.
//!
//! The authoritative CA-synchronisation state — applied generation, bundle
//! fingerprint, the pinned bundle-signing key, and the last-sync/last-success
//! timestamps — is already owned and persisted by
//! [`CaSyncService`](crate::protocol::ca_sync::CaSyncService) under the state
//! directory. This module adds the *runtime-level* pieces the daemon needs:
//!
//! * [`RuntimeStatus`] — a small, non-secret JSON snapshot
//!   (`runtime_status.json`) recording the agent version, machine id, start time,
//!   last heartbeat/sync results, applied generation, and whether the last stop
//!   was clean. It is written after meaningful events and on shutdown, and read
//!   back on startup for diagnostics — so it is *observed*, never dead data.
//! * [`read_generation`] — recover the currently-applied generation (for the
//!   heartbeat body) without a network call.
//! * [`pin_bundle_signing_key`] — persist the enrollment-provided bundle signing
//!   key as the trust-on-first-use pin, idempotently.
//! * [`ensure_state_dir`] — create the state directory `0700` on first run.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::errors::{Error, Result};
use crate::security;

/// File (under `state_dir`) holding the runtime status snapshot.
pub const RUNTIME_STATUS_FILE: &str = "runtime_status.json";

/// A non-secret snapshot of daemon runtime state, persisted across restarts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct RuntimeStatus {
    /// The agent version that last wrote this file.
    pub agent_version: String,
    /// The enrolled machine id.
    pub machine_id: String,
    /// When the current process started (Unix seconds).
    pub started_at_unix: i64,
    /// When the last heartbeat attempt completed (Unix seconds), if any.
    pub last_heartbeat_unix: Option<i64>,
    /// Whether the last heartbeat succeeded.
    pub last_heartbeat_ok: Option<bool>,
    /// When the last sync attempt completed (Unix seconds), if any.
    pub last_sync_unix: Option<i64>,
    /// A fixed, non-secret description of the last sync outcome.
    pub last_sync_outcome: Option<String>,
    /// The generation applied as of the last write.
    pub current_generation: u64,
    /// `true` if the daemon recorded a clean shutdown; `false` while running or
    /// after an unclean stop.
    pub clean_shutdown: bool,
}

impl RuntimeStatus {
    /// Absolute path to the runtime status file for `config`.
    pub fn path(config: &Config) -> PathBuf {
        config.state_dir.join(RUNTIME_STATUS_FILE)
    }

    /// Load the runtime status from `config`'s state directory.
    ///
    /// Returns `Ok(None)` when the file does not exist (first run) and a parse
    /// error otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] on read failure and [`Error::MachineRecordParse`]
    /// on malformed JSON.
    pub fn load(config: &Config) -> Result<Option<Self>> {
        let path = Self::path(config);
        match std::fs::read(&path) {
            Ok(bytes) => {
                let status = serde_json::from_slice(&bytes).map_err(Error::MachineRecordParse)?;
                Ok(Some(status))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Io(e)),
        }
    }

    /// Atomically persist this status to `config`'s state directory (`0644`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::MachineRecordSerialize`] on serialisation failure, or a
    /// write error.
    pub fn save(&self, config: &Config) -> Result<()> {
        let mut json = serde_json::to_vec_pretty(self).map_err(Error::MachineRecordSerialize)?;
        json.push(b'\n');
        security::secure_write(&Self::path(config), &json, security::MODE_PUBLIC)
    }
}

/// Ensure the state directory exists with `0700` permissions.
///
/// Creates the directory (and parents) on first run, then tightens its mode and
/// rejects a symlinked directory. Idempotent.
///
/// # Errors
///
/// Returns [`Error::Io`] on failure, or [`Error::UnexpectedSymlink`] if the path
/// is a symlink.
pub fn ensure_state_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).map_err(Error::Io)?;
    security::ensure_not_symlink(dir)?;
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(security::MODE_DIR))
        .map_err(Error::Io)?;
    Ok(())
}

/// Recover the currently-applied bundle generation from the state directory.
///
/// Returns `0` when no generation has been applied yet. Avoids any network call.
///
/// # Errors
///
/// Returns [`Error::Io`] on read failure, or [`Error::MachineRecordInvalid`] if
/// the stored value is not a non-negative integer.
pub fn read_generation(config: &Config) -> Result<u64> {
    match read_optional_string(&config.generation_path())? {
        None => Ok(0),
        Some(text) => text
            .trim()
            .parse::<u64>()
            .map_err(|_| Error::MachineRecordInvalid),
    }
}

/// Persist the server-provided bundle signing `key` as the trust-on-first-use
/// pin, idempotently.
///
/// A no-op when an operator pin is configured ([`Config::bundle_signing_public_key`]),
/// when `key` is absent, or when a pin file already exists — so re-running
/// enrollment recovery never clobbers an established pin. Returns whether a pin
/// was newly written.
///
/// # Errors
///
/// Returns a write error if the pin cannot be persisted.
pub fn pin_bundle_signing_key(config: &Config, key: Option<&str>) -> Result<bool> {
    if config.bundle_signing_public_key.is_some() {
        return Ok(false);
    }
    let Some(key) = key else { return Ok(false) };
    let path = config.bundle_signing_key_path();
    if read_optional_string(&path)?.is_some() {
        return Ok(false);
    }
    let contents = format!("{}\n", key.trim());
    security::secure_write(&path, contents.as_bytes(), security::MODE_PUBLIC)?;
    Ok(true)
}

/// Read a file as a trimmed, non-empty UTF-8 string, mapping missing/empty to
/// `None`.
fn read_optional_string(path: &Path) -> Result<Option<String>> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let text = String::from_utf8(bytes).map_err(|_| Error::MachineRecordInvalid)?;
            let trimmed = text.trim();
            Ok((!trimmed.is_empty()).then(|| trimmed.to_string()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::identity::keypair::MachineKeypair;

    fn config_in(dir: &Path, operator_pin: Option<&str>) -> Config {
        let pin_line = match operator_pin {
            Some(k) => format!("bundle_signing_public_key = \"{k}\"\n"),
            None => String::new(),
        };
        let toml = format!(
            "server_url = \"https://mayfly.example.com\"\nmachine_id = \"host-01\"\n\
state_dir = \"{}\"\n{pin_line}",
            dir.display()
        );
        Config::from_toml_with_env(&toml, |_| None).unwrap()
    }

    fn a_key() -> String {
        MachineKeypair::generate()
            .unwrap()
            .public_key_openssh()
            .unwrap()
    }

    #[test]
    fn status_round_trips_and_missing_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_in(dir.path(), None);
        assert!(RuntimeStatus::load(&config).unwrap().is_none());

        let status = RuntimeStatus {
            agent_version: "0.1.0".to_string(),
            machine_id: "srv_abc".to_string(),
            started_at_unix: 1_700_000_000,
            last_heartbeat_unix: Some(1_700_000_060),
            last_heartbeat_ok: Some(true),
            last_sync_unix: Some(1_700_000_300),
            last_sync_outcome: Some("updated".to_string()),
            current_generation: 7,
            clean_shutdown: true,
        };
        status.save(&config).unwrap();
        let loaded = RuntimeStatus::load(&config).unwrap().unwrap();
        assert_eq!(loaded, status);
    }

    #[test]
    fn read_generation_defaults_to_zero_then_reads_value() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_in(dir.path(), None);
        assert_eq!(read_generation(&config).unwrap(), 0);
        security::secure_write(&config.generation_path(), b"42\n", security::MODE_PUBLIC).unwrap();
        assert_eq!(read_generation(&config).unwrap(), 42);
    }

    #[test]
    fn pin_written_once_then_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_in(dir.path(), None);
        let key = a_key();
        assert!(pin_bundle_signing_key(&config, Some(&key)).unwrap());
        let on_disk = std::fs::read_to_string(config.bundle_signing_key_path()).unwrap();
        assert_eq!(on_disk.trim(), key.trim());
        // Second call is a no-op and does not clobber.
        assert!(!pin_bundle_signing_key(&config, Some(&a_key())).unwrap());
        let again = std::fs::read_to_string(config.bundle_signing_key_path()).unwrap();
        assert_eq!(again.trim(), key.trim());
    }

    #[test]
    fn pin_skipped_when_operator_pin_configured() {
        let dir = tempfile::tempdir().unwrap();
        let operator = a_key();
        let config = config_in(dir.path(), Some(&operator));
        assert!(!pin_bundle_signing_key(&config, Some(&a_key())).unwrap());
        assert!(!config.bundle_signing_key_path().exists());
    }

    #[test]
    fn pin_skipped_when_key_absent() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_in(dir.path(), None);
        assert!(!pin_bundle_signing_key(&config, None).unwrap());
        assert!(!config.bundle_signing_key_path().exists());
    }

    #[test]
    fn ensure_state_dir_creates_directory() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("var/lib/mayfly");
        ensure_state_dir(&nested).unwrap();
        assert!(nested.is_dir());
        // Idempotent.
        ensure_state_dir(&nested).unwrap();
    }
}
