//! The machine identity model and its persisted, on-disk record.
//!
//! [`MachineIdentity`] is the in-memory view of an enrolled machine. Only a
//! non-sensitive subset is persisted to disk as a [`MachineRecord`]
//! (`machine.json`): the server-assigned `machine_id`, the `server_url`, the two
//! intervals, the enrollment timestamp, and the hostname. The **enrollment
//! token is never written** here (it never touches disk at all), and the
//! private key lives solely in its own `0600` file — never in this record.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::errors::{Error, Result};
use crate::security;

/// The in-memory identity of an enrolled machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineIdentity {
    /// Server-assigned, stable machine identifier.
    pub machine_id: String,
    /// Hostname captured at enrollment time.
    pub hostname: String,
    /// The machine's Ed25519 public key (OpenSSH `authorized_keys` line).
    pub public_key: String,
    /// Path to the private key file (`machine_ed25519`).
    pub private_key_path: PathBuf,
    /// Path to the public key file (`machine_ed25519.pub`).
    pub public_key_path: PathBuf,
    /// When enrollment completed (UTC).
    pub enrolled_at: OffsetDateTime,
    /// Base URL of the Mayfly server this machine enrolled with.
    pub server_url: String,
    /// Server-assigned heartbeat interval.
    pub heartbeat_interval: Duration,
    /// Server-assigned sync interval.
    pub sync_interval: Duration,
}

/// The persisted, non-sensitive machine record (`machine.json`).
///
/// Intervals are stored as whole seconds and the timestamp as a Unix epoch, so
/// no extra `serde` time features are required and the format is unambiguous.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineRecord {
    /// Server-assigned machine identifier.
    pub machine_id: String,
    /// Hostname captured at enrollment time.
    pub hostname: String,
    /// Base URL of the Mayfly server.
    pub server_url: String,
    /// Heartbeat interval in seconds.
    pub heartbeat_interval_secs: u64,
    /// Sync interval in seconds.
    pub sync_interval_secs: u64,
    /// Enrollment time as a Unix timestamp (seconds).
    pub enrolled_at_unix: i64,
}

impl MachineRecord {
    /// Read and parse a machine record from `path`.
    ///
    /// # Errors
    ///
    /// * [`Error::Io`] if the file cannot be read.
    /// * [`Error::MachineRecordParse`] if the contents are not valid.
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).map_err(Error::Io)?;
        serde_json::from_slice(&bytes).map_err(Error::MachineRecordParse)
    }

    /// Atomically and securely persist this record to `path` (mode `0644`).
    ///
    /// # Errors
    ///
    /// * [`Error::MachineRecordSerialize`] if serialisation fails.
    /// * [`Error::Io`] / [`Error::InvalidPath`] if the write fails.
    pub fn save(&self, path: &Path) -> Result<()> {
        let mut json = serde_json::to_vec_pretty(self).map_err(Error::MachineRecordSerialize)?;
        json.push(b'\n');
        security::secure_write(path, &json, security::MODE_PUBLIC)
    }

    /// Build the in-memory [`MachineIdentity`] from this record plus the
    /// public key and key file paths.
    pub fn into_identity(
        self,
        public_key: String,
        private_key_path: PathBuf,
        public_key_path: PathBuf,
    ) -> Result<MachineIdentity> {
        let enrolled_at = OffsetDateTime::from_unix_timestamp(self.enrolled_at_unix)
            .map_err(|_| Error::MachineRecordInvalid)?;
        Ok(MachineIdentity {
            machine_id: self.machine_id,
            hostname: self.hostname,
            public_key,
            private_key_path,
            public_key_path,
            enrolled_at,
            server_url: self.server_url,
            heartbeat_interval: Duration::from_secs(self.heartbeat_interval_secs),
            sync_interval: Duration::from_secs(self.sync_interval_secs),
        })
    }
}

impl MachineIdentity {
    /// Project this identity into its persistable [`MachineRecord`].
    pub fn to_record(&self) -> MachineRecord {
        MachineRecord {
            machine_id: self.machine_id.clone(),
            hostname: self.hostname.clone(),
            server_url: self.server_url.clone(),
            heartbeat_interval_secs: self.heartbeat_interval.as_secs(),
            sync_interval_secs: self.sync_interval.as_secs(),
            enrolled_at_unix: self.enrolled_at.unix_timestamp(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn sample_record() -> MachineRecord {
        MachineRecord {
            machine_id: "srv_abc123".to_string(),
            hostname: "web-01".to_string(),
            server_url: "https://mayfly.example.com".to_string(),
            heartbeat_interval_secs: 60,
            sync_interval_secs: 300,
            enrolled_at_unix: 1_700_000_000,
        }
    }

    #[test]
    fn record_save_and_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("machine.json");
        let record = sample_record();
        record.save(&path).unwrap();
        let loaded = MachineRecord::load(&path).unwrap();
        assert_eq!(record, loaded);
    }

    #[test]
    fn record_does_not_contain_token_field() {
        let json = serde_json::to_string(&sample_record()).unwrap();
        assert!(!json.contains("token"));
        assert!(!json.contains("private"));
    }

    #[test]
    fn load_missing_record_is_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.json");
        assert!(matches!(
            MachineRecord::load(&path).unwrap_err(),
            Error::Io(_)
        ));
    }

    #[test]
    fn load_corrupt_record_is_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("machine.json");
        std::fs::write(&path, b"{ not valid json").unwrap();
        assert!(matches!(
            MachineRecord::load(&path).unwrap_err(),
            Error::MachineRecordParse(_)
        ));
    }

    #[test]
    fn record_rejects_unknown_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("machine.json");
        std::fs::write(
            &path,
            br#"{"machine_id":"x","hostname":"h","server_url":"https://s","heartbeat_interval_secs":60,"sync_interval_secs":300,"enrolled_at_unix":0,"secret":"oops"}"#,
        )
        .unwrap();
        assert!(matches!(
            MachineRecord::load(&path).unwrap_err(),
            Error::MachineRecordParse(_)
        ));
    }

    #[test]
    fn into_identity_and_back() {
        let record = sample_record();
        let identity = record
            .clone()
            .into_identity(
                "ssh-ed25519 AAAA".to_string(),
                PathBuf::from("/etc/mayfly-agent/machine_ed25519"),
                PathBuf::from("/etc/mayfly-agent/machine_ed25519.pub"),
            )
            .unwrap();
        assert_eq!(identity.machine_id, "srv_abc123");
        assert_eq!(identity.heartbeat_interval, Duration::from_secs(60));
        assert_eq!(identity.enrolled_at.unix_timestamp(), 1_700_000_000);
        assert_eq!(identity.to_record(), record);
    }
}
