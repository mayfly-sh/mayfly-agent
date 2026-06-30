//! Strongly typed configuration with environment overrides and validation.
//!
//! Configuration is read from `/etc/mayfly-agent/config.toml`
//! ([`DEFAULT_CONFIG_PATH`]), after which individual fields may be overridden by
//! environment variables prefixed `MAYFLY_AGENT_` (see [`Config::load`]). The
//! merged result is then validated by [`Config::validate`].
//!
//! Two layers of protection apply:
//!
//! 1. `#[serde(deny_unknown_fields)]` rejects typos and stray keys at parse time.
//! 2. [`Config::validate`] enforces semantic rules the type system cannot
//!    (https-only URLs unless insecure TLS is explicitly opted into, absolute
//!    managed paths, sane intervals, …).
//!
//! Validation error messages name the offending *field*, never a path or secret.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::errors::{Error, Result};

/// The default location of the configuration file.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/mayfly-agent/config.toml";

/// Prefix for environment-variable overrides (e.g. `MAYFLY_AGENT_SERVER_URL`).
pub const ENV_PREFIX: &str = "MAYFLY_AGENT_";

const DEFAULT_HEARTBEAT_SECS: u64 = 60;
const DEFAULT_SYNC_SECS: u64 = 300;
const MIN_INTERVAL_SECS: u64 = 1;
const MAX_INTERVAL_SECS: u64 = 86_400;
const MAX_MACHINE_ID_LEN: usize = 128;
const DEFAULT_TRUSTED_CA_PATH: &str = "/etc/ssh/mayfly/trusted_user_ca_keys";
const DEFAULT_SSHD_CONFIG_PATH: &str = "/etc/ssh/sshd_config.d/mayfly.conf";
const DEFAULT_STATE_DIR: &str = "/var/lib/mayfly";
const DEFAULT_IDENTITY_DIR: &str = "/etc/mayfly-agent";
const DEFAULT_HELPER_SOCKET_PATH: &str = "/run/mayfly/helper.sock";
const DEFAULT_HELPER_TOKEN_PATH: &str = "/etc/mayfly-agent/helper.token";

/// File name (under `state_dir`) holding the last-applied bundle generation.
pub const GENERATION_FILE: &str = "current_generation";
/// File name (under `state_dir`) holding the last-applied bundle fingerprint.
pub const BUNDLE_FINGERPRINT_FILE: &str = "current_bundle.sha256";
/// File name (under `state_dir`) holding the timestamp of the last sync attempt
/// that reached the server (RFC 3339).
pub const LAST_SYNC_FILE: &str = "last_sync";
/// File name (under `state_dir`) holding the timestamp of the last successful
/// application (RFC 3339).
pub const LAST_SUCCESS_FILE: &str = "last_success";
/// File name (under `state_dir`) holding the pinned bundle-signing public key
/// (OpenSSH Ed25519 line) established on first contact.
pub const SIGNING_KEY_FILE: &str = "bundle_signing_key.pub";

/// Default jitter ratio applied to poll intervals (10%).
const DEFAULT_POLL_JITTER_RATIO: f64 = 0.10;

/// Logging verbosity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Extremely verbose tracing.
    Trace,
    /// Debug-level diagnostics.
    Debug,
    /// Normal operational messages.
    #[default]
    Info,
    /// Warnings about recoverable problems.
    Warn,
    /// Errors only.
    Error,
}

impl LogLevel {
    /// The lowercase string accepted by `tracing`'s `EnvFilter`.
    pub const fn as_filter_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }

    /// Parse a case-insensitive level name.
    fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "trace" => Some(Self::Trace),
            "debug" => Some(Self::Debug),
            "info" => Some(Self::Info),
            "warn" => Some(Self::Warn),
            "error" => Some(Self::Error),
            _ => None,
        }
    }
}

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Machine-readable JSON, one object per line.
    #[default]
    Json,
    /// Human-readable, coloured output for interactive use.
    Pretty,
}

impl LogFormat {
    /// Parse a case-insensitive format name.
    fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "json" => Some(Self::Json),
            "pretty" => Some(Self::Pretty),
            _ => None,
        }
    }
}

/// The fully merged, validated agent configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Base URL of the Mayfly server. Must be `https://` unless
    /// [`allow_insecure_tls`](Config::allow_insecure_tls) is set.
    pub server_url: String,

    /// Stable identifier for this machine.
    pub machine_id: String,

    /// Interval between heartbeats (TOML key holds whole seconds).
    #[serde(with = "duration_secs", default = "default_heartbeat")]
    pub heartbeat_interval: Duration,

    /// Interval between CA synchronisations (TOML key holds whole seconds).
    #[serde(with = "duration_secs", default = "default_sync")]
    pub sync_interval: Duration,

    /// Absolute path to the managed `TrustedUserCAKeys` file.
    ///
    /// This is **informational** on the agent side: since BL-015 the privileged
    /// write is owned by the `mayfly-helper`, which holds the authoritative path
    /// (its own `MAYFLY_HELPER_TRUSTED_CA_PATH`). The field is retained for
    /// operator reference and config compatibility; the agent does not write it.
    #[serde(default = "default_trusted_ca_path")]
    pub trusted_ca_path: PathBuf,

    /// Absolute path to the managed sshd configuration drop-in.
    #[serde(default = "default_sshd_config_path")]
    pub sshd_config_path: PathBuf,

    /// Absolute path to the daemon's mutable state directory. Holds the
    /// persisted CA-bundle generation and fingerprint metadata.
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,

    /// Absolute path to the directory holding the machine identity: the Ed25519
    /// private/public key and the persisted machine record. Conventionally the
    /// agent's config directory (`/etc/mayfly-agent`); kept separate from
    /// [`state_dir`](Config::state_dir) so long-lived secrets live under `/etc`
    /// while mutable runtime state lives under `/var/lib`.
    #[serde(default = "default_identity_dir")]
    pub identity_dir: PathBuf,

    /// Absolute path to the privileged helper's Unix Domain Socket. The agent
    /// connects here to perform the root-only operations (apply
    /// `TrustedUserCAKeys`, manage the sshd drop-in, reload `sshd`). See ADR-0008.
    #[serde(default = "default_helper_socket_path")]
    pub helper_socket_path: PathBuf,

    /// Absolute path to the helper capability-token file. The token authenticates
    /// the agent to the helper; the file is owned `root:mayfly` mode `0640` and is
    /// never logged.
    #[serde(default = "default_helper_token_path")]
    pub helper_token_path: PathBuf,

    /// Operator-provisioned bundle-signing public key (OpenSSH Ed25519 line).
    ///
    /// When set, this is the trust anchor for bundle signatures: a bundle whose
    /// `bundle_signing_public_key` differs from this value is rejected. When
    /// unset, the agent pins the first key it sees (trust-on-first-use) under
    /// [`Config::bundle_signing_key_path`].
    #[serde(default)]
    pub bundle_signing_public_key: Option<String>,

    /// Fractional jitter applied to poll intervals, in `[0.0, 1.0]`. A value of
    /// `0.1` spreads polls across up to +10% of the base interval to avoid
    /// thundering-herd alignment across a fleet.
    #[serde(default = "default_poll_jitter_ratio")]
    pub poll_jitter_ratio: f64,

    /// Logging verbosity.
    #[serde(default)]
    pub log_level: LogLevel,

    /// Logging output format.
    #[serde(default)]
    pub log_format: LogFormat,

    /// Allow plaintext / unverified TLS. **Development only.**
    #[serde(default)]
    pub allow_insecure_tls: bool,

    /// Optional path to a PEM CA bundle to trust for the server's TLS, in
    /// addition to the built-in WebPKI roots. Use this to pin a private or
    /// internal CA that issues the Mayfly server's certificate. Certificate
    /// verification stays fully enabled; this is the **secure** alternative to
    /// [`allow_insecure_tls`](Config::allow_insecure_tls) (which disables
    /// verification entirely and must never be used in production).
    #[serde(default)]
    pub tls_ca_path: Option<PathBuf>,
}

fn default_heartbeat() -> Duration {
    Duration::from_secs(DEFAULT_HEARTBEAT_SECS)
}

fn default_sync() -> Duration {
    Duration::from_secs(DEFAULT_SYNC_SECS)
}

fn default_trusted_ca_path() -> PathBuf {
    PathBuf::from(DEFAULT_TRUSTED_CA_PATH)
}

fn default_sshd_config_path() -> PathBuf {
    PathBuf::from(DEFAULT_SSHD_CONFIG_PATH)
}

fn default_state_dir() -> PathBuf {
    PathBuf::from(DEFAULT_STATE_DIR)
}

fn default_identity_dir() -> PathBuf {
    PathBuf::from(DEFAULT_IDENTITY_DIR)
}

fn default_helper_socket_path() -> PathBuf {
    PathBuf::from(DEFAULT_HELPER_SOCKET_PATH)
}

fn default_helper_token_path() -> PathBuf {
    PathBuf::from(DEFAULT_HELPER_TOKEN_PATH)
}

fn default_poll_jitter_ratio() -> f64 {
    DEFAULT_POLL_JITTER_RATIO
}

impl Config {
    /// Load configuration from `path`, apply environment overrides from the
    /// process environment, and validate the result.
    ///
    /// # Errors
    ///
    /// * [`Error::ConfigRead`] if the file cannot be read.
    /// * [`Error::ConfigParse`] if the file is not valid TOML or has unknown
    ///   fields.
    /// * [`Error::ConfigInvalid`] if an override cannot be parsed or validation
    ///   fails.
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let raw = std::fs::read_to_string(path).map_err(Error::ConfigRead)?;
        Self::from_toml_with_env(&raw, |key| std::env::var(key).ok())
    }

    /// Parse `toml_str`, apply overrides obtained from `get_env`, and validate.
    ///
    /// `get_env` is the seam used by tests to inject a deterministic
    /// environment without touching the real process environment.
    ///
    /// # Errors
    ///
    /// See [`Config::load`].
    pub fn from_toml_with_env<F>(toml_str: &str, get_env: F) -> Result<Self>
    where
        F: Fn(&str) -> Option<String>,
    {
        let mut config: Config = toml::from_str(toml_str).map_err(Error::ConfigParse)?;
        config.apply_env_overrides(&get_env)?;
        config.validate()?;
        Ok(config)
    }

    /// Apply `MAYFLY_AGENT_*` overrides from `get_env` onto `self`.
    fn apply_env_overrides<F>(&mut self, get_env: &F) -> Result<()>
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(v) = get_env(&key("SERVER_URL")) {
            self.server_url = v;
        }
        if let Some(v) = get_env(&key("MACHINE_ID")) {
            self.machine_id = v;
        }
        if let Some(v) = get_env(&key("HEARTBEAT_INTERVAL")) {
            self.heartbeat_interval = Duration::from_secs(parse_u64("heartbeat_interval", &v)?);
        }
        if let Some(v) = get_env(&key("SYNC_INTERVAL")) {
            self.sync_interval = Duration::from_secs(parse_u64("sync_interval", &v)?);
        }
        if let Some(v) = get_env(&key("TRUSTED_CA_PATH")) {
            self.trusted_ca_path = PathBuf::from(v);
        }
        if let Some(v) = get_env(&key("SSHD_CONFIG_PATH")) {
            self.sshd_config_path = PathBuf::from(v);
        }
        if let Some(v) = get_env(&key("STATE_DIR")) {
            self.state_dir = PathBuf::from(v);
        }
        if let Some(v) = get_env(&key("IDENTITY_DIR")) {
            self.identity_dir = PathBuf::from(v);
        }
        if let Some(v) = get_env(&key("HELPER_SOCKET_PATH")) {
            self.helper_socket_path = PathBuf::from(v);
        }
        if let Some(v) = get_env(&key("HELPER_TOKEN_PATH")) {
            self.helper_token_path = PathBuf::from(v);
        }
        if let Some(v) = get_env(&key("BUNDLE_SIGNING_PUBLIC_KEY")) {
            let trimmed = v.trim();
            self.bundle_signing_public_key = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            };
        }
        if let Some(v) = get_env(&key("POLL_JITTER_RATIO")) {
            self.poll_jitter_ratio = parse_f64("poll_jitter_ratio", &v)?;
        }
        if let Some(v) = get_env(&key("LOG_LEVEL")) {
            self.log_level = LogLevel::parse(&v)
                .ok_or_else(|| Error::config_invalid("log_level is not a valid level"))?;
        }
        if let Some(v) = get_env(&key("LOG_FORMAT")) {
            self.log_format = LogFormat::parse(&v)
                .ok_or_else(|| Error::config_invalid("log_format must be 'json' or 'pretty'"))?;
        }
        if let Some(v) = get_env(&key("ALLOW_INSECURE_TLS")) {
            self.allow_insecure_tls = parse_bool("allow_insecure_tls", &v)?;
        }
        if let Some(v) = get_env(&key("TLS_CA_PATH")) {
            let trimmed = v.trim();
            self.tls_ca_path = if trimmed.is_empty() {
                None
            } else {
                Some(PathBuf::from(trimmed))
            };
        }
        Ok(())
    }

    /// Validate semantic invariants. See the module docs for the rules.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigInvalid`] describing the first violated rule.
    pub fn validate(&self) -> Result<()> {
        self.validate_server_url()?;
        validate_machine_id(&self.machine_id)?;
        validate_interval("heartbeat_interval", self.heartbeat_interval)?;
        validate_interval("sync_interval", self.sync_interval)?;
        validate_managed_path("trusted_ca_path", &self.trusted_ca_path)?;
        validate_managed_path("sshd_config_path", &self.sshd_config_path)?;
        validate_managed_path("state_dir", &self.state_dir)?;
        validate_managed_path("identity_dir", &self.identity_dir)?;
        validate_managed_path("helper_socket_path", &self.helper_socket_path)?;
        validate_managed_path("helper_token_path", &self.helper_token_path)?;
        validate_jitter_ratio(self.poll_jitter_ratio)?;
        validate_optional_signing_key(self.bundle_signing_public_key.as_deref())?;
        if let Some(path) = &self.tls_ca_path {
            validate_managed_path("tls_ca_path", path)?;
        }

        if self.allow_insecure_tls {
            tracing::warn!(
                "allow_insecure_tls is enabled; this disables TLS protections and must not be used in production"
            );
        }
        Ok(())
    }

    /// Absolute path to the file storing the last-applied bundle generation.
    pub fn generation_path(&self) -> PathBuf {
        self.state_dir.join(GENERATION_FILE)
    }

    /// Absolute path to the file storing the last-applied bundle fingerprint.
    pub fn bundle_fingerprint_path(&self) -> PathBuf {
        self.state_dir.join(BUNDLE_FINGERPRINT_FILE)
    }

    /// Absolute path to the file storing the last sync-attempt timestamp.
    pub fn last_sync_path(&self) -> PathBuf {
        self.state_dir.join(LAST_SYNC_FILE)
    }

    /// Absolute path to the file storing the last successful-apply timestamp.
    pub fn last_success_path(&self) -> PathBuf {
        self.state_dir.join(LAST_SUCCESS_FILE)
    }

    /// Absolute path to the file storing the pinned bundle-signing public key.
    pub fn bundle_signing_key_path(&self) -> PathBuf {
        self.state_dir.join(SIGNING_KEY_FILE)
    }

    fn validate_server_url(&self) -> Result<()> {
        let url = self.server_url.as_str();
        if url.trim().is_empty() {
            return Err(Error::config_invalid("server_url must not be empty"));
        }
        if url.trim() != url {
            return Err(Error::config_invalid(
                "server_url must not have leading/trailing whitespace",
            ));
        }

        if let Some(host) = url.strip_prefix("https://") {
            if host.is_empty() {
                return Err(Error::config_invalid("server_url must include a host"));
            }
            Ok(())
        } else if let Some(host) = url.strip_prefix("http://") {
            if !self.allow_insecure_tls {
                return Err(Error::config_invalid(
                    "server_url must use https unless allow_insecure_tls is set",
                ));
            }
            if host.is_empty() {
                return Err(Error::config_invalid("server_url must include a host"));
            }
            Ok(())
        } else {
            Err(Error::config_invalid("server_url must use http or https"))
        }
    }
}

/// The full environment-variable name for a field suffix.
fn key(suffix: &str) -> String {
    format!("{ENV_PREFIX}{suffix}")
}

fn parse_u64(field: &'static str, value: &str) -> Result<u64> {
    value
        .trim()
        .parse::<u64>()
        .map_err(|_| Error::config_invalid(format!("{field} must be a non-negative integer")))
}

fn parse_bool(field: &'static str, value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(Error::config_invalid(format!("{field} must be a boolean"))),
    }
}

fn parse_f64(field: &'static str, value: &str) -> Result<f64> {
    value
        .trim()
        .parse::<f64>()
        .map_err(|_| Error::config_invalid(format!("{field} must be a number")))
}

fn validate_jitter_ratio(ratio: f64) -> Result<()> {
    if !ratio.is_finite() || !(0.0..=1.0).contains(&ratio) {
        return Err(Error::config_invalid(
            "poll_jitter_ratio must be between 0.0 and 1.0",
        ));
    }
    Ok(())
}

fn validate_optional_signing_key(key: Option<&str>) -> Result<()> {
    let Some(key) = key else { return Ok(()) };
    if key.trim().is_empty() {
        return Err(Error::config_invalid(
            "bundle_signing_public_key must not be empty when set",
        ));
    }
    crate::identity::keypair::validate_ed25519_public_key(key)
        .map_err(|_| Error::config_invalid("bundle_signing_public_key is not a valid Ed25519 key"))
}

fn validate_machine_id(machine_id: &str) -> Result<()> {
    if machine_id.is_empty() {
        return Err(Error::config_invalid("machine_id must not be empty"));
    }
    if machine_id.len() > MAX_MACHINE_ID_LEN {
        return Err(Error::config_invalid("machine_id is too long"));
    }
    let ok = machine_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if !ok {
        return Err(Error::config_invalid(
            "machine_id may only contain ASCII letters, digits, '-', '_' and '.'",
        ));
    }
    Ok(())
}

fn validate_interval(field: &'static str, value: Duration) -> Result<()> {
    let secs = value.as_secs();
    if value.subsec_nanos() != 0 || secs < MIN_INTERVAL_SECS {
        return Err(Error::config_invalid(format!(
            "{field} must be at least {MIN_INTERVAL_SECS} second(s)"
        )));
    }
    if secs > MAX_INTERVAL_SECS {
        return Err(Error::config_invalid(format!(
            "{field} must be at most {MAX_INTERVAL_SECS} seconds"
        )));
    }
    Ok(())
}

fn validate_managed_path(field: &'static str, path: &std::path::Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Err(Error::config_invalid(format!("{field} must not be empty")));
    }
    if !path.is_absolute() {
        return Err(Error::config_invalid(format!(
            "{field} must be an absolute path"
        )));
    }
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(Error::config_invalid(format!(
            "{field} must not contain '..' components"
        )));
    }
    Ok(())
}

/// Serde adapter: (de)serialise a [`Duration`] as a whole number of seconds.
mod duration_secs {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub(super) fn serialize<S: Serializer>(value: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(value.as_secs())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let secs = u64::deserialize(d)?;
        Ok(Duration::from_secs(secs))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    const MINIMAL: &str = r#"
        server_url = "https://mayfly.example.com"
        machine_id = "host-01"
    "#;

    fn no_env(_: &str) -> Option<String> {
        None
    }

    fn load(toml: &str) -> Result<Config> {
        Config::from_toml_with_env(toml, no_env)
    }

    #[test]
    fn minimal_config_uses_defaults() {
        let cfg = load(MINIMAL).unwrap();
        assert_eq!(cfg.server_url, "https://mayfly.example.com");
        assert_eq!(cfg.machine_id, "host-01");
        assert_eq!(
            cfg.heartbeat_interval,
            Duration::from_secs(DEFAULT_HEARTBEAT_SECS)
        );
        assert_eq!(cfg.sync_interval, Duration::from_secs(DEFAULT_SYNC_SECS));
        assert_eq!(cfg.trusted_ca_path, PathBuf::from(DEFAULT_TRUSTED_CA_PATH));
        assert_eq!(
            cfg.sshd_config_path,
            PathBuf::from(DEFAULT_SSHD_CONFIG_PATH)
        );
        assert_eq!(cfg.state_dir, PathBuf::from(DEFAULT_STATE_DIR));
        assert_eq!(cfg.identity_dir, PathBuf::from(DEFAULT_IDENTITY_DIR));
        assert_eq!(
            cfg.helper_socket_path,
            PathBuf::from(DEFAULT_HELPER_SOCKET_PATH)
        );
        assert_eq!(
            cfg.helper_token_path,
            PathBuf::from(DEFAULT_HELPER_TOKEN_PATH)
        );
        assert_eq!(
            cfg.generation_path(),
            PathBuf::from("/var/lib/mayfly/current_generation")
        );
        assert_eq!(
            cfg.bundle_fingerprint_path(),
            PathBuf::from("/var/lib/mayfly/current_bundle.sha256")
        );
        assert_eq!(
            cfg.last_sync_path(),
            PathBuf::from("/var/lib/mayfly/last_sync")
        );
        assert_eq!(
            cfg.last_success_path(),
            PathBuf::from("/var/lib/mayfly/last_success")
        );
        assert_eq!(
            cfg.bundle_signing_key_path(),
            PathBuf::from("/var/lib/mayfly/bundle_signing_key.pub")
        );
        assert_eq!(cfg.bundle_signing_public_key, None);
        assert!((cfg.poll_jitter_ratio - DEFAULT_POLL_JITTER_RATIO).abs() < f64::EPSILON);
        assert_eq!(cfg.log_level, LogLevel::Info);
        assert_eq!(cfg.log_format, LogFormat::Json);
        assert!(!cfg.allow_insecure_tls);
    }

    #[test]
    fn rejects_out_of_range_jitter_ratio() {
        let toml = format!("{MINIMAL}\npoll_jitter_ratio = 1.5\n");
        assert!(matches!(load(&toml).unwrap_err(), Error::ConfigInvalid(_)));
    }

    #[test]
    fn tls_ca_path_defaults_to_none() {
        let cfg = load(MINIMAL).unwrap();
        assert_eq!(cfg.tls_ca_path, None);
    }

    #[test]
    fn accepts_absolute_tls_ca_path() {
        let toml = format!("{MINIMAL}\ntls_ca_path = \"/etc/mayfly-agent/ca.pem\"\n");
        let cfg = load(&toml).unwrap();
        assert_eq!(
            cfg.tls_ca_path,
            Some(PathBuf::from("/etc/mayfly-agent/ca.pem"))
        );
    }

    #[test]
    fn rejects_relative_tls_ca_path() {
        let toml = format!("{MINIMAL}\ntls_ca_path = \"ca.pem\"\n");
        assert!(matches!(load(&toml).unwrap_err(), Error::ConfigInvalid(_)));
    }

    #[test]
    fn tls_ca_path_env_override_sets_and_clears() {
        let with = |k: &str| -> Option<String> {
            (k == "MAYFLY_AGENT_TLS_CA_PATH").then(|| "/run/mayfly/ca.pem".to_string())
        };
        let cfg = Config::from_toml_with_env(MINIMAL, with).unwrap();
        assert_eq!(cfg.tls_ca_path, Some(PathBuf::from("/run/mayfly/ca.pem")));

        // An explicit empty override clears the pin.
        let clear =
            |k: &str| -> Option<String> { (k == "MAYFLY_AGENT_TLS_CA_PATH").then(String::new) };
        let toml = format!("{MINIMAL}\ntls_ca_path = \"/etc/mayfly-agent/ca.pem\"\n");
        let cfg = Config::from_toml_with_env(&toml, clear).unwrap();
        assert_eq!(cfg.tls_ca_path, None);
    }

    #[test]
    fn rejects_invalid_signing_key() {
        let toml = format!("{MINIMAL}\nbundle_signing_public_key = \"not-a-key\"\n");
        assert!(matches!(load(&toml).unwrap_err(), Error::ConfigInvalid(_)));
    }

    #[test]
    fn accepts_valid_pinned_signing_key() {
        let key = crate::identity::keypair::MachineKeypair::generate()
            .unwrap()
            .public_key_openssh()
            .unwrap();
        let toml = format!(
            "{MINIMAL}\nbundle_signing_public_key = \"{}\"\n",
            key.trim()
        );
        let cfg = load(&toml).unwrap();
        assert_eq!(cfg.bundle_signing_public_key.as_deref(), Some(key.trim()));
    }

    #[test]
    fn full_config_parses_all_fields() {
        let toml = r#"
            server_url = "https://srv.example.com"
            machine_id = "edge.node-7"
            heartbeat_interval = 15
            sync_interval = 120
            trusted_ca_path = "/etc/ssh/custom_ca.pub"
            sshd_config_path = "/etc/ssh/sshd_config.d/custom.conf"
            state_dir = "/var/lib/custom-mayfly"
            log_level = "debug"
            log_format = "pretty"
            allow_insecure_tls = false
        "#;
        let cfg = load(toml).unwrap();
        assert_eq!(cfg.heartbeat_interval, Duration::from_secs(15));
        assert_eq!(cfg.sync_interval, Duration::from_secs(120));
        assert_eq!(cfg.trusted_ca_path, PathBuf::from("/etc/ssh/custom_ca.pub"));
        assert_eq!(cfg.state_dir, PathBuf::from("/var/lib/custom-mayfly"));
        assert_eq!(cfg.log_level, LogLevel::Debug);
        assert_eq!(cfg.log_format, LogFormat::Pretty);
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let toml = format!("{MINIMAL}\nunexpected = true\n");
        assert!(matches!(load(&toml).unwrap_err(), Error::ConfigParse(_)));
    }

    #[test]
    fn missing_required_fields_fail() {
        let toml = r#"server_url = "https://x.example.com""#;
        assert!(matches!(load(toml).unwrap_err(), Error::ConfigParse(_)));
    }

    #[test]
    fn env_overrides_take_precedence() {
        let env = |k: &str| -> Option<String> {
            match k {
                "MAYFLY_AGENT_SERVER_URL" => Some("https://override.example.com".to_string()),
                "MAYFLY_AGENT_MACHINE_ID" => Some("overridden".to_string()),
                "MAYFLY_AGENT_HEARTBEAT_INTERVAL" => Some("10".to_string()),
                "MAYFLY_AGENT_SYNC_INTERVAL" => Some("90".to_string()),
                "MAYFLY_AGENT_LOG_LEVEL" => Some("warn".to_string()),
                "MAYFLY_AGENT_LOG_FORMAT" => Some("pretty".to_string()),
                _ => None,
            }
        };
        let cfg = Config::from_toml_with_env(MINIMAL, env).unwrap();
        assert_eq!(cfg.server_url, "https://override.example.com");
        assert_eq!(cfg.machine_id, "overridden");
        assert_eq!(cfg.heartbeat_interval, Duration::from_secs(10));
        assert_eq!(cfg.sync_interval, Duration::from_secs(90));
        assert_eq!(cfg.log_level, LogLevel::Warn);
        assert_eq!(cfg.log_format, LogFormat::Pretty);
    }

    #[test]
    fn env_override_with_invalid_integer_fails() {
        let env =
            |k: &str| (k == "MAYFLY_AGENT_HEARTBEAT_INTERVAL").then(|| "not-a-number".to_string());
        assert!(matches!(
            Config::from_toml_with_env(MINIMAL, env).unwrap_err(),
            Error::ConfigInvalid(_)
        ));
    }

    #[test]
    fn env_override_with_invalid_log_level_fails() {
        let env = |k: &str| (k == "MAYFLY_AGENT_LOG_LEVEL").then(|| "loud".to_string());
        assert!(matches!(
            Config::from_toml_with_env(MINIMAL, env).unwrap_err(),
            Error::ConfigInvalid(_)
        ));
    }

    #[test]
    fn http_url_requires_insecure_flag() {
        let toml = r#"
            server_url = "http://insecure.example.com"
            machine_id = "host"
        "#;
        assert!(matches!(load(toml).unwrap_err(), Error::ConfigInvalid(_)));

        let toml_ok = r#"
            server_url = "http://insecure.example.com"
            machine_id = "host"
            allow_insecure_tls = true
        "#;
        assert!(load(toml_ok).is_ok());
    }

    #[test]
    fn non_http_scheme_is_rejected() {
        let toml = r#"
            server_url = "ftp://example.com"
            machine_id = "host"
        "#;
        assert!(matches!(load(toml).unwrap_err(), Error::ConfigInvalid(_)));
    }

    #[test]
    fn empty_or_hostless_url_rejected() {
        for url in ["", "https://"] {
            let toml = format!("server_url = \"{url}\"\nmachine_id = \"host\"\n");
            assert!(matches!(load(&toml).unwrap_err(), Error::ConfigInvalid(_)));
        }
    }

    #[test]
    fn bad_machine_ids_are_rejected() {
        for bad in ["", "has space", "semi;colon", "slash/id", "tick`"] {
            let toml = format!("server_url = \"https://x.example.com\"\nmachine_id = \"{bad}\"\n");
            assert!(
                matches!(load(&toml).unwrap_err(), Error::ConfigInvalid(_)),
                "machine_id {bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn intervals_out_of_range_rejected() {
        let zero = format!("{MINIMAL}\nheartbeat_interval = 0\n");
        assert!(matches!(load(&zero).unwrap_err(), Error::ConfigInvalid(_)));

        let huge = format!("{MINIMAL}\nsync_interval = 999999\n");
        assert!(matches!(load(&huge).unwrap_err(), Error::ConfigInvalid(_)));
    }

    #[test]
    fn relative_or_traversal_paths_rejected() {
        let relative = format!("{MINIMAL}\ntrusted_ca_path = \"relative/ca.pub\"\n");
        assert!(matches!(
            load(&relative).unwrap_err(),
            Error::ConfigInvalid(_)
        ));

        let traversal = format!("{MINIMAL}\nsshd_config_path = \"/etc/ssh/../shadow\"\n");
        assert!(matches!(
            load(&traversal).unwrap_err(),
            Error::ConfigInvalid(_)
        ));
    }

    #[test]
    fn load_reads_from_disk_and_applies_no_env() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, MINIMAL).unwrap();
        // Use the env-injecting constructor for determinism; `load` itself is a
        // thin wrapper that reads the file then calls the same code path.
        let raw = std::fs::read_to_string(&path).unwrap();
        let cfg = Config::from_toml_with_env(&raw, no_env).unwrap();
        assert_eq!(cfg.machine_id, "host-01");
    }

    #[test]
    fn load_missing_file_reports_config_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.toml");
        assert!(matches!(
            Config::load(&path).unwrap_err(),
            Error::ConfigRead(_)
        ));
    }

    #[test]
    fn round_trips_through_toml() {
        let cfg = load(MINIMAL).unwrap();
        let serialized = toml::to_string(&cfg).unwrap();
        let reparsed = Config::from_toml_with_env(&serialized, no_env).unwrap();
        assert_eq!(cfg, reparsed);
    }
}
