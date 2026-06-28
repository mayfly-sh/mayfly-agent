//! Enrollment: DTOs, validation, the API-client abstraction, and the service
//! that ties machine-identity generation to enrollment.
//!
//! ## What this module does
//!
//! * Defines the strongly typed request/response DTOs for
//!   `POST /api/v1/machines/enroll`.
//! * Rigorously validates every input *and* every server response — server
//!   responses are never trusted.
//! * Defines [`MayflyApiClient`], the transport abstraction, plus a
//!   deterministic [`MockMayflyApiClient`] for tests.
//! * Provides [`EnrollmentService`], which generates/loads the machine keypair,
//!   builds the request, and persists the resulting machine record.
//!
//! ## What this module does NOT do
//!
//! There is **no HTTP implementation** and no request signing. The enrollment
//! token is never persisted or logged, and the private key never leaves the
//! identity layer.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::clock::Clock;
use crate::errors::{Error, Result, ServerResponseError};
use crate::identity::keypair::{validate_ed25519_public_key, MachineKeypair};
use crate::identity::machine::{MachineIdentity, MachineRecord};
use crate::platform::linux::effective_uid;
use crate::security;

/// Required prefix for enrollment tokens (`mf_enroll_...`).
pub const TOKEN_PREFIX: &str = "mf_enroll_";

/// Standard file name for the machine private key.
pub const PRIVATE_KEY_FILE: &str = "machine_ed25519";
/// Standard file name for the machine public key.
pub const PUBLIC_KEY_FILE: &str = "machine_ed25519.pub";
/// Standard file name for the persisted machine record.
pub const MACHINE_RECORD_FILE: &str = "machine.json";

const MAX_TOKEN_LEN: usize = 256;
const MAX_HOSTNAME_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;
const MAX_MACHINE_ID_LEN: usize = 128;
const MIN_INTERVAL_SECS: u64 = 1;
const MAX_INTERVAL_SECS: u64 = 86_400;

/// Request body for `POST /api/v1/machines/enroll`.
///
/// Note: the [`Debug`] implementation redacts the enrollment token so it cannot
/// leak into logs via accidental `{:?}` formatting.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentRequest {
    /// The one-time enrollment token (sent over TLS; never persisted/logged).
    pub enrollment_token: String,
    /// The machine's hostname.
    pub hostname: String,
    /// Operating system (`std::env::consts::OS`).
    pub os: String,
    /// CPU architecture (`std::env::consts::ARCH`).
    pub arch: String,
    /// The reporting agent's version.
    pub agent_version: String,
    /// The machine's Ed25519 public key (OpenSSH format). Public by definition.
    pub public_key: String,
}

impl std::fmt::Debug for EnrollmentRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollmentRequest")
            .field("enrollment_token", &"<redacted>")
            .field("hostname", &self.hostname)
            .field("os", &self.os)
            .field("arch", &self.arch)
            .field("agent_version", &self.agent_version)
            .field("public_key", &self.public_key)
            .finish()
    }
}

/// Response body for `POST /api/v1/machines/enroll`.
///
/// Unknown fields are intentionally **not** rejected, so the server may add
/// fields without breaking older agents; the values that are present are
/// validated strictly by [`validate_response`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentResponse {
    /// Server-assigned, stable machine identifier.
    pub machine_id: String,
    /// Heartbeat interval, in seconds.
    pub heartbeat_interval: u64,
    /// Sync interval, in seconds.
    pub sync_interval: u64,
    /// The server's identity key, used in a later phase to verify the server.
    pub server_identity: String,
    /// The server's Bundle Signing Key (OpenSSH Ed25519). When present, the
    /// agent **pins** this at enrollment and verifies every CA bundle against
    /// it. Optional because a server without a configured bundle signer omits
    /// it, in which case the agent falls back to trust-on-first-use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_signing_key: Option<String>,
}

/// Validate an enrollment token's structure.
///
/// # Errors
///
/// Returns [`Error::InvalidToken`]. The token value is never included in the
/// error.
pub fn validate_token(token: &str) -> Result<()> {
    if token.len() > MAX_TOKEN_LEN || token.chars().any(|c| c.is_control()) {
        return Err(Error::InvalidToken);
    }
    let Some(suffix) = token.strip_prefix(TOKEN_PREFIX) else {
        return Err(Error::InvalidToken);
    };
    if suffix.is_empty()
        || !suffix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(Error::InvalidToken);
    }
    Ok(())
}

/// Validate a hostname (a conservative subset of RFC 1123).
///
/// # Errors
///
/// Returns [`Error::InvalidHostname`].
pub fn validate_hostname(hostname: &str) -> Result<()> {
    if hostname.is_empty() || hostname.len() > MAX_HOSTNAME_LEN {
        return Err(Error::InvalidHostname);
    }
    for label in hostname.split('.') {
        if label.is_empty() || label.len() > MAX_LABEL_LEN {
            return Err(Error::InvalidHostname);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(Error::InvalidHostname);
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(Error::InvalidHostname);
        }
    }
    Ok(())
}

/// Validate a server URL (must be `https://` with a host).
///
/// # Errors
///
/// Returns [`Error::InvalidServerUrl`].
pub fn validate_server_url(url: &str) -> Result<()> {
    if url != url.trim() {
        return Err(Error::InvalidServerUrl);
    }
    match url.strip_prefix("https://") {
        Some(host) if !host.is_empty() => Ok(()),
        _ => Err(Error::InvalidServerUrl),
    }
}

/// Validate a server enrollment response. Server data is never trusted.
///
/// # Errors
///
/// Returns [`Error::InvalidServerResponse`] with a fixed, non-sensitive reason.
pub fn validate_response(response: &EnrollmentResponse) -> Result<()> {
    if response.machine_id.is_empty() {
        return Err(Error::InvalidServerResponse(
            ServerResponseError::EmptyMachineId,
        ));
    }
    if response.machine_id.len() > MAX_MACHINE_ID_LEN
        || !response
            .machine_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(Error::InvalidServerResponse(
            ServerResponseError::InvalidMachineId,
        ));
    }
    if !is_valid_interval(response.heartbeat_interval) || !is_valid_interval(response.sync_interval)
    {
        return Err(Error::InvalidServerResponse(
            ServerResponseError::IntervalOutOfRange,
        ));
    }
    validate_ed25519_public_key(&response.server_identity)
        .map_err(|_| Error::InvalidServerResponse(ServerResponseError::InvalidServerIdentity))?;
    if let Some(key) = response.bundle_signing_key.as_deref() {
        validate_ed25519_public_key(key).map_err(|_| {
            Error::InvalidServerResponse(ServerResponseError::InvalidBundleSigningKey)
        })?;
    }
    Ok(())
}

fn is_valid_interval(secs: u64) -> bool {
    (MIN_INTERVAL_SECS..=MAX_INTERVAL_SECS).contains(&secs)
}

/// Transport abstraction for talking to the Mayfly enrollment API.
///
/// Only enrollment is defined in this phase. There is no HTTP implementation;
/// production wiring lands in a later phase, and tests use
/// [`MockMayflyApiClient`].
#[allow(async_fn_in_trait)]
pub trait MayflyApiClient {
    /// Submit an enrollment request and return the validated-on-arrival
    /// response.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EnrollmentRejected`] if the server refuses enrollment,
    /// or [`Error::EnrollmentTransport`] on a communication failure.
    async fn enroll(&self, request: EnrollmentRequest) -> Result<EnrollmentResponse>;
}

/// The outcome a [`MockMayflyApiClient`] should produce.
#[derive(Debug, Clone)]
pub enum MockEnrollOutcome {
    /// Return the given response successfully.
    Success(EnrollmentResponse),
    /// Simulate the server rejecting the request.
    Rejected,
    /// Simulate a transport/communication failure.
    Transport,
}

/// A deterministic, in-memory [`MayflyApiClient`] for tests.
///
/// It records the requests it receives (for assertions) and returns a
/// pre-configured outcome. It performs no I/O.
#[derive(Debug)]
pub struct MockMayflyApiClient {
    outcome: MockEnrollOutcome,
    requests: Mutex<Vec<EnrollmentRequest>>,
}

impl MockMayflyApiClient {
    /// Construct a mock that returns `response` successfully.
    pub fn success(response: EnrollmentResponse) -> Self {
        Self::new(MockEnrollOutcome::Success(response))
    }

    /// Construct a mock that simulates server rejection.
    pub fn rejected() -> Self {
        Self::new(MockEnrollOutcome::Rejected)
    }

    /// Construct a mock that simulates a transport failure.
    pub fn transport_failure() -> Self {
        Self::new(MockEnrollOutcome::Transport)
    }

    /// Construct a mock with an explicit outcome.
    pub fn new(outcome: MockEnrollOutcome) -> Self {
        Self {
            outcome,
            requests: Mutex::new(Vec::new()),
        }
    }

    /// The requests this mock has received, in order.
    pub fn captured_requests(&self) -> Vec<EnrollmentRequest> {
        self.requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl MayflyApiClient for MockMayflyApiClient {
    async fn enroll(&self, request: EnrollmentRequest) -> Result<EnrollmentResponse> {
        self.requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(request);
        match &self.outcome {
            MockEnrollOutcome::Success(response) => Ok(response.clone()),
            MockEnrollOutcome::Rejected => Err(Error::EnrollmentRejected),
            MockEnrollOutcome::Transport => Err(Error::EnrollmentTransport),
        }
    }
}

/// Coordinates machine-identity generation, the enrollment exchange, and
/// persistence of the resulting machine record.
#[derive(Clone)]
pub struct EnrollmentService {
    private_key_path: PathBuf,
    public_key_path: PathBuf,
    record_path: PathBuf,
    clock: Arc<dyn Clock>,
}

impl EnrollmentService {
    /// Construct a service operating on the given Mayfly directory (e.g.
    /// `/etc/mayfly-agent`).
    pub fn new(dir: &Path, clock: Arc<dyn Clock>) -> Self {
        Self {
            private_key_path: dir.join(PRIVATE_KEY_FILE),
            public_key_path: dir.join(PUBLIC_KEY_FILE),
            record_path: dir.join(MACHINE_RECORD_FILE),
            clock,
        }
    }

    /// Whether this machine has already been enrolled (a machine record exists).
    pub fn is_enrolled(&self) -> bool {
        self.record_path.is_file()
    }

    /// Generate a new keypair and persist both key files. Refuses to overwrite
    /// an existing key.
    ///
    /// The private key is written `0600`, the public key `0644`, both
    /// atomically via the security helpers.
    ///
    /// # Errors
    ///
    /// * [`Error::KeyAlreadyExists`] if either key file already exists.
    /// * [`Error::KeyGeneration`] / [`Error::KeySerialize`] / [`Error::Io`] on
    ///   failure.
    pub fn generate_machine_keypair(&self) -> Result<MachineKeypair> {
        if path_exists(&self.private_key_path) || path_exists(&self.public_key_path) {
            return Err(Error::KeyAlreadyExists);
        }
        let keypair = MachineKeypair::generate()?;
        self.write_keypair(&keypair)?;
        Ok(keypair)
    }

    /// Load the machine identity from disk, validating key-file security first.
    ///
    /// # Errors
    ///
    /// Propagates security-validation failures ([`Error::UnexpectedSymlink`],
    /// [`Error::InsecureOwnership`], [`Error::InsecurePermissions`]), key parse
    /// errors, and record read/parse errors.
    pub fn load_machine_identity(&self) -> Result<MachineIdentity> {
        let keypair = self.read_keypair()?;
        let public_key = keypair.public_key_openssh()?;
        let record = MachineRecord::load(&self.record_path)?;
        record.into_identity(
            public_key,
            self.private_key_path.clone(),
            self.public_key_path.clone(),
        )
    }

    /// Load the machine keypair from disk, validating the private key file's
    /// on-disk security posture (owner, mode, no symlink) before reading it.
    ///
    /// Used to construct an authenticated client (e.g. the heartbeat client),
    /// which signs requests with this key.
    ///
    /// # Errors
    ///
    /// Propagates security-validation failures and key parse errors.
    pub fn load_machine_keypair(&self) -> Result<MachineKeypair> {
        self.read_keypair()
    }

    /// Build a validated enrollment request from a token, hostname, and the
    /// machine keypair.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidToken`], [`Error::InvalidHostname`], or
    /// [`Error::MalformedPublicKey`].
    pub fn create_enrollment_request(
        &self,
        token: &str,
        hostname: &str,
        keypair: &MachineKeypair,
    ) -> Result<EnrollmentRequest> {
        validate_token(token)?;
        validate_hostname(hostname)?;
        let public_key = keypair.public_key_openssh()?;
        validate_ed25519_public_key(&public_key)?;

        Ok(EnrollmentRequest {
            enrollment_token: token.to_string(),
            hostname: hostname.to_string(),
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            public_key,
        })
    }

    /// Validate a server response and persist the resulting machine record.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidServerUrl`], [`Error::InvalidHostname`],
    /// [`Error::InvalidServerResponse`], or a write error.
    pub fn persist_machine_identity(
        &self,
        server_url: &str,
        hostname: &str,
        keypair: &MachineKeypair,
        response: &EnrollmentResponse,
    ) -> Result<MachineIdentity> {
        validate_server_url(server_url)?;
        validate_hostname(hostname)?;
        validate_response(response)?;

        let identity = MachineIdentity {
            machine_id: response.machine_id.clone(),
            hostname: hostname.to_string(),
            public_key: keypair.public_key_openssh()?,
            private_key_path: self.private_key_path.clone(),
            public_key_path: self.public_key_path.clone(),
            enrolled_at: self.clock.now(),
            server_url: server_url.to_string(),
            heartbeat_interval: Duration::from_secs(response.heartbeat_interval),
            sync_interval: Duration::from_secs(response.sync_interval),
        };
        identity.to_record().save(&self.record_path)?;
        Ok(identity)
    }

    /// Full enrollment flow: refuse if already enrolled, ensure a keypair
    /// exists, build the request, call the API client, then validate and
    /// persist the response.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AlreadyEnrolled`] if a machine record already exists, or
    /// any validation/transport/persistence error encountered along the way.
    pub async fn enroll<C: MayflyApiClient>(
        &self,
        client: &C,
        server_url: &str,
        token: &str,
        hostname: &str,
    ) -> Result<MachineIdentity> {
        if self.is_enrolled() {
            return Err(Error::AlreadyEnrolled);
        }
        validate_server_url(server_url)?;
        validate_token(token)?;
        validate_hostname(hostname)?;

        let keypair = self.load_or_generate_keypair()?;
        let request = self.create_enrollment_request(token, hostname, &keypair)?;
        let response = client.enroll(request).await?;
        let identity = self.persist_machine_identity(server_url, hostname, &keypair, &response)?;

        tracing::info!(machine_id = %identity.machine_id, "machine enrolled");
        Ok(identity)
    }

    /// Validate the private key file's on-disk security posture.
    fn validate_private_key_security(&self) -> Result<()> {
        security::ensure_not_symlink(&self.private_key_path)?;
        security::validate_owner(&self.private_key_path, effective_uid())?;
        security::ensure_not_group_or_world_writable(&self.private_key_path)?;
        security::validate_mode_at_most(&self.private_key_path, security::MODE_SECRET)?;
        Ok(())
    }

    /// Validate security and then read+parse the private key.
    fn read_keypair(&self) -> Result<MachineKeypair> {
        self.validate_private_key_security()?;
        let pem = std::fs::read_to_string(&self.private_key_path).map_err(Error::Io)?;
        MachineKeypair::from_openssh_private(&pem)
    }

    /// Reuse an existing keypair if present (validating it), else generate one.
    fn load_or_generate_keypair(&self) -> Result<MachineKeypair> {
        if path_exists(&self.private_key_path) {
            self.read_keypair()
        } else {
            self.generate_machine_keypair()
        }
    }

    /// Write both key files atomically with correct permissions.
    fn write_keypair(&self, keypair: &MachineKeypair) -> Result<()> {
        let private_pem = keypair.to_openssh_private()?;
        security::secure_write(
            &self.private_key_path,
            private_pem.as_bytes(),
            security::MODE_SECRET,
        )?;

        let mut public_line = keypair.public_key_openssh()?;
        public_line.push('\n');
        security::secure_write(
            &self.public_key_path,
            public_line.as_bytes(),
            security::MODE_PUBLIC,
        )?;
        Ok(())
    }
}

/// Whether a filesystem entry exists at `path`, treating even a (possibly
/// broken) symlink as existing — so we never silently overwrite one.
fn path_exists(path: &Path) -> bool {
    path.symlink_metadata().is_ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::clock::FixedClock;

    // ---- minimal, dependency-free async executor for deterministic tests ----

    /// Block on a future to completion without an async runtime dependency.
    ///
    /// The futures under test never yield `Pending` (the mock resolves
    /// immediately), so a single poll suffices; the loop is a safety net.
    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        use std::sync::Arc;
        use std::task::{Context, Poll, Wake, Waker};

        struct NoopWaker;
        impl Wake for NoopWaker {
            fn wake(self: Arc<Self>) {}
        }

        let waker = Waker::from(Arc::new(NoopWaker));
        let mut cx = Context::from_waker(&waker);
        let mut future = std::pin::pin!(future);
        loop {
            if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
                return output;
            }
        }
    }

    fn clock() -> Arc<FixedClock> {
        Arc::new(FixedClock::from_unix(1_700_000_000))
    }

    fn service(dir: &Path) -> EnrollmentService {
        EnrollmentService::new(dir, clock())
    }

    fn valid_server_identity() -> String {
        MachineKeypair::generate()
            .unwrap()
            .public_key_openssh()
            .unwrap()
    }

    fn ok_response() -> EnrollmentResponse {
        EnrollmentResponse {
            machine_id: "srv_abc123".to_string(),
            heartbeat_interval: 60,
            sync_interval: 300,
            server_identity: valid_server_identity(),
            bundle_signing_key: None,
        }
    }

    const TOKEN: &str = "mf_enroll_abcDEF123456";
    const SERVER: &str = "https://mayfly.example.com";
    const HOST: &str = "web-01";

    // ---- token validation ----

    #[test]
    fn token_validation() {
        validate_token(TOKEN).unwrap();
        for bad in [
            "",
            "enroll_abc",
            "mf_enroll_",
            "mf_enroll_has space",
            "mf_enroll_semi;colon",
        ] {
            assert!(matches!(
                validate_token(bad).unwrap_err(),
                Error::InvalidToken
            ));
        }
    }

    // ---- hostname validation ----

    #[test]
    fn hostname_validation() {
        for good in ["web-01", "a", "host.example.com", "node-7.dc1"] {
            validate_hostname(good).unwrap();
        }
        for bad in [
            "",
            "has space",
            "-leading",
            "trailing-",
            "a..b",
            "under_score",
            "end.",
        ] {
            assert!(
                matches!(validate_hostname(bad).unwrap_err(), Error::InvalidHostname),
                "hostname {bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn server_url_validation() {
        validate_server_url(SERVER).unwrap();
        for bad in ["", "http://x.com", "https://", "ftp://x", " https://x.com"] {
            assert!(matches!(
                validate_server_url(bad).unwrap_err(),
                Error::InvalidServerUrl
            ));
        }
    }

    // ---- response validation ----

    #[test]
    fn response_validation_accepts_good_response() {
        validate_response(&ok_response()).unwrap();
    }

    #[test]
    fn response_validation_rejects_bad_responses() {
        let mut r = ok_response();
        r.machine_id = String::new();
        assert!(matches!(
            validate_response(&r).unwrap_err(),
            Error::InvalidServerResponse(ServerResponseError::EmptyMachineId)
        ));

        let mut r = ok_response();
        r.machine_id = "has space".to_string();
        assert!(matches!(
            validate_response(&r).unwrap_err(),
            Error::InvalidServerResponse(ServerResponseError::InvalidMachineId)
        ));

        let mut r = ok_response();
        r.heartbeat_interval = 0;
        assert!(matches!(
            validate_response(&r).unwrap_err(),
            Error::InvalidServerResponse(ServerResponseError::IntervalOutOfRange)
        ));

        let mut r = ok_response();
        r.sync_interval = 1_000_000;
        assert!(matches!(
            validate_response(&r).unwrap_err(),
            Error::InvalidServerResponse(ServerResponseError::IntervalOutOfRange)
        ));

        let mut r = ok_response();
        r.server_identity = "not-a-key".to_string();
        assert!(matches!(
            validate_response(&r).unwrap_err(),
            Error::InvalidServerResponse(ServerResponseError::InvalidServerIdentity)
        ));

        let mut r = ok_response();
        r.bundle_signing_key = Some("not-a-key".to_string());
        assert!(matches!(
            validate_response(&r).unwrap_err(),
            Error::InvalidServerResponse(ServerResponseError::InvalidBundleSigningKey)
        ));
    }

    #[test]
    fn response_validation_accepts_valid_bundle_signing_key() {
        let mut r = ok_response();
        r.bundle_signing_key = Some(valid_server_identity());
        validate_response(&r).unwrap();
    }

    // ---- DTO serialization ----

    #[test]
    fn request_serializes_with_expected_fields() {
        let dir = tempfile::tempdir().unwrap();
        let svc = service(dir.path());
        let kp = svc.generate_machine_keypair().unwrap();
        let req = svc.create_enrollment_request(TOKEN, HOST, &kp).unwrap();

        let value: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert_eq!(value["enrollment_token"], TOKEN);
        assert_eq!(value["hostname"], HOST);
        assert_eq!(value["os"], std::env::consts::OS);
        assert_eq!(value["arch"], std::env::consts::ARCH);
        assert_eq!(value["agent_version"], env!("CARGO_PKG_VERSION"));
        assert!(value["public_key"]
            .as_str()
            .unwrap()
            .starts_with("ssh-ed25519 "));
    }

    #[test]
    fn request_debug_redacts_token() {
        let req = EnrollmentRequest {
            enrollment_token: "mf_enroll_supersecret".to_string(),
            hostname: HOST.to_string(),
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            agent_version: "0.1.0".to_string(),
            public_key: "ssh-ed25519 AAAA".to_string(),
        };
        let debug = format!("{req:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("supersecret"));
    }

    #[test]
    fn response_parses_from_json() {
        let json = r#"{
            "machine_id": "srv_xyz",
            "heartbeat_interval": 60,
            "sync_interval": 300,
            "server_identity": "ssh-ed25519 AAAA...",
            "future_field": "ignored"
        }"#;
        let resp: EnrollmentResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.machine_id, "srv_xyz");
        assert_eq!(resp.heartbeat_interval, 60);
    }

    // ---- keypair generation / persistence ----

    #[test]
    fn generate_keypair_writes_files() {
        let dir = tempfile::tempdir().unwrap();
        let svc = service(dir.path());
        let kp = svc.generate_machine_keypair().unwrap();

        assert!(dir.path().join(PRIVATE_KEY_FILE).is_file());
        let pub_contents = std::fs::read_to_string(dir.path().join(PUBLIC_KEY_FILE)).unwrap();
        assert!(pub_contents.starts_with("ssh-ed25519 "));
        assert_eq!(
            pub_contents,
            format!("{}\n", kp.public_key_openssh().unwrap())
        );
    }

    #[cfg(unix)]
    #[test]
    fn generated_key_permissions_are_correct() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let svc = service(dir.path());
        svc.generate_machine_keypair().unwrap();

        let priv_mode = std::fs::metadata(dir.path().join(PRIVATE_KEY_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(priv_mode & 0o777, 0o600);

        let pub_mode = std::fs::metadata(dir.path().join(PUBLIC_KEY_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(pub_mode & 0o777, 0o644);
    }

    #[test]
    fn generate_keypair_refuses_to_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let svc = service(dir.path());
        let first = svc.generate_machine_keypair().unwrap();
        let err = svc.generate_machine_keypair().unwrap_err();
        assert!(matches!(err, Error::KeyAlreadyExists));

        // The original key is untouched.
        let reloaded = svc.read_keypair().unwrap();
        assert_eq!(first.fingerprint(), reloaded.fingerprint());
    }

    #[test]
    fn load_keypair_rejects_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real_key");
        std::fs::write(&real, b"data").unwrap();
        let link = dir.path().join(PRIVATE_KEY_FILE);
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let svc = service(dir.path());
        assert!(matches!(
            svc.read_keypair().unwrap_err(),
            Error::UnexpectedSymlink
        ));
    }

    #[cfg(unix)]
    #[test]
    fn load_keypair_rejects_world_writable() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let svc = service(dir.path());
        let kp = svc.generate_machine_keypair().unwrap();
        let _ = kp;

        std::fs::set_permissions(
            dir.path().join(PRIVATE_KEY_FILE),
            std::fs::Permissions::from_mode(0o666),
        )
        .unwrap();

        assert!(matches!(
            svc.read_keypair().unwrap_err(),
            Error::InsecurePermissions
        ));
    }

    #[test]
    fn load_missing_keypair_is_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let svc = service(dir.path());
        assert!(matches!(svc.read_keypair().unwrap_err(), Error::Io(_)));
    }

    #[cfg(unix)]
    #[test]
    fn load_corrupt_keypair_is_parse_error() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(PRIVATE_KEY_FILE);
        std::fs::write(&path, b"not a valid openssh key").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let svc = service(dir.path());
        assert!(matches!(svc.read_keypair().unwrap_err(), Error::KeyParse));
    }

    // ---- persistence / identity ----

    #[test]
    fn persist_then_load_identity_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let svc = service(dir.path());
        let kp = svc.generate_machine_keypair().unwrap();
        let identity = svc
            .persist_machine_identity(SERVER, HOST, &kp, &ok_response())
            .unwrap();

        assert_eq!(identity.machine_id, "srv_abc123");
        assert_eq!(identity.server_url, SERVER);
        assert_eq!(identity.heartbeat_interval, Duration::from_secs(60));
        assert_eq!(identity.enrolled_at.unix_timestamp(), 1_700_000_000);

        let loaded = svc.load_machine_identity().unwrap();
        assert_eq!(loaded.machine_id, identity.machine_id);
        assert_eq!(loaded.public_key, identity.public_key);
        assert_eq!(loaded.heartbeat_interval, identity.heartbeat_interval);
    }

    #[test]
    fn persisted_record_never_contains_token() {
        let dir = tempfile::tempdir().unwrap();
        let svc = service(dir.path());
        let kp = svc.generate_machine_keypair().unwrap();
        svc.persist_machine_identity(SERVER, HOST, &kp, &ok_response())
            .unwrap();

        let contents = std::fs::read_to_string(dir.path().join(MACHINE_RECORD_FILE)).unwrap();
        assert!(!contents.contains("token"));
        assert!(!contents.contains(TOKEN));
        assert!(!contents.contains("PRIVATE"));
    }

    #[test]
    fn is_enrolled_reflects_record_presence() {
        let dir = tempfile::tempdir().unwrap();
        let svc = service(dir.path());
        assert!(!svc.is_enrolled());
        let kp = svc.generate_machine_keypair().unwrap();
        svc.persist_machine_identity(SERVER, HOST, &kp, &ok_response())
            .unwrap();
        assert!(svc.is_enrolled());
    }

    // ---- full flow with mock client ----

    #[test]
    fn enroll_success_with_mock_client() {
        let dir = tempfile::tempdir().unwrap();
        let svc = service(dir.path());
        let client = MockMayflyApiClient::success(ok_response());

        let identity = block_on(svc.enroll(&client, SERVER, TOKEN, HOST)).unwrap();
        assert_eq!(identity.machine_id, "srv_abc123");
        assert!(svc.is_enrolled());

        // The client received exactly one request carrying our public key.
        let requests = client.captured_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].hostname, HOST);
        assert!(requests[0].public_key.starts_with("ssh-ed25519 "));
    }

    #[test]
    fn enroll_rejected_by_server() {
        let dir = tempfile::tempdir().unwrap();
        let svc = service(dir.path());
        let client = MockMayflyApiClient::rejected();

        let err = block_on(svc.enroll(&client, SERVER, TOKEN, HOST)).unwrap_err();
        assert!(matches!(err, Error::EnrollmentRejected));
        // Rejection must not leave a machine record behind.
        assert!(!svc.is_enrolled());
    }

    #[test]
    fn enroll_transport_failure() {
        let dir = tempfile::tempdir().unwrap();
        let svc = service(dir.path());
        let client = MockMayflyApiClient::transport_failure();

        let err = block_on(svc.enroll(&client, SERVER, TOKEN, HOST)).unwrap_err();
        assert!(matches!(err, Error::EnrollmentTransport));
        assert!(!svc.is_enrolled());
    }

    #[test]
    fn enroll_refuses_when_already_enrolled() {
        let dir = tempfile::tempdir().unwrap();
        let svc = service(dir.path());
        let client = MockMayflyApiClient::success(ok_response());

        block_on(svc.enroll(&client, SERVER, TOKEN, HOST)).unwrap();
        let err = block_on(svc.enroll(&client, SERVER, TOKEN, HOST)).unwrap_err();
        assert!(matches!(err, Error::AlreadyEnrolled));
    }

    #[test]
    fn enroll_rejects_invalid_inputs_before_calling_client() {
        let dir = tempfile::tempdir().unwrap();
        let svc = service(dir.path());
        let client = MockMayflyApiClient::success(ok_response());

        assert!(matches!(
            block_on(svc.enroll(&client, "http://insecure", TOKEN, HOST)).unwrap_err(),
            Error::InvalidServerUrl
        ));
        assert!(matches!(
            block_on(svc.enroll(&client, SERVER, "bad token", HOST)).unwrap_err(),
            Error::InvalidToken
        ));
        assert!(matches!(
            block_on(svc.enroll(&client, SERVER, TOKEN, "bad host")).unwrap_err(),
            Error::InvalidHostname
        ));

        // No request reached the client.
        assert!(client.captured_requests().is_empty());
    }

    #[test]
    fn failed_enrollment_can_be_retried_with_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let svc = service(dir.path());

        let rejecting = MockMayflyApiClient::rejected();
        assert!(block_on(svc.enroll(&rejecting, SERVER, TOKEN, HOST)).is_err());
        // Key was generated during the failed attempt.
        let key_after_fail = svc.read_keypair().unwrap().fingerprint();

        let succeeding = MockMayflyApiClient::success(ok_response());
        let identity = block_on(svc.enroll(&succeeding, SERVER, TOKEN, HOST)).unwrap();
        // The retry reused the existing key rather than generating a new one.
        assert_eq!(
            identity.public_key,
            svc.read_keypair().unwrap().public_key_openssh().unwrap()
        );
        assert_eq!(svc.read_keypair().unwrap().fingerprint(), key_after_fail);
    }
}
