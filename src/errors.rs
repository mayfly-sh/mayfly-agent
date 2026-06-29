//! The crate's single error type.
//!
//! ## Security property: no path leakage
//!
//! User-facing error messages (the [`Display`] output of [`Error`]) **never**
//! contain filesystem paths, file contents, or other potentially sensitive
//! context. Diagnostic detail such as the offending path is emitted via
//! structured [`tracing`](https://docs.rs/tracing) at the call site instead,
//! where it reaches operators' logs but not, for example, an error surfaced to a
//! remote caller in a later phase.
//!
//! This keeps the blast radius of an accidentally-propagated error small: an
//! `Error` value carries a category and an optional non-sensitive reason, never
//! a `/etc/...` path.

use std::fmt;

/// The single, crate-wide result type.
pub type Result<T> = std::result::Result<T, Error>;

/// The single, crate-wide error type.
///
/// Variants are intentionally coarse-grained and path-free. When more detail is
/// useful for debugging it is logged with structured fields at the point of
/// failure rather than embedded here.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The configuration could not be read from disk.
    #[error("failed to read configuration")]
    ConfigRead(#[source] std::io::Error),

    /// The configuration could not be parsed.
    #[error("failed to parse configuration")]
    ConfigParse(#[source] toml::de::Error),

    /// The configuration parsed but failed semantic validation.
    ///
    /// The contained reason describes the offending *field* and rule, never a
    /// filesystem path or secret value.
    #[error("invalid configuration: {0}")]
    ConfigInvalid(String),

    /// A filesystem operation failed. The path is logged, not included here.
    #[error("filesystem operation failed")]
    Io(#[source] std::io::Error),

    /// A managed path is a symlink where a regular file or directory is
    /// required.
    #[error("path failed security validation: unexpected symlink")]
    UnexpectedSymlink,

    /// A managed file has unsafe ownership (e.g. not owned by root).
    #[error("path failed security validation: insecure ownership")]
    InsecureOwnership,

    /// A managed file has unsafe permission bits (e.g. group/world writable).
    #[error("path failed security validation: insecure permissions")]
    InsecurePermissions,

    /// A required path component was missing (e.g. a file with no parent dir).
    #[error("path failed security validation: invalid path")]
    InvalidPath,

    /// The process is not running with the required privileges (root).
    #[error("insufficient privileges: root is required")]
    NotRoot,

    /// A trusted-CA-keys entry was malformed or used a disallowed algorithm.
    ///
    /// The contained reason is a fixed, non-sensitive description.
    #[error("invalid TrustedUserCAKeys entry: {0}")]
    InvalidTrustedCa(TrustedCaError),

    /// The machine is already enrolled; re-enrollment is refused.
    #[error("machine is already enrolled")]
    AlreadyEnrolled,

    /// A machine identity key already exists and must not be overwritten.
    #[error("machine identity key already exists")]
    KeyAlreadyExists,

    /// Generating a new machine identity key failed.
    #[error("failed to generate machine identity key")]
    KeyGeneration,

    /// Parsing a stored machine identity key failed.
    #[error("failed to parse machine identity key")]
    KeyParse,

    /// Serialising a machine identity key failed.
    #[error("failed to serialise machine identity key")]
    KeySerialize,

    /// A hostname failed validation.
    #[error("invalid hostname")]
    InvalidHostname,

    /// An enrollment token failed validation.
    ///
    /// The token value itself is never included, in keeping with the no-secret
    /// logging policy.
    #[error("invalid enrollment token")]
    InvalidToken,

    /// A server URL failed validation.
    #[error("invalid server URL")]
    InvalidServerUrl,

    /// A public key was not a well-formed, allowed key.
    #[error("malformed public key")]
    MalformedPublicKey,

    /// A server response failed validation. The reason is a fixed enum, so no
    /// server-controlled data reaches the message.
    #[error("untrusted server response: {0}")]
    InvalidServerResponse(ServerResponseError),

    /// The server rejected the enrollment request (e.g. invalid token).
    #[error("enrollment was rejected by the server")]
    EnrollmentRejected,

    /// Communication with the server failed.
    #[error("failed to communicate with the enrollment server")]
    EnrollmentTransport,

    /// Building or signing an authenticated request failed.
    #[error("failed to sign request")]
    RequestSigning,

    /// Communication with the server for an authenticated request failed.
    #[error("failed to communicate with the server")]
    HeartbeatTransport,

    /// The server rejected an authenticated request (e.g. bad signature).
    #[error("server rejected the request")]
    HeartbeatRejected,

    /// The server returned a heartbeat response that failed validation.
    #[error("untrusted heartbeat response")]
    InvalidHeartbeatResponse,

    /// Communication with the server while synchronising the CA bundle failed.
    #[error("failed to communicate with the CA bundle server")]
    CaBundleTransport,

    /// The server rejected a CA bundle request (non-success, non-304 status).
    #[error("server rejected the CA bundle request")]
    CaBundleRejected,

    /// A CA bundle response failed validation. The reason is a fixed enum, so
    /// no server-controlled data reaches the message.
    #[error("untrusted CA bundle: {0}")]
    InvalidCaBundle(CaBundleError),

    /// Reloading `sshd` after writing a new bundle failed; the previous bundle
    /// was restored. The path is logged, never included here.
    #[error("failed to reload sshd; previous CA bundle was restored")]
    CaReloadFailed,

    /// The persisted machine record could not be parsed.
    #[error("failed to parse machine record")]
    MachineRecordParse(#[source] serde_json::Error),

    /// The persisted machine record could not be serialised.
    #[error("failed to serialise machine record")]
    MachineRecordSerialize(#[source] serde_json::Error),

    /// The persisted machine record parsed but held a semantically invalid
    /// value (e.g. an out-of-range timestamp).
    #[error("machine record is invalid")]
    MachineRecordInvalid,

    /// The requested operation is intentionally not enabled in this build.
    ///
    /// Used by the architecture-only platform wrappers (e.g. reloading sshd)
    /// that exist but deliberately perform no action yet.
    #[error("operation is not supported in this build")]
    Unsupported,

    /// The privileged helper could not be reached over its socket.
    #[error("privileged helper is unavailable")]
    HelperUnavailable,

    /// A helper request or response violated the socket protocol (bad framing,
    /// oversized body, unsupported protocol version, or malformed JSON).
    #[error("helper protocol error")]
    HelperProtocol,

    /// The helper rejected a request as unauthenticated (missing or wrong
    /// capability token). The token value is never included.
    #[error("helper rejected the request: unauthenticated")]
    HelperUnauthenticated,

    /// A helper operation ran but reported failure. The reason is a fixed,
    /// non-sensitive string carried separately in logs/responses, never a path.
    #[error("helper operation failed")]
    HelperOperationFailed,

    /// `sshd -t` rejected the candidate configuration. The offending detail is
    /// logged, never included here.
    #[error("sshd configuration validation failed")]
    SshdValidationFailed,

    /// `sshd` was not active after a reload, or the service query failed.
    #[error("sshd is not active")]
    SshdInactive,
}

/// Fixed, non-sensitive reasons a server enrollment response can be rejected.
///
/// A closed enum guarantees no server-controlled string is ever interpolated
/// into an error message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ServerResponseError {
    /// The `machine_id` was empty.
    EmptyMachineId,
    /// The `machine_id` contained disallowed characters or was too long.
    InvalidMachineId,
    /// An interval was zero or outside the accepted range.
    IntervalOutOfRange,
    /// The `server_identity` was not a valid Ed25519 public key.
    InvalidServerIdentity,
    /// The `bundle_signing_key`, when present, was not a valid Ed25519 key.
    InvalidBundleSigningKey,
}

impl fmt::Display for ServerResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::EmptyMachineId => "machine_id is empty",
            Self::InvalidMachineId => "machine_id is invalid",
            Self::IntervalOutOfRange => "interval is out of range",
            Self::InvalidServerIdentity => "server_identity is not a valid key",
            Self::InvalidBundleSigningKey => "bundle_signing_key is not a valid key",
        };
        f.write_str(msg)
    }
}

/// Fixed, non-sensitive reasons a TrustedUserCAKeys entry can be rejected.
///
/// A closed enum (rather than a free-form string) keeps rejection reasons
/// auditable and guarantees no caller-controlled or path data leaks into an
/// error message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrustedCaError {
    /// The entry was empty or contained only whitespace.
    Empty,
    /// The entry did not have the expected `<algorithm> <base64>[ comment]`
    /// shape.
    Malformed,
    /// The key algorithm is not in the allow-list.
    DisallowedAlgorithm,
    /// The key blob was not valid base64.
    InvalidEncoding,
    /// The entry contained control characters or a NUL byte.
    IllegalCharacter,
}

impl fmt::Display for TrustedCaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::Empty => "entry is empty",
            Self::Malformed => "entry is malformed",
            Self::DisallowedAlgorithm => "key algorithm is not allowed",
            Self::InvalidEncoding => "key data is not valid base64",
            Self::IllegalCharacter => "entry contains illegal characters",
        };
        f.write_str(msg)
    }
}

/// Fixed, non-sensitive reasons a CA bundle response can be rejected.
///
/// A closed enum keeps rejection reasons auditable and guarantees no
/// server-controlled string is interpolated into an error message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CaBundleError {
    /// The bundle contained zero keys.
    Empty,
    /// The bundle contained more than the permitted maximum number of keys.
    TooManyKeys,
    /// Two keys shared a `key_id`.
    DuplicateKeyId,
    /// Two keys shared a public key.
    DuplicatePublicKey,
    /// A key was malformed, used a disallowed algorithm, or was not Ed25519.
    InvalidKey,
    /// The `generation` field was missing or not a positive integer.
    MissingGeneration,
    /// The `fingerprint` field was missing or empty.
    MissingFingerprint,
    /// The recomputed fingerprint did not match the advertised one.
    FingerprintMismatch,
    /// The `bundle_version` is absent or not a version this agent supports.
    UnsupportedVersion,
    /// The `signature_algorithm` is not one this agent accepts.
    UnsupportedSignatureAlgorithm,
    /// A `created_at`/`expires_at` timestamp was missing or unparseable.
    InvalidTimestamp,
    /// The bundle's validity window has elapsed (`expires_at` is in the past).
    Expired,
    /// The detached bundle signature did not verify against the signing key.
    SignatureInvalid,
    /// The bundle signing key differs from the pinned/expected signing key.
    SigningKeyMismatch,
    /// The advertised generation is older than the one already applied
    /// (a downgrade / rollback attack).
    GenerationRegressed,
}

impl fmt::Display for CaBundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::Empty => "bundle contains no keys",
            Self::TooManyKeys => "bundle contains too many keys",
            Self::DuplicateKeyId => "bundle contains a duplicate key id",
            Self::DuplicatePublicKey => "bundle contains a duplicate public key",
            Self::InvalidKey => "bundle contains an invalid key",
            Self::MissingGeneration => "bundle generation is missing or invalid",
            Self::MissingFingerprint => "bundle fingerprint is missing",
            Self::FingerprintMismatch => "bundle fingerprint does not match its contents",
            Self::UnsupportedVersion => "bundle version is not supported",
            Self::UnsupportedSignatureAlgorithm => "bundle signature algorithm is not supported",
            Self::InvalidTimestamp => "bundle timestamp is missing or invalid",
            Self::Expired => "bundle has expired",
            Self::SignatureInvalid => "bundle signature failed verification",
            Self::SigningKeyMismatch => "bundle signing key does not match the pinned key",
            Self::GenerationRegressed => "bundle generation is older than the applied generation",
        };
        f.write_str(msg)
    }
}

impl Error {
    /// Build a [`Error::ConfigInvalid`] from a static or owned reason.
    ///
    /// Callers must ensure the reason contains no paths or secrets.
    pub fn config_invalid(reason: impl Into<String>) -> Self {
        Self::ConfigInvalid(reason.into())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::path::Path;

    /// Every error's user-facing message must be free of filesystem paths.
    #[test]
    fn display_never_contains_paths() {
        let sensitive = "/etc/mayfly-agent/config.toml";
        let errors = [
            Error::ConfigRead(std::io::Error::new(std::io::ErrorKind::NotFound, sensitive)),
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                sensitive,
            )),
            Error::ConfigInvalid("server_url must use https".to_string()),
            Error::UnexpectedSymlink,
            Error::InsecureOwnership,
            Error::InsecurePermissions,
            Error::InvalidPath,
            Error::NotRoot,
            Error::InvalidTrustedCa(TrustedCaError::DisallowedAlgorithm),
            Error::AlreadyEnrolled,
            Error::KeyAlreadyExists,
            Error::KeyGeneration,
            Error::KeyParse,
            Error::KeySerialize,
            Error::InvalidHostname,
            Error::InvalidToken,
            Error::InvalidServerUrl,
            Error::MalformedPublicKey,
            Error::InvalidServerResponse(ServerResponseError::InvalidMachineId),
            Error::EnrollmentRejected,
            Error::EnrollmentTransport,
            Error::RequestSigning,
            Error::HeartbeatTransport,
            Error::HeartbeatRejected,
            Error::InvalidHeartbeatResponse,
            Error::CaBundleTransport,
            Error::CaBundleRejected,
            Error::InvalidCaBundle(CaBundleError::FingerprintMismatch),
            Error::CaReloadFailed,
            Error::Unsupported,
        ];
        for err in errors {
            let shown = err.to_string();
            assert!(
                !shown.contains('/'),
                "error message leaked a path-like value: {shown:?}"
            );
            assert!(
                !shown.contains(sensitive),
                "error message leaked sensitive context: {shown:?}"
            );
        }
    }

    #[test]
    fn token_value_never_appears_in_error_display() {
        // The token error is intentionally value-free.
        let err = Error::InvalidToken;
        assert_eq!(err.to_string(), "invalid enrollment token");
    }

    #[test]
    fn server_response_error_messages_are_stable() {
        assert_eq!(
            ServerResponseError::EmptyMachineId.to_string(),
            "machine_id is empty"
        );
        assert_eq!(
            ServerResponseError::InvalidServerIdentity.to_string(),
            "server_identity is not a valid key"
        );
    }

    #[test]
    fn config_invalid_reason_is_preserved() {
        let err = Error::config_invalid("machine_id must not be empty");
        assert!(err.to_string().contains("machine_id must not be empty"));
    }

    #[test]
    fn trusted_ca_error_messages_are_stable() {
        assert_eq!(TrustedCaError::Empty.to_string(), "entry is empty");
        assert_eq!(
            TrustedCaError::DisallowedAlgorithm.to_string(),
            "key algorithm is not allowed"
        );
    }

    #[test]
    fn ca_bundle_error_messages_are_stable() {
        assert_eq!(
            CaBundleError::FingerprintMismatch.to_string(),
            "bundle fingerprint does not match its contents"
        );
        assert_eq!(CaBundleError::Empty.to_string(), "bundle contains no keys");
    }

    #[test]
    fn io_source_is_preserved_for_diagnostics() {
        // The path stays out of Display, but the io::Error source remains
        // available for structured logging / debugging.
        let err = Error::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "denied",
        ));
        let source = std::error::Error::source(&err);
        assert!(source.is_some());
        // Sanity: the path helper used in other modules is unrelated here.
        let _ = Path::new("/unused");
    }
}
