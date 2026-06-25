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

    /// The requested operation is intentionally not enabled in this build.
    ///
    /// Used by the architecture-only platform wrappers (e.g. reloading sshd)
    /// that exist but deliberately perform no action yet.
    #[error("operation is not supported in this build")]
    Unsupported,
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
