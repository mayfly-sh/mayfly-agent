//! Parsing and validation of the `TrustedUserCAKeys` file.
//!
//! The file is an OpenSSH `authorized_keys`-style list: one CA public key per
//! line, blank lines and `#` comment lines ignored. Each key is
//! `"<algorithm> <base64-blob> [comment]"`.
//!
//! Validation here is **structural and conservative** — it is the gate that
//! decides whether content is well-formed enough to be considered at all. It
//! checks for illegal characters, an allow-listed algorithm, and a
//! syntactically valid base64 blob. It does not perform cryptographic
//! verification of the key material (that is layered on later); rejecting
//! obvious garbage early is a defence-in-depth measure for a file that governs
//! SSH trust.
//!
//! No network access and no filesystem writes happen in this module.

use crate::errors::{Error, Result, TrustedCaError};

/// Algorithms permitted for a trusted CA key.
///
/// Restricted to modern, widely-supported SSH CA key types. `ssh-dss` (DSA) is
/// intentionally excluded.
pub const ALLOWED_ALGORITHMS: &[&str] = &[
    "ssh-ed25519",
    "ssh-rsa",
    "rsa-sha2-256",
    "rsa-sha2-512",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

/// A single trusted CA public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaPublicKey {
    algorithm: String,
    key_data: String,
    comment: Option<String>,
}

impl CaPublicKey {
    /// The key algorithm (e.g. `ssh-ed25519`).
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// The base64-encoded key blob.
    pub fn key_data(&self) -> &str {
        &self.key_data
    }

    /// The optional trailing comment.
    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    /// Parse and validate a single non-empty key line.
    ///
    /// # Errors
    ///
    /// Returns a [`TrustedCaError`] describing why the entry is rejected.
    pub fn parse(line: &str) -> std::result::Result<Self, TrustedCaError> {
        if line.chars().any(|c| c.is_control()) {
            return Err(TrustedCaError::IllegalCharacter);
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Err(TrustedCaError::Empty);
        }

        // The first two whitespace-delimited fields are the algorithm and the
        // base64 blob; anything after them is a free-form comment.
        let mut tokens = trimmed.split_whitespace();
        let algorithm = tokens.next().ok_or(TrustedCaError::Malformed)?;
        let key_data = tokens.next().ok_or(TrustedCaError::Malformed)?;
        let comment = collect_comment(trimmed, algorithm, key_data);

        if !ALLOWED_ALGORITHMS.contains(&algorithm) {
            return Err(TrustedCaError::DisallowedAlgorithm);
        }
        if !is_valid_base64(key_data) {
            return Err(TrustedCaError::InvalidEncoding);
        }

        Ok(Self {
            algorithm: algorithm.to_string(),
            key_data: key_data.to_string(),
            comment,
        })
    }

    /// Render this key as a canonical single line (no trailing newline).
    pub fn render(&self) -> String {
        match &self.comment {
            Some(comment) => format!("{} {} {}", self.algorithm, self.key_data, comment),
            None => format!("{} {}", self.algorithm, self.key_data),
        }
    }
}

/// The validated contents of a `TrustedUserCAKeys` file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrustedCaKeys {
    keys: Vec<CaPublicKey>,
}

impl TrustedCaKeys {
    /// Parse and validate the full contents of a trusted-CA file.
    ///
    /// Blank lines and `#` comment lines are ignored. Every remaining line must
    /// be a valid CA key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidTrustedCa`] for the first invalid entry.
    pub fn parse(contents: &str) -> Result<Self> {
        let mut keys = Vec::new();
        for line in contents.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let key = CaPublicKey::parse(line).map_err(Error::InvalidTrustedCa)?;
            keys.push(key);
        }
        Ok(Self { keys })
    }

    /// The parsed keys, in file order.
    pub fn keys(&self) -> &[CaPublicKey] {
        &self.keys
    }

    /// The number of keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether there are no keys.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Render all keys to canonical file contents, one per line, with a trailing
    /// newline (empty string if there are no keys).
    pub fn render(&self) -> String {
        if self.keys.is_empty() {
            return String::new();
        }
        let mut out = String::new();
        for key in &self.keys {
            out.push_str(&key.render());
            out.push('\n');
        }
        out
    }
}

/// Extract the comment (everything after the first two fields), if any.
fn collect_comment(line: &str, algorithm: &str, key_data: &str) -> Option<String> {
    // Find where key_data ends and take the trimmed remainder.
    let after_algo = line.trim_start().strip_prefix(algorithm)?.trim_start();
    let after_key = after_algo.strip_prefix(key_data)?.trim();
    if after_key.is_empty() {
        None
    } else {
        Some(after_key.to_string())
    }
}

/// Validate that `s` is syntactically valid standard base64 (RFC 4648, no URL
/// alphabet), non-empty, correctly padded, and length a multiple of four.
fn is_valid_base64(s: &str) -> bool {
    if s.is_empty() || s.len() % 4 != 0 {
        return false;
    }

    let bytes = s.as_bytes();
    let padding = bytes.iter().rev().take_while(|&&b| b == b'=').count();
    if padding > 2 {
        return false;
    }

    let body_len = bytes.len() - padding;
    // Padding may only appear at the very end.
    for (i, &b) in bytes.iter().enumerate() {
        let is_padding = i >= body_len;
        if is_padding {
            if b != b'=' {
                return false;
            }
        } else if !is_base64_char(b) {
            return false;
        }
    }
    body_len > 0
}

fn is_base64_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/'
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// A syntactically valid base64 blob (68 chars, multiple of 4).
    fn blob() -> String {
        "A".repeat(68)
    }

    #[test]
    fn parses_single_ed25519_key() {
        let line = format!("ssh-ed25519 {}", blob());
        let key = CaPublicKey::parse(&line).unwrap();
        assert_eq!(key.algorithm(), "ssh-ed25519");
        assert_eq!(key.key_data(), blob());
        assert_eq!(key.comment(), None);
    }

    #[test]
    fn parses_key_with_comment() {
        let line = format!("ssh-ed25519 {} mayfly root ca", blob());
        let key = CaPublicKey::parse(&line).unwrap();
        assert_eq!(key.comment(), Some("mayfly root ca"));
    }

    #[test]
    fn rejects_disallowed_algorithm() {
        let line = format!("ssh-dss {}", blob());
        assert_eq!(
            CaPublicKey::parse(&line).unwrap_err(),
            TrustedCaError::DisallowedAlgorithm
        );
    }

    #[test]
    fn rejects_malformed_single_field() {
        assert_eq!(
            CaPublicKey::parse("ssh-ed25519").unwrap_err(),
            TrustedCaError::Malformed
        );
    }

    #[test]
    fn rejects_invalid_base64() {
        // Contains an illegal '*' and wrong length.
        let line = "ssh-ed25519 not*base64";
        assert_eq!(
            CaPublicKey::parse(line).unwrap_err(),
            TrustedCaError::InvalidEncoding
        );
    }

    #[test]
    fn rejects_control_characters() {
        let line = format!("ssh-ed25519 {}\t\u{7}", blob());
        assert_eq!(
            CaPublicKey::parse(&line).unwrap_err(),
            TrustedCaError::IllegalCharacter
        );
    }

    #[test]
    fn base64_validator_rules() {
        assert!(is_valid_base64("AAAA"));
        assert!(is_valid_base64("AAA="));
        assert!(is_valid_base64("AA=="));
        assert!(!is_valid_base64(""));
        assert!(!is_valid_base64("AAA")); // not multiple of 4
        assert!(!is_valid_base64("A===")); // too much padding
        assert!(!is_valid_base64("AA=A")); // padding not at end
        assert!(!is_valid_base64("AAA*")); // illegal char
    }

    #[test]
    fn parses_multi_key_file_ignoring_blanks_and_comments() {
        let contents = format!(
            "# Mayfly trusted CAs\n\nssh-ed25519 {b} primary\n   \nssh-rsa {b}\n# trailing comment\n",
            b = blob()
        );
        let keys = TrustedCaKeys::parse(&contents).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys.keys()[0].algorithm(), "ssh-ed25519");
        assert_eq!(keys.keys()[0].comment(), Some("primary"));
        assert_eq!(keys.keys()[1].algorithm(), "ssh-rsa");
    }

    #[test]
    fn empty_file_is_valid_and_empty() {
        let keys = TrustedCaKeys::parse("\n\n# only comments\n").unwrap();
        assert!(keys.is_empty());
        assert_eq!(keys.len(), 0);
        assert_eq!(keys.render(), "");
    }

    #[test]
    fn file_with_one_bad_entry_is_rejected() {
        let contents = format!("ssh-ed25519 {}\nssh-dss {}\n", blob(), blob());
        assert!(matches!(
            TrustedCaKeys::parse(&contents).unwrap_err(),
            Error::InvalidTrustedCa(TrustedCaError::DisallowedAlgorithm)
        ));
    }

    #[test]
    fn render_round_trips_through_parse() {
        let contents = format!("ssh-ed25519 {b} primary\nssh-rsa {b}\n", b = blob());
        let keys = TrustedCaKeys::parse(&contents).unwrap();
        let rendered = keys.render();
        let reparsed = TrustedCaKeys::parse(&rendered).unwrap();
        assert_eq!(keys, reparsed);
    }

    #[test]
    fn single_key_render_round_trips() {
        let line = format!("ssh-ed25519 {} some comment", blob());
        let key = CaPublicKey::parse(&line).unwrap();
        assert_eq!(CaPublicKey::parse(&key.render()).unwrap(), key);
    }
}
