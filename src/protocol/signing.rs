//! Canonical-string construction and request signing (agent side).
//!
//! This is the agent's half of the request-signing contract. The
//! [`canonical_string`] layout and [`body_sha256_hex`] computation here MUST be
//! byte-for-byte identical to the server's verifier (`agentauth::signing`), or
//! every signed request will be rejected. The canonical layout is:
//!
//! ```text
//! <SIGNING_DOMAIN>\n<machine_id>\n<timestamp>\n<nonce>\n<method>\n<path>\n<body_sha256>
//! ```
//!
//! The agent signs the UTF-8 bytes of that string with its Ed25519 machine key
//! and Base64-encodes the 64-byte signature for the `X-Mayfly-Signature` header.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::errors::{Error, Result};
use crate::identity::keypair::MachineKeypair;

/// Domain-separation label + protocol version. Must match the server.
pub const SIGNING_DOMAIN: &str = "mayfly-agent-auth-v1";

/// Header carrying the machine identifier.
pub const HEADER_MACHINE_ID: &str = "X-Mayfly-Machine-Id";
/// Header carrying the Unix-seconds timestamp.
pub const HEADER_TIMESTAMP: &str = "X-Mayfly-Timestamp";
/// Header carrying the per-request nonce.
pub const HEADER_NONCE: &str = "X-Mayfly-Nonce";
/// Header carrying the Base64 Ed25519 signature.
pub const HEADER_SIGNATURE: &str = "X-Mayfly-Signature";

/// Number of random bytes in a nonce (256 bits of entropy, hex-encoded).
const NONCE_BYTES: usize = 16;

/// Lowercase hex SHA-256 of a request body (`""` hashes the empty input).
pub fn body_sha256_hex(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    hex::encode(hasher.finalize())
}

/// Build the canonical string that is signed. See the module docs for layout.
pub fn canonical_string(
    machine_id: &str,
    timestamp: i64,
    nonce: &str,
    method: &str,
    path: &str,
    body_hash_hex: &str,
) -> String {
    format!(
        "{SIGNING_DOMAIN}\n{machine_id}\n{timestamp}\n{nonce}\n{method}\n{path}\n{body_hash_hex}"
    )
}

/// Generate a fresh per-request nonce: [`NONCE_BYTES`] of OS randomness, hex.
pub fn generate_nonce() -> String {
    let mut bytes = [0u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// The signed-request values destined for the `X-Mayfly-*` headers.
#[derive(Clone)]
pub struct SignedHeaders {
    /// Machine identifier (`X-Mayfly-Machine-Id`).
    pub machine_id: String,
    /// Unix-seconds timestamp (`X-Mayfly-Timestamp`).
    pub timestamp: i64,
    /// Per-request nonce (`X-Mayfly-Nonce`).
    pub nonce: String,
    /// Base64 Ed25519 signature (`X-Mayfly-Signature`).
    pub signature: String,
}

impl std::fmt::Debug for SignedHeaders {
    /// Never print the signature material verbatim.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedHeaders")
            .field("machine_id", &self.machine_id)
            .field("timestamp", &self.timestamp)
            .field("nonce", &self.nonce)
            .field("signature", &"<redacted>")
            .finish()
    }
}

/// Sign a request, producing the values for the four signing headers.
///
/// # Errors
///
/// Returns [`Error::RequestSigning`] if the keypair cannot produce a signature.
#[allow(clippy::too_many_arguments)]
pub fn sign_request(
    keypair: &MachineKeypair,
    machine_id: &str,
    timestamp: i64,
    nonce: &str,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<SignedHeaders> {
    let body_hash = body_sha256_hex(body);
    let canonical = canonical_string(machine_id, timestamp, nonce, method, path, &body_hash);
    let signature = keypair
        .sign(canonical.as_bytes())
        .map_err(|_| Error::RequestSigning)?;
    Ok(SignedHeaders {
        machine_id: machine_id.to_string(),
        timestamp,
        nonce: nonce.to_string(),
        signature: BASE64.encode(signature),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    /// Recover the Ed25519 verifying key from an OpenSSH public-key line.
    fn verifying_key(openssh: &str) -> VerifyingKey {
        let key = ssh_key::PublicKey::from_openssh(openssh).unwrap();
        let ed = key.key_data().ed25519().unwrap();
        VerifyingKey::from_bytes(&ed.0).unwrap()
    }

    #[test]
    fn canonical_layout_is_exact_and_matches_spec() {
        let c = canonical_string("m", 5, "n", "POST", "/p", "deadbeef");
        assert_eq!(c, "mayfly-agent-auth-v1\nm\n5\nn\nPOST\n/p\ndeadbeef");
    }

    #[test]
    fn empty_body_hash_is_known_vector() {
        assert_eq!(
            body_sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn nonces_are_unique_and_hex() {
        let a = generate_nonce();
        let b = generate_nonce();
        assert_ne!(a, b);
        assert_eq!(a.len(), NONCE_BYTES * 2);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn signature_verifies_against_machine_public_key() {
        let keypair = MachineKeypair::generate().unwrap();
        let public = keypair.public_key_openssh().unwrap();
        let body = br#"{"agent_version":"0.1.0"}"#;

        let signed = sign_request(
            &keypair,
            "srv_abc",
            1_700_000_000,
            "nonce123",
            "POST",
            "/api/v1/agent/heartbeat",
            body,
        )
        .unwrap();

        // Reconstruct exactly what the server would verify.
        let canonical = canonical_string(
            "srv_abc",
            1_700_000_000,
            "nonce123",
            "POST",
            "/api/v1/agent/heartbeat",
            &body_sha256_hex(body),
        );
        let sig_bytes: [u8; 64] = BASE64
            .decode(&signed.signature)
            .unwrap()
            .try_into()
            .unwrap();
        let signature = Signature::from_bytes(&sig_bytes);
        verifying_key(&public)
            .verify(canonical.as_bytes(), &signature)
            .expect("signature must verify");
    }

    #[test]
    fn debug_redacts_signature() {
        let keypair = MachineKeypair::generate().unwrap();
        let signed = sign_request(&keypair, "m", 1, "n", "POST", "/p", b"{}").unwrap();
        let rendered = format!("{signed:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains(&signed.signature));
    }
}
