//! The CA-bundle data model: parsing, signature verification, validation,
//! canonical fingerprinting, and rendering of the `TrustedUserCAKeys` file.
//!
//! This module is **pure**: it performs no I/O, no networking, and no privileged
//! actions. It is the trusted gate that decides whether a server-supplied bundle
//! is authentic and well-formed enough to be applied. Everything here is
//! deterministic and exhaustively tested so that the orchestration layer
//! ([`super::ca_sync`]) can be a thin, auditable adapter.
//!
//! ## Two distinct canonicalizations
//!
//! There are two stable-forever canonical encodings, and they are different:
//!
//! * [`canonical_json`] / [`compute_fingerprint`] cover **`generation` + `keys`
//!   only**. The fingerprint is `sha256` over this and is what the server
//!   advertises and uses as the HTTP `ETag`. It deliberately excludes the
//!   signature envelope so the fingerprint is a pure function of the trusted key
//!   set.
//! * [`canonical_signing_payload`] covers the **entire signed envelope**
//!   (`bundle_version`, `created_at`, `expires_at`, `fingerprint`, `generation`,
//!   `keys`). The detached Ed25519 signature is computed over these bytes. The
//!   agent verifies this signature *before* trusting any field.
//!
//! Both encodings emit object members in fixed (alphabetical) order, sort keys
//! by `key_id`, and escape strings with [`json_escape_into`]. The server MUST
//! mirror them byte-for-byte.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::errors::{CaBundleError, Error, Result};
use crate::identity::keypair::validate_ed25519_public_key;

/// API path for fetching the current CA bundle. Signed verbatim, so it must
/// match the server route exactly.
pub const CA_BUNDLE_PATH: &str = "/api/v1/agent/ca-bundle";

/// API path for acknowledging a sync. Signed verbatim.
pub const CA_BUNDLE_ACK_PATH: &str = "/api/v1/agent/ca-bundle/ack";

/// Request header carrying the cached ETag (the bundle fingerprint, quoted).
pub const HEADER_IF_NONE_MATCH: &str = "If-None-Match";

/// Response header carrying the ETag (the bundle fingerprint, quoted).
pub const HEADER_ETAG: &str = "ETag";

/// Prefix on every fingerprint string (`sha256:<64 hex chars>`).
pub const FINGERPRINT_PREFIX: &str = "sha256:";

/// The only bundle wire-format version this agent understands.
pub const SUPPORTED_BUNDLE_VERSION: u32 = 1;

/// The only bundle signature algorithm this agent accepts.
pub const SIGNATURE_ALGORITHM: &str = "ssh-ed25519";

/// Clock-skew grace applied to the not-yet-valid (future-bundle) check. Mirrors
/// the server's ±60s signed-request timestamp tolerance so benign skew does not
/// reject an otherwise-valid bundle, while a bundle dated far into the future is
/// rejected fail-closed.
pub const CLOCK_SKEW_GRACE: time::Duration = time::Duration::seconds(60);

/// Minimum number of keys a valid bundle must contain.
pub const MIN_KEYS: usize = 1;

/// Maximum number of keys a valid bundle may contain.
pub const MAX_KEYS: usize = 64;

/// Upper bound on the length of a `key_id`, to keep rendered comment lines sane.
const MAX_KEY_ID_LEN: usize = 64;

/// A single CA key as it appears in the bundle and the canonical encodings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CaBundleKey {
    /// Stable identifier for the CA key (e.g. `ca-01`).
    pub key_id: String,
    /// The CA public key as an OpenSSH line (`ssh-ed25519 AAAA...`).
    pub public_key: String,
}

/// The raw, **untrusted** signed bundle exactly as deserialised from the server.
///
/// Every field is optional so that a missing field becomes a precise
/// [`CaBundleError`] during validation rather than an opaque deserialisation
/// failure.
#[derive(Debug, Clone, Deserialize)]
pub struct CaBundleResponse {
    /// Wire-format version. Must equal [`SUPPORTED_BUNDLE_VERSION`].
    pub bundle_version: Option<u32>,
    /// Monotonic bundle generation. Must be present and positive.
    pub generation: Option<u64>,
    /// Advertised canonical fingerprint (`sha256:<hex>`).
    pub fingerprint: Option<String>,
    /// Bundle creation time (RFC 3339).
    pub created_at: Option<String>,
    /// Bundle expiry time (RFC 3339).
    pub expires_at: Option<String>,
    /// The CA keys. Must contain between [`MIN_KEYS`] and [`MAX_KEYS`] entries.
    #[serde(default)]
    pub keys: Vec<CaBundleKey>,
    /// Detached-signature algorithm. Must equal [`SIGNATURE_ALGORITHM`].
    pub signature_algorithm: Option<String>,
    /// Base64 Ed25519 detached signature over [`canonical_signing_payload`].
    pub signature: Option<String>,
    /// OpenSSH Ed25519 public key the signature verifies against.
    pub bundle_signing_public_key: Option<String>,
}

impl CaBundleResponse {
    /// Parse a bundle from raw JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidCaBundle`] with [`CaBundleError::InvalidKey`] if
    /// the payload is not the expected JSON shape. Field-level validation is
    /// performed later by [`CaBundle::from_response`].
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|_| Error::InvalidCaBundle(CaBundleError::InvalidKey))
    }
}

/// A fully validated, **authenticated** CA bundle.
///
/// Construction guarantees: a supported version; an accepted signature
/// algorithm; a signing key that matches the pin (when one is supplied); a
/// detached signature that verifies over the canonical envelope; a parseable,
/// not-yet-expired validity window; non-empty, in-bounds, unique, Ed25519 keys
/// sorted by `key_id`; and a recomputed fingerprint that matches the advertised
/// one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaBundle {
    bundle_version: u32,
    generation: u64,
    fingerprint: String,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    keys: Vec<CaBundleKey>,
    signing_public_key: String,
}

impl CaBundle {
    /// Validate and authenticate an untrusted [`CaBundleResponse`].
    ///
    /// `now` is the current time (from the injected clock) used for the expiry
    /// check. `expected_signing_key`, when `Some`, is the pinned signing key the
    /// bundle's own signing key must equal (downgrade / key-swap protection);
    /// when `None`, the bundle's signing key is accepted on trust-on-first-use
    /// and the caller is responsible for pinning it.
    ///
    /// Checks run in security order: **authenticate first, then trust the
    /// content.** Field presence → version → algorithm → signing-key
    /// validity/pin → signature verification → key validation → fingerprint
    /// recomputation → timestamps/expiry.
    ///
    /// # Errors
    ///
    /// Returns the specific [`CaBundleError`] for the first failing rule.
    pub fn from_response(
        raw: CaBundleResponse,
        now: OffsetDateTime,
        expected_signing_key: Option<&str>,
    ) -> std::result::Result<Self, CaBundleError> {
        // --- Presence of every required field. ---
        let bundle_version = raw
            .bundle_version
            .ok_or(CaBundleError::UnsupportedVersion)?;
        let generation = raw.generation.unwrap_or(0);
        let fingerprint = raw.fingerprint.unwrap_or_default();
        let created_at_str = raw.created_at.unwrap_or_default();
        let expires_at_str = raw.expires_at.unwrap_or_default();
        let algorithm = raw.signature_algorithm.unwrap_or_default();
        let signature = raw.signature.unwrap_or_default();
        let signing_key = raw.bundle_signing_public_key.unwrap_or_default();

        // --- Version & algorithm gate (cheap, before any crypto). ---
        if bundle_version != SUPPORTED_BUNDLE_VERSION {
            return Err(CaBundleError::UnsupportedVersion);
        }
        if algorithm != SIGNATURE_ALGORITHM {
            return Err(CaBundleError::UnsupportedSignatureAlgorithm);
        }

        // --- Signing key: well-formed, and matches the pin if we have one. ---
        if signing_key.trim().is_empty() || validate_ed25519_public_key(&signing_key).is_err() {
            return Err(CaBundleError::SignatureInvalid);
        }
        if let Some(expected) = expected_signing_key {
            if !public_keys_equal(expected, &signing_key) {
                return Err(CaBundleError::SigningKeyMismatch);
            }
        }

        // --- Authenticate the envelope BEFORE trusting any field. ---
        if fingerprint.trim().is_empty() {
            return Err(CaBundleError::MissingFingerprint);
        }
        let payload = canonical_signing_payload(
            bundle_version,
            generation,
            &fingerprint,
            &created_at_str,
            &expires_at_str,
            &raw.keys,
        );
        verify_signature(payload.as_bytes(), &signature, &signing_key)?;

        // --- Content is now authenticated; validate it. ---
        if generation == 0 {
            return Err(CaBundleError::MissingGeneration);
        }
        if raw.keys.len() < MIN_KEYS {
            return Err(CaBundleError::Empty);
        }
        if raw.keys.len() > MAX_KEYS {
            return Err(CaBundleError::TooManyKeys);
        }
        for key in &raw.keys {
            validate_key_id(&key.key_id)?;
            validate_ed25519_public_key(&key.public_key).map_err(|_| CaBundleError::InvalidKey)?;
        }

        let mut by_id: Vec<&CaBundleKey> = raw.keys.iter().collect();
        by_id.sort_by(|a, b| a.key_id.cmp(&b.key_id));
        for pair in by_id.windows(2) {
            if pair[0].key_id == pair[1].key_id {
                return Err(CaBundleError::DuplicateKeyId);
            }
        }
        let mut by_pubkey: Vec<&str> = raw.keys.iter().map(|k| k.public_key.as_str()).collect();
        by_pubkey.sort_unstable();
        for pair in by_pubkey.windows(2) {
            if pair[0] == pair[1] {
                return Err(CaBundleError::DuplicatePublicKey);
            }
        }

        let mut keys = raw.keys;
        keys.sort_by(|a, b| a.key_id.cmp(&b.key_id));

        let computed = compute_fingerprint(generation, &keys);
        if !fingerprints_equal(&computed, &fingerprint) {
            return Err(CaBundleError::FingerprintMismatch);
        }

        // --- Validity window. ---
        let created_at = OffsetDateTime::parse(&created_at_str, &Rfc3339)
            .map_err(|_| CaBundleError::InvalidTimestamp)?;
        let expires_at = OffsetDateTime::parse(&expires_at_str, &Rfc3339)
            .map_err(|_| CaBundleError::InvalidTimestamp)?;
        if expires_at <= created_at {
            return Err(CaBundleError::InvalidTimestamp);
        }
        if now >= expires_at {
            return Err(CaBundleError::Expired);
        }
        // Fail closed on a not-yet-valid (future) bundle. A small grace absorbs
        // benign clock skew between server and agent (mirrors the server's ±60s
        // signed-request skew tolerance) without trusting a bundle dated well
        // into the future; a falsely-rejected bundle is simply retried next sync.
        if created_at - now > CLOCK_SKEW_GRACE {
            return Err(CaBundleError::NotYetValid);
        }

        Ok(Self {
            bundle_version,
            generation,
            fingerprint: computed,
            created_at,
            expires_at,
            keys,
            signing_public_key: signing_key,
        })
    }

    /// The wire-format version.
    pub fn bundle_version(&self) -> u32 {
        self.bundle_version
    }

    /// The bundle generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The canonical fingerprint (`sha256:<hex>`), as recomputed by the agent.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// The bundle creation time.
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// The bundle expiry time.
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// The signing public key the bundle's signature verified against.
    pub fn signing_public_key(&self) -> &str {
        &self.signing_public_key
    }

    /// The validated keys, sorted by `key_id`.
    pub fn keys(&self) -> &[CaBundleKey] {
        &self.keys
    }

    /// Render the canonical `TrustedUserCAKeys` file contents.
    ///
    /// The output carries a managed header (so operators know the file is owned
    /// by the daemon and which version/generation/fingerprint it reflects)
    /// followed by one CA key per line in `key_id` order. Each key line is
    /// normalised to `<algorithm> <blob> mayfly:<key_id>`. The result always
    /// ends with a trailing newline.
    pub fn render_trusted_user_ca_keys(&self) -> String {
        let mut out = String::new();
        out.push_str("# Managed by mayfly-agent. DO NOT EDIT.\n");
        out.push_str(&format!("# bundle_version: {}\n", self.bundle_version));
        out.push_str(&format!("# generation: {}\n", self.generation));
        out.push_str(&format!("# fingerprint: {}\n", self.fingerprint));
        for key in &self.keys {
            out.push_str(&render_key_line(key));
            out.push('\n');
        }
        out
    }
}

/// Verify a detached Ed25519 signature over `payload` using an OpenSSH Ed25519
/// public key.
///
/// Uses [`VerifyingKey::verify_strict`], matching the server byte-for-byte
/// (`mayfly-server/src/bundle/signer.rs` and `agentauth/signing.rs`). Strict
/// verification rejects signatures made with small-order / non-canonical public
/// keys, closing Ed25519 malleability gaps; the whole platform therefore shares
/// identical verification semantics (BL-025). All error mappings collapse to
/// [`CaBundleError::SignatureInvalid`] as before.
fn verify_signature(
    payload: &[u8],
    signature_b64: &str,
    signing_key_openssh: &str,
) -> std::result::Result<(), CaBundleError> {
    let key = ssh_key::PublicKey::from_openssh(signing_key_openssh)
        .map_err(|_| CaBundleError::SignatureInvalid)?;
    let ed = key
        .key_data()
        .ed25519()
        .ok_or(CaBundleError::SignatureInvalid)?;
    let verifying_key =
        VerifyingKey::from_bytes(&ed.0).map_err(|_| CaBundleError::SignatureInvalid)?;

    let sig_bytes = BASE64
        .decode(signature_b64.trim())
        .map_err(|_| CaBundleError::SignatureInvalid)?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| CaBundleError::SignatureInvalid)?;
    let signature = Signature::from_bytes(&sig_array);

    verifying_key
        .verify_strict(payload, &signature)
        .map_err(|_| CaBundleError::SignatureInvalid)
}

/// Render a single normalised key line: `<algorithm> <blob> mayfly:<key_id>`.
fn render_key_line(key: &CaBundleKey) -> String {
    let mut tokens = key.public_key.split_whitespace();
    let algorithm = tokens.next().unwrap_or("ssh-ed25519");
    let blob = tokens.next().unwrap_or_default();
    format!("{algorithm} {blob} mayfly:{}", key.key_id)
}

/// Validate a `key_id`: non-empty, not too long, printable ASCII with no
/// whitespace (so it is safe to embed as a `TrustedUserCAKeys` comment).
fn validate_key_id(key_id: &str) -> std::result::Result<(), CaBundleError> {
    if key_id.is_empty() || key_id.len() > MAX_KEY_ID_LEN {
        return Err(CaBundleError::InvalidKey);
    }
    if key_id
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || !c.is_ascii_graphic())
    {
        return Err(CaBundleError::InvalidKey);
    }
    Ok(())
}

/// Compute the canonical bundle fingerprint: `sha256:` + lowercase hex of the
/// SHA-256 digest over [`canonical_json`].
pub fn compute_fingerprint(generation: u64, keys: &[CaBundleKey]) -> String {
    let canonical = canonical_json(generation, keys);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    format!("{FINGERPRINT_PREFIX}{}", hex::encode(hasher.finalize()))
}

/// Produce the canonical JSON the **fingerprint** is computed over
/// (`generation` + `keys` only). Keys are sorted by `key_id`.
pub fn canonical_json(generation: u64, keys: &[CaBundleKey]) -> String {
    let mut sorted: Vec<&CaBundleKey> = keys.iter().collect();
    sorted.sort_by(|a, b| a.key_id.cmp(&b.key_id));

    let mut out = String::new();
    out.push_str("{\"generation\":");
    out.push_str(&generation.to_string());
    out.push_str(",\"keys\":");
    append_keys_array(&sorted, &mut out);
    out.push('}');
    out
}

/// Produce the canonical JSON the **signature** is computed over (the full
/// envelope). Members are in alphabetical order; keys are sorted by `key_id`.
///
/// Layout (stable forever):
/// `{"bundle_version":V,"created_at":"..","expires_at":"..","fingerprint":"..","generation":G,"keys":[{"key_id":"..","public_key":".."},..]}`
pub fn canonical_signing_payload(
    bundle_version: u32,
    generation: u64,
    fingerprint: &str,
    created_at: &str,
    expires_at: &str,
    keys: &[CaBundleKey],
) -> String {
    let mut sorted: Vec<&CaBundleKey> = keys.iter().collect();
    sorted.sort_by(|a, b| a.key_id.cmp(&b.key_id));

    let mut out = String::new();
    out.push_str("{\"bundle_version\":");
    out.push_str(&bundle_version.to_string());
    out.push_str(",\"created_at\":\"");
    json_escape_into(created_at, &mut out);
    out.push_str("\",\"expires_at\":\"");
    json_escape_into(expires_at, &mut out);
    out.push_str("\",\"fingerprint\":\"");
    json_escape_into(fingerprint, &mut out);
    out.push_str("\",\"generation\":");
    out.push_str(&generation.to_string());
    out.push_str(",\"keys\":");
    append_keys_array(&sorted, &mut out);
    out.push('}');
    out
}

/// Append `[{"key_id":..,"public_key":..},..]` for already-sorted keys.
fn append_keys_array(sorted: &[&CaBundleKey], out: &mut String) {
    out.push('[');
    for (i, key) in sorted.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"key_id\":\"");
        json_escape_into(&key.key_id, out);
        out.push_str("\",\"public_key\":\"");
        json_escape_into(&key.public_key, out);
        out.push_str("\"}");
    }
    out.push(']');
}

/// Append `s` to `out`, escaped as a JSON string body (no surrounding quotes).
fn json_escape_into(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
}

/// Compare two fingerprint strings for equality (length-checked full scan).
fn fingerprints_equal(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Compare two OpenSSH public-key lines by their key material, ignoring the
/// trailing comment and surrounding whitespace.
fn public_keys_equal(a: &str, b: &str) -> bool {
    fn material(s: &str) -> Option<(String, String)> {
        let mut t = s.split_whitespace();
        let algo = t.next()?;
        let blob = t.next()?;
        Some((algo.to_string(), blob.to_string()))
    }
    match (material(a), material(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::identity::keypair::MachineKeypair;
    use ed25519_dalek::{Signer, SigningKey};

    /// A freshly generated, valid Ed25519 OpenSSH public-key line.
    fn pubkey() -> String {
        MachineKeypair::generate()
            .unwrap()
            .public_key_openssh()
            .unwrap()
    }

    fn key(id: &str, public_key: &str) -> CaBundleKey {
        CaBundleKey {
            key_id: id.to_string(),
            public_key: public_key.to_string(),
        }
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()
    }

    /// A throwaway Ed25519 bundle-signing key and its OpenSSH public form.
    struct Signer25519 {
        signing: SigningKey,
        public_openssh: String,
    }

    impl Signer25519 {
        fn new() -> Self {
            // Deterministic-but-arbitrary seed; the test only needs a valid key.
            let signing = SigningKey::from_bytes(&[7u8; 32]);
            let vk = signing.verifying_key();
            let ssh = ssh_key::public::Ed25519PublicKey(vk.to_bytes());
            let public =
                ssh_key::PublicKey::new(ssh_key::public::KeyData::Ed25519(ssh), "bundle-signing");
            Self {
                public_openssh: public.to_openssh().unwrap(),
                signing,
            }
        }

        fn sign(&self, payload: &[u8]) -> String {
            BASE64.encode(self.signing.sign(payload).to_bytes())
        }
    }

    /// Build a fully-signed, valid raw response with the given validity window.
    fn signed_raw(
        signer: &Signer25519,
        generation: u64,
        keys: Vec<CaBundleKey>,
        created: OffsetDateTime,
        expires: OffsetDateTime,
    ) -> CaBundleResponse {
        let fingerprint = compute_fingerprint(generation, &keys);
        let created_at = created.format(&Rfc3339).unwrap();
        let expires_at = expires.format(&Rfc3339).unwrap();
        let payload = canonical_signing_payload(
            SUPPORTED_BUNDLE_VERSION,
            generation,
            &fingerprint,
            &created_at,
            &expires_at,
            &keys,
        );
        CaBundleResponse {
            bundle_version: Some(SUPPORTED_BUNDLE_VERSION),
            generation: Some(generation),
            fingerprint: Some(fingerprint),
            created_at: Some(created_at),
            expires_at: Some(expires_at),
            keys,
            signature_algorithm: Some(SIGNATURE_ALGORITHM.to_string()),
            signature: Some(signer.sign(payload.as_bytes())),
            bundle_signing_public_key: Some(signer.public_openssh.clone()),
        }
    }

    fn valid(signer: &Signer25519, generation: u64, keys: Vec<CaBundleKey>) -> CaBundleResponse {
        signed_raw(
            signer,
            generation,
            keys,
            now() - time::Duration::hours(1),
            now() + time::Duration::hours(1),
        )
    }

    #[test]
    fn canonical_json_layout_is_exact_and_stable() {
        let keys = vec![
            key("ca-02", "ssh-ed25519 BBBB"),
            key("ca-01", "ssh-ed25519 AAAA"),
        ];
        assert_eq!(
            canonical_json(42, &keys),
            "{\"generation\":42,\"keys\":[\
{\"key_id\":\"ca-01\",\"public_key\":\"ssh-ed25519 AAAA\"},\
{\"key_id\":\"ca-02\",\"public_key\":\"ssh-ed25519 BBBB\"}]}"
        );
    }

    #[test]
    fn canonical_signing_payload_layout_is_exact_and_stable() {
        let keys = vec![key("ca-01", "ssh-ed25519 AAAA")];
        assert_eq!(
            canonical_signing_payload(
                1,
                42,
                "sha256:ab",
                "2026-01-01T00:00:00Z",
                "2026-02-01T00:00:00Z",
                &keys
            ),
            "{\"bundle_version\":1,\"created_at\":\"2026-01-01T00:00:00Z\",\
\"expires_at\":\"2026-02-01T00:00:00Z\",\"fingerprint\":\"sha256:ab\",\
\"generation\":42,\"keys\":[{\"key_id\":\"ca-01\",\"public_key\":\"ssh-ed25519 AAAA\"}]}"
        );
    }

    #[test]
    fn fingerprint_matches_known_vector() {
        let keys = vec![key("ca-01", "ssh-ed25519 AAAA")];
        assert_eq!(
            compute_fingerprint(1, &keys),
            "sha256:aaa4a001b964adfb2217ef11e804f8334ae417719f25e44b1978e3220f722d23"
        );
    }

    #[test]
    fn validates_signed_minimal_bundle() {
        let signer = Signer25519::new();
        let bundle = CaBundle::from_response(
            valid(&signer, 7, vec![key("ca-01", &pubkey())]),
            now(),
            None,
        )
        .unwrap();
        assert_eq!(bundle.generation(), 7);
        assert_eq!(bundle.bundle_version(), 1);
        assert!(bundle.fingerprint().starts_with("sha256:"));
    }

    #[test]
    fn accepts_maximum_keys() {
        let signer = Signer25519::new();
        let keys: Vec<CaBundleKey> = (0..MAX_KEYS)
            .map(|i| key(&format!("ca-{i:02}"), &pubkey()))
            .collect();
        let bundle = CaBundle::from_response(valid(&signer, 1, keys), now(), None).unwrap();
        assert_eq!(bundle.keys().len(), MAX_KEYS);
    }

    #[test]
    fn rejects_unsupported_version() {
        let signer = Signer25519::new();
        let mut raw = valid(&signer, 1, vec![key("ca-01", &pubkey())]);
        raw.bundle_version = Some(2);
        assert_eq!(
            CaBundle::from_response(raw, now(), None).unwrap_err(),
            CaBundleError::UnsupportedVersion
        );
    }

    #[test]
    fn rejects_unsupported_signature_algorithm() {
        let signer = Signer25519::new();
        let mut raw = valid(&signer, 1, vec![key("ca-01", &pubkey())]);
        raw.signature_algorithm = Some("rsa-sha2-512".to_string());
        assert_eq!(
            CaBundle::from_response(raw, now(), None).unwrap_err(),
            CaBundleError::UnsupportedSignatureAlgorithm
        );
    }

    #[test]
    fn rejects_tampered_keys() {
        let signer = Signer25519::new();
        let mut raw = valid(&signer, 1, vec![key("ca-01", &pubkey())]);
        // Swap in a different key after signing: signature must fail.
        raw.keys = vec![key("ca-01", &pubkey())];
        assert_eq!(
            CaBundle::from_response(raw, now(), None).unwrap_err(),
            CaBundleError::SignatureInvalid
        );
    }

    #[test]
    fn rejects_tampered_generation() {
        let signer = Signer25519::new();
        let mut raw = valid(&signer, 1, vec![key("ca-01", &pubkey())]);
        raw.generation = Some(999);
        assert_eq!(
            CaBundle::from_response(raw, now(), None).unwrap_err(),
            CaBundleError::SignatureInvalid
        );
    }

    #[test]
    fn rejects_bad_signature() {
        let signer = Signer25519::new();
        let mut raw = valid(&signer, 1, vec![key("ca-01", &pubkey())]);
        raw.signature = Some(BASE64.encode([0u8; 64]));
        assert_eq!(
            CaBundle::from_response(raw, now(), None).unwrap_err(),
            CaBundleError::SignatureInvalid
        );
    }

    #[test]
    fn rejects_signing_key_mismatch_against_pin() {
        let signer = Signer25519::new();
        let raw = valid(&signer, 1, vec![key("ca-01", &pubkey())]);
        // Pin a different key than the one that signed the bundle.
        let other_pin = pubkey();
        assert_eq!(
            CaBundle::from_response(raw, now(), Some(&other_pin)).unwrap_err(),
            CaBundleError::SigningKeyMismatch
        );
    }

    #[test]
    fn accepts_matching_pinned_signing_key() {
        let signer = Signer25519::new();
        let raw = valid(&signer, 1, vec![key("ca-01", &pubkey())]);
        let pin = signer.public_openssh.clone();
        assert!(CaBundle::from_response(raw, now(), Some(&pin)).is_ok());
    }

    #[test]
    fn rejects_expired_bundle() {
        let signer = Signer25519::new();
        let raw = signed_raw(
            &signer,
            1,
            vec![key("ca-01", &pubkey())],
            now() - time::Duration::hours(2),
            now() - time::Duration::hours(1),
        );
        assert_eq!(
            CaBundle::from_response(raw, now(), None).unwrap_err(),
            CaBundleError::Expired
        );
    }

    #[test]
    fn rejects_not_yet_valid_bundle() {
        // A correctly-signed bundle whose validity window starts well in the
        // future (beyond the skew grace) must be rejected fail-closed.
        let signer = Signer25519::new();
        let raw = signed_raw(
            &signer,
            1,
            vec![key("ca-01", &pubkey())],
            now() + time::Duration::hours(1),
            now() + time::Duration::hours(2),
        );
        assert_eq!(
            CaBundle::from_response(raw, now(), None).unwrap_err(),
            CaBundleError::NotYetValid
        );
    }

    #[test]
    fn accepts_bundle_created_within_skew_grace() {
        // A bundle created slightly in the future (within the skew grace) is
        // accepted, so benign server/agent clock skew does not falsely reject.
        let signer = Signer25519::new();
        let raw = signed_raw(
            &signer,
            1,
            vec![key("ca-01", &pubkey())],
            now() + time::Duration::seconds(30),
            now() + time::Duration::hours(2),
        );
        assert!(CaBundle::from_response(raw, now(), None).is_ok());
    }

    #[test]
    fn rejects_lying_fingerprint_even_when_signed() {
        // A malicious/buggy signer that signs an advertised fingerprint which
        // does not match the keys must still be rejected (FingerprintMismatch):
        // the agent independently recomputes the fingerprint from the key set.
        let signer = Signer25519::new();
        let keys = vec![key("ca-01", &pubkey())];
        let created_at = (now() - time::Duration::hours(1)).format(&Rfc3339).unwrap();
        let expires_at = (now() + time::Duration::hours(1)).format(&Rfc3339).unwrap();
        let lying_fingerprint = format!("{FINGERPRINT_PREFIX}{}", "0".repeat(64));
        let payload = canonical_signing_payload(
            SUPPORTED_BUNDLE_VERSION,
            1,
            &lying_fingerprint,
            &created_at,
            &expires_at,
            &keys,
        );
        let raw = CaBundleResponse {
            bundle_version: Some(SUPPORTED_BUNDLE_VERSION),
            generation: Some(1),
            fingerprint: Some(lying_fingerprint),
            created_at: Some(created_at),
            expires_at: Some(expires_at),
            keys,
            signature_algorithm: Some(SIGNATURE_ALGORITHM.to_string()),
            signature: Some(signer.sign(payload.as_bytes())),
            bundle_signing_public_key: Some(signer.public_openssh.clone()),
        };
        assert_eq!(
            CaBundle::from_response(raw, now(), None).unwrap_err(),
            CaBundleError::FingerprintMismatch
        );
    }

    #[test]
    fn rejects_inverted_validity_window() {
        let signer = Signer25519::new();
        let raw = signed_raw(
            &signer,
            1,
            vec![key("ca-01", &pubkey())],
            now() + time::Duration::hours(2),
            now() + time::Duration::hours(1),
        );
        assert_eq!(
            CaBundle::from_response(raw, now(), None).unwrap_err(),
            CaBundleError::InvalidTimestamp
        );
    }

    #[test]
    fn rejects_unparseable_timestamp() {
        let signer = Signer25519::new();
        let keys = vec![key("ca-01", &pubkey())];
        let generation = 1;
        let fingerprint = compute_fingerprint(generation, &keys);
        let created_at = "not-a-time".to_string();
        let expires_at = "also-bad".to_string();
        let payload = canonical_signing_payload(
            SUPPORTED_BUNDLE_VERSION,
            generation,
            &fingerprint,
            &created_at,
            &expires_at,
            &keys,
        );
        let raw = CaBundleResponse {
            bundle_version: Some(SUPPORTED_BUNDLE_VERSION),
            generation: Some(generation),
            fingerprint: Some(fingerprint),
            created_at: Some(created_at),
            expires_at: Some(expires_at),
            keys,
            signature_algorithm: Some(SIGNATURE_ALGORITHM.to_string()),
            signature: Some(signer.sign(payload.as_bytes())),
            bundle_signing_public_key: Some(signer.public_openssh.clone()),
        };
        assert_eq!(
            CaBundle::from_response(raw, now(), None).unwrap_err(),
            CaBundleError::InvalidTimestamp
        );
    }

    #[test]
    fn rejects_empty_bundle() {
        let signer = Signer25519::new();
        assert_eq!(
            CaBundle::from_response(valid(&signer, 1, vec![]), now(), None).unwrap_err(),
            CaBundleError::Empty
        );
    }

    #[test]
    fn rejects_too_many_keys() {
        let signer = Signer25519::new();
        let keys: Vec<CaBundleKey> = (0..=MAX_KEYS)
            .map(|i| key(&format!("ca-{i:03}"), &pubkey()))
            .collect();
        assert_eq!(
            CaBundle::from_response(valid(&signer, 1, keys), now(), None).unwrap_err(),
            CaBundleError::TooManyKeys
        );
    }

    #[test]
    fn rejects_duplicate_key_id() {
        let signer = Signer25519::new();
        let raw = valid(
            &signer,
            1,
            vec![key("dup", &pubkey()), key("dup", &pubkey())],
        );
        assert_eq!(
            CaBundle::from_response(raw, now(), None).unwrap_err(),
            CaBundleError::DuplicateKeyId
        );
    }

    #[test]
    fn rejects_duplicate_public_key() {
        let signer = Signer25519::new();
        let pk = pubkey();
        let raw = valid(&signer, 1, vec![key("ca-01", &pk), key("ca-02", &pk)]);
        assert_eq!(
            CaBundle::from_response(raw, now(), None).unwrap_err(),
            CaBundleError::DuplicatePublicKey
        );
    }

    #[test]
    fn rejects_invalid_public_key() {
        let signer = Signer25519::new();
        let raw = valid(&signer, 1, vec![key("ca-01", "ssh-ed25519 not-base64!!")]);
        assert_eq!(
            CaBundle::from_response(raw, now(), None).unwrap_err(),
            CaBundleError::InvalidKey
        );
    }

    #[test]
    fn renders_managed_trusted_user_ca_keys() {
        let signer = Signer25519::new();
        let pk = pubkey();
        let bundle =
            CaBundle::from_response(valid(&signer, 9, vec![key("ca-01", &pk)]), now(), None)
                .unwrap();
        let rendered = bundle.render_trusted_user_ca_keys();
        assert!(rendered.starts_with("# Managed by mayfly-agent. DO NOT EDIT.\n"));
        assert!(rendered.contains("# bundle_version: 1\n"));
        assert!(rendered.contains("# generation: 9\n"));
        assert!(rendered.contains(&format!("# fingerprint: {}\n", bundle.fingerprint())));
        assert!(rendered.ends_with('\n'));

        let mut tokens = pk.split_whitespace();
        let algo = tokens.next().unwrap();
        let blob = tokens.next().unwrap();
        assert!(rendered.contains(&format!("{algo} {blob} mayfly:ca-01\n")));
    }

    #[test]
    fn from_json_rejects_garbage() {
        assert!(matches!(
            CaBundleResponse::from_json(b"not json").unwrap_err(),
            Error::InvalidCaBundle(CaBundleError::InvalidKey)
        ));
    }

    #[test]
    fn public_keys_equal_ignores_comment() {
        let signer = Signer25519::new();
        let base = signer.public_openssh.clone();
        let with_comment = format!("{} a-different-comment", base.trim());
        assert!(public_keys_equal(&base, &with_comment));
    }

    /// Build an OpenSSH `ssh-ed25519` line from raw 32-byte public-key material.
    fn openssh_from_raw(raw: [u8; 32]) -> String {
        let ssh = ssh_key::public::Ed25519PublicKey(raw);
        ssh_key::PublicKey::new(ssh_key::public::KeyData::Ed25519(ssh), "test")
            .to_openssh()
            .unwrap()
    }

    /// BL-025 parity: `verify_signature` must accept exactly the signatures the
    /// server produces — a well-formed Ed25519 signature over the payload.
    #[test]
    fn verify_signature_accepts_valid_ed25519_signature() {
        let signer = Signer25519::new();
        let payload = b"mayfly-bundle-canonical-payload";
        let sig = signer.sign(payload);
        assert!(verify_signature(payload, &sig, &signer.public_openssh).is_ok());
    }

    /// A signature over a different payload must fail (no malleability).
    #[test]
    fn verify_signature_rejects_payload_mismatch() {
        let signer = Signer25519::new();
        let sig = signer.sign(b"original-payload");
        assert_eq!(
            verify_signature(b"tampered-payload", &sig, &signer.public_openssh).unwrap_err(),
            CaBundleError::SignatureInvalid
        );
    }

    /// BL-025 regression: this is the behaviour that distinguishes
    /// `verify_strict` (server semantics) from plain `verify`. The Edwards
    /// identity element is a small-order public key; `VerifyingKey::from_bytes`
    /// accepts it, and the all-zero signature (R = identity, s = 0) satisfies the
    /// *cofactorless* equation that plain `verify` uses — so plain `verify` would
    /// ACCEPT this forgery. `verify_strict` rejects it on the small-order key,
    /// exactly as the server does. If this ever reverts to `.verify()`, the
    /// assertion below fails.
    #[test]
    fn verify_strict_rejects_small_order_signing_key_forgery() {
        let mut identity = [0u8; 32];
        identity[0] = 1; // canonical encoding of the order-1 Edwards point
        let openssh = openssh_from_raw(identity);
        let forged_sig = BASE64.encode([0u8; 64]); // R = identity, s = 0
        assert_eq!(
            verify_signature(b"any-payload", &forged_sig, &openssh).unwrap_err(),
            CaBundleError::SignatureInvalid
        );
    }

    /// The same small-order-key rejection must hold through the full
    /// `CaBundle::from_response` path, mapping to `SignatureInvalid`.
    #[test]
    fn from_response_rejects_small_order_signer() {
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let openssh = openssh_from_raw(identity);
        let keys = vec![key("ca-01", &pubkey())];
        let generation = 1;
        let fingerprint = compute_fingerprint(generation, &keys);
        let created_at = (now() - time::Duration::hours(1)).format(&Rfc3339).unwrap();
        let expires_at = (now() + time::Duration::hours(1)).format(&Rfc3339).unwrap();
        let raw = CaBundleResponse {
            bundle_version: Some(SUPPORTED_BUNDLE_VERSION),
            generation: Some(generation),
            fingerprint: Some(fingerprint),
            created_at: Some(created_at),
            expires_at: Some(expires_at),
            keys,
            signature_algorithm: Some(SIGNATURE_ALGORITHM.to_string()),
            signature: Some(BASE64.encode([0u8; 64])),
            bundle_signing_public_key: Some(openssh),
        };
        assert_eq!(
            CaBundle::from_response(raw, now(), None).unwrap_err(),
            CaBundleError::SignatureInvalid
        );
    }
}
