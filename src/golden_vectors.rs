//! Cross-repository golden protocol vectors — agent side (BL-026, milestone 009D).
//!
//! These tests load the byte-identical golden vectors vendored from the single
//! canonical source (`.cursor/contracts/golden/protocol-vectors.json`) and
//! recompute every value from the agent's **real** canonical functions, asserting
//! equality. The server runs an independent mirror of these checks against the
//! same bytes. If either repository's canonicalization, signing, fingerprinting,
//! ETag, or IPC framing ever drifts, its golden test fails — guaranteeing
//! permanent cross-repository protocol compatibility.
//!
//! No serialization mocks: the vectors are consumed by the production code paths
//! (`canonical_json`, `canonical_signing_payload`, `compute_fingerprint`,
//! `CaBundle::from_response`, `signing::*`, `ipc::protocol::*`). No literals are
//! duplicated: every expected value lives only in the vendored JSON.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::errors::CaBundleError;
use crate::ipc::protocol as ipc;
use crate::protocol::ca_bundle::{
    canonical_json, canonical_signing_payload, compute_fingerprint, CaBundle, CaBundleKey,
    CaBundleResponse,
};
use crate::protocol::signing;

/// The vendored, byte-identical copy of the canonical golden vectors.
const VECTORS_JSON: &str = include_str!("../tests/vectors/protocol-vectors.json");

#[derive(Deserialize)]
struct Vectors {
    signing_domain: String,
    bundle: BundleVectors,
    request_signing: RequestSigningVectors,
    helper_ipc: HelperIpcVectors,
}

#[derive(Deserialize)]
struct BundleVectors {
    bundle_version: u32,
    generation: u64,
    created_at: String,
    expires_at: String,
    signature_algorithm: String,
    keys: Vec<CaBundleKey>,
    fingerprint_payload: String,
    fingerprint: String,
    etag: String,
    signing_key: String,
    signing_payload: String,
    signed_response_json: String,
}

#[derive(Deserialize)]
struct RequestSigningVectors {
    machine_id: String,
    timestamp: i64,
    nonce: String,
    method: String,
    path: String,
    body: String,
    body_sha256: String,
    canonical_string: String,
    machine_public_key: String,
    signature: String,
    minimal_canonical_string: String,
}

#[derive(Deserialize)]
struct HelperIpcVectors {
    max_body_bytes: usize,
    request_json: String,
    framed_hex: String,
}

fn vectors() -> Vectors {
    serde_json::from_str(VECTORS_JSON).expect("golden vectors must parse")
}

#[test]
fn signing_domain_matches() {
    assert_eq!(vectors().signing_domain, signing::SIGNING_DOMAIN);
}

#[test]
fn bundle_fingerprint_payload_matches() {
    let b = vectors().bundle;
    assert_eq!(canonical_json(b.generation, &b.keys), b.fingerprint_payload);
}

#[test]
fn bundle_fingerprint_and_etag_match() {
    let b = vectors().bundle;
    let fp = compute_fingerprint(b.generation, &b.keys);
    assert_eq!(fp, b.fingerprint);
    assert_eq!(format!("\"{fp}\""), b.etag);
}

#[test]
fn bundle_signing_payload_matches() {
    let b = vectors().bundle;
    assert_eq!(b.bundle_version, 1);
    assert_eq!(b.signature_algorithm, "ssh-ed25519");
    let payload = canonical_signing_payload(
        b.bundle_version,
        b.generation,
        &b.fingerprint,
        &b.created_at,
        &b.expires_at,
        &b.keys,
    );
    assert_eq!(payload, b.signing_payload);
}

#[test]
fn signed_bundle_example_verifies_end_to_end() {
    let b = vectors().bundle;
    // A clock inside the bundle's validity window.
    let now = OffsetDateTime::parse("2026-01-15T00:00:00Z", &Rfc3339).unwrap();
    let raw = CaBundleResponse::from_json(b.signed_response_json.as_bytes()).unwrap();
    let bundle = CaBundle::from_response(raw, now, Some(&b.signing_key))
        .expect("golden signed bundle must verify (incl. verify_strict + fingerprint + pin)");
    assert_eq!(bundle.generation(), b.generation);
    assert_eq!(bundle.fingerprint(), b.fingerprint.as_str());
}

#[test]
fn signed_bundle_example_rejects_wrong_pin() {
    let b = vectors().bundle;
    let now = OffsetDateTime::parse("2026-01-15T00:00:00Z", &Rfc3339).unwrap();
    let raw = CaBundleResponse::from_json(b.signed_response_json.as_bytes()).unwrap();
    // Pin a different (valid) key than the one that signed the bundle.
    let err = CaBundle::from_response(raw, now, Some(&b.keys[0].public_key)).unwrap_err();
    assert_eq!(err, CaBundleError::SigningKeyMismatch);
}

#[test]
fn signed_bundle_example_rejects_tampered_signature() {
    let b = vectors().bundle;
    let now = OffsetDateTime::parse("2026-01-15T00:00:00Z", &Rfc3339).unwrap();
    let mut raw = CaBundleResponse::from_json(b.signed_response_json.as_bytes()).unwrap();
    // Flip the signature to an all-zero one: must fail closed.
    raw.signature = Some(BASE64.encode([0u8; 64]));
    let err = CaBundle::from_response(raw, now, Some(&b.signing_key)).unwrap_err();
    assert_eq!(err, CaBundleError::SignatureInvalid);
}

#[test]
fn request_signing_canonical_strings_match() {
    let r = vectors().request_signing;
    assert_eq!(signing::body_sha256_hex(r.body.as_bytes()), r.body_sha256);
    let canonical = signing::canonical_string(
        &r.machine_id,
        r.timestamp,
        &r.nonce,
        &r.method,
        &r.path,
        &r.body_sha256,
    );
    assert_eq!(canonical, r.canonical_string);
    assert_eq!(
        signing::canonical_string("m", 5, "n", "POST", "/p", "deadbeef"),
        r.minimal_canonical_string
    );
}

#[test]
fn request_signature_verifies_against_machine_key() {
    let r = vectors().request_signing;
    let key = ssh_key::PublicKey::from_openssh(&r.machine_public_key).unwrap();
    let ed = key.key_data().ed25519().unwrap();
    let vk = VerifyingKey::from_bytes(&ed.0).unwrap();
    let sig_bytes: [u8; 64] = BASE64.decode(&r.signature).unwrap().try_into().unwrap();
    let signature = Signature::from_bytes(&sig_bytes);
    vk.verify_strict(r.canonical_string.as_bytes(), &signature)
        .expect("golden request signature must verify (verify_strict)");
}

#[test]
fn helper_ipc_framing_matches() {
    let v = vectors().helper_ipc;
    assert_eq!(v.max_body_bytes, ipc::MAX_BODY_BYTES);

    let req = ipc::Request::new("golden-test-token", ipc::Operation::Ping);
    let body = ipc::encode_request(&req).unwrap();
    assert_eq!(String::from_utf8(body.clone()).unwrap(), v.request_json);

    let mut framed = (u32::try_from(body.len()).unwrap()).to_be_bytes().to_vec();
    framed.extend_from_slice(&body);
    assert_eq!(hex::encode(&framed), v.framed_hex);

    // Round-trip: the framed bytes decode back to the same request.
    let mut cursor = std::io::Cursor::new(framed);
    let decoded_body = ipc::read_frame(&mut cursor).unwrap();
    let decoded = ipc::decode_request(&decoded_body).unwrap();
    assert_eq!(decoded, req);
}
