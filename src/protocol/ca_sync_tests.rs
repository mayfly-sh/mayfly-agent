//! Unit tests for [`super`] (the CA-bundle synchronisation service).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Mutex;

use super::*;
use crate::clock::FixedClock;
use crate::identity::keypair::MachineKeypair;
use crate::protocol::ca_bundle::{
    canonical_signing_payload, compute_fingerprint, CaBundleKey, HEADER_IF_NONE_MATCH,
    SIGNATURE_ALGORITHM, SUPPORTED_BUNDLE_VERSION,
};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const NOW_UNIX: i64 = 1_700_000_000;

/// A throwaway Ed25519 bundle-signing key and its OpenSSH public form.
struct TestSigner {
    signing: SigningKey,
    public_openssh: String,
}

impl TestSigner {
    fn new(seed: u8) -> Self {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        let vk = signing.verifying_key();
        let ssh = ssh_key::public::Ed25519PublicKey(vk.to_bytes());
        let public =
            ssh_key::PublicKey::new(ssh_key::public::KeyData::Ed25519(ssh), "bundle-signing");
        Self {
            public_openssh: public.to_openssh().unwrap(),
            signing,
        }
    }

    fn sign_b64(&self, payload: &[u8]) -> String {
        BASE64.encode(self.signing.sign(payload).to_bytes())
    }
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(NOW_UNIX).unwrap()
}

fn pubkey() -> String {
    MachineKeypair::generate()
        .unwrap()
        .public_key_openssh()
        .unwrap()
}

/// Build a fully-signed JSON bundle body valid for one hour around `now`.
fn bundle_body(signer: &TestSigner, generation: u64, keys: &[(&str, &str)]) -> Vec<u8> {
    let keys: Vec<CaBundleKey> = keys
        .iter()
        .map(|(id, pk)| CaBundleKey {
            key_id: (*id).to_string(),
            public_key: (*pk).to_string(),
        })
        .collect();
    let fingerprint = compute_fingerprint(generation, &keys);
    let created_at = (now() - time::Duration::hours(1)).format(&Rfc3339).unwrap();
    let expires_at = (now() + time::Duration::hours(1)).format(&Rfc3339).unwrap();
    let payload = canonical_signing_payload(
        SUPPORTED_BUNDLE_VERSION,
        generation,
        &fingerprint,
        &created_at,
        &expires_at,
        &keys,
    );
    let signature = signer.sign_b64(payload.as_bytes());
    let entries: Vec<String> = keys
        .iter()
        .map(|k| {
            format!(
                "{{\"key_id\":\"{}\",\"public_key\":\"{}\"}}",
                k.key_id, k.public_key
            )
        })
        .collect();
    format!(
        "{{\"bundle_version\":{SUPPORTED_BUNDLE_VERSION},\"generation\":{generation},\
\"fingerprint\":\"{fingerprint}\",\"created_at\":\"{created_at}\",\"expires_at\":\"{expires_at}\",\
\"keys\":[{}],\"signature_algorithm\":\"{SIGNATURE_ALGORITHM}\",\"signature\":\"{signature}\",\
\"bundle_signing_public_key\":\"{}\"}}",
        entries.join(","),
        signer.public_openssh
    )
    .into_bytes()
}

/// A scripted transport: returns a queued GET response and records acks.
struct MockTransport {
    get_response: Mutex<Result<HttpResponse>>,
    ack_response: Mutex<Result<HttpResponse>>,
    last_get: Mutex<Option<HttpRequest>>,
    last_ack: Mutex<Option<HttpRequest>>,
}

impl MockTransport {
    fn new(get: Result<HttpResponse>) -> Self {
        Self {
            get_response: Mutex::new(get),
            ack_response: Mutex::new(Ok(HttpResponse {
                status: 200,
                body: b"{}".to_vec(),
            })),
            last_get: Mutex::new(None),
            last_ack: Mutex::new(None),
        }
    }

    fn with_ack(self, ack: Result<HttpResponse>) -> Self {
        *self.ack_response.lock().unwrap() = ack;
        self
    }
}

impl CaBundleTransport for MockTransport {
    fn get(&self, request: &HttpRequest) -> Result<HttpResponse> {
        *self.last_get.lock().unwrap() = Some(request.clone());
        clone_result(&self.get_response.lock().unwrap())
    }

    fn post(&self, request: &HttpRequest) -> Result<HttpResponse> {
        *self.last_ack.lock().unwrap() = Some(request.clone());
        clone_result(&self.ack_response.lock().unwrap())
    }
}

fn clone_result(r: &Result<HttpResponse>) -> Result<HttpResponse> {
    match r {
        Ok(resp) => Ok(resp.clone()),
        Err(_) => Err(Error::CaBundleTransport),
    }
}

/// A reloader whose reload/verify failures can be transient (fail the first N
/// calls, then succeed) so both happy-rollback and broken-rollback paths can be
/// exercised deterministically.
struct MockReloader {
    reload_fail_remaining: Mutex<u32>,
    verify_fail_remaining: Mutex<u32>,
    reloads: Mutex<u32>,
    verifies: Mutex<u32>,
}

impl MockReloader {
    fn make(reload_fails: u32, verify_fails: u32) -> Self {
        Self {
            reload_fail_remaining: Mutex::new(reload_fails),
            verify_fail_remaining: Mutex::new(verify_fails),
            reloads: Mutex::new(0),
            verifies: Mutex::new(0),
        }
    }

    fn healthy() -> Self {
        Self::make(0, 0)
    }

    /// Reload fails once (the apply), then succeeds (the rollback).
    fn reload_fails_first() -> Self {
        Self::make(1, 0)
    }

    /// Verify fails once (the apply), then succeeds (the rollback).
    fn verify_fails_first() -> Self {
        Self::make(0, 1)
    }

    /// Reload never succeeds, so even rollback cannot restore service.
    fn reload_always_fails() -> Self {
        Self::make(u32::MAX, 0)
    }

    fn reloads(&self) -> u32 {
        *self.reloads.lock().unwrap()
    }
}

impl SshdReloader for MockReloader {
    fn reload(&self) -> Result<()> {
        *self.reloads.lock().unwrap() += 1;
        let mut remaining = self.reload_fail_remaining.lock().unwrap();
        if *remaining > 0 {
            *remaining -= 1;
            Err(Error::Unsupported)
        } else {
            Ok(())
        }
    }

    fn verify(&self) -> Result<()> {
        *self.verifies.lock().unwrap() += 1;
        let mut remaining = self.verify_fail_remaining.lock().unwrap();
        if *remaining > 0 {
            *remaining -= 1;
            Err(Error::Unsupported)
        } else {
            Ok(())
        }
    }
}

struct Harness {
    dir: tempfile::TempDir,
    pin: Option<String>,
}

impl Harness {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            pin: None,
        }
    }

    fn with_pin(mut self, pin: String) -> Self {
        self.pin = Some(pin);
        self
    }

    fn p(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
    fn ca_path(&self) -> PathBuf {
        self.p("trusted_user_ca_keys")
    }

    fn service<T: CaBundleTransport, R: SshdReloader>(
        &self,
        transport: T,
        reloader: R,
    ) -> CaSyncService<T, R> {
        CaSyncService::new(
            transport,
            reloader,
            Arc::new(FixedClock::from_unix(NOW_UNIX)),
            MachineKeypair::generate().unwrap(),
            "srv_abc".to_string(),
            "https://mayfly.example.com".to_string(),
            self.pin.clone(),
            self.ca_path(),
            self.p("current_generation"),
            self.p("current_bundle.sha256"),
            self.p("bundle_signing_key.pub"),
            self.p("last_sync"),
            self.p("last_success"),
        )
    }
}

fn ok(body: Vec<u8>) -> Result<HttpResponse> {
    Ok(HttpResponse { status: 200, body })
}

#[test]
fn updates_on_new_signed_bundle_and_acks() {
    let h = Harness::new();
    let signer = TestSigner::new(11);
    let pk = pubkey();
    let service = h.service(
        MockTransport::new(ok(bundle_body(&signer, 42, &[("ca-01", &pk)]))),
        MockReloader::healthy(),
    );

    let outcome = service.synchronize().unwrap();
    match outcome {
        SyncOutcome::Updated {
            generation,
            acknowledged,
            ..
        } => {
            assert_eq!(generation, 42);
            assert!(acknowledged);
        }
        other => panic!("expected Updated, got {other:?}"),
    }

    let written = std::fs::read_to_string(h.ca_path()).unwrap();
    assert!(written.starts_with("# Managed by mayfly-agent"));
    assert!(written.contains("mayfly:ca-01"));
    assert_eq!(
        std::fs::read_to_string(h.p("current_generation"))
            .unwrap()
            .trim(),
        "42"
    );
    // last_sync, last_success, and the TOFU pin were all persisted.
    assert!(h.p("last_sync").exists());
    assert!(h.p("last_success").exists());
    assert_eq!(
        std::fs::read_to_string(h.p("bundle_signing_key.pub"))
            .unwrap()
            .trim(),
        signer.public_openssh
    );

    // Ack body carries the full status report.
    let ack = service.transport.last_ack.lock().unwrap().clone().unwrap();
    let body = String::from_utf8(ack.body).unwrap();
    assert!(body.contains("\"applied\":true"));
    assert!(body.contains("\"reload_success\":true"));
    assert!(body.contains("\"generation\":42"));
}

#[test]
fn skips_everything_on_304() {
    let h = Harness::new();
    std::fs::write(h.p("current_generation"), "42\n").unwrap();
    std::fs::write(h.p("current_bundle.sha256"), "sha256:abc\n").unwrap();

    let service = h.service(
        MockTransport::new(Ok(HttpResponse {
            status: 304,
            body: Vec::new(),
        })),
        MockReloader::healthy(),
    );

    assert_eq!(
        service.synchronize().unwrap(),
        SyncOutcome::NotModified { generation: 42 }
    );
    assert_eq!(service.reloader.reloads(), 0);
    assert!(!h.ca_path().exists());

    // The persisted fingerprint was sent as a quoted If-None-Match ETag.
    let get = service.transport.last_get.lock().unwrap().clone().unwrap();
    let etag = get
        .headers
        .iter()
        .find(|(n, _)| n == HEADER_IF_NONE_MATCH)
        .map(|(_, v)| v.clone());
    assert_eq!(etag.as_deref(), Some("\"sha256:abc\""));
}

#[test]
fn no_op_when_validated_bundle_already_applied() {
    let h = Harness::new();
    let signer = TestSigner::new(5);
    let pk = pubkey();
    let body = bundle_body(&signer, 7, &[("ca-01", &pk)]);
    let fingerprint = {
        let raw = CaBundleResponse::from_json(&body).unwrap();
        CaBundle::from_response(raw, now(), None)
            .unwrap()
            .fingerprint()
            .to_string()
    };
    std::fs::write(h.p("current_generation"), "7\n").unwrap();
    std::fs::write(h.p("current_bundle.sha256"), format!("{fingerprint}\n")).unwrap();

    let service = h.service(MockTransport::new(ok(body)), MockReloader::healthy());
    assert_eq!(
        service.synchronize().unwrap(),
        SyncOutcome::Unchanged { generation: 7 }
    );
    assert_eq!(service.reloader.reloads(), 0);
    assert!(!h.ca_path().exists());
}

#[test]
fn rejects_signing_key_swap_against_persisted_pin() {
    let h = Harness::new();
    let original = TestSigner::new(1);
    let pk = pubkey();
    // First sync pins the original signer.
    h.service(
        MockTransport::new(ok(bundle_body(&original, 1, &[("ca-01", &pk)]))),
        MockReloader::healthy(),
    )
    .synchronize()
    .unwrap();

    // Attacker presents a validly-signed bundle from a DIFFERENT signing key.
    let attacker = TestSigner::new(2);
    let service = h.service(
        MockTransport::new(ok(bundle_body(&attacker, 2, &[("ca-02", &pubkey())]))),
        MockReloader::healthy(),
    );
    assert!(matches!(
        service.synchronize().unwrap_err(),
        Error::InvalidCaBundle(crate::errors::CaBundleError::SigningKeyMismatch)
    ));
}

#[test]
fn rejects_generation_downgrade() {
    let h = Harness::new();
    let signer = TestSigner::new(9);
    let pk = pubkey();
    // Apply generation 5.
    h.service(
        MockTransport::new(ok(bundle_body(&signer, 5, &[("ca-01", &pk)]))),
        MockReloader::healthy(),
    )
    .synchronize()
    .unwrap();

    // Server (or attacker) offers an older, validly-signed generation 3.
    let service = h.service(
        MockTransport::new(ok(bundle_body(&signer, 3, &[("ca-01", &pk)]))),
        MockReloader::healthy(),
    );
    assert!(matches!(
        service.synchronize().unwrap_err(),
        Error::InvalidCaBundle(crate::errors::CaBundleError::GenerationRegressed)
    ));
}

#[test]
fn rolls_back_on_reload_failure() {
    let h = Harness::new();
    std::fs::write(h.ca_path(), "PREVIOUS\n").unwrap();
    let signer = TestSigner::new(3);
    let pk = pubkey();
    let service = h.service(
        MockTransport::new(ok(bundle_body(&signer, 99, &[("ca-01", &pk)]))),
        MockReloader::reload_fails_first(),
    );

    assert!(matches!(
        service.synchronize().unwrap_err(),
        Error::CaReloadFailed
    ));
    assert_eq!(std::fs::read_to_string(h.ca_path()).unwrap(), "PREVIOUS\n");
    assert!(!h.p("current_generation").exists());
    // Reload attempted twice: once for the new file, once after restoring.
    assert_eq!(service.reloader.reloads(), 2);

    // A failure ack was still reported (applied=false), and rollback succeeded.
    let ack = service.transport.last_ack.lock().unwrap().clone().unwrap();
    let body = String::from_utf8(ack.body).unwrap();
    assert!(body.contains("\"applied\":false"));
    assert!(body.contains("\"reload_success\":false"));
    assert!(body.contains("previous bundle restored"));
}

#[test]
fn rolls_back_on_verify_failure() {
    let h = Harness::new();
    std::fs::write(h.ca_path(), "PREVIOUS\n").unwrap();
    let signer = TestSigner::new(3);
    let pk = pubkey();
    let service = h.service(
        MockTransport::new(ok(bundle_body(&signer, 99, &[("ca-01", &pk)]))),
        MockReloader::verify_fails_first(),
    );

    assert!(matches!(
        service.synchronize().unwrap_err(),
        Error::CaReloadFailed
    ));
    // Previous content restored even though reload() "succeeded" but verify failed.
    assert_eq!(std::fs::read_to_string(h.ca_path()).unwrap(), "PREVIOUS\n");
    let ack = service.transport.last_ack.lock().unwrap().clone().unwrap();
    let body = String::from_utf8(ack.body).unwrap();
    assert!(body.contains("previous bundle restored"));
}

#[test]
fn reports_rollback_failure_when_sshd_permanently_broken() {
    let h = Harness::new();
    std::fs::write(h.ca_path(), "PREVIOUS\n").unwrap();
    let signer = TestSigner::new(3);
    let pk = pubkey();
    let service = h.service(
        MockTransport::new(ok(bundle_body(&signer, 99, &[("ca-01", &pk)]))),
        MockReloader::reload_always_fails(),
    );

    assert!(matches!(
        service.synchronize().unwrap_err(),
        Error::CaReloadFailed
    ));
    // The file content was still restored even though sshd cannot be reloaded.
    assert_eq!(std::fs::read_to_string(h.ca_path()).unwrap(), "PREVIOUS\n");
    // The ack must NOT claim success; it reports the rollback could not complete.
    let ack = service.transport.last_ack.lock().unwrap().clone().unwrap();
    let body = String::from_utf8(ack.body).unwrap();
    assert!(body.contains("\"applied\":false"));
    assert!(body.contains("rollback also failed"));
}

#[test]
fn rejected_status_is_error() {
    let h = Harness::new();
    let service = h.service(
        MockTransport::new(Ok(HttpResponse {
            status: 401,
            body: b"{}".to_vec(),
        })),
        MockReloader::healthy(),
    );
    assert!(matches!(
        service.synchronize().unwrap_err(),
        Error::CaBundleRejected
    ));
    // last_sync recorded the contact even though it failed.
    assert!(h.p("last_sync").exists());
}

#[test]
fn invalid_signature_is_rejected_before_write() {
    let h = Harness::new();
    let signer = TestSigner::new(7);
    let pk = pubkey();
    let body = bundle_body(&signer, 1, &[("ca-01", &pk)]);
    // Replace the signature with a well-formed but wrong 64-byte signature.
    let text = String::from_utf8(body).unwrap();
    let valid_len_wrong_sig = BASE64.encode([0u8; 64]);
    let needle = "\"signature\":\"";
    let start = text.find(needle).unwrap() + needle.len();
    let end = start + text[start..].find('"').unwrap();
    let tampered = format!("{}{valid_len_wrong_sig}{}", &text[..start], &text[end..]);
    let service = h.service(
        MockTransport::new(ok(tampered.into_bytes())),
        MockReloader::healthy(),
    );
    assert!(matches!(
        service.synchronize().unwrap_err(),
        Error::InvalidCaBundle(crate::errors::CaBundleError::SignatureInvalid)
    ));
    assert!(!h.ca_path().exists());
}

#[test]
fn unsupported_version_is_rejected() {
    let h = Harness::new();
    let signer = TestSigner::new(7);
    let pk = pubkey();
    let body = bundle_body(&signer, 1, &[("ca-01", &pk)]);
    let text = String::from_utf8(body)
        .unwrap()
        .replace("\"bundle_version\":1", "\"bundle_version\":2");
    let service = h.service(
        MockTransport::new(ok(text.into_bytes())),
        MockReloader::healthy(),
    );
    assert!(matches!(
        service.synchronize().unwrap_err(),
        Error::InvalidCaBundle(crate::errors::CaBundleError::UnsupportedVersion)
    ));
}

#[test]
fn operator_pin_overrides_and_rejects_other_signers() {
    // Operator pins a specific key; a bundle signed by a different key is rejected
    // even on first contact (no TOFU).
    let pinned = TestSigner::new(20);
    let h = Harness::new().with_pin(pinned.public_openssh.clone());
    let attacker = TestSigner::new(21);
    let service = h.service(
        MockTransport::new(ok(bundle_body(&attacker, 1, &[("ca-01", &pubkey())]))),
        MockReloader::healthy(),
    );
    assert!(matches!(
        service.synchronize().unwrap_err(),
        Error::InvalidCaBundle(crate::errors::CaBundleError::SigningKeyMismatch)
    ));
}

#[test]
fn ack_failure_is_non_fatal() {
    let h = Harness::new();
    let signer = TestSigner::new(4);
    let pk = pubkey();
    let service = h.service(
        MockTransport::new(ok(bundle_body(&signer, 5, &[("ca-01", &pk)])))
            .with_ack(Err(Error::CaBundleTransport)),
        MockReloader::healthy(),
    );
    match service.synchronize().unwrap() {
        SyncOutcome::Updated { acknowledged, .. } => assert!(!acknowledged),
        other => panic!("expected Updated, got {other:?}"),
    }
    assert_eq!(
        std::fs::read_to_string(h.p("current_generation"))
            .unwrap()
            .trim(),
        "5"
    );
}

#[test]
fn rejects_symlinked_trusted_ca_path() {
    let h = Harness::new();
    let target = h.dir.path().join("real_target");
    std::fs::write(&target, "x").unwrap();
    std::os::unix::fs::symlink(&target, h.ca_path()).unwrap();

    let signer = TestSigner::new(8);
    let service = h.service(
        MockTransport::new(ok(bundle_body(&signer, 1, &[("ca-01", &pubkey())]))),
        MockReloader::healthy(),
    );
    assert!(matches!(
        service.synchronize().unwrap_err(),
        Error::UnexpectedSymlink
    ));
}

#[test]
fn second_pass_sends_etag_from_persisted_fingerprint() {
    let h = Harness::new();
    let signer = TestSigner::new(6);
    let pk = pubkey();
    // First pass applies and persists a fingerprint.
    h.service(
        MockTransport::new(ok(bundle_body(&signer, 1, &[("ca-01", &pk)]))),
        MockReloader::healthy(),
    )
    .synchronize()
    .unwrap();
    let persisted_fp = std::fs::read_to_string(h.p("current_bundle.sha256"))
        .unwrap()
        .trim()
        .to_string();

    // Second pass: a fresh service reads persisted state and sends the ETag.
    let service = h.service(
        MockTransport::new(ok(bundle_body(
            &signer,
            2,
            &[("ca-01", &pk), ("ca-02", &pubkey())],
        ))),
        MockReloader::healthy(),
    );
    service.synchronize().unwrap();
    let get = service.transport.last_get.lock().unwrap().clone().unwrap();
    let etag = get
        .headers
        .iter()
        .find(|(n, _)| n == HEADER_IF_NONE_MATCH)
        .map(|(_, v)| v.clone());
    assert_eq!(
        etag.as_deref(),
        Some(format!("\"{persisted_fp}\"").as_str())
    );
}

#[test]
fn join_url_avoids_double_slash() {
    assert_eq!(
        super::join_url("https://h/", CA_BUNDLE_PATH),
        "https://h/api/v1/agent/ca-bundle"
    );
}
