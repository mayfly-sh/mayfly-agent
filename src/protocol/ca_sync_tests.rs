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

/// What the mock privileged applier should do when invoked.
#[derive(Clone, Copy)]
enum MockApplyResult {
    /// The helper applied the bundle and `sshd` is healthy.
    Applied,
    /// The helper failed and restored the previous bundle (fail-closed).
    RolledBack,
    /// The helper could not be reached; nothing was changed.
    Unavailable,
}

/// A mock privileged applier standing in for the `mayfly-helper`. It records the
/// rendered `TrustedUserCAKeys` body it was asked to apply and the call count,
/// so tests can prove the helper received exactly the rendered request and was
/// (or was not) invoked.
struct MockApplier {
    result: Mutex<MockApplyResult>,
    last_contents: Mutex<Option<String>>,
    calls: Mutex<u32>,
}

impl MockApplier {
    fn new(result: MockApplyResult) -> Self {
        Self {
            result: Mutex::new(result),
            last_contents: Mutex::new(None),
            calls: Mutex::new(0),
        }
    }

    /// The helper applies cleanly.
    fn healthy() -> Self {
        Self::new(MockApplyResult::Applied)
    }

    /// The helper fails the apply and rolls back to the previous bundle.
    fn rolls_back() -> Self {
        Self::new(MockApplyResult::RolledBack)
    }

    /// The helper is unreachable.
    fn unavailable() -> Self {
        Self::new(MockApplyResult::Unavailable)
    }

    fn calls(&self) -> u32 {
        *self.calls.lock().unwrap()
    }

    fn last_contents(&self) -> Option<String> {
        self.last_contents.lock().unwrap().clone()
    }
}

impl BundleApplier for MockApplier {
    fn apply(&self, trusted_ca_keys: &str) -> Result<BundleApplyOutcome> {
        *self.calls.lock().unwrap() += 1;
        *self.last_contents.lock().unwrap() = Some(trusted_ca_keys.to_string());
        match *self.result.lock().unwrap() {
            MockApplyResult::Applied => Ok(BundleApplyOutcome::Applied),
            MockApplyResult::RolledBack => Ok(BundleApplyOutcome::RolledBack),
            MockApplyResult::Unavailable => Err(Error::HelperUnavailable),
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

    fn service<T: CaBundleTransport, A: BundleApplier>(
        &self,
        transport: T,
        applier: A,
    ) -> CaSyncService<T, A> {
        CaSyncService::new(
            transport,
            applier,
            Arc::new(FixedClock::from_unix(NOW_UNIX)),
            MachineKeypair::generate().unwrap(),
            "srv_abc".to_string(),
            "https://mayfly.example.com".to_string(),
            self.pin.clone(),
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
        MockApplier::healthy(),
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

    // The rendered body was handed to the privileged applier (the helper),
    // exactly once — the agent itself wrote no TrustedUserCAKeys file.
    assert_eq!(service.applier.calls(), 1);
    let written = service.applier.last_contents().unwrap();
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
    assert!(body.contains("\"status\":\"applied\""));
    assert!(body.contains("\"generation\":42"));
    // A successful apply omits the reason entirely.
    assert!(!body.contains("\"reason\""));
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
        MockApplier::healthy(),
    );

    assert_eq!(
        service.synchronize().unwrap(),
        SyncOutcome::NotModified { generation: 42 }
    );
    // A 304 must never reach the privileged applier.
    assert_eq!(service.applier.calls(), 0);

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

    let service = h.service(MockTransport::new(ok(body)), MockApplier::healthy());
    assert_eq!(
        service.synchronize().unwrap(),
        SyncOutcome::Unchanged { generation: 7 }
    );
    // An already-applied bundle must never reach the privileged applier.
    assert_eq!(service.applier.calls(), 0);
}

#[test]
fn rejects_signing_key_swap_against_persisted_pin() {
    let h = Harness::new();
    let original = TestSigner::new(1);
    let pk = pubkey();
    // First sync pins the original signer.
    h.service(
        MockTransport::new(ok(bundle_body(&original, 1, &[("ca-01", &pk)]))),
        MockApplier::healthy(),
    )
    .synchronize()
    .unwrap();

    // Attacker presents a validly-signed bundle from a DIFFERENT signing key.
    let attacker = TestSigner::new(2);
    let service = h.service(
        MockTransport::new(ok(bundle_body(&attacker, 2, &[("ca-02", &pubkey())]))),
        MockApplier::healthy(),
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
        MockApplier::healthy(),
    )
    .synchronize()
    .unwrap();

    // Server (or attacker) offers an older, validly-signed generation 3.
    let service = h.service(
        MockTransport::new(ok(bundle_body(&signer, 3, &[("ca-01", &pk)]))),
        MockApplier::healthy(),
    );
    assert!(matches!(
        service.synchronize().unwrap_err(),
        Error::InvalidCaBundle(crate::errors::CaBundleError::GenerationRegressed)
    ));
}

#[test]
fn helper_rollback_does_not_advance_generation_and_acks_rollback() {
    // The helper received the apply, failed it, and restored the previous bundle
    // (it owns rollback). The agent must report CaReloadFailed, never advance its
    // generation, and ack a rollback (never success).
    let h = Harness::new();
    std::fs::write(h.p("current_generation"), "1\n").unwrap();
    let signer = TestSigner::new(3);
    let pk = pubkey();
    let service = h.service(
        MockTransport::new(ok(bundle_body(&signer, 99, &[("ca-01", &pk)]))),
        MockApplier::rolls_back(),
    );

    assert!(matches!(
        service.synchronize().unwrap_err(),
        Error::CaReloadFailed
    ));
    // The helper was asked exactly once, with the rendered body.
    assert_eq!(service.applier.calls(), 1);
    assert!(service
        .applier
        .last_contents()
        .unwrap()
        .contains("mayfly:ca-01"));
    // Persisted generation is unchanged (still the previous, applied value).
    assert_eq!(
        std::fs::read_to_string(h.p("current_generation"))
            .unwrap()
            .trim(),
        "1"
    );

    // A failure ack was reported with status=rollback (and a fixed reason).
    let ack = service.transport.last_ack.lock().unwrap().clone().unwrap();
    let body = String::from_utf8(ack.body).unwrap();
    assert!(body.contains("\"status\":\"rollback\""));
    assert!(body.contains("previous bundle restored"));
}

#[test]
fn helper_unavailable_propagates_and_sends_no_ack() {
    // If the privileged apply cannot even be attempted (helper down), the host is
    // unchanged: propagate the error, advance nothing, and send no ack — there is
    // no apply outcome to acknowledge.
    let h = Harness::new();
    let signer = TestSigner::new(3);
    let pk = pubkey();
    let service = h.service(
        MockTransport::new(ok(bundle_body(&signer, 99, &[("ca-01", &pk)]))),
        MockApplier::unavailable(),
    );

    assert!(matches!(
        service.synchronize().unwrap_err(),
        Error::HelperUnavailable
    ));
    assert_eq!(service.applier.calls(), 1);
    assert!(!h.p("current_generation").exists());
    // No acknowledgement was sent.
    assert!(service.transport.last_ack.lock().unwrap().is_none());
}

#[test]
fn rejected_status_is_error() {
    let h = Harness::new();
    let service = h.service(
        MockTransport::new(Ok(HttpResponse {
            status: 401,
            body: b"{}".to_vec(),
        })),
        MockApplier::healthy(),
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
        MockApplier::healthy(),
    );
    assert!(matches!(
        service.synchronize().unwrap_err(),
        Error::InvalidCaBundle(crate::errors::CaBundleError::SignatureInvalid)
    ));
    // An unauthenticated bundle must be rejected before reaching the helper.
    assert_eq!(service.applier.calls(), 0);
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
        MockApplier::healthy(),
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
        MockApplier::healthy(),
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
        MockApplier::healthy(),
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
fn second_pass_sends_etag_from_persisted_fingerprint() {
    let h = Harness::new();
    let signer = TestSigner::new(6);
    let pk = pubkey();
    // First pass applies and persists a fingerprint.
    h.service(
        MockTransport::new(ok(bundle_body(&signer, 1, &[("ca-01", &pk)]))),
        MockApplier::healthy(),
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
        MockApplier::healthy(),
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

/// GOLDEN (ack wire shape): the agent serializes an applied ack with exactly
/// `generation`, `fingerprint`, `status` and omits `reason`; a rollback ack adds
/// `reason`. These bytes must deserialize into the server's `BundleAckRequest`.
#[test]
fn ack_report_serializes_to_server_schema() {
    let applied = AckReport {
        generation: 42,
        fingerprint: "sha256:ab".to_string(),
        status: "applied".to_string(),
        reason: None,
    };
    assert_eq!(
        serde_json::to_string(&applied).unwrap(),
        "{\"generation\":42,\"fingerprint\":\"sha256:ab\",\"status\":\"applied\"}"
    );

    let rollback = AckReport {
        generation: 42,
        fingerprint: "sha256:ab".to_string(),
        status: "rollback".to_string(),
        reason: Some("sshd reload failed; previous bundle restored".to_string()),
    };
    assert_eq!(
        serde_json::to_string(&rollback).unwrap(),
        "{\"generation\":42,\"fingerprint\":\"sha256:ab\",\"status\":\"rollback\",\
\"reason\":\"sshd reload failed; previous bundle restored\"}"
    );
}
