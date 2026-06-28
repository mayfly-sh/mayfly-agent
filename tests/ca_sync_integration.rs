//! End-to-end integration tests for signed CA-bundle synchronisation.
//!
//! These drive [`CaSyncService`] through a complete lifecycle against an
//! in-memory simulated server that **signs** bundles with an Ed25519
//! bundle-signing key, honours `If-None-Match` (ETag = fingerprint), and records
//! acknowledgements — plus a mock `sshd` reloader, a real temp-dir filesystem,
//! and a fixed clock.
//!
//! No sleeps, no network, and no real `systemctl` are involved.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use mayfly_agent::clock::FixedClock;
use mayfly_agent::errors::{Error, Result};
use mayfly_agent::identity::keypair::MachineKeypair;
use mayfly_agent::protocol::ca_bundle::{
    canonical_signing_payload, compute_fingerprint, CaBundleKey, HEADER_IF_NONE_MATCH,
    SIGNATURE_ALGORITHM, SUPPORTED_BUNDLE_VERSION,
};
use mayfly_agent::protocol::ca_sync::{
    CaBundleTransport, CaSyncService, SshdReloader, SyncOutcome,
};
use mayfly_agent::protocol::heartbeat::{HttpRequest, HttpResponse};

const NOW_UNIX: i64 = 1_700_000_000;

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(NOW_UNIX).unwrap()
}

/// One CA key the simulated server distributes.
#[derive(Clone)]
struct ServerKey {
    key_id: String,
    public_key: String,
}

/// A minimal in-memory CA server that signs the bundles it serves.
struct SimServer {
    signing: SigningKey,
    signing_public: String,
    generation: u64,
    keys: Vec<ServerKey>,
    expires_at: OffsetDateTime,
    last_ack: Option<String>,
}

impl SimServer {
    fn new(seed: u8, generation: u64, keys: Vec<ServerKey>) -> Self {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        let ssh = ssh_key::public::Ed25519PublicKey(signing.verifying_key().to_bytes());
        let public =
            ssh_key::PublicKey::new(ssh_key::public::KeyData::Ed25519(ssh), "bundle-signing");
        Self {
            signing,
            signing_public: public.to_openssh().unwrap(),
            generation,
            keys,
            expires_at: now() + time::Duration::hours(1),
            last_ack: None,
        }
    }

    fn bundle_keys(&self) -> Vec<CaBundleKey> {
        self.keys
            .iter()
            .map(|k| CaBundleKey {
                key_id: k.key_id.clone(),
                public_key: k.public_key.clone(),
            })
            .collect()
    }

    fn fingerprint(&self) -> String {
        compute_fingerprint(self.generation, &self.bundle_keys())
    }

    fn bundle_json(&self) -> Vec<u8> {
        let keys = self.bundle_keys();
        let fingerprint = self.fingerprint();
        let created_at = (now() - time::Duration::hours(1)).format(&Rfc3339).unwrap();
        let expires_at = self.expires_at.format(&Rfc3339).unwrap();
        let payload = canonical_signing_payload(
            SUPPORTED_BUNDLE_VERSION,
            self.generation,
            &fingerprint,
            &created_at,
            &expires_at,
            &keys,
        );
        let signature = BASE64.encode(self.signing.sign(payload.as_bytes()).to_bytes());
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
            "{{\"bundle_version\":{SUPPORTED_BUNDLE_VERSION},\"generation\":{},\
\"fingerprint\":\"{fingerprint}\",\"created_at\":\"{created_at}\",\"expires_at\":\"{expires_at}\",\
\"keys\":[{}],\"signature_algorithm\":\"{SIGNATURE_ALGORITHM}\",\"signature\":\"{signature}\",\
\"bundle_signing_public_key\":\"{}\"}}",
            self.generation,
            entries.join(","),
            self.signing_public
        )
        .into_bytes()
    }
}

/// Transport wired to a shared [`SimServer`].
#[derive(Clone)]
struct SimTransport {
    server: Arc<Mutex<SimServer>>,
}

impl CaBundleTransport for SimTransport {
    fn get(&self, request: &HttpRequest) -> Result<HttpResponse> {
        let server = self.server.lock().unwrap();
        let if_none_match = request
            .headers
            .iter()
            .find(|(n, _)| n == HEADER_IF_NONE_MATCH)
            .map(|(_, v)| v.trim_matches('"').to_string());

        if if_none_match.as_deref() == Some(server.fingerprint().as_str()) {
            return Ok(HttpResponse {
                status: 304,
                body: Vec::new(),
            });
        }
        Ok(HttpResponse {
            status: 200,
            body: server.bundle_json(),
        })
    }

    fn post(&self, request: &HttpRequest) -> Result<HttpResponse> {
        let body = String::from_utf8(request.body.clone()).unwrap();
        self.server.lock().unwrap().last_ack = Some(body);
        Ok(HttpResponse {
            status: 200,
            body: b"{\"status\":\"ok\"}".to_vec(),
        })
    }
}

/// A reloader whose health (reload + verify) is toggleable mid-test.
struct ToggleReloader {
    healthy: Arc<Mutex<bool>>,
    reloads: Arc<Mutex<u32>>,
}

impl SshdReloader for ToggleReloader {
    fn reload(&self) -> Result<()> {
        *self.reloads.lock().unwrap() += 1;
        if *self.healthy.lock().unwrap() {
            Ok(())
        } else {
            Err(Error::Unsupported)
        }
    }

    fn verify(&self) -> Result<()> {
        if *self.healthy.lock().unwrap() {
            Ok(())
        } else {
            Err(Error::Unsupported)
        }
    }
}

struct Fixture {
    dir: tempfile::TempDir,
    server: Arc<Mutex<SimServer>>,
    healthy: Arc<Mutex<bool>>,
    reloads: Arc<Mutex<u32>>,
}

impl Fixture {
    fn new(server: SimServer) -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            server: Arc::new(Mutex::new(server)),
            healthy: Arc::new(Mutex::new(true)),
            reloads: Arc::new(Mutex::new(0)),
        }
    }

    fn p(&self, name: &str) -> std::path::PathBuf {
        self.dir.path().join(name)
    }

    fn service(&self) -> CaSyncService<SimTransport, ToggleReloader> {
        CaSyncService::new(
            SimTransport {
                server: self.server.clone(),
            },
            ToggleReloader {
                healthy: self.healthy.clone(),
                reloads: self.reloads.clone(),
            },
            Arc::new(FixedClock::from_unix(NOW_UNIX)),
            MachineKeypair::generate().unwrap(),
            "srv_integration".to_string(),
            "https://mayfly.example.com".to_string(),
            None,
            self.p("trusted_user_ca_keys"),
            self.p("current_generation"),
            self.p("current_bundle.sha256"),
            self.p("bundle_signing_key.pub"),
            self.p("last_sync"),
            self.p("last_success"),
        )
    }
}

fn server_key(id: &str) -> ServerKey {
    ServerKey {
        key_id: id.to_string(),
        public_key: MachineKeypair::generate()
            .unwrap()
            .public_key_openssh()
            .unwrap(),
    }
}

#[test]
fn full_lifecycle_download_verify_apply_ack_then_304_then_update() {
    let fx = Fixture::new(SimServer::new(1, 1, vec![server_key("ca-01")]));

    // 1) First sync: download, verify signature, write, reload+verify, ack.
    let outcome = fx.service().synchronize().unwrap();
    assert!(matches!(
        outcome,
        SyncOutcome::Updated {
            generation: 1,
            acknowledged: true,
            ..
        }
    ));
    assert!(fx.p("trusted_user_ca_keys").exists());
    assert_eq!(
        std::fs::read_to_string(fx.p("current_generation"))
            .unwrap()
            .trim(),
        "1"
    );
    // TOFU-pinned the server's signing key.
    assert_eq!(
        std::fs::read_to_string(fx.p("bundle_signing_key.pub"))
            .unwrap()
            .trim(),
        fx.server.lock().unwrap().signing_public
    );
    assert!(fx
        .server
        .lock()
        .unwrap()
        .last_ack
        .as_ref()
        .unwrap()
        .contains("\"applied\":true"));

    // 2) Same generation -> server answers 304 (ETag match), nothing changes.
    let outcome = fx.service().synchronize().unwrap();
    assert_eq!(outcome, SyncOutcome::NotModified { generation: 1 });

    // 3) Server rotates to a new generation with an extra key (multiple CAs).
    {
        let mut server = fx.server.lock().unwrap();
        server.generation = 2;
        server.keys.push(server_key("ca-02"));
    }
    let outcome = fx.service().synchronize().unwrap();
    assert!(matches!(
        outcome,
        SyncOutcome::Updated { generation: 2, .. }
    ));

    let rendered = std::fs::read_to_string(fx.p("trusted_user_ca_keys")).unwrap();
    assert!(rendered.contains("mayfly:ca-01"));
    assert!(rendered.contains("mayfly:ca-02"));
    assert!(rendered.contains("# generation: 2"));
}

#[test]
fn reload_failure_rolls_back_and_preserves_previous_generation() {
    let fx = Fixture::new(SimServer::new(1, 1, vec![server_key("ca-01")]));
    fx.service().synchronize().unwrap();
    let applied = std::fs::read_to_string(fx.p("trusted_user_ca_keys")).unwrap();

    // Server rotates; sshd reload now fails.
    {
        let mut server = fx.server.lock().unwrap();
        server.generation = 2;
        server.keys = vec![server_key("ca-09")];
    }
    *fx.healthy.lock().unwrap() = false;

    assert!(matches!(
        fx.service().synchronize().unwrap_err(),
        Error::CaReloadFailed
    ));
    // Previous bundle restored; persisted generation still 1.
    assert_eq!(
        std::fs::read_to_string(fx.p("trusted_user_ca_keys")).unwrap(),
        applied
    );
    assert_eq!(
        std::fs::read_to_string(fx.p("current_generation"))
            .unwrap()
            .trim(),
        "1"
    );

    // sshd recovers; next pass cleanly advances to generation 2.
    *fx.healthy.lock().unwrap() = true;
    assert!(matches!(
        fx.service().synchronize().unwrap(),
        SyncOutcome::Updated { generation: 2, .. }
    ));
}

#[test]
fn rejects_expired_bundle() {
    let mut server = SimServer::new(1, 5, vec![server_key("ca-01")]);
    server.expires_at = now() - time::Duration::minutes(1);
    let fx = Fixture::new(server);

    assert!(matches!(
        fx.service().synchronize().unwrap_err(),
        Error::InvalidCaBundle(_)
    ));
    assert!(!fx.p("trusted_user_ca_keys").exists());
}

#[test]
fn rejects_tampered_bundle_body() {
    let fx = Fixture::new(SimServer::new(1, 3, vec![server_key("ca-01")]));

    // Tamper the served body by mutating a key id after signing.
    struct TamperTransport {
        inner: SimTransport,
    }
    impl CaBundleTransport for TamperTransport {
        fn get(&self, request: &HttpRequest) -> Result<HttpResponse> {
            let mut resp = self.inner.get(request)?;
            if resp.status == 200 {
                let body = String::from_utf8(resp.body)
                    .unwrap()
                    .replace("ca-01", "ca-99");
                resp.body = body.into_bytes();
            }
            Ok(resp)
        }
        fn post(&self, request: &HttpRequest) -> Result<HttpResponse> {
            self.inner.post(request)
        }
    }

    let service = CaSyncService::new(
        TamperTransport {
            inner: SimTransport {
                server: fx.server.clone(),
            },
        },
        ToggleReloader {
            healthy: fx.healthy.clone(),
            reloads: fx.reloads.clone(),
        },
        Arc::new(FixedClock::from_unix(NOW_UNIX)),
        MachineKeypair::generate().unwrap(),
        "srv_integration".to_string(),
        "https://mayfly.example.com".to_string(),
        None,
        fx.p("trusted_user_ca_keys"),
        fx.p("current_generation"),
        fx.p("current_bundle.sha256"),
        fx.p("bundle_signing_key.pub"),
        fx.p("last_sync"),
        fx.p("last_success"),
    );
    assert!(matches!(
        service.synchronize().unwrap_err(),
        Error::InvalidCaBundle(_)
    ));
    assert!(!fx.p("trusted_user_ca_keys").exists());
}

#[test]
fn idempotent_repeated_syncs_do_not_rewrite() {
    let fx = Fixture::new(SimServer::new(
        1,
        5,
        vec![server_key("ca-01"), server_key("ca-02")],
    ));
    assert!(matches!(
        fx.service().synchronize().unwrap(),
        SyncOutcome::Updated { generation: 5, .. }
    ));
    let reloads_after_first = *fx.reloads.lock().unwrap();

    for _ in 0..3 {
        assert_eq!(
            fx.service().synchronize().unwrap(),
            SyncOutcome::NotModified { generation: 5 }
        );
    }
    assert_eq!(*fx.reloads.lock().unwrap(), reloads_after_first);
}
