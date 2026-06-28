//! End-to-end integration test for the daemon poll loop wiring.
//!
//! Drives [`run_poll_loop`] with:
//! * a mock heartbeat transport (counts signed heartbeats),
//! * an in-memory signing CA server + reloader (full apply path),
//! * a mock clock advanced by a custom sleeper that requests shutdown once a
//!   target time is reached.
//!
//! It proves the runtime wiring the milestone is about: heartbeats are sent and
//! CA synchronisation applies on the jittered cadence, runtime status is
//! persisted (survives "restart"), and a shutdown request stops the loop. The
//! CA verify/apply/rollback internals are covered separately in
//! `ca_sync_integration.rs`; here we exercise the loop that drives them.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::cell::RefCell;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use mayfly_agent::clock::{Clock, MockClock};
use mayfly_agent::config::Config;
use mayfly_agent::errors::Result;
use mayfly_agent::identity::keypair::MachineKeypair;
use mayfly_agent::platform::linux::HostFacts;
use mayfly_agent::protocol::ca_bundle::{
    canonical_signing_payload, compute_fingerprint, CaBundleKey, HEADER_IF_NONE_MATCH,
    SIGNATURE_ALGORITHM, SUPPORTED_BUNDLE_VERSION,
};
use mayfly_agent::protocol::ca_sync::{CaBundleTransport, CaSyncService, SshdReloader};
use mayfly_agent::protocol::heartbeat::{
    HeartbeatClient, HeartbeatTransport, HttpRequest, HttpResponse,
};
use mayfly_agent::service::daemon::run_poll_loop;
use mayfly_agent::service::runtime_state::{self, RuntimeStatus};
use mayfly_agent::service::scheduler::{FixedRandom, JitteredInterval, Scheduler};
use mayfly_agent::service::shutdown::Shutdown;

const NOW_UNIX: i64 = 1_700_000_000;

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(NOW_UNIX).unwrap()
}

// ---- signing CA server (mirrors ca_sync_integration.rs) ----

struct SimServer {
    signing: SigningKey,
    signing_public: String,
    generation: u64,
    keys: Vec<CaBundleKey>,
}

impl SimServer {
    fn new(seed: u8, generation: u64, key_id: &str) -> Self {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        let ssh = ssh_key::public::Ed25519PublicKey(signing.verifying_key().to_bytes());
        let public =
            ssh_key::PublicKey::new(ssh_key::public::KeyData::Ed25519(ssh), "bundle-signing");
        let public_key = MachineKeypair::generate()
            .unwrap()
            .public_key_openssh()
            .unwrap();
        Self {
            signing,
            signing_public: public.to_openssh().unwrap(),
            generation,
            keys: vec![CaBundleKey {
                key_id: key_id.to_string(),
                public_key,
            }],
        }
    }

    fn fingerprint(&self) -> String {
        compute_fingerprint(self.generation, &self.keys)
    }

    fn bundle_json(&self) -> Vec<u8> {
        let fingerprint = self.fingerprint();
        let created_at = (now() - time::Duration::hours(1)).format(&Rfc3339).unwrap();
        let expires_at = (now() + time::Duration::hours(1)).format(&Rfc3339).unwrap();
        let payload = canonical_signing_payload(
            SUPPORTED_BUNDLE_VERSION,
            self.generation,
            &fingerprint,
            &created_at,
            &expires_at,
            &self.keys,
        );
        let signature = BASE64.encode(self.signing.sign(payload.as_bytes()).to_bytes());
        let entries: Vec<String> = self
            .keys
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

#[derive(Clone)]
struct SimCaTransport {
    server: Arc<Mutex<SimServer>>,
}

impl CaBundleTransport for SimCaTransport {
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

    fn post(&self, _request: &HttpRequest) -> Result<HttpResponse> {
        Ok(HttpResponse {
            status: 200,
            body: b"{\"status\":\"ok\"}".to_vec(),
        })
    }
}

struct OkReloader;
impl SshdReloader for OkReloader {
    fn reload(&self) -> Result<()> {
        Ok(())
    }
    fn verify(&self) -> Result<()> {
        Ok(())
    }
}

// ---- heartbeat mock transport ----

struct CountingHeartbeatTransport {
    count: Arc<Mutex<u32>>,
}

impl HeartbeatTransport for CountingHeartbeatTransport {
    fn post(&self, _request: &HttpRequest) -> Result<HttpResponse> {
        *self.count.lock().unwrap() += 1;
        Ok(HttpResponse {
            status: 200,
            body: br#"{"status":"ok","server_time":"2026-06-29T00:00:00Z","next_heartbeat_seconds":60}"#
                .to_vec(),
        })
    }
}

// ---- sleeper: advance the mock clock, then request shutdown at `stop_at` ----

struct DrivingSleeper {
    clock: Arc<MockClock>,
    shutdown: Shutdown,
    stop_at_unix: i64,
}

impl mayfly_agent::service::scheduler::Sleeper for DrivingSleeper {
    fn sleep(&self, duration: Duration) {
        self.clock.advance(duration);
        if self.clock.now().unix_timestamp() >= self.stop_at_unix {
            self.shutdown.request();
        }
    }
}

fn config_in(state_dir: &std::path::Path) -> Config {
    let toml = format!(
        "server_url = \"https://mayfly.example.com\"\nmachine_id = \"host-01\"\nstate_dir = \"{}\"\n",
        state_dir.display()
    );
    Config::from_toml_with_env(&toml, |_| None).unwrap()
}

fn host_facts() -> HostFacts {
    HostFacts {
        hostname: "web-01".to_string(),
        os: "linux".to_string(),
        kernel: "6.12-test".to_string(),
        arch: "x86_64".to_string(),
        ip: "10.0.0.5".to_string(),
    }
}

#[test]
fn daemon_loop_heartbeats_syncs_persists_and_stops_on_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    let p = |name: &str| dir.path().join(name);
    let config = config_in(dir.path());

    let clock = Arc::new(MockClock::from_unix(NOW_UNIX));
    let dyn_clock: Arc<dyn Clock> = clock.clone();
    let rng = FixedRandom(0); // no jitter → deterministic cadence
    let shutdown = Shutdown::new();

    // Heartbeat client over a counting transport.
    let hb_count = Arc::new(Mutex::new(0u32));
    let heartbeat = HeartbeatClient::new(
        CountingHeartbeatTransport {
            count: hb_count.clone(),
        },
        dyn_clock.clone(),
        "srv_runtime".to_string(),
        MachineKeypair::generate().unwrap(),
        "https://mayfly.example.com".to_string(),
    );

    // CA sync service over a signing server + healthy reloader (full apply).
    let server = Arc::new(Mutex::new(SimServer::new(7, 1, "ca-01")));
    let sync = CaSyncService::new(
        SimCaTransport {
            server: server.clone(),
        },
        OkReloader,
        dyn_clock.clone(),
        MachineKeypair::generate().unwrap(),
        "srv_runtime".to_string(),
        "https://mayfly.example.com".to_string(),
        None,
        p("trusted_user_ca_keys"),
        p("current_generation"),
        p("current_bundle.sha256"),
        p("bundle_signing_key.pub"),
        p("last_sync"),
        p("last_success"),
    );

    // Heartbeat every 10s, sync every 20s, no jitter. Stop once the clock
    // reaches NOW+20 (so: heartbeats at +10 and +20; one sync at +20).
    let startup = clock.now();
    let mut scheduler = Scheduler::new(
        startup,
        JitteredInterval::new(Duration::from_secs(10), 0.0),
        JitteredInterval::new(Duration::from_secs(20), 0.0),
        &rng,
    );
    let sleeper = DrivingSleeper {
        clock: clock.clone(),
        shutdown: shutdown.clone(),
        stop_at_unix: NOW_UNIX + 20,
    };

    let status = RefCell::new(RuntimeStatus {
        agent_version: "test".to_string(),
        machine_id: "srv_runtime".to_string(),
        started_at_unix: startup.unix_timestamp(),
        ..RuntimeStatus::default()
    });

    run_poll_loop(
        &heartbeat,
        &sync,
        &mut scheduler,
        &dyn_clock,
        &rng,
        &sleeper,
        &shutdown,
        &host_facts(),
        &config,
        startup,
        &status,
    );

    // The loop stopped because shutdown was requested.
    assert!(shutdown.is_requested());

    // Two heartbeats were sent (t=+10, t=+20).
    assert_eq!(*hb_count.lock().unwrap(), 2, "expected two heartbeats");

    // CA synchronisation applied the bundle: file written, generation persisted.
    assert!(p("trusted_user_ca_keys").exists());
    assert_eq!(
        std::fs::read_to_string(p("current_generation"))
            .unwrap()
            .trim(),
        "1"
    );
    // TOFU-pinned the server's signing key.
    assert_eq!(
        std::fs::read_to_string(p("bundle_signing_key.pub"))
            .unwrap()
            .trim(),
        server.lock().unwrap().signing_public
    );

    // Runtime status persisted and survives "restart" (re-read from disk).
    let persisted = RuntimeStatus::load(&config).unwrap().unwrap();
    assert_eq!(persisted.current_generation, 1);
    assert_eq!(persisted.last_heartbeat_ok, Some(true));
    assert_eq!(persisted.last_sync_outcome.as_deref(), Some("updated"));

    // Recovery helper reads the same applied generation without a network call.
    assert_eq!(runtime_state::read_generation(&config).unwrap(), 1);
}
