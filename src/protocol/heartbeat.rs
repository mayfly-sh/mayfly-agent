//! The agent heartbeat client.
//!
//! [`HeartbeatClient`] signs a heartbeat with the machine's Ed25519 identity and
//! sends it to the server. The HTTP transport is abstracted behind
//! [`HeartbeatTransport`] so the signing/serialization logic is fully testable
//! without a network, and so the real client ([`ReqwestTransport`]) stays a thin
//! adapter. There is intentionally **no retry logic** here yet.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::clock::Clock;
use crate::errors::{Error, Result};
use crate::identity::keypair::MachineKeypair;
use crate::protocol::signing::{self, SignedHeaders};

/// API path for the heartbeat endpoint. Signed verbatim, so it must match the
/// server route exactly.
pub const HEARTBEAT_PATH: &str = "/api/v1/agent/heartbeat";

/// Accepted bounds for the server-suggested next-heartbeat interval (seconds).
const MIN_NEXT_HEARTBEAT_SECS: u64 = 1;
const MAX_NEXT_HEARTBEAT_SECS: u64 = 86_400;

/// Request body for `POST /api/v1/agent/heartbeat`.
#[derive(Debug, Clone, Serialize)]
pub struct HeartbeatRequest {
    /// Agent software version.
    pub agent_version: String,
    /// Current hostname.
    pub hostname: String,
    /// Operating system, e.g. `linux`.
    pub os: String,
    /// Kernel version string.
    pub kernel: String,
    /// Self-reported IP address.
    pub ip: String,
    /// Configuration generation currently applied.
    pub current_generation: u64,
    /// Process uptime in seconds.
    pub uptime_seconds: u64,
}

/// Validated response from a successful heartbeat.
#[derive(Debug, Clone, Deserialize)]
pub struct HeartbeatResponse {
    /// Server status string (e.g. `"ok"`).
    pub status: String,
    /// Server's current time (RFC 3339).
    pub server_time: String,
    /// Seconds to wait before the next heartbeat.
    pub next_heartbeat_seconds: u64,
}

/// A minimal HTTP request the transport must perform.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// Absolute URL.
    pub url: String,
    /// Header name/value pairs to set.
    pub headers: Vec<(String, String)>,
    /// Raw request body.
    pub body: Vec<u8>,
}

/// A minimal HTTP response the transport returns.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Raw response body.
    pub body: Vec<u8>,
}

/// Abstraction over the HTTP transport used to deliver a signed request.
pub trait HeartbeatTransport: Send + Sync {
    /// Perform a `POST` and return the status and body.
    ///
    /// # Errors
    ///
    /// Returns [`Error::HeartbeatTransport`] on any connection/protocol error.
    fn post(&self, request: &HttpRequest) -> Result<HttpResponse>;
}

/// Production [`HeartbeatTransport`] backed by a blocking `reqwest` client over
/// rustls (ring provider).
pub struct ReqwestTransport {
    client: reqwest::blocking::Client,
}

impl ReqwestTransport {
    /// Build a transport with the given request `timeout`.
    ///
    /// When `allow_insecure_tls` is set, certificate validation is disabled —
    /// this is for local development only and must never be used in production.
    ///
    /// # Errors
    ///
    /// Returns [`Error::HeartbeatTransport`] if the client cannot be built.
    pub fn new(timeout: Duration, allow_insecure_tls: bool) -> Result<Self> {
        let user_agent = format!("mayfly-agent/{}", env!("CARGO_PKG_VERSION"));
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .user_agent(user_agent)
            .danger_accept_invalid_certs(allow_insecure_tls)
            .build()
            .map_err(|_| Error::HeartbeatTransport)?;
        Ok(Self { client })
    }
}

impl ReqwestTransport {
    /// Borrow the underlying blocking client so sibling transports (e.g. the CA
    /// bundle transport) can reuse the same connection pool and TLS config.
    pub(crate) fn client(&self) -> &reqwest::blocking::Client {
        &self.client
    }
}

impl HeartbeatTransport for ReqwestTransport {
    fn post(&self, request: &HttpRequest) -> Result<HttpResponse> {
        let mut builder = self.client.post(&request.url).body(request.body.clone());
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        let response = builder.send().map_err(|_| Error::HeartbeatTransport)?;
        let status = response.status().as_u16();
        let body = response
            .bytes()
            .map_err(|_| Error::HeartbeatTransport)?
            .to_vec();
        Ok(HttpResponse { status, body })
    }
}

/// Signs and sends heartbeats for one enrolled machine.
pub struct HeartbeatClient<T: HeartbeatTransport> {
    transport: T,
    clock: Arc<dyn Clock>,
    machine_id: String,
    keypair: MachineKeypair,
    server_url: String,
}

impl<T: HeartbeatTransport> HeartbeatClient<T> {
    /// Construct a heartbeat client.
    ///
    /// `server_url` is the base URL (scheme + host); the heartbeat path is
    /// appended internally and is the exact path that gets signed.
    pub fn new(
        transport: T,
        clock: Arc<dyn Clock>,
        machine_id: String,
        keypair: MachineKeypair,
        server_url: String,
    ) -> Self {
        Self {
            transport,
            clock,
            machine_id,
            keypair,
            server_url,
        }
    }

    /// Sign and send a heartbeat, returning the validated server response.
    ///
    /// # Errors
    ///
    /// * [`Error::RequestSigning`] if the body cannot be serialized or signed.
    /// * [`Error::HeartbeatTransport`] on transport failure.
    /// * [`Error::HeartbeatRejected`] if the server returns a non-2xx status.
    /// * [`Error::InvalidHeartbeatResponse`] if the response fails validation.
    pub fn send_heartbeat(&self, request: &HeartbeatRequest) -> Result<HeartbeatResponse> {
        let body = serde_json::to_vec(request).map_err(|_| Error::RequestSigning)?;
        let timestamp = self.clock.now().unix_timestamp();
        let nonce = signing::generate_nonce();

        let signed = signing::sign_request(
            &self.keypair,
            &self.machine_id,
            timestamp,
            &nonce,
            "POST",
            HEARTBEAT_PATH,
            &body,
        )?;

        let http_request = HttpRequest {
            url: join_url(&self.server_url, HEARTBEAT_PATH),
            headers: build_headers(&signed),
            body,
        };

        let response = self.transport.post(&http_request)?;
        if !(200..300).contains(&response.status) {
            tracing::warn!(
                status = response.status,
                machine_id = %self.machine_id,
                "heartbeat rejected by server"
            );
            return Err(Error::HeartbeatRejected);
        }

        let parsed: HeartbeatResponse =
            serde_json::from_slice(&response.body).map_err(|_| Error::InvalidHeartbeatResponse)?;
        validate_response(&parsed)?;
        Ok(parsed)
    }
}

/// Build the full header set for a signed request.
fn build_headers(signed: &SignedHeaders) -> Vec<(String, String)> {
    vec![
        ("content-type".to_string(), "application/json".to_string()),
        (
            signing::HEADER_MACHINE_ID.to_string(),
            signed.machine_id.clone(),
        ),
        (
            signing::HEADER_TIMESTAMP.to_string(),
            signed.timestamp.to_string(),
        ),
        (signing::HEADER_NONCE.to_string(), signed.nonce.clone()),
        (
            signing::HEADER_SIGNATURE.to_string(),
            signed.signature.clone(),
        ),
    ]
}

/// Join a base URL and an absolute path without duplicating the separating `/`.
fn join_url(base: &str, path: &str) -> String {
    format!("{}{}", base.trim_end_matches('/'), path)
}

/// Validate a heartbeat response. The server is authenticated by TLS but its
/// response is still range-checked before the agent acts on it.
fn validate_response(response: &HeartbeatResponse) -> Result<()> {
    if response.status.trim().is_empty() {
        return Err(Error::InvalidHeartbeatResponse);
    }
    if !(MIN_NEXT_HEARTBEAT_SECS..=MAX_NEXT_HEARTBEAT_SECS)
        .contains(&response.next_heartbeat_seconds)
    {
        return Err(Error::InvalidHeartbeatResponse);
    }
    if response.server_time.trim().is_empty() {
        return Err(Error::InvalidHeartbeatResponse);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::clock::FixedClock;
    use crate::protocol::signing::{body_sha256_hex, canonical_string};
    use base64::Engine as _;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use std::sync::Mutex;

    /// Transport that records the last request and returns a programmed result.
    struct MockTransport {
        last: Mutex<Option<HttpRequest>>,
        response: Result<HttpResponse>,
    }

    impl MockTransport {
        fn ok(body: &[u8]) -> Self {
            Self {
                last: Mutex::new(None),
                response: Ok(HttpResponse {
                    status: 200,
                    body: body.to_vec(),
                }),
            }
        }

        fn with(status: u16, body: &[u8]) -> Self {
            Self {
                last: Mutex::new(None),
                response: Ok(HttpResponse {
                    status,
                    body: body.to_vec(),
                }),
            }
        }
    }

    impl HeartbeatTransport for MockTransport {
        fn post(&self, request: &HttpRequest) -> Result<HttpResponse> {
            *self.last.lock().unwrap() = Some(request.clone());
            self.response
                .as_ref()
                .map(Clone::clone)
                .map_err(|_| Error::HeartbeatTransport)
        }
    }

    fn client(transport: MockTransport) -> HeartbeatClient<MockTransport> {
        HeartbeatClient::new(
            transport,
            Arc::new(FixedClock::from_unix(1_700_000_000)),
            "srv_abc".to_string(),
            MachineKeypair::generate().unwrap(),
            "https://mayfly.example.com/".to_string(),
        )
    }

    fn request() -> HeartbeatRequest {
        HeartbeatRequest {
            agent_version: "0.1.0".to_string(),
            hostname: "pi-zero".to_string(),
            os: "linux".to_string(),
            kernel: "6.12".to_string(),
            ip: "192.168.1.20".to_string(),
            current_generation: 17,
            uptime_seconds: 123_456,
        }
    }

    const OK_BODY: &[u8] =
        br#"{"status":"ok","server_time":"2026-06-24T12:00:00.000Z","next_heartbeat_seconds":60}"#;

    #[test]
    fn join_url_avoids_double_slash() {
        assert_eq!(
            join_url("https://h", "/api/v1/agent/heartbeat"),
            "https://h/api/v1/agent/heartbeat"
        );
        assert_eq!(
            join_url("https://h/", "/api/v1/agent/heartbeat"),
            "https://h/api/v1/agent/heartbeat"
        );
    }

    #[test]
    fn send_heartbeat_signs_and_parses() {
        let client = client(MockTransport::ok(OK_BODY));
        let response = client.send_heartbeat(&request()).unwrap();
        assert_eq!(response.status, "ok");
        assert_eq!(response.next_heartbeat_seconds, 60);

        // Inspect the captured request: URL, all signing headers present.
        let sent = client.transport.last.lock().unwrap().clone().unwrap();
        assert_eq!(
            sent.url,
            "https://mayfly.example.com/api/v1/agent/heartbeat"
        );
        let names: Vec<&str> = sent.headers.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&signing::HEADER_MACHINE_ID));
        assert!(names.contains(&signing::HEADER_TIMESTAMP));
        assert!(names.contains(&signing::HEADER_NONCE));
        assert!(names.contains(&signing::HEADER_SIGNATURE));
    }

    #[test]
    fn sent_signature_verifies_over_sent_body() {
        let keypair = MachineKeypair::generate().unwrap();
        let public = keypair.public_key_openssh().unwrap();
        let client = HeartbeatClient::new(
            MockTransport::ok(OK_BODY),
            Arc::new(FixedClock::from_unix(1_700_000_000)),
            "srv_abc".to_string(),
            keypair,
            "https://mayfly.example.com".to_string(),
        );
        client.send_heartbeat(&request()).unwrap();

        let sent = client.transport.last.lock().unwrap().clone().unwrap();
        let header = |name: &str| -> String {
            sent.headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
                .unwrap()
        };
        let timestamp: i64 = header(signing::HEADER_TIMESTAMP).parse().unwrap();
        let nonce = header(signing::HEADER_NONCE);
        let sig_b64 = header(signing::HEADER_SIGNATURE);

        let canonical = canonical_string(
            "srv_abc",
            timestamp,
            &nonce,
            "POST",
            HEARTBEAT_PATH,
            &body_sha256_hex(&sent.body),
        );
        let key = ssh_key::PublicKey::from_openssh(&public).unwrap();
        let vk = VerifyingKey::from_bytes(&key.key_data().ed25519().unwrap().0).unwrap();
        let sig_bytes: [u8; 64] = base64::engine::general_purpose::STANDARD
            .decode(&sig_b64)
            .unwrap()
            .try_into()
            .unwrap();
        vk.verify(canonical.as_bytes(), &Signature::from_bytes(&sig_bytes))
            .expect("server would accept this signature");
    }

    #[test]
    fn non_2xx_is_rejected() {
        let client = client(MockTransport::with(401, b"{}"));
        assert!(matches!(
            client.send_heartbeat(&request()).unwrap_err(),
            Error::HeartbeatRejected
        ));
    }

    #[test]
    fn invalid_json_response_is_rejected() {
        let client = client(MockTransport::with(200, b"not json"));
        assert!(matches!(
            client.send_heartbeat(&request()).unwrap_err(),
            Error::InvalidHeartbeatResponse
        ));
    }

    #[test]
    fn out_of_range_next_heartbeat_is_rejected() {
        let body = br#"{"status":"ok","server_time":"t","next_heartbeat_seconds":0}"#;
        let client = client(MockTransport::with(200, body));
        assert!(matches!(
            client.send_heartbeat(&request()).unwrap_err(),
            Error::InvalidHeartbeatResponse
        ));
    }

    #[test]
    fn transport_error_propagates() {
        let transport = MockTransport {
            last: Mutex::new(None),
            response: Err(Error::HeartbeatTransport),
        };
        let client = client(transport);
        assert!(matches!(
            client.send_heartbeat(&request()).unwrap_err(),
            Error::HeartbeatTransport
        ));
    }
}
