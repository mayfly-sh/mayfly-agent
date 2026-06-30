//! The production HTTP enrollment client.
//!
//! [`HttpEnrollmentClient`] implements the [`MayflyApiClient`] transport
//! abstraction over a blocking `reqwest` client (rustls + ring), turning the
//! agent's enrollment exchange into real network traffic. Enrollment is the one
//! *unauthenticated* exchange in the protocol — the single-use token in the
//! request body is the only credential — so, unlike heartbeat and CA-bundle
//! requests, nothing here is signed.
//!
//! The HTTP layer is split behind [`EnrollmentHttp`] so the client's URL
//! building, status mapping, and response capture are testable without a
//! network. The successful response is retained ([`HttpEnrollmentClient::last_response`])
//! so the runtime can pin the server-provided bundle signing key after
//! enrollment completes.

use std::sync::Mutex;
use std::time::Duration;

use crate::errors::{Error, Result};
use crate::identity::enrollment::{EnrollmentRequest, EnrollmentResponse, MayflyApiClient};
use crate::protocol::heartbeat::HttpResponse;

/// API path for the enrollment endpoint. Must match the server route exactly.
pub const ENROLL_PATH: &str = "/api/v1/machines/enroll";

/// Default request timeout for the enrollment exchange.
pub const DEFAULT_ENROLL_TIMEOUT: Duration = Duration::from_secs(30);

/// Minimal HTTP seam used by [`HttpEnrollmentClient`].
///
/// Split from the signed transports because enrollment is unauthenticated and
/// only needs a plain JSON `POST`. Injected so the client is testable without a
/// network.
pub trait EnrollmentHttp: Send + Sync {
    /// `POST` a JSON `body` to `url` and return the status and raw body.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EnrollmentTransport`] on any connection/protocol error.
    fn post_json(&self, url: &str, body: &[u8]) -> Result<HttpResponse>;
}

/// Production [`EnrollmentHttp`] backed by a blocking `reqwest` client over
/// rustls (ring provider), mirroring the signed transports' configuration.
pub struct ReqwestEnrollmentHttp {
    client: reqwest::blocking::Client,
}

impl ReqwestEnrollmentHttp {
    /// Build an enrollment transport with the given request `timeout`.
    ///
    /// When `tls_ca_path` is set, the referenced PEM CA bundle is trusted in
    /// addition to the built-in roots (full verification stays enabled). When
    /// `allow_insecure_tls` is set, certificate validation is disabled — for
    /// local development only; never in production.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EnrollmentTransport`] if the client cannot be built, or
    /// a config error if `tls_ca_path` cannot be read or parsed.
    pub fn new(
        timeout: Duration,
        allow_insecure_tls: bool,
        tls_ca_path: Option<&std::path::Path>,
    ) -> Result<Self> {
        let user_agent = format!("mayfly-agent/{}", env!("CARGO_PKG_VERSION"));
        let mut builder = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .user_agent(user_agent)
            .danger_accept_invalid_certs(allow_insecure_tls);
        if let Some(path) = tls_ca_path {
            for cert in crate::tls::load_root_certs(path)? {
                builder = builder.add_root_certificate(cert);
            }
        }
        let client = builder.build().map_err(|_| Error::EnrollmentTransport)?;
        Ok(Self { client })
    }
}

impl EnrollmentHttp for ReqwestEnrollmentHttp {
    fn post_json(&self, url: &str, body: &[u8]) -> Result<HttpResponse> {
        let response = self
            .client
            .post(url)
            .header("content-type", "application/json")
            .body(body.to_vec())
            .send()
            .map_err(|_| Error::EnrollmentTransport)?;
        let status = response.status().as_u16();
        let body = response
            .bytes()
            .map_err(|_| Error::EnrollmentTransport)?
            .to_vec();
        Ok(HttpResponse { status, body })
    }
}

/// A [`MayflyApiClient`] that performs enrollment over a real HTTP transport.
pub struct HttpEnrollmentClient<H: EnrollmentHttp> {
    http: H,
    server_url: String,
    last_response: Mutex<Option<EnrollmentResponse>>,
}

impl<H: EnrollmentHttp> HttpEnrollmentClient<H> {
    /// Construct a client targeting `server_url` (scheme + host; the enrollment
    /// path is appended internally).
    pub fn new(http: H, server_url: String) -> Self {
        Self {
            http,
            server_url,
            last_response: Mutex::new(None),
        }
    }

    /// The most recent successfully-parsed enrollment response, if any.
    ///
    /// Used by the runtime to pin the server-provided bundle signing key after a
    /// successful enrollment.
    pub fn last_response(&self) -> Option<EnrollmentResponse> {
        self.last_response
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl<H: EnrollmentHttp> MayflyApiClient for HttpEnrollmentClient<H> {
    async fn enroll(&self, request: EnrollmentRequest) -> Result<EnrollmentResponse> {
        let body = serde_json::to_vec(&request).map_err(|_| Error::EnrollmentTransport)?;
        let url = join_url(&self.server_url, ENROLL_PATH);

        let response = self.http.post_json(&url, &body)?;
        if !(200..300).contains(&response.status) {
            tracing::warn!(status = response.status, "enrollment rejected by server");
            return Err(Error::EnrollmentRejected);
        }

        // A 2xx with a body we cannot parse is a protocol violation; fail closed.
        let parsed: EnrollmentResponse = serde_json::from_slice(&response.body).map_err(|_| {
            tracing::warn!("enrollment response was not valid JSON");
            Error::EnrollmentRejected
        })?;

        *self.last_response.lock().unwrap_or_else(|e| e.into_inner()) = Some(parsed.clone());
        Ok(parsed)
    }
}

/// Join a base URL and an absolute path without duplicating the separating `/`.
fn join_url(base: &str, path: &str) -> String {
    format!("{}{}", base.trim_end_matches('/'), path)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::identity::keypair::MachineKeypair;
    use crate::service::block_on;

    /// A scripted [`EnrollmentHttp`] returning a queued response and recording
    /// the last URL/body it was given.
    struct MockHttp {
        response: Result<HttpResponse>,
        last_url: Mutex<Option<String>>,
    }

    impl MockHttp {
        fn with(status: u16, body: &[u8]) -> Self {
            Self {
                response: Ok(HttpResponse {
                    status,
                    body: body.to_vec(),
                }),
                last_url: Mutex::new(None),
            }
        }

        fn failing() -> Self {
            Self {
                response: Err(Error::EnrollmentTransport),
                last_url: Mutex::new(None),
            }
        }
    }

    impl EnrollmentHttp for MockHttp {
        fn post_json(&self, url: &str, _body: &[u8]) -> Result<HttpResponse> {
            *self.last_url.lock().unwrap() = Some(url.to_string());
            self.response
                .as_ref()
                .map(Clone::clone)
                .map_err(|_| Error::EnrollmentTransport)
        }
    }

    fn server_key() -> String {
        MachineKeypair::generate()
            .unwrap()
            .public_key_openssh()
            .unwrap()
    }

    fn request() -> EnrollmentRequest {
        EnrollmentRequest {
            enrollment_token: "mf_enroll_abc123".to_string(),
            hostname: "web-01".to_string(),
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            agent_version: "0.1.0".to_string(),
            public_key: "ssh-ed25519 AAAA".to_string(),
        }
    }

    fn ok_body(bundle_signing_key: Option<&str>) -> Vec<u8> {
        let bsk = match bundle_signing_key {
            Some(k) => format!(",\"bundle_signing_key\":\"{k}\""),
            None => String::new(),
        };
        format!(
            "{{\"machine_id\":\"srv_abc\",\"heartbeat_interval\":60,\"sync_interval\":300,\
\"server_identity\":\"{}\"{bsk}}}",
            server_key()
        )
        .into_bytes()
    }

    #[test]
    fn enroll_success_parses_and_records_response() {
        let key = server_key();
        let http = MockHttp::with(200, &ok_body(Some(&key)));
        let client = HttpEnrollmentClient::new(http, "https://mayfly.example.com".to_string());

        let response = block_on(client.enroll(request())).unwrap();
        assert_eq!(response.machine_id, "srv_abc");
        assert_eq!(response.bundle_signing_key.as_deref(), Some(key.as_str()));

        // The URL was built correctly and the response captured for pinning.
        let url = client.http.last_url.lock().unwrap().clone().unwrap();
        assert_eq!(url, "https://mayfly.example.com/api/v1/machines/enroll");
        assert_eq!(
            client
                .last_response()
                .unwrap()
                .bundle_signing_key
                .as_deref(),
            Some(key.as_str())
        );
    }

    #[test]
    fn enroll_without_bundle_signing_key_is_none() {
        let http = MockHttp::with(200, &ok_body(None));
        let client = HttpEnrollmentClient::new(http, "https://h".to_string());
        let response = block_on(client.enroll(request())).unwrap();
        assert!(response.bundle_signing_key.is_none());
    }

    #[test]
    fn non_2xx_is_rejected_and_not_recorded() {
        let http = MockHttp::with(401, b"{}");
        let client = HttpEnrollmentClient::new(http, "https://h".to_string());
        assert!(matches!(
            block_on(client.enroll(request())).unwrap_err(),
            Error::EnrollmentRejected
        ));
        assert!(client.last_response().is_none());
    }

    #[test]
    fn malformed_2xx_body_is_rejected() {
        let http = MockHttp::with(200, b"not json");
        let client = HttpEnrollmentClient::new(http, "https://h".to_string());
        assert!(matches!(
            block_on(client.enroll(request())).unwrap_err(),
            Error::EnrollmentRejected
        ));
    }

    #[test]
    fn transport_failure_propagates() {
        let http = MockHttp::failing();
        let client = HttpEnrollmentClient::new(http, "https://h".to_string());
        assert!(matches!(
            block_on(client.enroll(request())).unwrap_err(),
            Error::EnrollmentTransport
        ));
    }

    #[test]
    fn join_url_avoids_double_slash() {
        assert_eq!(
            join_url("https://h/", ENROLL_PATH),
            "https://h/api/v1/machines/enroll"
        );
    }
}
