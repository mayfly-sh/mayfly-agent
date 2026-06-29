//! The CA-bundle synchronisation service (agent side).
//!
//! [`CaSyncService`] performs a single, transactional, **authenticated**
//! synchronisation pass. It is the agent's half of Mayfly fleet synchronisation:
//!
//! ```text
//! load persisted state (generation, fingerprint, pinned signing key)
//!   → signed GET /ca-bundle  (If-None-Match: "<fingerprint>")
//!     → 304? record last_sync/last_success, done (NotModified)
//!     → non-2xx? record last_sync, fail (CaBundleRejected)
//!     → 200: parse envelope
//!       → CaBundle::from_response  (verify signature → version → algo
//!                                    → signing-key pin → keys → fingerprint
//!                                    → expiry)
//!       → generation regressed vs. persisted? fail (downgrade protection)
//!       → identical to persisted? record last_success, done (Unchanged)
//!       → render TrustedUserCAKeys → re-parse to validate
//!         → delegate the privileged apply to the helper ([`BundleApplier`]):
//!             atomic write + `sshd -t` + reload + verify + rollback
//!           → helper rolled back? ack failure; fail (generation NOT advanced)
//!           → persist generation, fingerprint, pin, last_success
//!             → ack success
//! ```
//!
//! The agent itself performs **no** privileged filesystem writes to the managed
//! `TrustedUserCAKeys` and never reloads `sshd`: those steps belong to the root
//! `mayfly-helper`, reached through the [`BundleApplier`] port (ADR-0008/0012).
//! Everything that touches the outside world — HTTP and the privileged apply —
//! is injected behind a trait, so the whole flow is deterministic under test
//! with a mock transport, a mock clock, a temp-dir filesystem (for the agent's
//! own state), and a mock applier. There are **no sleeps** here; cadence and
//! jitter live in [`crate::service::scheduler`].
//!
//! ## Trust model (hostile network assumed)
//!
//! TLS authenticates the server and machine-signing authenticates the agent,
//! but the bundle is *additionally* protected by a detached Ed25519 signature
//! that the agent verifies before trusting any field. The signing key is
//! **pinned**: either operator-provisioned ([`crate::config::Config`]) or
//! trust-on-first-use, persisted under the state directory. A bundle whose
//! signing key differs from the pin is rejected, and the generation may never
//! regress — together these give downgrade and key-swap resistance on top of
//! TLS.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;
use time::format_description::well_known::Rfc3339;

use crate::clock::Clock;
use crate::errors::{Error, Result};
use crate::identity::keypair::MachineKeypair;
use crate::protocol::ca_bundle::{
    CaBundle, CaBundleResponse, CA_BUNDLE_ACK_PATH, CA_BUNDLE_PATH, HEADER_IF_NONE_MATCH,
};
use crate::protocol::heartbeat::{HttpRequest, HttpResponse, ReqwestTransport};
use crate::protocol::signing::{self, SignedHeaders};
use crate::security;
use crate::ssh::trusted_ca::TrustedCaKeys;

/// HTTP status the server returns when the agent's ETag is current.
const STATUS_NOT_MODIFIED: u16 = 304;

/// Abstraction over the HTTP transport for CA-bundle requests.
///
/// Split from the heartbeat transport so the two can evolve independently; the
/// production [`ReqwestTransport`] implements both.
pub trait CaBundleTransport: Send + Sync {
    /// Perform the signed `GET` for the current bundle.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CaBundleTransport`] on any connection/protocol error.
    fn get(&self, request: &HttpRequest) -> Result<HttpResponse>;

    /// Perform the signed `POST` acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CaBundleTransport`] on any connection/protocol error.
    fn post(&self, request: &HttpRequest) -> Result<HttpResponse>;
}

impl CaBundleTransport for ReqwestTransport {
    fn get(&self, request: &HttpRequest) -> Result<HttpResponse> {
        let mut builder = self.client().get(&request.url);
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        let response = builder.send().map_err(|_| Error::CaBundleTransport)?;
        let status = response.status().as_u16();
        let body = response
            .bytes()
            .map_err(|_| Error::CaBundleTransport)?
            .to_vec();
        Ok(HttpResponse { status, body })
    }

    fn post(&self, request: &HttpRequest) -> Result<HttpResponse> {
        let mut builder = self.client().post(&request.url).body(request.body.clone());
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        let response = builder.send().map_err(|_| Error::CaBundleTransport)?;
        let status = response.status().as_u16();
        let body = response
            .bytes()
            .map_err(|_| Error::CaBundleTransport)?
            .to_vec();
        Ok(HttpResponse { status, body })
    }
}

/// Abstraction over applying a rendered `TrustedUserCAKeys` body to the host.
///
/// This is the agent's **port** to the privileged boundary. The implementor owns
/// every privileged step — atomic write, `sshd -t`, reload, verify, and rollback
/// — so the (unprivileged) agent performs no privileged filesystem writes or
/// `sshd` control itself. In production the adapter is
/// [`crate::ipc::HelperBundleApplier`], which delegates to the root
/// `mayfly-helper` over an authenticated Unix Domain Socket (ADR-0008/0012);
/// tests inject a mock.
pub trait BundleApplier: Send + Sync {
    /// Apply a fully-rendered `TrustedUserCAKeys` body, owning the privileged
    /// write + `sshd -t` + reload + verify + rollback.
    ///
    /// # Errors
    ///
    /// Returns an error only if the apply could not be *attempted* (for example
    /// the privileged helper is unreachable or rejects the caller); in that case
    /// the host is left unchanged. A privileged-side failure that was safely
    /// rolled back is reported as [`BundleApplyOutcome::RolledBack`], not `Err`.
    fn apply(&self, trusted_ca_keys: &str) -> Result<BundleApplyOutcome>;
}

/// The result of delegating an apply to a [`BundleApplier`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleApplyOutcome {
    /// The new `TrustedUserCAKeys` was applied (written, `sshd -t`, reloaded and
    /// verified) or was already current — the host now trusts the new bundle.
    Applied,
    /// The privileged side could not apply the new bundle and restored the
    /// previous one (fail-closed). The host still trusts the previous bundle, so
    /// the agent must not advance its generation.
    RolledBack,
}

/// Status values the agent reports in an [`AckReport`].
///
/// These are the exact wire strings the server's `AckOutcome::parse` accepts:
/// a successful apply advances the server's `synced_generation`, while a
/// rollback is audited without advancing it.
const ACK_STATUS_APPLIED: &str = "applied";
const ACK_STATUS_ROLLBACK: &str = "rollback";

/// Fixed, non-sensitive reason reported when the helper rolled an apply back.
///
/// The privileged helper guarantees rollback-safety (it restores the previous
/// `TrustedUserCAKeys`, or removes it if none existed), so the agent reports a
/// single, stable reason. It is never a path or secret.
const ACK_ROLLBACK_REASON: &str = "sshd apply failed; previous bundle restored";

/// The acknowledgement reported to the server after a sync pass.
///
/// This is the wire body of `POST /api/v1/agent/ca-bundle/ack` and matches the
/// server's `BundleAckRequest` field-for-field. `reason`, when present, is a
/// fixed agent-controlled string — never a path or secret — so it is safe to
/// transmit; it is omitted entirely on success.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AckReport {
    /// The generation the pass concerned.
    pub generation: u64,
    /// The bundle fingerprint the pass concerned.
    pub fingerprint: String,
    /// Outcome status: `applied` (file replaced and reload verified) or
    /// `rollback` (apply failed and the previous bundle was restored).
    pub status: String,
    /// A fixed, non-sensitive detail string, omitted on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The result of a single synchronisation pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOutcome {
    /// The server returned `304`: the cached ETag is current.
    NotModified {
        /// The generation currently applied.
        generation: u64,
    },
    /// A `200` whose validated bundle already matched persisted state.
    Unchanged {
        /// The generation currently applied.
        generation: u64,
    },
    /// A new bundle was authenticated, written atomically, `sshd` reloaded and
    /// verified, and the new state persisted.
    Updated {
        /// The newly-applied generation.
        generation: u64,
        /// The newly-applied canonical fingerprint.
        fingerprint: String,
        /// Whether the server acknowledged the update (non-fatal if `false`).
        acknowledged: bool,
    },
}

/// The outcome of delegating the privileged apply to the [`BundleApplier`].
enum ApplyResult {
    /// The helper applied the new bundle and `sshd` is healthy.
    Applied,
    /// The helper could not apply and restored the previous bundle (fail-closed).
    RolledBack,
}

/// Persisted local state read at the start of a pass.
#[derive(Default)]
struct PersistedState {
    generation: Option<u64>,
    fingerprint: Option<String>,
    signing_key: Option<String>,
}

/// Synchronises the host's `TrustedUserCAKeys` with the server's signed bundle.
///
/// The managed `TrustedUserCAKeys` path is **not** held here: the agent renders
/// the file body and hands it to the [`BundleApplier`], which owns the path and
/// every privileged operation. The paths this struct does hold are the agent's
/// own, unprivileged state files under the state directory.
pub struct CaSyncService<T: CaBundleTransport, A: BundleApplier> {
    transport: T,
    applier: A,
    clock: Arc<dyn Clock>,
    keypair: MachineKeypair,
    machine_id: String,
    server_url: String,
    pinned_signing_key: Option<String>,
    generation_path: PathBuf,
    fingerprint_path: PathBuf,
    signing_key_path: PathBuf,
    last_sync_path: PathBuf,
    last_success_path: PathBuf,
}

impl<T: CaBundleTransport, A: BundleApplier> CaSyncService<T, A> {
    /// Construct a synchronisation service.
    ///
    /// `pinned_signing_key` is the operator-provisioned trust anchor (from
    /// configuration); when `None`, the agent pins the first signing key it sees
    /// under `signing_key_path`. `applier` is the privileged-apply port (in
    /// production, the `mayfly-helper` client).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transport: T,
        applier: A,
        clock: Arc<dyn Clock>,
        keypair: MachineKeypair,
        machine_id: String,
        server_url: String,
        pinned_signing_key: Option<String>,
        generation_path: PathBuf,
        fingerprint_path: PathBuf,
        signing_key_path: PathBuf,
        last_sync_path: PathBuf,
        last_success_path: PathBuf,
    ) -> Self {
        Self {
            transport,
            applier,
            clock,
            keypair,
            machine_id,
            server_url,
            pinned_signing_key,
            generation_path,
            fingerprint_path,
            signing_key_path,
            last_sync_path,
            last_success_path,
        }
    }

    /// Run one synchronisation pass.
    ///
    /// # Errors
    ///
    /// * [`Error::RequestSigning`] if a request cannot be signed.
    /// * [`Error::CaBundleTransport`] on transport failure fetching the bundle.
    /// * [`Error::CaBundleRejected`] if the server returns a non-success,
    ///   non-`304` status.
    /// * [`Error::InvalidCaBundle`] if the response fails authentication or
    ///   validation (bad signature, version, expiry, fingerprint, downgrade).
    /// * [`Error::InvalidTrustedCa`] if the rendered file fails re-parse.
    /// * [`Error::CaReloadFailed`] if the helper could not apply the bundle and
    ///   rolled back to the previous one (generation is not advanced).
    /// * [`Error::HelperUnavailable`] / [`Error::HelperUnauthenticated`] /
    ///   [`Error::HelperOperationFailed`] if the privileged apply could not be
    ///   attempted; the host is left unchanged.
    /// * [`Error::Io`] on failures writing the agent's own state files.
    pub fn synchronize(&self) -> Result<SyncOutcome> {
        let persisted = self.load_state()?;

        let response = self.fetch_bundle(persisted.fingerprint.as_deref())?;
        // We reached the server; record the attempt regardless of outcome.
        self.write_timestamp(&self.last_sync_path)?;

        if response.status == STATUS_NOT_MODIFIED {
            tracing::debug!(
                generation = persisted.generation.unwrap_or(0),
                "server reports CA bundle unchanged (304)"
            );
            self.write_timestamp(&self.last_success_path)?;
            return Ok(SyncOutcome::NotModified {
                generation: persisted.generation.unwrap_or(0),
            });
        }
        if !(200..300).contains(&response.status) {
            tracing::warn!(status = response.status, "CA bundle request rejected");
            return Err(Error::CaBundleRejected);
        }

        let raw = CaBundleResponse::from_json(&response.body)?;
        let expected = self.expected_signing_key(&persisted);
        let now = self.clock.now();
        let bundle = CaBundle::from_response(raw, now, expected.as_deref())
            .map_err(Error::InvalidCaBundle)?;

        // Downgrade protection: the generation may never go backwards.
        if let Some(prev) = persisted.generation {
            if bundle.generation() < prev {
                tracing::warn!(
                    applied = prev,
                    offered = bundle.generation(),
                    "rejecting CA bundle: generation regressed"
                );
                return Err(Error::InvalidCaBundle(
                    crate::errors::CaBundleError::GenerationRegressed,
                ));
            }
        }

        // Identical to what we already have: no write, no reload.
        if persisted.generation == Some(bundle.generation())
            && persisted.fingerprint.as_deref() == Some(bundle.fingerprint())
        {
            tracing::debug!(
                generation = bundle.generation(),
                "validated CA bundle already applied; no change"
            );
            self.persist_pin_if_needed(&bundle)?;
            self.write_timestamp(&self.last_success_path)?;
            return Ok(SyncOutcome::Unchanged {
                generation: bundle.generation(),
            });
        }

        match self.apply(&bundle)? {
            ApplyResult::Applied => {
                self.persist_after_apply(&bundle)?;
                let report = AckReport {
                    generation: bundle.generation(),
                    fingerprint: bundle.fingerprint().to_string(),
                    status: ACK_STATUS_APPLIED.to_string(),
                    reason: None,
                };
                let acknowledged = self.acknowledge(&report);
                Ok(SyncOutcome::Updated {
                    generation: bundle.generation(),
                    fingerprint: bundle.fingerprint().to_string(),
                    acknowledged,
                })
            }
            ApplyResult::RolledBack => {
                let report = AckReport {
                    generation: bundle.generation(),
                    fingerprint: bundle.fingerprint().to_string(),
                    status: ACK_STATUS_ROLLBACK.to_string(),
                    reason: Some(ACK_ROLLBACK_REASON.to_string()),
                };
                // Report failure but never claim success.
                let _ = self.acknowledge(&report);
                Err(Error::CaReloadFailed)
            }
        }
    }

    /// Render the new `TrustedUserCAKeys` body and delegate the privileged apply
    /// to the [`BundleApplier`] (the `mayfly-helper`), which owns the atomic
    /// write, `sshd -t`, reload, verify, and rollback.
    ///
    /// Returns `Err` only when the apply could not be *attempted* (render
    /// re-parse failure, or the helper being unreachable/unauthenticated); a
    /// privileged-side failure that the helper safely rolled back is returned as
    /// [`ApplyResult::RolledBack`].
    fn apply(&self, bundle: &CaBundle) -> Result<ApplyResult> {
        let contents = bundle.render_trusted_user_ca_keys();
        // Defence in depth: never ask the helper to apply a body we cannot parse.
        TrustedCaKeys::parse(&contents)?;

        match self.applier.apply(&contents)? {
            BundleApplyOutcome::Applied => Ok(ApplyResult::Applied),
            BundleApplyOutcome::RolledBack => {
                tracing::error!(
                    generation = bundle.generation(),
                    "helper rejected CA bundle apply and restored the previous bundle"
                );
                Ok(ApplyResult::RolledBack)
            }
        }
    }

    /// Determine the signing key the bundle must be verified against: the
    /// operator pin if configured, else the trust-on-first-use persisted pin,
    /// else `None` (first contact).
    fn expected_signing_key(&self, persisted: &PersistedState) -> Option<String> {
        self.pinned_signing_key
            .clone()
            .or_else(|| persisted.signing_key.clone())
    }

    /// Persist the bundle's signing key as the pin when there is no operator pin
    /// and none has been recorded yet (trust-on-first-use).
    fn persist_pin_if_needed(&self, bundle: &CaBundle) -> Result<()> {
        if self.pinned_signing_key.is_some() {
            return Ok(());
        }
        if read_optional(&self.signing_key_path)?.is_some() {
            return Ok(());
        }
        let contents = format!("{}\n", bundle.signing_public_key());
        security::secure_write(
            &self.signing_key_path,
            contents.as_bytes(),
            security::MODE_PUBLIC,
        )
    }

    /// Persist all post-apply state: generation, fingerprint, pin, last_success.
    fn persist_after_apply(&self, bundle: &CaBundle) -> Result<()> {
        self.write_generation(bundle.generation())?;
        self.write_fingerprint(bundle.fingerprint())?;
        self.persist_pin_if_needed(bundle)?;
        self.write_timestamp(&self.last_success_path)?;
        Ok(())
    }

    /// Send the signed acknowledgement. Returns whether it succeeded; never
    /// fails the synchronisation, since application state is already persisted.
    fn acknowledge(&self, report: &AckReport) -> bool {
        match self.try_acknowledge(report) {
            Ok(()) => true,
            Err(err) => {
                tracing::warn!(
                    generation = report.generation,
                    error = %err,
                    "failed to acknowledge CA bundle sync; will retry on next pass"
                );
                false
            }
        }
    }

    fn try_acknowledge(&self, report: &AckReport) -> Result<()> {
        let body = serde_json::to_vec(report).map_err(|_| Error::RequestSigning)?;
        let signed = self.sign("POST", CA_BUNDLE_ACK_PATH, &body)?;
        let mut headers = signing_headers(&signed);
        headers.push(("content-type".to_string(), "application/json".to_string()));
        let request = HttpRequest {
            url: join_url(&self.server_url, CA_BUNDLE_ACK_PATH),
            headers,
            body,
        };
        let response = self.transport.post(&request)?;
        if !(200..300).contains(&response.status) {
            return Err(Error::CaBundleRejected);
        }
        Ok(())
    }

    /// Build and send the signed `GET`, attaching `If-None-Match` with the
    /// cached fingerprint (as a quoted ETag) when one has been applied.
    fn fetch_bundle(&self, current_fingerprint: Option<&str>) -> Result<HttpResponse> {
        let signed = self.sign("GET", CA_BUNDLE_PATH, &[])?;
        let mut headers = signing_headers(&signed);
        if let Some(fingerprint) = current_fingerprint {
            headers.push((
                HEADER_IF_NONE_MATCH.to_string(),
                format!("\"{fingerprint}\""),
            ));
        }
        let request = HttpRequest {
            url: join_url(&self.server_url, CA_BUNDLE_PATH),
            headers,
            body: Vec::new(),
        };
        self.transport.get(&request)
    }

    /// Sign a request with the machine identity at the current clock time.
    fn sign(&self, method: &str, path: &str, body: &[u8]) -> Result<SignedHeaders> {
        let timestamp = self.clock.now().unix_timestamp();
        let nonce = signing::generate_nonce();
        signing::sign_request(
            &self.keypair,
            &self.machine_id,
            timestamp,
            &nonce,
            method,
            path,
            body,
        )
    }

    /// Load persisted generation, fingerprint, and pinned signing key.
    fn load_state(&self) -> Result<PersistedState> {
        Ok(PersistedState {
            generation: self.read_generation()?,
            fingerprint: read_optional_string(&self.fingerprint_path)?,
            signing_key: read_optional_string(&self.signing_key_path)?,
        })
    }

    fn read_generation(&self) -> Result<Option<u64>> {
        match read_optional_string(&self.generation_path)? {
            None => Ok(None),
            Some(text) => {
                let value = text
                    .trim()
                    .parse::<u64>()
                    .map_err(|_| Error::MachineRecordInvalid)?;
                Ok(Some(value))
            }
        }
    }

    fn write_generation(&self, generation: u64) -> Result<()> {
        let contents = format!("{generation}\n");
        security::secure_write(
            &self.generation_path,
            contents.as_bytes(),
            security::MODE_PUBLIC,
        )
    }

    fn write_fingerprint(&self, fingerprint: &str) -> Result<()> {
        let contents = format!("{fingerprint}\n");
        security::secure_write(
            &self.fingerprint_path,
            contents.as_bytes(),
            security::MODE_PUBLIC,
        )
    }

    /// Write the current clock time (RFC 3339) to `path`.
    fn write_timestamp(&self, path: &Path) -> Result<()> {
        let stamp = self
            .clock
            .now()
            .format(&Rfc3339)
            .map_err(|_| Error::MachineRecordInvalid)?;
        let contents = format!("{stamp}\n");
        security::secure_write(path, contents.as_bytes(), security::MODE_PUBLIC)
    }
}

/// Build the signing headers (without `content-type`) for a CA-bundle request.
fn signing_headers(signed: &SignedHeaders) -> Vec<(String, String)> {
    vec![
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

/// Read a file's bytes, mapping a missing file to `None`.
fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "failed to read file");
            Err(Error::Io(e))
        }
    }
}

/// Read a file as a trimmed, non-empty UTF-8 string, mapping missing/empty to
/// `None`.
fn read_optional_string(path: &Path) -> Result<Option<String>> {
    match read_optional(path)? {
        None => Ok(None),
        Some(bytes) => {
            let text = String::from_utf8(bytes).map_err(|_| Error::MachineRecordInvalid)?;
            let trimmed = text.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed.to_string()))
            }
        }
    }
}

#[cfg(test)]
#[path = "ca_sync_tests.rs"]
mod tests;
