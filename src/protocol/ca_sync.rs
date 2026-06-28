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
//!         → secure_write temp + fsync + atomic rename + dir fsync
//!           → reload sshd → verify reload
//!             → failure: restore previous file, reload, verify; ack failure; fail
//!           → persist generation, fingerprint, pin, last_success
//!             → ack success
//! ```
//!
//! Everything that touches the outside world — HTTP and the `sshd`
//! reload/verify — is injected behind a trait, so the whole flow is
//! deterministic under test with a mock transport, a mock clock, a temp-dir
//! filesystem, and a mock reloader. There are **no sleeps** here; cadence and
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

/// Abstraction over reloading `sshd` and verifying it accepted the new config.
///
/// Injected so synchronisation can be tested without a real service manager,
/// and so this security-sensitive capability is added in exactly one place.
pub trait SshdReloader: Send + Sync {
    /// Reload `sshd`'s configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the reload could not be performed.
    fn reload(&self) -> Result<()>;

    /// Verify `sshd` is active and accepted the (re)loaded configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if `sshd` is not healthy after the reload.
    fn verify(&self) -> Result<()>;
}

/// Production reloader delegating to the platform's systemd wrappers.
///
/// Note: in this build the underlying `platform::systemd` operations are
/// architecture-only and return [`Error::Unsupported`]; wiring them to the
/// service manager is a deliberate, separately-reviewed step.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemdSshdReloader;

impl SshdReloader for SystemdSshdReloader {
    fn reload(&self) -> Result<()> {
        crate::platform::systemd::reload_sshd()
    }

    fn verify(&self) -> Result<()> {
        crate::platform::systemd::verify_sshd_active()
    }
}

/// The acknowledgement reported to the server after a sync pass.
///
/// `error`, when present, is a fixed agent-controlled string — never a path or
/// secret — so it is safe to transmit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AckReport {
    /// The generation the pass concerned.
    pub generation: u64,
    /// The bundle fingerprint the pass concerned.
    pub fingerprint: String,
    /// Whether the new bundle was applied (file replaced and reload verified).
    pub applied: bool,
    /// Whether the `sshd` reload was verified successful.
    pub reload_success: bool,
    /// A fixed, non-sensitive failure description, if the pass failed.
    pub error: Option<String>,
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

/// The outcome of the file-replacement + reload phase.
enum ApplyResult {
    /// File replaced, `sshd` reloaded and verified.
    Applied,
    /// Reload or verify failed after the write; the previous file was restored.
    ReloadFailed {
        /// Whether the previous bundle was successfully restored.
        rolled_back: bool,
    },
}

/// Persisted local state read at the start of a pass.
#[derive(Default)]
struct PersistedState {
    generation: Option<u64>,
    fingerprint: Option<String>,
    signing_key: Option<String>,
}

/// Synchronises the local `TrustedUserCAKeys` with the server's signed bundle.
pub struct CaSyncService<T: CaBundleTransport, R: SshdReloader> {
    transport: T,
    reloader: R,
    clock: Arc<dyn Clock>,
    keypair: MachineKeypair,
    machine_id: String,
    server_url: String,
    pinned_signing_key: Option<String>,
    trusted_ca_path: PathBuf,
    generation_path: PathBuf,
    fingerprint_path: PathBuf,
    signing_key_path: PathBuf,
    last_sync_path: PathBuf,
    last_success_path: PathBuf,
}

impl<T: CaBundleTransport, R: SshdReloader> CaSyncService<T, R> {
    /// Construct a synchronisation service.
    ///
    /// `pinned_signing_key` is the operator-provisioned trust anchor (from
    /// configuration); when `None`, the agent pins the first signing key it sees
    /// under `signing_key_path`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transport: T,
        reloader: R,
        clock: Arc<dyn Clock>,
        keypair: MachineKeypair,
        machine_id: String,
        server_url: String,
        pinned_signing_key: Option<String>,
        trusted_ca_path: PathBuf,
        generation_path: PathBuf,
        fingerprint_path: PathBuf,
        signing_key_path: PathBuf,
        last_sync_path: PathBuf,
        last_success_path: PathBuf,
    ) -> Self {
        Self {
            transport,
            reloader,
            clock,
            keypair,
            machine_id,
            server_url,
            pinned_signing_key,
            trusted_ca_path,
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
    /// * [`Error::CaReloadFailed`] if `sshd` could not be reloaded/verified (the
    ///   previous bundle is restored before this is returned).
    /// * [`Error::Io`] / [`Error::UnexpectedSymlink`] on filesystem failures.
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
                    applied: true,
                    reload_success: true,
                    error: None,
                };
                let acknowledged = self.acknowledge(&report);
                Ok(SyncOutcome::Updated {
                    generation: bundle.generation(),
                    fingerprint: bundle.fingerprint().to_string(),
                    acknowledged,
                })
            }
            ApplyResult::ReloadFailed { rolled_back } => {
                let error = if rolled_back {
                    "sshd reload failed; previous bundle restored"
                } else {
                    "sshd reload failed; rollback also failed"
                };
                let report = AckReport {
                    generation: bundle.generation(),
                    fingerprint: bundle.fingerprint().to_string(),
                    applied: false,
                    reload_success: false,
                    error: Some(error.to_string()),
                };
                // Report failure but never claim success.
                let _ = self.acknowledge(&report);
                Err(Error::CaReloadFailed)
            }
        }
    }

    /// Replace the `TrustedUserCAKeys` file and reload+verify `sshd`, rolling
    /// back the file on failure.
    ///
    /// Returns `Err` only for *pre-write* failures (symlink, invalid render,
    /// I/O); a post-write reload/verify failure is reported via
    /// [`ApplyResult::ReloadFailed`] after rollback.
    fn apply(&self, bundle: &CaBundle) -> Result<ApplyResult> {
        security::ensure_not_symlink(&self.trusted_ca_path)?;
        let previous = read_optional(&self.trusted_ca_path)?;

        let contents = bundle.render_trusted_user_ca_keys();
        // Defence in depth: never write a file we cannot parse back.
        TrustedCaKeys::parse(&contents)?;

        security::secure_write(
            &self.trusted_ca_path,
            contents.as_bytes(),
            security::MODE_PUBLIC,
        )?;

        if let Err(err) = self.reload_and_verify() {
            tracing::error!(
                path = %self.trusted_ca_path.display(),
                error = %err,
                "sshd reload/verify failed; restoring previous CA bundle"
            );
            let rolled_back = self.rollback(previous.as_deref()).is_ok();
            return Ok(ApplyResult::ReloadFailed { rolled_back });
        }
        Ok(ApplyResult::Applied)
    }

    /// Reload `sshd` then verify it accepted the configuration.
    fn reload_and_verify(&self) -> Result<()> {
        self.reloader.reload()?;
        self.reloader.verify()
    }

    /// Restore the previous trusted-CA file (or remove it if none existed), then
    /// reload and verify `sshd`. Returns `Ok` only if the full restore succeeds.
    fn rollback(&self, previous: Option<&[u8]>) -> Result<()> {
        match previous {
            Some(bytes) => {
                security::secure_write(&self.trusted_ca_path, bytes, security::MODE_PUBLIC)?;
            }
            None => remove_optional(&self.trusted_ca_path)?,
        }
        self.reload_and_verify()
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

/// Remove a file, treating a missing file as success.
fn remove_optional(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "failed to remove file");
            Err(Error::Io(e))
        }
    }
}

#[cfg(test)]
#[path = "ca_sync_tests.rs"]
mod tests;
