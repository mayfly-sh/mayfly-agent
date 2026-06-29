//! The production daemon: startup, enrollment/recovery, and the poll loop.
//!
//! [`Daemon::run`] is the agent's main entry point once configuration is loaded
//! and logging is initialised. It composes the already-implemented building
//! blocks — [`EnrollmentService`], [`HeartbeatClient`], [`CaSyncService`],
//! [`Scheduler`] — into a long-running process:
//!
//! ```text
//! diagnostics → ensure state dir → install signal handlers
//!   → enrolled? (recover) : (enroll with backoff, pin signing key)
//!   → load identity + keypair → recover applied generation + runtime status
//!   → build transports/clients/scheduler
//!   → initial best-effort heartbeat + sync
//!   → run_polling (heartbeat + CA sync on jittered cadence) until SIGINT/SIGTERM
//!   → persist runtime status (clean shutdown) and exit
//! ```
//!
//! The runtime is synchronous and thread-based: blocking transports, a
//! `thread::sleep`-backed (but shutdown-interruptible) sleeper, and the one
//! vestigial async call bridged by [`block_on`](crate::service::block_on). No
//! async runtime is introduced.
//!
//! ## Privileged boundary
//!
//! The privileged apply — replacing the managed `TrustedUserCAKeys`, validating
//! with `sshd -t`, reloading `sshd`, and rolling back on failure — is delegated
//! to the root `mayfly-helper` via [`HelperBundleApplier`] over an authenticated
//! Unix Domain Socket. The agent runs unprivileged and performs no privileged
//! filesystem writes itself. If the helper is unreachable a *new* bundle apply
//! fails non-fatally (logged, retried next cadence); enrollment, heartbeats,
//! bundle fetch/verify, `304` handling, and state persistence all operate
//! normally.

use std::cell::RefCell;
use std::sync::Arc;
use std::time::Duration;

use time::OffsetDateTime;

use crate::clock::Clock;
use crate::config::Config;
use crate::errors::{Error, Result};
use crate::identity::api_client::{
    HttpEnrollmentClient, ReqwestEnrollmentHttp, DEFAULT_ENROLL_TIMEOUT,
};
use crate::identity::enrollment::{validate_token, EnrollmentService};
use crate::identity::machine::MachineIdentity;
use crate::ipc::HelperBundleApplier;
use crate::platform::linux::{self, HostFacts};
use crate::platform::systemd;
use crate::protocol::ca_sync::{BundleApplier, CaBundleTransport, CaSyncService, SyncOutcome};
use crate::protocol::heartbeat::{
    HeartbeatClient, HeartbeatRequest, HeartbeatTransport, ReqwestTransport,
};
use crate::service::backoff::{retry_with_backoff, BackoffPolicy};
use crate::service::block_on;
use crate::service::runtime_state::{self, RuntimeStatus};
use crate::service::scheduler::{
    run_polling, JitteredInterval, OsRandom, RandomSource, Scheduler, Sleeper,
};
use crate::service::shutdown::{install_signal_handlers, InterruptibleSleeper, Shutdown};
use crate::state::AppState;

/// Environment variable carrying the single-use enrollment token.
///
/// The token is read only when the machine is not yet enrolled and is **never**
/// persisted to disk, matching the enrollment layer's secrecy guarantees.
pub const ENROLLMENT_TOKEN_ENV: &str = "MAYFLY_AGENT_ENROLLMENT_TOKEN";

/// Request timeout for the signed heartbeat/CA-bundle transports.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// The Mayfly agent daemon.
#[derive(Clone, Debug)]
pub struct Daemon {
    state: AppState,
}

impl Daemon {
    /// Construct a daemon around shared application state.
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    /// Borrow the shared application state.
    pub fn state(&self) -> &AppState {
        &self.state
    }

    /// Run the daemon until a termination signal is received.
    ///
    /// # Errors
    ///
    /// Returns an error only for unrecoverable startup failures (e.g. missing
    /// enrollment token, identity load failure, transport construction). Steady-
    /// state heartbeat/sync failures are logged and retried on the next cadence,
    /// not propagated.
    pub fn run(&self) -> Result<()> {
        let config = self.state.config();
        let clock: Arc<dyn Clock> = Arc::clone(self.state.clock());
        let rng = OsRandom;

        self.log_startup_diagnostics(config);

        runtime_state::ensure_state_dir(&config.state_dir)?;

        let shutdown = Shutdown::new();
        install_signal_handlers(&shutdown)?;
        let sleeper = InterruptibleSleeper::new(shutdown.clone());

        let host = linux::host_facts();
        tracing::info!(
            hostname = %host.hostname,
            os = %host.os,
            kernel = %host.kernel,
            arch = %host.arch,
            "gathered host facts"
        );

        let enrollment = EnrollmentService::new(&config.identity_dir, Arc::clone(&clock));
        let identity = self.ensure_enrolled(
            config,
            &enrollment,
            &host,
            &shutdown,
            &clock,
            &rng,
            &sleeper,
        )?;

        if shutdown.is_requested() {
            tracing::info!("shutdown requested during enrollment; exiting before polling");
            return Ok(());
        }

        // Two independent transports/keypairs: the heartbeat client and the CA
        // sync service each own their transport and signing key.
        let hb_keypair = enrollment.load_machine_keypair()?;
        let sync_keypair = enrollment.load_machine_keypair()?;

        let current_generation = runtime_state::read_generation(config)?;
        if let Some(previous) = RuntimeStatus::load(config)? {
            tracing::info!(
                clean_shutdown = previous.clean_shutdown,
                last_generation = previous.current_generation,
                "recovered previous runtime status"
            );
        }
        tracing::info!(
            machine_id = %identity.machine_id,
            current_generation,
            heartbeat_interval_secs = identity.heartbeat_interval.as_secs(),
            sync_interval_secs = identity.sync_interval.as_secs(),
            "runtime state recovered; starting workers"
        );

        let hb_transport = ReqwestTransport::new(HTTP_TIMEOUT, config.allow_insecure_tls)?;
        let ca_transport = ReqwestTransport::new(HTTP_TIMEOUT, config.allow_insecure_tls)?;

        let heartbeat = HeartbeatClient::new(
            hb_transport,
            Arc::clone(&clock),
            identity.machine_id.clone(),
            hb_keypair,
            identity.server_url.clone(),
        );
        // Privileged apply is delegated to the root mayfly-helper over its UDS;
        // the agent itself never writes the managed TrustedUserCAKeys or reloads
        // sshd. The applier reads the capability token per call, so a helper
        // installed (or rotated) after startup is picked up without a restart.
        let applier = HelperBundleApplier::new(
            config.helper_socket_path.clone(),
            config.helper_token_path.clone(),
        );
        let sync = CaSyncService::new(
            ca_transport,
            applier,
            Arc::clone(&clock),
            sync_keypair,
            identity.machine_id.clone(),
            identity.server_url.clone(),
            config.bundle_signing_public_key.clone(),
            config.generation_path(),
            config.bundle_fingerprint_path(),
            config.bundle_signing_key_path(),
            config.last_sync_path(),
            config.last_success_path(),
        );

        let startup = self.state.startup_time();
        let mut scheduler = Scheduler::new(
            clock.now(),
            JitteredInterval::new(identity.heartbeat_interval, config.poll_jitter_ratio),
            JitteredInterval::new(identity.sync_interval, config.poll_jitter_ratio),
            &rng,
        );

        let status = RefCell::new(RuntimeStatus {
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            machine_id: identity.machine_id.clone(),
            started_at_unix: startup.unix_timestamp(),
            current_generation,
            clean_shutdown: false,
            ..RuntimeStatus::default()
        });
        status.borrow().save(config)?;

        // Initial best-effort contact so a freshly-enrolled host heartbeats and
        // applies the bundle promptly rather than waiting a full interval.
        tracing::info!("performing initial heartbeat and CA synchronisation");
        let _ = record_heartbeat(&heartbeat, &host, &clock, startup, &status, config);
        let _ = record_sync(&sync, &clock, &status, config);

        run_poll_loop(
            &heartbeat,
            &sync,
            &mut scheduler,
            &clock,
            &rng,
            &sleeper,
            &shutdown,
            &host,
            config,
            startup,
            &status,
        );

        status.borrow_mut().clean_shutdown = true;
        status.borrow().save(config)?;
        tracing::info!("mayfly-agent stopped cleanly");
        Ok(())
    }

    /// Log read-only observations about the environment at startup.
    fn log_startup_diagnostics(&self, config: &Config) {
        let running_as_root = linux::validate_root().is_ok();
        tracing::info!(
            agent_version = env!("CARGO_PKG_VERSION"),
            server_url = %config.server_url,
            identity_dir = %config.identity_dir.display(),
            state_dir = %config.state_dir.display(),
            systemd = systemd::is_systemd(),
            running_as_root,
            allow_insecure_tls = config.allow_insecure_tls,
            "mayfly-agent starting"
        );
        if running_as_root {
            tracing::warn!(
                "running as root is unnecessary; privileged operations are delegated to the \
                 mayfly-helper. Prefer running the agent unprivileged."
            );
        }
        if config.allow_insecure_tls {
            tracing::warn!("allow_insecure_tls is set; TLS verification is DISABLED (dev only)");
        }
    }

    /// Ensure the machine is enrolled, returning its identity.
    ///
    /// If already enrolled, loads the persisted identity (no network). Otherwise
    /// reads the enrollment token from the environment and enrolls with
    /// exponential backoff (cancellable via `shutdown`), then pins the
    /// server-provided bundle signing key. Idempotent across restarts and races.
    #[allow(clippy::too_many_arguments)]
    fn ensure_enrolled(
        &self,
        config: &Config,
        enrollment: &EnrollmentService,
        host: &HostFacts,
        shutdown: &Shutdown,
        clock: &Arc<dyn Clock>,
        rng: &dyn RandomSource,
        sleeper: &dyn Sleeper,
    ) -> Result<MachineIdentity> {
        if enrollment.is_enrolled() {
            tracing::info!("machine already enrolled; loading persisted identity");
            return enrollment.load_machine_identity();
        }

        let token = std::env::var(ENROLLMENT_TOKEN_ENV).map_err(|_| {
            tracing::error!(
                "machine is not enrolled and {ENROLLMENT_TOKEN_ENV} is not set; cannot enroll"
            );
            Error::InvalidToken
        })?;
        // Fail fast on a structurally invalid token rather than retrying it.
        validate_token(&token)?;

        let http = ReqwestEnrollmentHttp::new(DEFAULT_ENROLL_TIMEOUT, config.allow_insecure_tls)?;
        let client = HttpEnrollmentClient::new(http, config.server_url.clone());
        let policy = BackoffPolicy::default();

        let identity = retry_with_backoff(
            &policy,
            clock.as_ref(),
            rng,
            sleeper,
            || !shutdown.is_requested(),
            |attempt| {
                tracing::info!(attempt, "attempting enrollment");
                match block_on(enrollment.enroll(
                    &client,
                    &config.server_url,
                    &token,
                    &host.hostname,
                )) {
                    Ok(identity) => Ok(identity),
                    // A concurrent enroll (or prior partial run) already wrote the
                    // record: treat as success and load it.
                    Err(Error::AlreadyEnrolled) => enrollment.load_machine_identity(),
                    Err(err) => Err(err),
                }
            },
        )?;

        if let Some(response) = client.last_response() {
            match runtime_state::pin_bundle_signing_key(
                config,
                response.bundle_signing_key.as_deref(),
            ) {
                Ok(true) => tracing::info!("pinned bundle signing key from enrollment response"),
                Ok(false) => {}
                Err(err) => {
                    tracing::error!(error = %err, "failed to persist bundle signing key pin");
                    return Err(err);
                }
            }
        }

        Ok(identity)
    }
}

/// Run the heartbeat + CA-sync poll loop until shutdown is requested.
///
/// Time, randomness, and sleeping are injected, so this is fully testable with a
/// mock clock, fixed RNG, and an advancing/triggering sleeper. Callback errors
/// are logged and swallowed by [`run_polling`]; the next cadence retries.
#[allow(clippy::too_many_arguments)]
pub fn run_poll_loop<T, U, A>(
    heartbeat: &HeartbeatClient<T>,
    sync: &CaSyncService<U, A>,
    scheduler: &mut Scheduler,
    clock: &Arc<dyn Clock>,
    rng: &dyn RandomSource,
    sleeper: &dyn Sleeper,
    shutdown: &Shutdown,
    host: &HostFacts,
    config: &Config,
    startup: OffsetDateTime,
    status: &RefCell<RuntimeStatus>,
) where
    T: HeartbeatTransport,
    U: CaBundleTransport,
    A: BundleApplier,
{
    run_polling(
        scheduler,
        clock.as_ref(),
        rng,
        sleeper,
        || record_heartbeat(heartbeat, host, clock, startup, status, config),
        || record_sync(sync, clock, status, config),
        |_cycle| !shutdown.is_requested(),
    );
}

/// Send one heartbeat and record the outcome in the runtime status.
fn record_heartbeat<T: HeartbeatTransport>(
    client: &HeartbeatClient<T>,
    host: &HostFacts,
    clock: &Arc<dyn Clock>,
    startup: OffsetDateTime,
    status: &RefCell<RuntimeStatus>,
    config: &Config,
) -> Result<()> {
    let now = clock.now();
    let uptime_seconds = (now - startup).whole_seconds().max(0) as u64;
    let current_generation = status.borrow().current_generation;

    let request = HeartbeatRequest {
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        hostname: host.hostname.clone(),
        os: host.os.clone(),
        kernel: host.kernel.clone(),
        ip: host.ip.clone(),
        current_generation,
        uptime_seconds,
    };

    let result = client.send_heartbeat(&request);
    {
        let mut s = status.borrow_mut();
        s.last_heartbeat_unix = Some(now.unix_timestamp());
        s.last_heartbeat_ok = Some(result.is_ok());
    }
    persist_status(status, config);

    match &result {
        Ok(response) => tracing::debug!(
            next_heartbeat_seconds = response.next_heartbeat_seconds,
            "heartbeat acknowledged"
        ),
        Err(err) => tracing::warn!(error = %err, "heartbeat failed"),
    }
    result.map(|_| ())
}

/// Run one CA-sync pass and record the outcome in the runtime status.
fn record_sync<U: CaBundleTransport, A: BundleApplier>(
    client: &CaSyncService<U, A>,
    clock: &Arc<dyn Clock>,
    status: &RefCell<RuntimeStatus>,
    config: &Config,
) -> Result<()> {
    let result = client.synchronize();
    {
        let mut s = status.borrow_mut();
        s.last_sync_unix = Some(clock.now().unix_timestamp());
        match &result {
            Ok(outcome) => {
                let (label, generation) = match outcome {
                    SyncOutcome::NotModified { generation } => ("not_modified", *generation),
                    SyncOutcome::Unchanged { generation } => ("unchanged", *generation),
                    SyncOutcome::Updated { generation, .. } => ("updated", *generation),
                };
                s.last_sync_outcome = Some(label.to_string());
                s.current_generation = generation;
            }
            Err(_) => s.last_sync_outcome = Some("error".to_string()),
        }
    }
    persist_status(status, config);

    match &result {
        Ok(outcome) => tracing::info!(?outcome, "CA synchronisation pass complete"),
        Err(err) => tracing::warn!(error = %err, "CA synchronisation failed"),
    }
    result.map(|_| ())
}

/// Persist the runtime status, logging (but not propagating) any write failure.
fn persist_status(status: &RefCell<RuntimeStatus>, config: &Config) {
    if let Err(err) = status.borrow().save(config) {
        tracing::warn!(error = %err, "failed to persist runtime status");
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::clock::MockClock;
    use crate::config::Config;

    fn config(state_dir: &std::path::Path) -> Config {
        let toml = format!(
            "server_url = \"https://mayfly.example.com\"\nmachine_id = \"host-01\"\n\
state_dir = \"{}\"\n",
            state_dir.display()
        );
        Config::from_toml_with_env(&toml, |_| None).unwrap()
    }

    #[test]
    fn daemon_exposes_state() {
        let clock = Arc::new(MockClock::from_unix(0));
        let dir = tempfile::tempdir().unwrap();
        let state = AppState::new(config(dir.path()), clock);
        let daemon = Daemon::new(state);
        assert_eq!(daemon.state().config().machine_id, "host-01");
    }
}
