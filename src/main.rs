//! `mayfly-agent` binary entry point.
//!
//! In this foundation phase, start-up:
//!
//! 1. resolves the configuration path (`MAYFLY_AGENT_CONFIG`, else
//!    [`DEFAULT_CONFIG_PATH`]);
//! 2. loads, env-overrides, and validates the configuration;
//! 3. initialises structured logging from the configuration;
//! 4. builds the shared [`AppState`] (with the real [`SystemClock`]) and an
//!    [`Agent`];
//! 5. logs read-only observations about the environment (systemd presence, root
//!    status) and exits.
//!
//! There is deliberately no networking, no enrollment, no CA synchronisation,
//! and no modification of `sshd` here.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use mayfly_agent::clock::SystemClock;
use mayfly_agent::config::{Config, LogFormat, LogLevel, DEFAULT_CONFIG_PATH};
use mayfly_agent::platform::{linux, systemd};
use mayfly_agent::service::Agent;
use mayfly_agent::state::AppState;
use mayfly_agent::{logging, Result};

fn config_path() -> std::path::PathBuf {
    std::env::var_os("MAYFLY_AGENT_CONFIG")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(DEFAULT_CONFIG_PATH))
}

fn run(config: Config) -> Result<()> {
    let clock = std::sync::Arc::new(SystemClock::new());
    let state = AppState::new(config, clock);
    let agent = Agent::new(state);

    let config = agent.state().config();
    let running_as_root = linux::validate_root().is_ok();

    tracing::info!(
        machine_id = %config.machine_id,
        server_url = %config.server_url,
        systemd = systemd::is_systemd(),
        running_as_root,
        "mayfly-agent foundation initialised (no networking in this phase)"
    );

    if !running_as_root {
        tracing::warn!(
            "not running as root; privileged operations will be unavailable once implemented"
        );
    }

    Ok(())
}

fn main() -> ExitCode {
    let path = config_path();

    match Config::load(&path) {
        Ok(config) => {
            logging::init_from_config(&config);
            match run(config) {
                Ok(()) => ExitCode::SUCCESS,
                Err(err) => {
                    tracing::error!(error = %err, "mayfly-agent failed during startup");
                    ExitCode::FAILURE
                }
            }
        }
        Err(err) => {
            // Configuration failed before we know the desired log format; fall
            // back to a sane default so the failure is still reported.
            logging::init(LogLevel::Info, LogFormat::Pretty);
            tracing::error!(error = %err, "failed to load configuration");
            ExitCode::FAILURE
        }
    }
}
