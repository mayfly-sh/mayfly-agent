//! `mayfly-agent` binary entry point.
//!
//! Start-up:
//!
//! 1. resolves the configuration path (`MAYFLY_AGENT_CONFIG`, else
//!    [`DEFAULT_CONFIG_PATH`]);
//! 2. loads, env-overrides, and validates the configuration;
//! 3. initialises structured logging from the configuration;
//! 4. builds the shared [`AppState`] (with the real [`SystemClock`]) and runs the
//!    [`Daemon`], which enrolls (if needed), then heartbeats and synchronises the
//!    signed CA bundle on a jittered cadence until `SIGINT`/`SIGTERM`.
//!
//! See [`mayfly_agent::service::daemon`] for the full runtime flow.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use mayfly_agent::clock::SystemClock;
use mayfly_agent::config::{Config, LogFormat, LogLevel, DEFAULT_CONFIG_PATH};
use mayfly_agent::service::Daemon;
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
    Daemon::new(state).run()
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
