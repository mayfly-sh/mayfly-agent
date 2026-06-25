//! Structured logging built on [`tracing`].
//!
//! Two output formats are supported, selected by configuration:
//!
//! * [`LogFormat::Json`] — one JSON object per line, for production log
//!   aggregation;
//! * [`LogFormat::Pretty`] — human-readable, coloured output for interactive
//!   use.
//!
//! The verbosity is taken from the `RUST_LOG` environment variable when set,
//! otherwise from the configured [`LogLevel`]. Initialisation is idempotent so
//! it is safe to call from both the binary and tests.

use tracing_subscriber::EnvFilter;

use crate::config::{Config, LogFormat, LogLevel};

/// Initialise the global subscriber for the given level and format.
///
/// Returns `true` if this call installed the subscriber, or `false` if one was
/// already installed (subsequent calls are no-ops rather than panics).
pub fn init(level: LogLevel, format: LogFormat) -> bool {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level.as_filter_str()));

    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);

    match format {
        LogFormat::Json => builder.json().try_init().is_ok(),
        LogFormat::Pretty => builder.pretty().try_init().is_ok(),
    }
}

/// Initialise logging from a [`Config`]'s `log_level` and `log_format`.
///
/// Convenience wrapper around [`init`].
pub fn init_from_config(config: &Config) -> bool {
    init(config.log_level, config.log_format)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn init_is_idempotent() {
        // Whichever test wins the race installs the global subscriber; every
        // subsequent call must return false without panicking.
        let _ = init(LogLevel::Info, LogFormat::Json);
        assert!(!init(LogLevel::Debug, LogFormat::Pretty));
    }

    #[test]
    fn level_maps_to_filter_string() {
        assert_eq!(LogLevel::Trace.as_filter_str(), "trace");
        assert_eq!(LogLevel::Error.as_filter_str(), "error");
    }
}
