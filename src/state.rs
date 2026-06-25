//! Shared application state.
//!
//! [`AppState`] bundles the validated [`Config`], the injected [`Clock`], and
//! the daemon's startup time. It is cheap to clone (everything shareable is
//! behind an [`Arc`]) so it can be handed to multiple tasks once asynchronous
//! work is introduced in a later phase.
//!
//! Because the clock is injected, time-dependent behaviour such as
//! [`AppState::uptime`] is fully deterministic under test.

use std::sync::Arc;
use std::time::Duration;

use time::OffsetDateTime;

use crate::clock::Clock;
use crate::config::Config;

/// Shared, cheaply-cloneable application state.
#[derive(Clone, Debug)]
pub struct AppState {
    config: Arc<Config>,
    clock: Arc<dyn Clock>,
    startup_time: OffsetDateTime,
}

impl AppState {
    /// Construct application state, stamping the startup time from `clock`.
    pub fn new(config: Config, clock: Arc<dyn Clock>) -> Self {
        let startup_time = clock.now();
        Self {
            config: Arc::new(config),
            clock,
            startup_time,
        }
    }

    /// The validated configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// The injected clock.
    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// The time at which this state (and thus the daemon) started.
    pub fn startup_time(&self) -> OffsetDateTime {
        self.startup_time
    }

    /// Elapsed time since startup, according to the injected clock.
    ///
    /// Returns [`Duration::ZERO`] if the clock has gone backwards relative to
    /// the recorded startup time, so callers never observe a negative duration.
    pub fn uptime(&self) -> Duration {
        let delta = self.clock.now() - self.startup_time;
        if delta.is_negative() {
            Duration::ZERO
        } else {
            delta.unsigned_abs()
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::clock::{FixedClock, MockClock};
    use crate::config::Config;

    fn config() -> Config {
        Config::from_toml_with_env(
            r#"
                server_url = "https://mayfly.example.com"
                machine_id = "host-01"
            "#,
            |_| None,
        )
        .unwrap()
    }

    #[test]
    fn startup_time_comes_from_clock() {
        let clock = Arc::new(FixedClock::from_unix(1_700_000_000));
        let state = AppState::new(config(), clock);
        assert_eq!(state.startup_time().unix_timestamp(), 1_700_000_000);
    }

    #[test]
    fn uptime_tracks_mock_clock_advance() {
        let clock = Arc::new(MockClock::from_unix(1_000));
        let state = AppState::new(config(), clock.clone());
        assert_eq!(state.uptime(), Duration::ZERO);

        clock.advance(Duration::from_secs(42));
        assert_eq!(state.uptime(), Duration::from_secs(42));
    }

    #[test]
    fn uptime_is_zero_if_clock_goes_backwards() {
        let clock = Arc::new(MockClock::from_unix(5_000));
        let state = AppState::new(config(), clock.clone());
        clock.set(OffsetDateTime::from_unix_timestamp(4_000).unwrap());
        assert_eq!(state.uptime(), Duration::ZERO);
    }

    #[test]
    fn config_is_accessible() {
        let clock = Arc::new(FixedClock::from_unix(0));
        let state = AppState::new(config(), clock);
        assert_eq!(state.config().machine_id, "host-01");
    }

    #[test]
    fn state_is_cloneable_and_shares_config() {
        let clock = Arc::new(FixedClock::from_unix(0));
        let state = AppState::new(config(), clock);
        let cloned = state.clone();
        assert_eq!(state.config().machine_id, cloned.config().machine_id);
    }
}
