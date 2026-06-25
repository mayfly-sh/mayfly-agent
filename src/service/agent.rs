//! The agent orchestrator.
//!
//! [`Agent`] owns the shared [`AppState`] and is the future home of the
//! synchronisation loop. For now it exposes only safe, read-only accessors so
//! the rest of the system can be wired and tested without any networking or
//! privileged behaviour.

use std::time::Duration;

use crate::state::AppState;

/// The Mayfly agent.
///
/// Holds the shared application state. Long-running behaviour (heartbeats, CA
/// synchronisation) is added in a later phase; this type currently provides the
/// state plumbing and lifecycle accessors only.
#[derive(Clone, Debug)]
pub struct Agent {
    state: AppState,
}

impl Agent {
    /// Construct an agent around the given application state.
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    /// Borrow the shared application state.
    pub fn state(&self) -> &AppState {
        &self.state
    }

    /// Time elapsed since the agent's state was created, per the injected clock.
    pub fn uptime(&self) -> Duration {
        self.state.uptime()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::Arc;

    use super::*;
    use crate::clock::MockClock;
    use crate::config::Config;

    fn state(clock: Arc<MockClock>) -> AppState {
        let config = Config::from_toml_with_env(
            r#"
                server_url = "https://mayfly.example.com"
                machine_id = "host-01"
            "#,
            |_| None,
        )
        .unwrap();
        AppState::new(config, clock)
    }

    #[test]
    fn agent_exposes_state() {
        let clock = Arc::new(MockClock::from_unix(0));
        let agent = Agent::new(state(clock));
        assert_eq!(agent.state().config().machine_id, "host-01");
    }

    #[test]
    fn agent_uptime_follows_clock() {
        let clock = Arc::new(MockClock::from_unix(0));
        let agent = Agent::new(state(clock.clone()));
        assert_eq!(agent.uptime(), Duration::ZERO);
        clock.advance(Duration::from_secs(5));
        assert_eq!(agent.uptime(), Duration::from_secs(5));
    }
}
