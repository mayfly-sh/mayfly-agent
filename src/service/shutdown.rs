//! Graceful-shutdown signalling and an interruptible sleeper.
//!
//! The daemon must stop promptly on `SIGINT`/`SIGTERM` (systemd sends `SIGTERM`
//! and waits a bounded grace period before `SIGKILL`). Because the agent is
//! thread-based rather than async, shutdown is modelled as a shared
//! [`AtomicBool`]: the signal handler — installed via [`signal_hook`], whose
//! handler only stores `true` (async-signal-safe) — flips the flag, and the
//! poll loop observes it between sleep slices.
//!
//! [`InterruptibleSleeper`] is the bridge: it implements the scheduler's
//! [`Sleeper`] by sleeping in small steps and returning early the moment the
//! flag is set, so even a long inter-poll wait (up to the sync interval) does not
//! delay shutdown by more than one step.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::errors::{Error, Result};
use crate::service::scheduler::Sleeper;

/// Default granularity at which [`InterruptibleSleeper`] re-checks the flag.
const DEFAULT_SLEEP_STEP: Duration = Duration::from_millis(500);

/// A shared, cheaply-cloneable shutdown flag.
#[derive(Clone, Debug, Default)]
pub struct Shutdown {
    flag: Arc<AtomicBool>,
}

impl Shutdown {
    /// Create a fresh, un-requested shutdown flag.
    pub fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Whether shutdown has been requested.
    pub fn is_requested(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// Request shutdown (used by tests and by an in-process trigger).
    pub fn request(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    /// The underlying flag, for registering OS signal handlers against it.
    pub fn flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.flag)
    }
}

/// Install `SIGINT` and `SIGTERM` handlers that set `shutdown`'s flag.
///
/// The handlers are async-signal-safe (they only store into an [`AtomicBool`]);
/// no allocation, locking, or logging happens inside them.
///
/// # Errors
///
/// Returns [`Error::Io`] if a handler cannot be registered.
pub fn install_signal_handlers(shutdown: &Shutdown) -> Result<()> {
    use signal_hook::consts::{SIGINT, SIGTERM};

    let flag = shutdown.flag();
    signal_hook::flag::register(SIGTERM, Arc::clone(&flag)).map_err(Error::Io)?;
    signal_hook::flag::register(SIGINT, flag).map_err(Error::Io)?;
    Ok(())
}

/// A [`Sleeper`] that wakes early when a [`Shutdown`] is requested.
///
/// It sleeps in steps of at most [`DEFAULT_SLEEP_STEP`] (or a custom step),
/// checking the flag before each step, so a pending shutdown is honoured within
/// one step regardless of the requested duration.
#[derive(Debug, Clone)]
pub struct InterruptibleSleeper {
    shutdown: Shutdown,
    step: Duration,
}

impl InterruptibleSleeper {
    /// Construct a sleeper using the default step granularity.
    pub fn new(shutdown: Shutdown) -> Self {
        Self {
            shutdown,
            step: DEFAULT_SLEEP_STEP,
        }
    }

    /// Construct a sleeper with a custom step (clamped to at least 1 ms so the
    /// loop always makes progress).
    pub fn with_step(shutdown: Shutdown, step: Duration) -> Self {
        Self {
            shutdown,
            step: step.max(Duration::from_millis(1)),
        }
    }
}

impl Sleeper for InterruptibleSleeper {
    fn sleep(&self, duration: Duration) {
        let mut remaining = duration;
        while !remaining.is_zero() {
            if self.shutdown.is_requested() {
                return;
            }
            let chunk = remaining.min(self.step);
            std::thread::sleep(chunk);
            remaining = remaining.saturating_sub(chunk);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::time::Instant;

    use super::*;

    #[test]
    fn flag_round_trips() {
        let s = Shutdown::new();
        assert!(!s.is_requested());
        s.request();
        assert!(s.is_requested());
        // Clones share the same flag.
        let c = s.clone();
        assert!(c.is_requested());
    }

    #[test]
    fn sleeper_returns_immediately_when_shutdown_requested() {
        let shutdown = Shutdown::new();
        shutdown.request();
        let sleeper = InterruptibleSleeper::with_step(shutdown, Duration::from_millis(10));
        let start = Instant::now();
        // Asked to sleep a long time, but shutdown is already set.
        sleeper.sleep(Duration::from_secs(30));
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn sleeper_wakes_when_flag_set_mid_sleep() {
        let shutdown = Shutdown::new();
        let sleeper = InterruptibleSleeper::with_step(shutdown.clone(), Duration::from_millis(10));
        let trigger = shutdown.clone();
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            trigger.request();
        });
        let start = Instant::now();
        sleeper.sleep(Duration::from_secs(30));
        let elapsed = start.elapsed();
        handle.join().unwrap();
        assert!(elapsed < Duration::from_secs(2), "woke late: {elapsed:?}");
    }

    #[test]
    fn sleeper_sleeps_full_duration_without_shutdown() {
        let shutdown = Shutdown::new();
        let sleeper = InterruptibleSleeper::with_step(shutdown, Duration::from_millis(10));
        let start = Instant::now();
        sleeper.sleep(Duration::from_millis(60));
        assert!(start.elapsed() >= Duration::from_millis(40));
    }

    #[test]
    fn installing_handlers_succeeds() {
        // Registering handlers must not error; we do not raise signals here to
        // avoid disturbing the test process.
        let shutdown = Shutdown::new();
        install_signal_handlers(&shutdown).unwrap();
    }
}
