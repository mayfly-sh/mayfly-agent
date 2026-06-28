//! Cancellable retry with exponential backoff and jitter.
//!
//! Used for the one-shot startup operations that must eventually succeed —
//! chiefly enrollment — where "retry on the next cadence" (the scheduler's
//! model for steady-state heartbeat/sync) does not apply because there is no
//! cadence yet. Steady-state polling deliberately has **no** inner retry loop;
//! see [`crate::service::scheduler`].
//!
//! All time and sleeping are injected ([`Clock`], [`Sleeper`]) so the policy is
//! deterministic under test, and the loop is *cancellable*: a `should_continue`
//! predicate (wired to the shutdown flag in production) is checked before every
//! attempt and before every sleep, so a SIGTERM during backoff exits promptly.

use std::time::Duration;

use crate::clock::Clock;
use crate::errors::Result;
use crate::service::scheduler::{RandomSource, Sleeper};

/// Exponential-backoff parameters.
#[derive(Debug, Clone, Copy)]
pub struct BackoffPolicy {
    /// Delay before the second attempt (the first attempt is immediate).
    pub initial: Duration,
    /// Upper bound on any single delay (before jitter).
    pub max: Duration,
    /// Multiplier applied to the delay after each failed attempt.
    pub multiplier: f64,
    /// Fractional jitter in `[0.0, 1.0]` added on top of each delay.
    pub jitter_ratio: f64,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(2),
            max: Duration::from_secs(60),
            multiplier: 2.0,
            jitter_ratio: 0.2,
        }
    }
}

impl BackoffPolicy {
    /// The delay to wait after `attempt` failed attempts (1-based), capped at
    /// [`max`](BackoffPolicy::max) and with up to `jitter_ratio` extra jitter.
    fn delay(&self, attempt: u32, rng: &dyn RandomSource) -> Duration {
        let factor = self.multiplier.powi(attempt.saturating_sub(1) as i32);
        let base = self.initial.as_secs_f64() * factor;
        let capped = base.min(self.max.as_secs_f64()).max(0.0);
        let jitter = if self.jitter_ratio > 0.0 {
            let fraction = (rng.next_u64() % 1_000_000) as f64 / 1_000_000.0;
            capped * self.jitter_ratio * fraction
        } else {
            0.0
        };
        Duration::from_secs_f64(capped + jitter)
    }
}

/// Run `op` until it succeeds, retrying transient failures with exponential
/// backoff. Returns the first `Ok`, or the most recent `Err` once cancelled.
///
/// `should_continue()` is checked before each attempt and before each sleep;
/// when it returns `false` (e.g. shutdown requested) the loop stops and returns
/// the last error. `op` receives the 1-based attempt number.
///
/// # Errors
///
/// Returns the last error produced by `op` if cancellation occurs before a
/// success.
pub fn retry_with_backoff<T, O, C>(
    policy: &BackoffPolicy,
    clock: &dyn Clock,
    rng: &dyn RandomSource,
    sleeper: &dyn Sleeper,
    should_continue: C,
    mut op: O,
) -> Result<T>
where
    O: FnMut(u32) -> Result<T>,
    C: Fn() -> bool,
{
    let _ = clock; // reserved for future deadline support; keeps the signature stable.
    let mut attempt: u32 = 0;
    let mut last_err = None;
    while should_continue() {
        attempt = attempt.saturating_add(1);
        match op(attempt) {
            Ok(value) => return Ok(value),
            Err(err) => {
                tracing::warn!(attempt, error = %err, "operation failed; backing off");
                last_err = Some(err);
            }
        }
        if !should_continue() {
            break;
        }
        let delay = policy.delay(attempt, rng);
        sleeper.sleep(delay);
    }
    // Cancelled (or never entered the loop). Surface the last error, or a
    // transport error if we never attempted.
    Err(last_err.unwrap_or(crate::errors::Error::EnrollmentTransport))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::cell::Cell;
    use std::sync::Mutex;

    use super::*;
    use crate::clock::FixedClock;
    use crate::errors::Error;
    use crate::service::scheduler::FixedRandom;

    /// A sleeper that records the delays it was asked to wait, without sleeping.
    #[derive(Default)]
    struct RecordingSleeper {
        delays: Mutex<Vec<Duration>>,
    }

    impl Sleeper for RecordingSleeper {
        fn sleep(&self, duration: Duration) {
            self.delays.lock().unwrap().push(duration);
        }
    }

    fn clock() -> FixedClock {
        FixedClock::from_unix(0)
    }

    #[test]
    fn succeeds_on_first_attempt_without_sleeping() {
        let sleeper = RecordingSleeper::default();
        let policy = BackoffPolicy::default();
        let result: Result<u32> = retry_with_backoff(
            &policy,
            &clock(),
            &FixedRandom(0),
            &sleeper,
            || true,
            |attempt| {
                assert_eq!(attempt, 1);
                Ok(42)
            },
        );
        assert_eq!(result.unwrap(), 42);
        assert!(sleeper.delays.lock().unwrap().is_empty());
    }

    #[test]
    fn succeeds_after_transient_failures() {
        let sleeper = RecordingSleeper::default();
        let policy = BackoffPolicy {
            jitter_ratio: 0.0,
            ..BackoffPolicy::default()
        };
        let calls = Cell::new(0u32);
        let result: Result<&str> = retry_with_backoff(
            &policy,
            &clock(),
            &FixedRandom(0),
            &sleeper,
            || true,
            |attempt| {
                calls.set(attempt);
                if attempt < 3 {
                    Err(Error::EnrollmentTransport)
                } else {
                    Ok("ok")
                }
            },
        );
        assert_eq!(result.unwrap(), "ok");
        assert_eq!(calls.get(), 3);
        // Two backoffs before the third (successful) attempt; no sleep after success.
        assert_eq!(sleeper.delays.lock().unwrap().len(), 2);
    }

    #[test]
    fn cancellation_stops_and_returns_last_error() {
        let sleeper = RecordingSleeper::default();
        let policy = BackoffPolicy::default();
        let attempts = Cell::new(0u32);
        // Allow exactly one attempt, then cancel.
        let result: Result<()> = retry_with_backoff(
            &policy,
            &clock(),
            &FixedRandom(0),
            &sleeper,
            || attempts.get() == 0,
            |attempt| {
                attempts.set(attempt);
                Err(Error::EnrollmentRejected)
            },
        );
        assert!(matches!(result.unwrap_err(), Error::EnrollmentRejected));
        assert_eq!(attempts.get(), 1);
        // Cancelled before sleeping.
        assert!(sleeper.delays.lock().unwrap().is_empty());
    }

    #[test]
    fn delay_grows_and_is_capped() {
        let policy = BackoffPolicy {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(10),
            multiplier: 2.0,
            jitter_ratio: 0.0,
        };
        let rng = FixedRandom(0);
        assert_eq!(policy.delay(1, &rng), Duration::from_secs(1));
        assert_eq!(policy.delay(2, &rng), Duration::from_secs(2));
        assert_eq!(policy.delay(3, &rng), Duration::from_secs(4));
        assert_eq!(policy.delay(4, &rng), Duration::from_secs(8));
        // Capped at max.
        assert_eq!(policy.delay(5, &rng), Duration::from_secs(10));
        assert_eq!(policy.delay(20, &rng), Duration::from_secs(10));
    }
}
