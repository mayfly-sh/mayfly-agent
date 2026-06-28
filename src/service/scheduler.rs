//! Poll scheduling with injectable randomness.
//!
//! The agent polls on two independent, jittered cadences — heartbeat and CA
//! bundle synchronisation — so a large fleet does not align its requests into
//! thundering herds. All time and randomness are **injected**:
//!
//! * the current time comes from a [`Clock`](crate::clock::Clock);
//! * jitter comes from a [`RandomSource`].
//!
//! This makes scheduling fully deterministic under test with no real sleeps:
//! [`Scheduler`] is a pure state machine over `(now, rng)`, and the optional
//! [`run_polling`] driver takes an injected [`Sleeper`] so even the loop can be
//! tested by advancing a mock clock instead of waiting.

use std::time::Duration;

use rand::rngs::OsRng;
use rand::RngCore;
use time::OffsetDateTime;

use crate::clock::Clock;
use crate::errors::Result;

/// Resolution used to turn a random `u64` into a jitter fraction in `[0, 1)`.
const JITTER_RESOLUTION: u64 = 1_000_000;

/// A source of randomness for jitter. Injected so tests are deterministic.
pub trait RandomSource: Send + Sync + std::fmt::Debug {
    /// Return the next random `u64`.
    fn next_u64(&self) -> u64;
}

/// Production randomness backed by the operating-system CSPRNG.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRandom;

impl RandomSource for OsRandom {
    fn next_u64(&self) -> u64 {
        let mut bytes = [0u8; 8];
        OsRng.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }
}

/// A deterministic [`RandomSource`] that always yields the same value. Useful
/// for reproducible jitter in tests.
#[derive(Debug, Clone, Copy)]
pub struct FixedRandom(pub u64);

impl RandomSource for FixedRandom {
    fn next_u64(&self) -> u64 {
        self.0
    }
}

/// A base interval with proportional jitter applied on each draw.
///
/// `ratio` is clamped to `[0.0, 1.0]`; the realised delay lies in
/// `[base, base + base*ratio)`.
#[derive(Debug, Clone, Copy)]
pub struct JitteredInterval {
    base: Duration,
    ratio: f64,
}

impl JitteredInterval {
    /// Construct a jittered interval. `ratio` outside `[0, 1]` (or non-finite)
    /// is clamped into range.
    pub fn new(base: Duration, ratio: f64) -> Self {
        let ratio = if ratio.is_finite() {
            ratio.clamp(0.0, 1.0)
        } else {
            0.0
        };
        Self { base, ratio }
    }

    /// Draw the next delay, adding up to `base * ratio` of jitter.
    pub fn next_delay(&self, rng: &dyn RandomSource) -> Duration {
        if self.ratio <= 0.0 {
            return self.base;
        }
        let fraction = (rng.next_u64() % JITTER_RESOLUTION) as f64 / JITTER_RESOLUTION as f64;
        let extra = self.base.as_secs_f64() * self.ratio * fraction;
        self.base + Duration::from_secs_f64(extra)
    }
}

/// A poll action that has come due.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollAction {
    /// Send a heartbeat.
    Heartbeat,
    /// Run a CA-bundle synchronisation pass.
    BundleSync,
}

/// Tracks the next-due time for the heartbeat and bundle-sync cadences.
#[derive(Debug)]
pub struct Scheduler {
    heartbeat: JitteredInterval,
    sync: JitteredInterval,
    heartbeat_due: OffsetDateTime,
    sync_due: OffsetDateTime,
}

impl Scheduler {
    /// Create a scheduler, drawing the first due time for each cadence from
    /// `now` using `rng` for jitter.
    pub fn new(
        now: OffsetDateTime,
        heartbeat: JitteredInterval,
        sync: JitteredInterval,
        rng: &dyn RandomSource,
    ) -> Self {
        let heartbeat_due = now + heartbeat.next_delay(rng);
        let sync_due = now + sync.next_delay(rng);
        Self {
            heartbeat,
            sync,
            heartbeat_due,
            sync_due,
        }
    }

    /// The earliest time at which some action becomes due.
    pub fn next_due(&self) -> OffsetDateTime {
        self.heartbeat_due.min(self.sync_due)
    }

    /// Return the actions due at `now` (heartbeat ordered before bundle sync),
    /// rescheduling each from `now` with fresh jitter.
    pub fn take_due(&mut self, now: OffsetDateTime, rng: &dyn RandomSource) -> Vec<PollAction> {
        let mut due = Vec::new();
        if now >= self.heartbeat_due {
            due.push(PollAction::Heartbeat);
            self.heartbeat_due = now + self.heartbeat.next_delay(rng);
        }
        if now >= self.sync_due {
            due.push(PollAction::BundleSync);
            self.sync_due = now + self.sync.next_delay(rng);
        }
        due
    }
}

/// Abstraction over blocking the current thread until the next due time.
///
/// Injected so [`run_polling`] can be driven deterministically in tests.
pub trait Sleeper: Send + Sync {
    /// Block for (at least) `duration`.
    fn sleep(&self, duration: Duration);
}

/// Production [`Sleeper`] backed by [`std::thread::sleep`].
#[derive(Debug, Default, Clone, Copy)]
pub struct ThreadSleeper;

impl Sleeper for ThreadSleeper {
    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// Drive the poll loop: sleep until the next due time, then run the due
/// actions, repeating while `should_continue(cycle)` returns `true`.
///
/// Callback errors are logged and swallowed so a transient failure does not
/// terminate the daemon; the next cadence simply tries again (this is the only
/// "retry" mechanism — there is no inner retry loop).
///
/// Time and randomness are injected, and sleeping goes through [`Sleeper`], so
/// this is fully testable without real waits.
pub fn run_polling<H, S, C>(
    scheduler: &mut Scheduler,
    clock: &dyn Clock,
    rng: &dyn RandomSource,
    sleeper: &dyn Sleeper,
    mut on_heartbeat: H,
    mut on_bundle_sync: S,
    mut should_continue: C,
) where
    H: FnMut() -> Result<()>,
    S: FnMut() -> Result<()>,
    C: FnMut(u64) -> bool,
{
    let mut cycle: u64 = 0;
    while should_continue(cycle) {
        cycle += 1;

        let now = clock.now();
        let wait = scheduler.next_due() - now;
        if wait.is_positive() {
            sleeper.sleep(wait.unsigned_abs());
        }

        let now = clock.now();
        for action in scheduler.take_due(now, rng) {
            let result = match action {
                PollAction::Heartbeat => on_heartbeat(),
                PollAction::BundleSync => on_bundle_sync(),
            };
            if let Err(err) = result {
                tracing::warn!(?action, error = %err, "poll action failed; will retry next cadence");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::clock::MockClock;

    fn at(unix: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(unix).unwrap()
    }

    #[test]
    fn zero_jitter_returns_base() {
        let interval = JitteredInterval::new(Duration::from_secs(60), 0.0);
        assert_eq!(
            interval.next_delay(&FixedRandom(12345)),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn jitter_stays_within_bounds() {
        let interval = JitteredInterval::new(Duration::from_secs(100), 0.5);
        // Max fraction (resolution-1) yields close to base + 50%.
        let high = interval.next_delay(&FixedRandom(JITTER_RESOLUTION - 1));
        assert!(high >= Duration::from_secs(100));
        assert!(high < Duration::from_secs(150));
        // Zero fraction yields exactly base.
        let low = interval.next_delay(&FixedRandom(0));
        assert_eq!(low, Duration::from_secs(100));
    }

    #[test]
    fn ratio_is_clamped() {
        let interval = JitteredInterval::new(Duration::from_secs(10), 5.0);
        let d = interval.next_delay(&FixedRandom(JITTER_RESOLUTION - 1));
        // Clamped to ratio 1.0 → strictly below base*2.
        assert!(d < Duration::from_secs(20));
    }

    #[test]
    fn scheduler_orders_heartbeat_before_sync() {
        let rng = FixedRandom(0); // no jitter
        let mut sched = Scheduler::new(
            at(0),
            JitteredInterval::new(Duration::from_secs(10), 0.0),
            JitteredInterval::new(Duration::from_secs(10), 0.0),
            &rng,
        );
        // Both due at t=10.
        let due = sched.take_due(at(10), &rng);
        assert_eq!(due, vec![PollAction::Heartbeat, PollAction::BundleSync]);
    }

    #[test]
    fn scheduler_returns_only_due_actions() {
        let rng = FixedRandom(0);
        let mut sched = Scheduler::new(
            at(0),
            JitteredInterval::new(Duration::from_secs(10), 0.0),
            JitteredInterval::new(Duration::from_secs(60), 0.0),
            &rng,
        );
        // At t=10 only the heartbeat is due.
        assert_eq!(sched.take_due(at(10), &rng), vec![PollAction::Heartbeat]);
        // Heartbeat rescheduled to t=20; sync still at t=60.
        assert_eq!(sched.take_due(at(15), &rng), vec![]);
        assert_eq!(sched.take_due(at(20), &rng), vec![PollAction::Heartbeat]);
        // At t=60 the (overdue) heartbeat and the sync are both due, heartbeat first.
        assert_eq!(
            sched.take_due(at(60), &rng),
            vec![PollAction::Heartbeat, PollAction::BundleSync]
        );
    }

    #[test]
    fn next_due_is_minimum() {
        let rng = FixedRandom(0);
        let sched = Scheduler::new(
            at(100),
            JitteredInterval::new(Duration::from_secs(30), 0.0),
            JitteredInterval::new(Duration::from_secs(5), 0.0),
            &rng,
        );
        assert_eq!(sched.next_due(), at(105));
    }

    /// A sleeper that advances a shared mock clock instead of really sleeping.
    #[derive(Clone)]
    struct AdvancingSleeper {
        clock: Arc<MockClock>,
        slept: Arc<Mutex<Vec<Duration>>>,
    }

    impl Sleeper for AdvancingSleeper {
        fn sleep(&self, duration: Duration) {
            self.slept.lock().unwrap().push(duration);
            self.clock.advance(duration);
        }
    }

    #[test]
    fn run_polling_drives_actions_without_real_sleep() {
        let clock = Arc::new(MockClock::from_unix(0));
        let rng = FixedRandom(0); // deterministic, no jitter
        let sleeper = AdvancingSleeper {
            clock: clock.clone(),
            slept: Arc::new(Mutex::new(Vec::new())),
        };
        let mut sched = Scheduler::new(
            clock.now(),
            JitteredInterval::new(Duration::from_secs(10), 0.0),
            JitteredInterval::new(Duration::from_secs(20), 0.0),
            &rng,
        );

        let heartbeats = Arc::new(Mutex::new(0u32));
        let syncs = Arc::new(Mutex::new(0u32));
        let hb = heartbeats.clone();
        let sy = syncs.clone();

        // Run four cycles: heartbeats at 10,20,30,40; syncs at 20,40.
        run_polling(
            &mut sched,
            clock.as_ref(),
            &rng,
            &sleeper,
            || {
                *hb.lock().unwrap() += 1;
                Ok(())
            },
            || {
                *sy.lock().unwrap() += 1;
                Ok(())
            },
            |cycle| cycle < 4,
        );

        assert_eq!(*heartbeats.lock().unwrap(), 4);
        assert_eq!(*syncs.lock().unwrap(), 2);
    }

    #[test]
    fn run_polling_swallows_callback_errors() {
        let clock = Arc::new(MockClock::from_unix(0));
        let rng = FixedRandom(0);
        let sleeper = AdvancingSleeper {
            clock: clock.clone(),
            slept: Arc::new(Mutex::new(Vec::new())),
        };
        let mut sched = Scheduler::new(
            clock.now(),
            JitteredInterval::new(Duration::from_secs(10), 0.0),
            JitteredInterval::new(Duration::from_secs(10), 0.0),
            &rng,
        );

        let syncs = Arc::new(Mutex::new(0u32));
        let sy = syncs.clone();
        // Heartbeat always errors; loop must continue and still run syncs.
        run_polling(
            &mut sched,
            clock.as_ref(),
            &rng,
            &sleeper,
            || Err(crate::errors::Error::HeartbeatTransport),
            || {
                *sy.lock().unwrap() += 1;
                Ok(())
            },
            |cycle| cycle < 2,
        );
        assert_eq!(*syncs.lock().unwrap(), 2);
    }
}
