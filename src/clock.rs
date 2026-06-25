//! An injectable clock abstraction.
//!
//! Business logic must never call [`std::time::SystemTime::now`] or
//! [`time::OffsetDateTime::now_utc`] directly. Instead it depends on the
//! [`Clock`] trait and is handed a concrete implementation (typically
//! [`SystemClock`] in production, or one of the deterministic test clocks).
//! This keeps all time-dependent behaviour testable and auditable, and confines
//! the single real call to the wall clock to one place: [`SystemClock::now`].

use std::sync::Mutex;

use time::OffsetDateTime;

/// A source of the current UTC wall-clock time.
///
/// Implementations must be cheap to call and safe to share across threads.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Return the current time in UTC.
    fn now(&self) -> OffsetDateTime;
}

/// The production clock, backed by the operating system wall clock.
///
/// This is the **only** place in the crate permitted to read the real time.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl SystemClock {
    /// Construct a [`SystemClock`].
    pub const fn new() -> Self {
        Self
    }
}

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// A clock frozen at a fixed instant; never advances.
///
/// Useful for tests that need a stable, reproducible timestamp.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock {
    instant: OffsetDateTime,
}

impl FixedClock {
    /// Construct a [`FixedClock`] frozen at `instant`.
    pub const fn new(instant: OffsetDateTime) -> Self {
        Self { instant }
    }

    /// Construct a [`FixedClock`] from a Unix timestamp in seconds.
    ///
    /// # Panics
    ///
    /// Panics if `unix_seconds` is out of the representable range. Intended for
    /// tests with known-good constants.
    #[allow(clippy::expect_used)]
    pub fn from_unix(unix_seconds: i64) -> Self {
        let instant =
            OffsetDateTime::from_unix_timestamp(unix_seconds).expect("unix timestamp out of range");
        Self { instant }
    }
}

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.instant
    }
}

/// A manually-advanced clock for tests that need to observe the passage of time.
///
/// Time only moves when [`MockClock::advance`] or [`MockClock::set`] is called,
/// making time-dependent logic fully deterministic.
#[derive(Debug)]
pub struct MockClock {
    current: Mutex<OffsetDateTime>,
}

impl MockClock {
    /// Construct a [`MockClock`] starting at `start`.
    pub fn new(start: OffsetDateTime) -> Self {
        Self {
            current: Mutex::new(start),
        }
    }

    /// Construct a [`MockClock`] starting at a Unix timestamp in seconds.
    ///
    /// # Panics
    ///
    /// Panics if `unix_seconds` is out of the representable range.
    #[allow(clippy::expect_used)]
    pub fn from_unix(unix_seconds: i64) -> Self {
        Self::new(
            OffsetDateTime::from_unix_timestamp(unix_seconds).expect("unix timestamp out of range"),
        )
    }

    /// Advance the clock by `duration`.
    pub fn advance(&self, duration: std::time::Duration) {
        // Recover rather than panic if a prior holder poisoned the lock: the
        // protected value (a timestamp) is always in a consistent state.
        let mut guard = self.current.lock().unwrap_or_else(|e| e.into_inner());
        *guard += duration;
    }

    /// Set the clock to an absolute `instant`.
    pub fn set(&self, instant: OffsetDateTime) {
        let mut guard = self.current.lock().unwrap_or_else(|e| e.into_inner());
        *guard = instant;
    }
}

impl Clock for MockClock {
    fn now(&self) -> OffsetDateTime {
        *self.current.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::time::Duration;
    use time::macros::datetime;

    #[test]
    fn system_clock_is_monotonic_nondecreasing() {
        let clock = SystemClock::new();
        let a = clock.now();
        let b = clock.now();
        assert!(b >= a);
    }

    #[test]
    fn fixed_clock_never_changes() {
        let clock = FixedClock::new(datetime!(2024-01-01 00:00:00 UTC));
        let first = clock.now();
        let second = clock.now();
        assert_eq!(first, second);
        assert_eq!(first, datetime!(2024-01-01 00:00:00 UTC));
    }

    #[test]
    fn fixed_clock_from_unix() {
        let clock = FixedClock::from_unix(1_700_000_000);
        assert_eq!(clock.now().unix_timestamp(), 1_700_000_000);
    }

    #[test]
    fn mock_clock_advances_only_when_told() {
        let clock = MockClock::from_unix(1_000);
        assert_eq!(clock.now().unix_timestamp(), 1_000);

        clock.advance(Duration::from_secs(60));
        assert_eq!(clock.now().unix_timestamp(), 1_060);

        // Reading again does not advance it.
        assert_eq!(clock.now().unix_timestamp(), 1_060);
    }

    #[test]
    fn mock_clock_can_be_set_absolutely() {
        let clock = MockClock::from_unix(0);
        clock.set(datetime!(2030-06-15 12:00:00 UTC));
        assert_eq!(clock.now(), datetime!(2030-06-15 12:00:00 UTC));
    }

    #[test]
    fn clock_is_object_safe() {
        // Confirm the trait can be used as a trait object, which AppState relies
        // on for injection.
        let clock: std::sync::Arc<dyn Clock> = std::sync::Arc::new(FixedClock::from_unix(42));
        assert_eq!(clock.now().unix_timestamp(), 42);
    }
}
