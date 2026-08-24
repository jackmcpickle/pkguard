//! The clock seam.
//!
//! The second injection seam in the core, alongside `CommandRunner`. Two
//! things in pkguard depend on the current date: uv's `exclude-newer` setting,
//! which is checked against a minimum age in days, and the advisory cache TTL.
//! Both were reading `SystemTime::now()` directly, so neither could be tested
//! deterministically — the uv date checks could only be written against dates
//! far enough in the past to be safe, and cache expiry could only be exercised
//! with a zero TTL.

use std::time::{SystemTime, UNIX_EPOCH};

const SECS_PER_DAY: u64 = 86_400;

/// Reads wall-clock time.
pub trait Clock: Send + Sync {
    /// Seconds since the Unix epoch.
    fn now_secs(&self) -> u64;

    /// Whole days since the Unix epoch.
    fn today(&self) -> i64 {
        (self.now_secs() / SECS_PER_DAY).cast_signed()
    }
}

/// The real clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
}

/// A clock stopped at a chosen instant, for tests.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock {
    secs: u64,
}

impl FixedClock {
    #[must_use]
    pub const fn at_secs(secs: u64) -> Self {
        Self { secs }
    }

    /// Midnight on the given day since the Unix epoch.
    #[must_use]
    pub fn at_day(day: i64) -> Self {
        Self {
            secs: day.max(0).cast_unsigned() * SECS_PER_DAY,
        }
    }
}

impl Clock for FixedClock {
    fn now_secs(&self) -> u64 {
        self.secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fixed_clock_does_not_move() {
        let clock = FixedClock::at_secs(1_700_000_000);
        assert_eq!(clock.now_secs(), 1_700_000_000);
        assert_eq!(clock.now_secs(), 1_700_000_000);
    }

    #[test]
    fn days_are_whole_days_since_the_epoch() {
        assert_eq!(FixedClock::at_secs(0).today(), 0);
        assert_eq!(FixedClock::at_secs(SECS_PER_DAY - 1).today(), 0);
        assert_eq!(FixedClock::at_secs(SECS_PER_DAY).today(), 1);
        assert_eq!(FixedClock::at_day(19_782).today(), 19_782);
    }

    #[test]
    fn the_system_clock_is_after_2024() {
        // 2024-01-01 is 19723 days after the epoch.
        assert!(SystemClock.today() > 19_723);
    }
}
