// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

// timefmt.rs — rendering a transaction lock time for a human.
//
// Kaspa reads a lock time below `LOCK_TIME_THRESHOLD` as a DAA score and at
// or above it as a Unix timestamp in milliseconds
// (`consensus/core/src/constants.rs:22` in rusty-kaspa 2.0.1, and
// `check_tx_is_finalized`). The device signs the value either way; this
// module only decides what the review screen prints next to it. A DAA score
// is printed as the number. A timestamp is printed as a UTC date and time,
// because a thirteen-digit millisecond count is not something a person can
// compare against "when did I mean this to become spendable".
//
// Pure integer arithmetic, no clock, no allocation. Here rather than in the
// UI so the calendar conversion has a host test.

/// Same value as rusty-kaspa `LOCK_TIME_THRESHOLD`.
pub const LOCK_TIME_THRESHOLD: u64 = 500_000_000_000;

/// Calendar fields of a Unix timestamp, UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Civil {
    pub year: i32,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

/// Days since 1970-01-01 to a proleptic Gregorian date. Howard Hinnant's
/// `civil_from_days`, exact for the whole i64 day range this can see.
pub fn civil_from_days(z: i64) -> (i32, u8, u8) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u8; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d)
}

/// UTC calendar fields of a Unix millisecond timestamp.
pub fn civil_from_unix_ms(ms: u64) -> Civil {
    let secs = ms / 1000;
    let days = (secs / 86_400) as i64;
    let sod = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    Civil {
        year,
        month,
        day,
        hour: (sod / 3600) as u8,
        minute: ((sod % 3600) / 60) as u8,
        second: (sod % 60) as u8,
    }
}

/// What a lock time means, for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockTime {
    /// Zero: no lock time, the transaction is not shown as locked.
    None,
    /// Below the threshold: a DAA score the DAG must reach.
    DaaScore(u64),
    /// At or above the threshold: a wall-clock moment, UTC.
    Timestamp(Civil),
}

pub fn classify_lock_time(lock: u64) -> LockTime {
    if lock == 0 {
        LockTime::None
    } else if lock < LOCK_TIME_THRESHOLD {
        LockTime::DaaScore(lock)
    } else {
        LockTime::Timestamp(civil_from_unix_ms(lock))
    }
}

/// Write the review-screen label into `out`, returning the length. Never
/// longer than 40 bytes: "Locked until 2038-01-19 03:14 UTC" is 33, and a
/// DAA score prints as at most 20 digits after the 17-byte prefix.
pub fn lock_time_label(lock: u64, out: &mut [u8; 40]) -> usize {
    use core::fmt::Write;
    struct W<'a> { buf: &'a mut [u8; 40], n: usize }
    impl Write for W<'_> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let b = s.as_bytes();
            if self.n + b.len() > self.buf.len() { return Err(core::fmt::Error); }
            self.buf[self.n..self.n + b.len()].copy_from_slice(b);
            self.n += b.len();
            Ok(())
        }
    }
    let mut w = W { buf: out, n: 0 };
    let _ = match classify_lock_time(lock) {
        LockTime::None => Ok(()),
        LockTime::DaaScore(d) => write!(w, "Locked until DAA {d}"),
        LockTime::Timestamp(c) => write!(
            w, "Locked until {:04}-{:02}-{:02} {:02}:{:02} UTC",
            c.year, c.month, c.day, c.hour, c.minute
        ),
    };
    w.n
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn label(lock: u64) -> std::string::String {
        let mut b = [0u8; 40];
        let n = lock_time_label(lock, &mut b);
        std::string::String::from(core::str::from_utf8(&b[..n]).unwrap())
    }

    #[test]
    fn known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(10_957), (2000, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        assert_eq!(civil_from_days(19_782), (2024, 2, 29)); // leap day
        assert_eq!(civil_from_days(24_837), (2038, 1, 1));
        assert_eq!(civil_from_days(24_855), (2038, 1, 19));
    }

    #[test]
    fn unix_ms_to_civil() {
        // 2021-03-11 11:28:09 UTC (the timestamp used in the pskb tests),
        // expected values from Python's datetime, not from this code.
        let c = civil_from_unix_ms(1_615_462_089_000);
        assert_eq!((c.year, c.month, c.day, c.hour, c.minute, c.second), (2021, 3, 11, 11, 28, 9));
        // The Y2038 second.
        let c = civil_from_unix_ms(2_147_483_647_000);
        assert_eq!((c.year, c.month, c.day, c.hour, c.minute, c.second), (2038, 1, 19, 3, 14, 7));
    }

    #[test]
    fn classification_matches_consensus_threshold() {
        assert_eq!(classify_lock_time(0), LockTime::None);
        assert_eq!(classify_lock_time(1), LockTime::DaaScore(1));
        assert_eq!(classify_lock_time(LOCK_TIME_THRESHOLD - 1), LockTime::DaaScore(LOCK_TIME_THRESHOLD - 1));
        assert!(matches!(classify_lock_time(LOCK_TIME_THRESHOLD), LockTime::Timestamp(_)));
    }

    #[test]
    fn labels() {
        assert_eq!(label(0), "");
        assert_eq!(label(123_456_789), "Locked until DAA 123456789");
        assert_eq!(label(1_615_462_089_000), "Locked until 2021-03-11 11:28 UTC");
        assert!(label(u64::MAX).len() <= 40);
        // Every label fits the buffer, whatever the value.
        for v in [1u64, LOCK_TIME_THRESHOLD - 1, LOCK_TIME_THRESHOLD, u64::MAX / 2, u64::MAX] {
            let mut b = [0u8; 40];
            assert!(lock_time_label(v, &mut b) <= 40);
        }
    }
}
