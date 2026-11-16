// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! A clock, and a way to wait.
//!
//! A capture that cannot time out freezes the device, and a rate-limited
//! entropy draw spaces its RNG reads by a real 2 µs, measured from the clock:
//! a spin-loop count is not a time.
//!
//! [`Timer::now_us`] is 64-bit: a 32-bit microsecond count wraps in about 71
//! minutes, well inside the time a signer can be left on a desk.

/// A monotonic clock and a blocking delay.
pub trait Timer {
    /// Microseconds since a fixed point: monotonic, and does not wrap in any
    /// realistic session.
    fn now_us(&self) -> u64;

    /// Block for at least `us` microseconds; no upper bound is promised.
    fn delay_us(&mut self, us: u32);

    /// Block for at least `ms` milliseconds.
    fn delay_ms(&mut self, ms: u32) {
        for _ in 0..ms {
            self.delay_us(1_000);
        }
    }

    /// Microseconds elapsed since `start`. Saturating: a clock that appears
    /// to go backwards gives zero, not a wrapped, huge value.
    fn since(&self, start: u64) -> u64 {
        self.now_us().saturating_sub(start)
    }
}

/// A deadline: build one, then poll until the work finishes or it expires.
///
/// Every bounded wait in this crate takes this shape, so none lacks an exit:
/// a sensor that stops clocking pixels must not freeze the whole device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deadline {
    at: u64,
}

impl Deadline {
    /// A deadline `us` microseconds from now.
    pub fn after<T: Timer + ?Sized>(timer: &T, us: u32) -> Self {
        Self {
            at: timer.now_us().saturating_add(us as u64),
        }
    }

    /// Whether it has passed.
    pub fn expired<T: Timer + ?Sized>(&self, timer: &T) -> bool {
        timer.now_us() >= self.at
    }

    /// Microseconds left, zero once expired.
    pub fn remaining_us<T: Timer + ?Sized>(&self, timer: &T) -> u64 {
        self.at.saturating_sub(timer.now_us())
    }
}
