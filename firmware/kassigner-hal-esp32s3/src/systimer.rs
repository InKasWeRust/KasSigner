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

//! The ESP32-S3 system timer.
//!
//! Implements [`kassigner_hal::timer::Timer`] over SYSTIMER, which counts at
//! 16 MHz whatever the CPU clock.
//!
//! # Why not a spin loop
//!
//! The TRM caps `RNG_DATA_REG` reads at 500 kHz, one per 2 µs, and a count
//! of `spin_loop()` iterations cannot express that: what it compiles to on
//! Xtensa and how link-time optimisation schedules the loop both move the
//! real delay. A loop count is not a time.
//!
//! # Reading the counter without tearing
//!
//! The counter is two registers; read separately, they can straddle a carry
//! and give a time that never existed. Writing the update bit latches both
//! halves at once, so no read-high, read-low, read-high-again is needed.
//!
//! **After the latch has completed, not after it was asked for.** The latch
//! crosses into the timer's clock domain: the TRM's procedure (11.5.1) is to
//! write `UPDATE`, poll `VALUE_VALID` until it reads 1, and only then read.
//! Read straight after the write, the registers can still hold the previous
//! latch. esp-hal's own read polls the same bit.

use kassigner_hal::timer::Timer;

/// `SYSTIMER_UNIT0_OP_REG` (TRM register 11.2). Writing bit 30 latches the
/// counter for reading.
const OP: u32 = 0x6002_3004;
/// `SYSTIMER_UNIT0_VALUE_HI_REG`, the latched high word.
const VALUE_HI: u32 = 0x6002_3040;
/// `SYSTIMER_UNIT0_VALUE_LO_REG`, the latched low word.
const VALUE_LO: u32 = 0x6002_3044;
/// The bit that latches the counter.
const UPDATE: u32 = 1 << 30;
/// Set once a latch has completed and the value registers hold it; cleared
/// by the next `UPDATE`.
const VALUE_VALID: u32 = 1 << 29;

/// Ticks per microsecond: SYSTIMER runs from XTAL at a fixed 16 MHz,
/// whatever the CPU clock.
pub const TICKS_PER_US: u64 = 16;

/// Microseconds from a tick count. A function of its own so a host test can
/// check it, as the register reads cannot run off the chip.
pub const fn ticks_to_us(ticks: u64) -> u64 {
    ticks / TICKS_PER_US
}

/// Ticks from a microsecond count, saturating: a wait that silently became
/// brief would be worse than one too long.
pub const fn us_to_ticks(us: u32) -> u64 {
    (us as u64).saturating_mul(TICKS_PER_US)
}

/// The system timer: write `SysTimer`. The counter is a register, so a
/// handle owns no state, holding one is not exclusive, and every use is a
/// read.
#[derive(Clone, Copy, Debug)]
pub struct SysTimer;

impl SysTimer {
    /// The raw tick count, for a caller that wants ticks rather than
    /// microseconds.
    pub fn ticks(&self) -> u64 {
        // SAFETY: volatile accesses to SYSTIMER registers at the TRM's
        // addresses: the write latches the counter, the poll waits for the
        // latch to land, and the two reads take the latched value. No other
        // peripheral shares these addresses, and nothing here is
        // read-modify-write.
        //
        // One instant only while one core reads the timer: a latch by the
        // other core between the two reads would pair this high word with
        // that low word. Only core 0 reads it; core 1's decode worker never
        // does. A second reader would need the two reads under a lock.
        unsafe {
            core::ptr::write_volatile(OP as *mut u32, UPDATE);
            // The TRM's poll, unbounded as there and in esp-hal: the bit sets
            // within a few timer cycles, and a timer that never latched would
            // hang every delay on the unit anyway.
            while core::ptr::read_volatile(OP as *const u32) & VALUE_VALID == 0 {}
            let hi = core::ptr::read_volatile(VALUE_HI as *const u32) as u64;
            let lo = core::ptr::read_volatile(VALUE_LO as *const u32) as u64;
            (hi << 32) | lo
        }
    }
}

impl Timer for SysTimer {
    /// Microseconds since the counter started. The counter is 52 bits (the
    /// high register holds 20): at 16 MHz it wraps after about 8.9 years.
    fn now_us(&self) -> u64 {
        ticks_to_us(self.ticks())
    }

    /// Block for at least `us` microseconds.
    ///
    /// Compares ticks, not microseconds, so a sub-microsecond wait is still
    /// a wait. `wrapping_sub` here and `saturating_sub` in the trait's
    /// `since`, on purpose: if the counter seemed to go backwards, a
    /// saturating difference would be zero and this loop would never end, a
    /// hang on a device someone is holding, while a wrapping one exits at
    /// once, a few microseconds wrong. `since` reports elapsed time, where a
    /// huge number would be a lie and zero only uninformative.
    fn delay_us(&mut self, us: u32) {
        let target = us_to_ticks(us);
        let start = self.ticks();
        while self.ticks().wrapping_sub(start) < target {
            core::hint::spin_loop();
        }
    }
}
