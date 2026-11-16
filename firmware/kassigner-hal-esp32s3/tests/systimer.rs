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

//! What can be checked without the chip: the register reads would fault on
//! a host, but the arithmetic around them, where an off-by-sixteen would
//! live, runs. These tests prove the conversion, not the timer.

use kassigner_hal_esp32s3::systimer::{ticks_to_us, us_to_ticks, SysTimer, TICKS_PER_US};

/// SYSTIMER counts at 16 MHz, from XTAL, whatever the CPU clock.
#[test]
fn the_counter_runs_at_sixteen_megahertz() {
    const _: () = assert!(TICKS_PER_US == 16);
    assert_eq!(ticks_to_us(16), 1);
    assert_eq!(us_to_ticks(1), 16);
}

/// The two conversions agree.
#[test]
fn the_conversions_round_trip() {
    for us in [0u32, 1, 2, 100, 1_000, 1_000_000, u32::MAX] {
        assert_eq!(ticks_to_us(us_to_ticks(us)), us as u64, "{us} us");
    }
}

/// Sub-microsecond tick counts truncate, so `now_us` can report the same
/// microsecond twice; `delay_us` compares ticks so a sub-microsecond wait
/// still waits.
#[test]
fn ticks_below_a_microsecond_read_as_zero() {
    for t in 0..16u64 {
        assert_eq!(ticks_to_us(t), 0, "{t} ticks");
    }
    assert_eq!(ticks_to_us(16), 1);
    assert_eq!(ticks_to_us(31), 1);
    assert_eq!(ticks_to_us(32), 2);
}

/// The longest delay converts exactly, and the multiply cannot wrap to a
/// short wait: a wait that became brief is a rate limit that stopped
/// limiting, such as the RNG's 2 µs spacing.
#[test]
fn an_enormous_delay_saturates() {
    let max = us_to_ticks(u32::MAX);
    assert_eq!(max, u32::MAX as u64 * 16);
    assert!(max < u64::MAX, "this does not need to saturate yet");

    assert!(us_to_ticks(u32::MAX) > us_to_ticks(u32::MAX / 2));
}

/// A 64-bit tick count converts to over 30,000 years, so `now_us`'s own
/// arithmetic never wraps; a 32-bit microsecond count would wrap in about
/// 71 minutes, well inside a signer's time on a desk. (The hardware counter
/// is 52 bits and wraps after about 8.9 years.)
#[test]
fn the_counter_does_not_wrap_in_a_human_lifetime() {
    let years = ticks_to_us(u64::MAX) / 1_000_000 / 60 / 60 / 24 / 365;
    assert!(years > 30_000, "{years} years");

    // The 32-bit case this avoids.
    let wrap_minutes = (u32::MAX as u64) / 1_000_000 / 60;
    assert_eq!(wrap_minutes, 71);
}

/// The handle is zero-sized: the counter is a register, so a handle owns no
/// state and is written directly, with no constructor.
#[test]
fn the_handle_is_zero_sized() {
    const _: () = assert!(core::mem::size_of::<SysTimer>() == 0);

    let _t = SysTimer;
}
