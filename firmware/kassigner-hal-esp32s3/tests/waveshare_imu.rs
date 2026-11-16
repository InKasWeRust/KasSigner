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

//! The IMU's health judgement, without an IMU.
//!
//! The bus reads cannot run here; what decides whether a collected buffer is
//! worth anything can. An axis alive at boot can be frozen by the time a
//! seed is drawn, so a source is checked where it is used: these tests are
//! on that check.

#![cfg(feature = "waveshare")]

use kassigner_hal_esp32s3::waveshare::imu::{
    axis_distinct, axis_first_byte, buffer_is_healthy, HEALTHY_DISTINCT_PCT,
};

/// A buffer of `passes` samples, three axes each, with a supplied generator.
fn buffer(passes: usize, mut f: impl FnMut(usize, usize) -> u8) -> Vec<u8> {
    let mut v = Vec::with_capacity(passes * 3);
    for p in 0..passes {
        for axis in 0..3 {
            v.push(f(p, axis));
        }
    }
    v
}

/// **A frozen axis fails, even when the other two are lively**: two good axes
/// must not carry a dead one.
#[test]
fn one_frozen_axis_fails_the_whole_buffer() {
    let lively = buffer(32, |p, axis| (p * 7 + axis * 13) as u8);
    assert!(buffer_is_healthy(&lively), "all three moving");

    for frozen in 0..3 {
        let b = buffer(32, |p, axis| {
            if axis == frozen {
                0x5A
            } else {
                (p * 7 + axis * 13) as u8
            }
        });
        assert!(
            !buffer_is_healthy(&b),
            "axis {frozen} frozen and the buffer passed"
        );
    }
}

/// Zero bytes, or too few samples to judge, are refused rather than passing
/// an all-distinct test trivially.
#[test]
fn too_little_data_is_not_healthy() {
    assert!(!buffer_is_healthy(&[]));
    assert!(!buffer_is_healthy(&[1, 2, 3]), "one pass says nothing");
    assert!(
        !buffer_is_healthy(&[1, 2, 3, 4, 5, 6, 7, 8, 9]),
        "three passes"
    );
}

/// An all-zero buffer, what a bus that answers with nothing gives, is
/// refused.
#[test]
fn a_silent_bus_is_not_healthy() {
    assert!(!buffer_is_healthy(&[0u8; 96]));
    assert!(!buffer_is_healthy(&[0xFFu8; 96]), "and all-ones too");
}

/// **The bar sits where it says**: a buffer exactly at it passes, one below
/// does not. A healthy axis is about 94% distinct, the bar 60%.
#[test]
fn the_threshold_sits_between_the_two_cases() {
    const PASSES: usize = 32;
    let needed = (PASSES as u32 * HEALTHY_DISTINCT_PCT / 100) as usize;

    // Exactly the threshold. The repeats reuse 0, already in the set: a
    // fresh value would itself count as distinct.
    let at = buffer(PASSES, |p, _| if p < needed { p as u8 } else { 0 });
    assert_eq!(axis_distinct(&at)[0], needed as u32, "exactly at the bar");
    assert!(buffer_is_healthy(&at), "at the threshold");

    // One below.
    let under = buffer(PASSES, |p, _| if p < needed - 1 { p as u8 } else { 0 });
    assert_eq!(axis_distinct(&under)[0], needed as u32 - 1);
    assert!(!buffer_is_healthy(&under), "one short of the threshold");
}

/// Distinctness is counted per axis: three axes each repeating its own value
/// would look varied counted together.
#[test]
fn distinctness_is_per_axis() {
    let b = buffer(32, |_, axis| (0x10 + axis) as u8);
    assert_eq!(axis_distinct(&b), [1, 1, 1], "each axis holds one value");
    assert!(!buffer_is_healthy(&b));

    assert_eq!(axis_first_byte(&b), [0x10, 0x11, 0x12]);
}

/// A ragged buffer does not panic or read past its end: `collect` writes what
/// it managed, so a length not a multiple of three is normal.
#[test]
fn a_ragged_buffer_is_handled() {
    for len in 0..40usize {
        let b: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let _ = buffer_is_healthy(&b);
        let _ = axis_distinct(&b);
        let _ = axis_first_byte(&b);
    }
}
