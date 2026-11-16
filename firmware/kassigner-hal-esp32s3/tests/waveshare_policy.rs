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

//! The decode policy, checked without a decoder: the downsample and the
//! sticky threshold window, as `waveshare::decoder` applies them. None of it
//! needs `rqrr` or a second core.
//!
//! The wrapper itself needs the `decode` feature and so `rqrr`, so the rules
//! are reimplemented below from the policy's numbers. This checks the rules,
//! not the code that applies them, which is weaker than it looks; it keeps
//! the policy readable in one screen.

/// The fast pass decodes a square of this side.
const FAST_SIDE: usize = 240;
/// Full frame, one axis.
const FRAME_SIDE: usize = 480;
const DENOM_NARROW: usize = 8;
const DENOM_WIDE: usize = 3;
const MISS_BEFORE_SWITCH: u8 = 2;

/// **The downsample skips nothing.** 480 to 240 is exactly 2:1, so each
/// output pixel averages its own four source pixels and every source row is
/// read. From 640 (2.67:1), 160 rows would never be sampled, which on a QR
/// code eats module edges.
#[test]
fn the_downsample_covers_every_source_row() {
    let mut sampled = vec![false; FRAME_SIDE];
    for dy in 0..FAST_SIDE {
        let sr0 = (dy * FRAME_SIDE) / FAST_SIDE;
        let sr1 = (sr0 + 1).min(FRAME_SIDE - 1);
        sampled[sr0] = true;
        sampled[sr1] = true;
    }
    let missed = sampled.iter().filter(|s| !**s).count();
    assert_eq!(missed, 0, "{missed} source rows never sampled");

    // And the ratio is exact, which makes that true; checked at compile
    // time, as both are constants.
    const _: () = assert!(FRAME_SIDE.is_multiple_of(FAST_SIDE));
    const _: () = assert!(FRAME_SIDE / FAST_SIDE == 2);
}

/// The window is sticky: it switches only after two consecutive misses, so a
/// stream that decodes settles on one instead of alternating.
#[test]
fn the_window_switches_only_after_two_misses() {
    let mut denom = DENOM_NARROW;
    let mut misses: u8 = 0;

    let miss = |denom: &mut usize, misses: &mut u8| {
        *misses += 1;
        if *misses >= MISS_BEFORE_SWITCH {
            *denom = if *denom == DENOM_NARROW {
                DENOM_WIDE
            } else {
                DENOM_NARROW
            };
            *misses = 0;
        }
    };

    miss(&mut denom, &mut misses);
    assert_eq!(denom, DENOM_NARROW, "one miss does not switch");

    miss(&mut denom, &mut misses);
    assert_eq!(denom, DENOM_WIDE, "two does");

    // A decode in between resets the count: miss, decode, miss, no switch.
    miss(&mut denom, &mut misses);
    assert_eq!(denom, DENOM_WIDE, "one miss at the new window");
    misses = 0; // a decode
    miss(&mut denom, &mut misses);
    assert_eq!(denom, DENOM_WIDE, "and the count started over");
}

/// The two windows are the firmware's, and distinct: 8, the quirc default,
/// suits dense symbols; 3 is wide and rescues V1 and V2, whose large modules
/// wash out under a narrow window.
#[test]
fn the_two_windows_are_the_firmwares() {
    const _: () = assert!(DENOM_NARROW == 8);
    const _: () = assert!(DENOM_WIDE == 3);
    const _: () = assert!(DENOM_NARROW != DENOM_WIDE);

    // Neither is 1: a window the width of the image is near-global
    // thresholding.
    const _: () = assert!(DENOM_WIDE > 1);
}

/// The fast job has a quarter of the full frame's pixels: one takes 20 ms,
/// the other over 100, which is why every pass decodes the fast square.
#[test]
fn the_fast_job_is_much_smaller() {
    let fast = FAST_SIDE * FAST_SIDE;
    let full = FRAME_SIDE * FRAME_SIDE;
    assert_eq!(fast, 57_600);
    assert_eq!(full, 230_400);
    assert_eq!(full / fast, 4, "four times the pixels");
}

/// **The DMA copy length must be clamped to the bounce buffer, not just to the
/// frame.** The descriptor's twelve-bit length can report up to 4095 and the
/// bounce buffers are 4032: the destination check guards the write into
/// PSRAM, but without a second clamp the *source* read runs past the buffer.
///
/// Arithmetic, since the copy needs a DMA engine: it pins the relation that
/// makes the clamp necessary.
#[test]
fn the_descriptor_length_can_exceed_the_bounce_buffer() {
    const BOUNCE_SIZE: usize = 4032;
    const DESC_LEN_MAX: usize = 0xFFF;

    // If this stops being true the clamp is redundant, not wrong. Checked at
    // compile time, as both are constants.
    const _: () = assert!(DESC_LEN_MAX > BOUNCE_SIZE);
    const _: () = assert!(DESC_LEN_MAX - BOUNCE_SIZE == 63);

    // The clamp the driver applies.
    let clamp = |reported: usize| reported.min(BOUNCE_SIZE);
    assert_eq!(clamp(4032), 4032, "a full descriptor is untouched");
    assert_eq!(
        clamp(4095),
        BOUNCE_SIZE,
        "the worst case is cut to the buffer"
    );
    assert_eq!(clamp(0), 0);
}
