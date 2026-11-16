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

//! What can be checked without the chip: the register accesses cannot run
//! here, but the contract around them can. An unstarted generator refuses
//! and leaves nothing behind, the read spacing and window size are pinned,
//! and the health tests reject what a dead generator, or one read at a
//! wrong address, gives.

use kassigner_hal::entropy::{health, Entropy, Error};
use kassigner_hal_esp32s3::entropy::{Rng, READ_SPACING_US, WINDOW_WORDS};

/// An unstarted generator refuses and zeroes the buffer, so a caller that
/// ignores the result finds nothing that looks like randomness.
#[test]
fn an_unstarted_generator_refuses() {
    let mut rng = Rng::new();
    assert!(!rng.is_started());

    let mut out = [0xFFu8; 32];
    assert_eq!(rng.fill(&mut out).err(), Some(Error::Unavailable));
    assert_eq!(out, [0u8; 32], "the buffer was left holding something");

    assert_eq!(rng.aux().err(), Some(Error::Unavailable));
    assert!(rng.draw_window().is_none());
}

/// The read spacing is the TRM's ceiling: with the SAR ADC feeding it, the
/// generator gets two bits per 20 MHz cycle, so a fresh 32-bit word needs
/// 500 kHz or slower. Pinned, as a wrong number here fails silently.
#[test]
fn the_read_spacing_is_two_microseconds() {
    const _: () = assert!(READ_SPACING_US == 2);
}

/// The window is the size the health tests were calibrated against.
#[test]
fn the_window_is_thirty_two_words() {
    const _: () = assert!(WINDOW_WORDS == 32);
    assert_eq!(WINDOW_WORDS * 32, 1024, "bits per window");
}

/// The health tests the module relies on reject what a dead generator
/// gives: if they stopped catching zeros, the module would return them.
#[test]
fn the_tests_this_module_relies_on_reject_zeros() {
    let dead = [0u32; WINDOW_WORDS];
    assert!(!health::all(&dead));

    // And a counter, which a wrong address gives if it lands on a timer.
    let counter: Vec<u32> = (0..WINDOW_WORDS as u32)
        .map(|i| 0x6DB6_DB40u32.wrapping_add(i * 0x40))
        .collect();
    assert!(!health::all(&counter));
}

/// Construction starts nothing: the generator's clock, the jitter feed and
/// the SAR ADC are `start`'s.
#[test]
fn construction_enables_nothing() {
    let rng = Rng::new();
    assert!(!rng.is_started());

    let other = Rng::default();
    assert!(!other.is_started());
}
