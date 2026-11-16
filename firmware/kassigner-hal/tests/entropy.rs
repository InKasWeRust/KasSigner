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

//! The entropy trait, and the sources it must reject: a test supplies a
//! source that is dead, stuck or a counter, and checks that the health tests
//! notice.

use kassigner_hal::entropy::{health, Entropy, Error};

/// A source that returns whatever it was given.
struct Canned {
    words: &'static [u32],
    healthy: bool,
}

impl Entropy for Canned {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        if !self.healthy {
            out.fill(0);
            return Err(Error::Unhealthy);
        }
        for (i, b) in out.iter_mut().enumerate() {
            *b = self.words[(i / 4) % self.words.len()].to_le_bytes()[i % 4];
        }
        Ok(())
    }
}

/// A source with nothing behind it.
struct Absent;

impl Entropy for Absent {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        out.fill(0);
        Err(Error::Unavailable)
    }
}

/// A dead register reads zero, and every test says so. The RNG read at the
/// ESP32's address on an S3 returns zero on every read, and thirty-two zero
/// words hash to a respectable-looking digest.
#[test]
fn a_dead_register_fails_every_test() {
    let dead = [0u32; 32];
    assert!(!health::no_repeats(&dead));
    assert!(!health::all_distinct(&dead));
    assert!(!health::no_stuck_bits(&dead));
    assert!(!health::balanced(&dead));
    assert!(!health::all(&dead));
}

/// A free-running counter is caught. Repetition, distinctness and bit
/// balance all answer the same question and none detects structure, and the
/// mistake that gives a dead register, an address on the wrong peripheral,
/// gives a counter if it lands on a timer.
#[test]
fn a_counter_is_caught_by_the_tests_added_for_it() {
    // A SYSTIMER-like counter with a 0x40 stride, from a base chosen so the
    // window's bit count is ordinary, about 50%. From a sparse base the
    // balance band alone would catch it, and the test would pass for the
    // wrong reason: the claim is that the three structure-blind tests pass
    // something with almost no entropy.
    let counter: Vec<u32> = (0..32u32)
        .map(|i| 0x6DB6_DB40u32.wrapping_add(i * 0x40))
        .collect();

    // The three structure-blind tests all pass it.
    assert!(health::no_repeats(&counter), "no two are equal");
    assert!(health::all_distinct(&counter), "all thirty-two differ");
    assert!(
        health::balanced(&counter),
        "and the bit count sits in the band"
    );

    // The two structure tests do not.
    assert!(
        !health::no_stuck_bits(&counter),
        "its high and low bits never move"
    );
    assert!(
        !health::not_monotonic(&counter),
        "and every step goes the same way"
    );

    assert!(!health::all(&counter));
}

/// A source with a stuck half is caught: upper sixteen bits frozen, lower
/// sixteen live; distinct, non-repeating, with a plausible bit count.
#[test]
fn a_half_stuck_source_is_caught() {
    let stuck: Vec<u32> = (0..32u32)
        .map(|i| 0xDEAD_0000 | (i.wrapping_mul(0x9E37) & 0xFFFF))
        .collect();

    assert!(health::no_repeats(&stuck));
    assert!(health::all_distinct(&stuck));
    assert!(
        !health::no_stuck_bits(&stuck),
        "the upper half never changes"
    );
    assert!(!health::all(&stuck));
}

/// A healthy-looking window passes: the control, since tests that only ever
/// reject are satisfied by a function that always returns false.
#[test]
fn a_live_looking_window_passes() {
    // A xorshift: no good RNG, but the tests ask whether a source has died,
    // not whether it is strong.
    let mut x: u32 = 0x2545_F491;
    let live: Vec<u32> = (0..32)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x
        })
        .collect();

    assert!(health::no_repeats(&live));
    assert!(health::all_distinct(&live));
    assert!(health::no_stuck_bits(&live));
    assert!(health::not_monotonic(&live));
    assert!(health::balanced(&live));
    assert!(health::all(&live));
}

/// **A window under five words, too short to judge, passes the monotonic
/// check:** three or four words cannot give two steps each way. From five, a
/// counter is caught and a window that turns about passes.
#[test]
fn the_monotonic_check_judges_five_words_and_more() {
    for short in [&[1u32, 9, 4][..], &[1, 9, 4, 7], &[9, 1, 4, 2]] {
        assert!(health::not_monotonic(short), "{short:?}");
    }
    assert!(!health::not_monotonic(&[1, 2, 3, 4, 5]), "a counter");
    assert!(health::not_monotonic(&[1, 9, 4, 7, 2]), "up and down");
}

/// A biased source is caught by the band, but only a badly biased one: the
/// band is wide on purpose, as thirty-two words say nothing about quality. A
/// window with about 31% of its bits set passes and one under 2% does not.
#[test]
fn the_band_catches_gross_bias_only() {
    let mild: Vec<u32> = (0..32u32)
        .map(|i| 0x1111_1111 ^ i.wrapping_mul(7))
        .collect();
    assert!(health::balanced(&mild), "mild bias is not this test's job");

    let gross: Vec<u32> = (0..32u32).map(|i| i & 1).collect();
    assert!(!health::balanced(&gross), "almost all zeros is");
}

/// An absent source errors and leaves nothing behind: a caller that ignores
/// the result must not find something that looks like randomness.
#[test]
fn an_absent_source_leaves_the_buffer_zeroed() {
    let mut out = [0xFFu8; 32];
    assert_eq!(Absent.fill(&mut out).err(), Some(Error::Unavailable));
    assert_eq!(out, [0u8; 32]);

    assert_eq!(Absent.aux().err(), Some(Error::Unavailable));
}

/// An unhealthy source errors rather than returning what it drew.
#[test]
fn an_unhealthy_source_refuses() {
    let mut src = Canned {
        words: &[0, 0, 0, 0],
        healthy: false,
    };
    let mut out = [0xFFu8; 32];
    assert_eq!(src.fill(&mut out).err(), Some(Error::Unhealthy));
    assert_eq!(out, [0u8; 32], "nothing is left behind");
}

/// `aux` fills exactly what BIP340 signing needs.
#[test]
fn aux_is_thirty_two_bytes() {
    let mut src = Canned {
        words: &[0x1234_5678, 0x9ABC_DEF0],
        healthy: true,
    };
    let a = src.aux().expect("healthy");
    assert_eq!(a.len(), 32);
    assert_ne!(a, [0u8; 32]);
}

/// A degenerate window is not called healthy.
#[test]
fn an_empty_window_is_not_healthy() {
    assert!(!health::no_stuck_bits(&[]));
    assert!(!health::balanced(&[]));
    assert!(!health::all(&[]));
}
