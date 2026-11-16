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

//! The boot self-tests, run on the host.
//!
//! The host does 64-bit arithmetic in hardware, so this proves less than on
//! a unit; it proves the expected values are right, so a mistyped constant
//! fails here rather than as a false silicon fault on a device.

use kassigner_crypto::container::Argon2Block;
use kassigner_crypto::kat;
use kassigner_fw::selftest;
use kassigner_hal::memory::Words;
use kassigner_hal::timer::Timer;

#[test]
fn arithmetic_passes_where_arithmetic_is_known_good() {
    let (passed, total) = selftest::arithmetic(&mut Plain(vec![0; 2]));
    assert_eq!(total, 14, "the arithmetic set changed size");
    assert_eq!(passed, total, "arithmetic: {passed}/{total}");
}

/// A host region: plain memory, holding what it is given. The fault models
/// below test the patterns.
struct Plain(Vec<u32>);

impl Words for Plain {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn write(&mut self, i: usize, value: u32) {
        self.0[i] = value;
    }
    fn read(&self, i: usize) -> u32 {
        self.0[i]
    }
}

/// Healthy memory the size a board gives for internal RAM.
#[test]
fn internal_sized_region_passes_every_pattern() {
    let mut words = Plain(vec![0; selftest::INTERNAL_WORDS]);
    let (passed, total) = selftest::memory(&mut words);
    assert_eq!(total, 5, "the pattern set changed size");
    assert_eq!(passed, total, "internal RAM: {passed}/{total}");
}

/// Healthy memory the size a board gives for PSRAM passes, and comes back
/// zeroed.
#[test]
fn a_region_the_size_given_for_psram_passes_and_comes_back_zeroed() {
    let mut words = Plain(vec![0x1234_5678; selftest::PSRAM_WORDS]);
    let (passed, total) = selftest::memory(&mut words);
    assert_eq!(passed, total, "PSRAM-sized region: {passed}/{total}");
    assert!(words.0.iter().all(|&w| w == 0), "left with a pattern in it");
}

/// An empty region passes vacuously but still reports every pattern, so a
/// caller that passed nothing shows a total, not a skipped line.
#[test]
fn an_empty_region_still_reports_its_patterns() {
    assert_eq!(selftest::memory(&mut Plain(Vec::new())), (5, 5));
}

// ── Faults the patterns exist to catch ───────────────────────────────────────
//
// Each model is healthy memory with one defect, and each test asserts the
// check fails.

/// One bit of one word stuck at 1.
struct StuckHigh(Plain);

impl Words for StuckHigh {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn write(&mut self, i: usize, value: u32) {
        self.0.write(i, value);
    }
    fn read(&self, i: usize) -> u32 {
        let v = self.0.read(i);
        if i == 5 {
            v | (1 << 3)
        } else {
            v
        }
    }
}

#[test]
fn a_bit_stuck_high_fails() {
    let mut words = StuckHigh(Plain(vec![0; 64]));
    let (passed, total) = selftest::memory(&mut words);
    assert!(passed < total, "a stuck bit passed {passed}/{total}");
}

/// Two neighbouring bits of one word shorted: both read as their AND.
struct Shorted(Plain);

impl Words for Shorted {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn write(&mut self, i: usize, value: u32) {
        self.0.write(i, value);
    }
    fn read(&self, i: usize) -> u32 {
        let v = self.0.read(i);
        if i != 9 {
            return v;
        }
        let both = (v >> 4) & (v >> 5) & 1;
        (v & !(0b11 << 4)) | (both << 4) | (both << 5)
    }
}

#[test]
fn two_shorted_bits_fail() {
    let mut words = Shorted(Plain(vec![0; 64]));
    let (passed, total) = selftest::memory(&mut words);
    assert!(passed < total, "shorted bits passed {passed}/{total}");
}

/// The top half of the region reaches the bottom half's cells: a wrong
/// external RAM size, seen from the inside.
struct Aliased(Plain);

impl Words for Aliased {
    fn len(&self) -> usize {
        self.0.len() * 2
    }
    fn write(&mut self, i: usize, value: u32) {
        let half = self.0.len();
        self.0.write(i % half, value);
    }
    fn read(&self, i: usize) -> u32 {
        let half = self.0.len();
        self.0.read(i % half)
    }
}

/// Aliasing passes every uniform pattern: each cell holds the same value
/// whichever address wrote it last. Only the index pattern fails.
#[test]
fn aliasing_fails_only_the_index_pattern() {
    let mut words = Aliased(Plain(vec![0; 64]));
    let (passed, total) = selftest::memory(&mut words);
    assert_eq!((passed, total), (4, 5), "aliasing: {passed}/{total}");
}

// ── The fault report ────────────────────────────────────────────────────────

#[test]
fn healthy_memory_reports_no_fault() {
    assert_eq!(selftest::memory_fault(&mut Plain(vec![0; 64])), None);
}

/// Aliasing is reported as the index pattern failing over exactly the
/// bottom half: each word was overwritten by the later write to its alias.
#[test]
fn aliasing_is_reported_as_the_index_pattern_over_half_the_region() {
    let fault = selftest::memory_fault(&mut Aliased(Plain(vec![0; 64]))).expect("a fault");
    assert_eq!(fault.pattern, "index");
    assert_eq!(fault.bad_words, 64, "the bottom half, and only that");
    assert_eq!(fault.word, 0, "the first word lost its value to its alias");
}

/// Two shorted bits are reported under the first checkerboard, in one word,
/// with exactly those two bits disagreeing.
#[test]
fn shorted_bits_are_reported_under_the_checkerboard_in_one_word() {
    let fault = selftest::memory_fault(&mut Shorted(Plain(vec![0; 64]))).expect("a fault");
    assert_eq!(fault.pattern, "checkerboard");
    assert_eq!((fault.word, fault.bad_words), (9, 1));
    assert_eq!(
        (fault.wrote ^ fault.read) & !(0b11 << 4),
        0,
        "only bits 4 and 5"
    );
}

/// A host clock that advances one microsecond at every read.
struct Tick(core::cell::Cell<u64>);

impl Timer for Tick {
    fn now_us(&self) -> u64 {
        let t = self.0.get() + 1;
        self.0.set(t);
        t
    }
    fn delay_us(&mut self, us: u32) {
        self.0.set(self.0.get() + u64::from(us));
    }
}

/// The whole boot set, in order, every line passing: 14 arithmetic, 5 and 5
/// memory, 39 known answers, and one more where Argon2id's memory is lent
/// (as the P4 does), which comes back wiped.
#[test]
fn the_runner_reports_every_line_and_every_line_passes() {
    for lent in [false, true] {
        let timer = Tick(core::cell::Cell::new(0));
        let mut internal = Plain(vec![0; selftest::INTERNAL_WORDS]);
        let mut psram = Plain(vec![0; selftest::PSRAM_WORDS]);
        let mut argon2 = vec![Argon2Block::default(); kat::ARGON2ID_BLOCKS];
        let report = selftest::run(
            &timer,
            &mut internal,
            &mut psram,
            lent.then_some(&mut argon2[..]),
        );

        let names: Vec<&str> = report.iter().map(|l| l.name).collect();
        assert_eq!(
            names,
            [
                "arithmetic",
                "internal RAM",
                "PSRAM",
                "BIP39",
                "BIP32",
                "BIP340",
                "seed slot",
                "seal/open",
                "address",
                "45' multisig",
                "sighash",
            ]
        );
        for line in &report {
            assert!(line.ok(), "{}: {}/{}", line.name, line.passed, line.total);
        }
        let total: u32 = report.iter().map(|l| l.total).sum();
        let expected = if lent { 64 } else { 63 };
        assert_eq!(total, expected, "the boot set changed size, lent {lent}");
        assert!(
            argon2.iter().all(|b| b.as_ref().iter().all(|&w| w == 0)),
            "Argon2id's memory comes back wiped"
        );
    }
}
