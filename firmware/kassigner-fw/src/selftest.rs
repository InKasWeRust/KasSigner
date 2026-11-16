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

//! Checks a unit runs on itself at boot, before anything touches a seed.
//!
//! The known answers in `kassigner_crypto::kat` and `kassigner_kaspa::kat`
//! check the primitives; this checks what they stand on: the code the
//! compiler emitted for this target, on this silicon. Each function returns
//! `(passed, total)`, as the known answers do, so one runner adds them up and
//! a report says which part failed.

use core::hint::black_box;

use kassigner_crypto::container::Argon2Block;
use kassigner_hal::memory::Words;
use kassigner_hal::timer::Timer;

/// 64-bit arithmetic, run on the silicon rather than folded by the compiler.
///
/// # Why a signer checks that division works
///
/// All three units have 32-bit cores, so every `u64` division, remainder,
/// wide multiply and variable shift calls a support routine chosen at build
/// time. On the P4 a ROM routine, reached through a table for another
/// silicon revision, returned `sum - count` for a 64-bit division; nothing
/// crashed, and every host test passed, since the host divides in hardware.
/// BIP32 derivation, the secp256k1 field arithmetic and every amount a
/// review shows go through these routines: a wrong quotient is a wrong key
/// or a wrong number on a confirm screen.
///
/// # Why every operand comes back through memory
///
/// Written plainly, `u64::MAX / 3` is folded by the compiler and the routine
/// never runs, so the check would pass on the silicon it exists to catch.
/// Each operand is written to `scratch` and read back through the board's
/// volatile access ([`Words`]), so its value is unknown at compile time and
/// the operation runs on the target, through the code a derivation uses.
/// `black_box` is only best effort, and a check that fails by passing
/// silently must not rest on best effort.
///
/// # The values
///
/// Worked off-line and checked by recombining each quotient and remainder
/// into its dividend. They cover unsigned division by divisors under and
/// over 32 bits, wrapping multiplication, signed division (truncating toward
/// zero, the remainder negative), a widening 128-bit product, and shifts by
/// a runtime amount, which lower to their own routines on these cores.
pub fn arithmetic<W: Words + ?Sized>(scratch: &mut W) -> (u32, u32) {
    let mut o = |v: u64| opaque(scratch, v);
    let results = [
        // Unsigned division, a divisor that fits in 32 bits.
        o(u64::MAX) / o(3) == 0x5555_5555_5555_5555,
        o(u64::MAX) % o(3) == 0,
        // A divisor over 32 bits, the case a 32-bit shortcut gets wrong.
        o(0x0123_4567_89AB_CDEF) / o(0x1_0000_0003) == 0x0123_4567,
        o(0x0123_4567_89AB_CDEF) % o(0x1_0000_0003) == 0x8641_FDBA,
        o(0xFEDC_BA98_7654_3210) / o(0xFFFF_FFFB) == 0xFEDC_BA9D,
        o(0xFEDC_BA98_7654_3210) % o(0xFFFF_FFFB) == 0x70A3_D721,
        // Wrapping multiplication.
        o(0x1_0000_0001).wrapping_mul(o(0x1_0000_0001)) == 0x2_0000_0001,
        o(0x9E37_79B9_7F4A_7C15).wrapping_mul(o(0xBF58_476D_1CE4_E5B9)) == 0xD674_11C4_6C86_742D,
        // Signed division truncates toward zero, and the remainder keeps the
        // dividend's sign.
        (o(-7_i64 as u64) as i64) / (o(2) as i64) == -3,
        (o(-7_i64 as u64) as i64) % (o(2) as i64) == -1,
        (o(-0x7FFF_FFFF_FFFF_FFFF_i64 as u64) as i64) / (o(12345) as i64) == -0x2_A783_BE38_C73E,
        (o(-0x7FFF_FFFF_FFFF_FFFF_i64 as u64) as i64) % (o(12345) as i64) == -817,
        // A widening product, the shape of a field multiplication's limbs.
        (o(u64::MAX) as u128) * (o(u64::MAX) as u128) == 0xFFFF_FFFF_FFFF_FFFE_0000_0000_0000_0001,
        // Shifts by an amount known only at runtime.
        (o(1) << o(63)) >> o(62) == 2,
    ];
    let passed = results.iter().filter(|&&ok| ok).count() as u32;
    (passed, results.len() as u32)
}

/// `v`, written into `scratch` and read back volatile, so the compiler
/// cannot know it. Uses the first two words of the region.
fn opaque<W: Words + ?Sized>(scratch: &mut W, v: u64) -> u64 {
    scratch.write(0, v as u32);
    scratch.write(1, (v >> 32) as u32);
    u64::from(scratch.read(0)) | (u64::from(scratch.read(1)) << 32)
}

/// Words a caller should give [`memory`] for the internal RAM check: 4 KB,
/// taken from the stack, the RAM every key derivation runs in.
pub const INTERNAL_WORDS: usize = 1024;

/// Words a caller should give [`memory`] for the PSRAM check: 512 KB.
///
/// PSRAM is reached through the cache, so a region that fits in the cache
/// never reaches the chip. The largest cache on these units is well under
/// this, so a pass means the external RAM answered, not a copy of it.
pub const PSRAM_WORDS: usize = 128 * 1024;

/// A pattern test over `words`, leaving them zeroed.
///
/// # What it catches, and why five passes
///
/// All zeros and all ones find a bit stuck at either value; the
/// checkerboard and its inverse, two neighbouring bits shorted together. A
/// value from each word's own index finds aliasing, two addresses reaching
/// the same cell, which no uniform pattern can see. Aliasing is what a
/// misconfigured external RAM shows (the wrong mode or size): the top half
/// of the heap quietly overwrites the bottom.
///
/// # Why it takes [`Words`] rather than a slice
///
/// Over a slice the compiler may prove each comparison from the value it
/// wrote and never read memory. `black_box` is best effort and atomics are
/// not promised either; only volatile access is guaranteed to reach memory.
/// Volatile needs `unsafe`, which this crate forbids, so the board supplies
/// the two volatile operations behind [`Words`], and the patterns and the
/// verdict stay here, once for every board.
///
/// Returns `(passed, total)`, one per pattern.
pub fn memory<W: Words + ?Sized>(words: &mut W) -> (u32, u32) {
    let passed = PATTERNS
        .iter()
        .filter(|(_, pattern)| one_pattern(words, *pattern).is_none())
        .count() as u32;
    clear(words);
    (passed, PATTERNS.len() as u32)
}

/// A memory pattern: its name, and the value it writes at each word.
pub type Pattern = (&'static str, fn(usize) -> u32);

/// The patterns, named, in the order [`memory`] runs them.
pub const PATTERNS: [Pattern; 5] = [
    ("zeros", |_| 0),
    ("ones", |_| u32::MAX),
    ("checkerboard", |i| {
        if i % 2 == 0 {
            0xAAAA_AAAA
        } else {
            0x5555_5555
        }
    }),
    ("inverse checkerboard", |i| {
        if i % 2 == 0 {
            0x5555_5555
        } else {
            0xAAAA_AAAA
        }
    }),
    ("index", |i| {
        (i as u32).wrapping_mul(0x9E37_79B9) ^ 0xA5A5_A5A5
    }),
];

/// How a memory check first went wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault {
    /// Which pattern, by its name in [`PATTERNS`].
    pub pattern: &'static str,
    /// The first word that read back wrong.
    pub word: usize,
    /// What was written there.
    pub wrote: u32,
    /// What came back.
    pub read: u32,
    /// How many words in the region read back wrong under that pattern.
    pub bad_words: usize,
}

/// Rerun [`memory`]'s patterns and describe the first that fails.
///
/// A count says a region is broken; this says how. Aliasing fails only the
/// index pattern, with the bad words in a block. A signal problem fails the
/// pattern hardest on the bus, usually a checkerboard, with the same bit
/// wrong in scattered words. `wrote` against `read` shows which bits, and
/// `bad_words` how widespread.
///
/// For a failure report, not the boot path: it runs the patterns again.
/// Leaves the region zeroed.
pub fn memory_fault<W: Words + ?Sized>(words: &mut W) -> Option<Fault> {
    let fault = PATTERNS.iter().find_map(|(name, pattern)| {
        one_pattern(words, *pattern).map(|(word, wrote, read, bad_words)| Fault {
            pattern: name,
            word,
            wrote,
            read,
            bad_words,
        })
    });
    clear(words);
    fault
}

/// Write one pattern and read it back: the first bad word, what was written
/// and read there, and how many words were bad, or `None` if all came back.
fn one_pattern<W: Words + ?Sized>(
    words: &mut W,
    pattern: fn(usize) -> u32,
) -> Option<(usize, u32, u32, usize)> {
    let n = words.len();
    for i in 0..n {
        words.write(i, pattern(i));
    }
    let mut first = None;
    let mut bad = 0;
    for i in 0..n {
        let read = words.read(i);
        if read != pattern(i) {
            if first.is_none() {
                first = Some((i, pattern(i), read));
            }
            bad += 1;
        }
    }
    first.map(|(i, wrote, read)| (i, wrote, read, bad))
}

/// Zero a region on the way out, so it is not left holding the last pattern
/// for whatever reuses it.
fn clear<W: Words + ?Sized>(words: &mut W) {
    for i in 0..words.len() {
        words.write(i, 0);
    }
}

/// One line of the boot self-test's report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Line {
    /// What was checked.
    pub name: &'static str,
    /// Checks that passed.
    pub passed: u32,
    /// Checks that ran. Zero means nothing ran, which is not a pass.
    pub total: u32,
    /// How long it took, in microseconds.
    pub us: u64,
}

impl Line {
    /// Every check ran and passed.
    pub const fn ok(&self) -> bool {
        self.total > 0 && self.passed == self.total
    }
}

/// Lines in the report, in the order [`run`] produces them.
pub const ITEMS: usize = 11;

/// Run every boot check and time each one.
///
/// It reports and does not decide: the binary prints every line, then halts
/// the unit if any is not [`Line::ok`], by reporting the start-up checks as
/// failed to the flow.
///
/// `internal` and `psram` are the memory check's regions, with the board's
/// volatile access behind them, sized [`INTERNAL_WORDS`] and
/// [`PSRAM_WORDS`]; both are left zeroed. `argon2` is the memory Argon2id's
/// known answer runs in ([`kassigner_crypto::kat::ARGON2ID_BLOCKS`]), lent
/// by a board that seals and opens under Argon2id (the P4) and handed back
/// wiped; `None` on a board that never does, which skips that check.
///
/// # The order
///
/// Arithmetic first: every other check divides, and a wrong quotient would
/// make any later failure unreadable. Then the memory the rest runs in,
/// internal and external. Then the hashes and the curve, a seed through a
/// slot to a wallet's key, sealing and opening a backup, and last Kaspa's
/// own rules, which stand on all of the above.
pub fn run<T, I, P>(
    timer: &T,
    internal: &mut I,
    psram: &mut P,
    mut argon2: Option<&mut [Argon2Block]>,
) -> [Line; ITEMS]
where
    T: Timer + ?Sized,
    I: Words + ?Sized,
    P: Words + ?Sized,
{
    // One statement per check: the arithmetic borrows two words of the
    // internal region and the memory check the whole, so the two borrows
    // must not share a statement.
    let arith = timed(timer, "arithmetic", &mut || arithmetic(internal));
    let ram = timed(timer, "internal RAM", &mut || memory(internal));
    let ext = timed(timer, "PSRAM", &mut || memory(psram));
    [
        arith,
        ram,
        ext,
        timed(timer, "BIP39", &mut kassigner_crypto::kat::bip39),
        timed(timer, "BIP32", &mut kassigner_crypto::kat::bip32),
        timed(timer, "BIP340", &mut kassigner_crypto::kat::bip340),
        timed(timer, "seed slot", &mut kassigner_crypto::kat::slot),
        timed(timer, "seal/open", &mut || seal_open(argon2.as_deref_mut())),
        timed(timer, "address", &mut kassigner_kaspa::kat::address),
        timed(
            timer,
            "45' multisig",
            &mut kassigner_kaspa::kat::multisig_45,
        ),
        timed(timer, "sighash", &mut kassigner_kaspa::kat::sighash),
    ]
}

/// Sealing and opening a backup, one line: the cipher, PBKDF2 and the
/// container on every unit, and Argon2id where `argon2` is lent
/// ([`kassigner_crypto::kat::container`], [`kassigner_crypto::kat::argon2id`]).
fn seal_open(argon2: Option<&mut [Argon2Block]>) -> (u32, u32) {
    let (mut passed, mut total) = kassigner_crypto::kat::container();
    if let Some(memory) = argon2 {
        let (p, t) = kassigner_crypto::kat::argon2id(memory);
        passed += p;
        total += t;
    }
    (passed, total)
}

/// One check, with its time.
///
/// # Why the check arrives as an opaque call
///
/// Reading the timer is a volatile access, and volatile accesses are only
/// ordered against each other: the compiler may move a pure computation, or
/// ordinary loads and stores, across them. Passed as a `dyn` function
/// through `black_box`, the call's target is unseen, so the compiler must
/// assume it could do anything and cannot move it across either read. This
/// guards against a move the language allows, whether or not a given build
/// makes it.
fn timed<T: Timer + ?Sized>(
    timer: &T,
    name: &'static str,
    check: &mut dyn FnMut() -> (u32, u32),
) -> Line {
    let check = black_box(check);
    let start = timer.now_us();
    let (passed, total) = check();
    let end = timer.now_us();
    Line {
        name,
        passed,
        total,
        us: end.saturating_sub(start),
    }
}
