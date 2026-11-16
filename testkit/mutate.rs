// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The mutation loop the fuzz tests run their readers under: each crate's
//! `tests/fuzz.rs`, and the test files whose helpers they share in
//! `kassigner-qr` and `kassigner-fw` (`qr.rs`, `scan.rs`, `flow/fuzz.rs`).
//!
//! A reader handed any bytes must return, never panic, overflow or loop: on
//! a unit a panic is a reset and an overflow is a panic (the release profile
//! keeps overflow checks), and a code shown to the camera or a file on the
//! card can carry such bytes. Some targets check more of what they accept,
//! such as that it writes back as it was read.
//!
//! # What a target is fed
//!
//! 1. Each seed as given: valid inputs from the crate's writers and
//!    `spec/vectors/`, and edge cases built by hand.
//! 2. Each seed cut short, at up to [`CUTS`] lengths: what a scan that
//!    stopped early hands over.
//! 3. Each text seed with one value changed at a time ([`values`]): these
//!    keep a JSON schema intact, so they reach the arithmetic behind it.
//! 4. Mutations of the seeds and of those values ([`Inputs::mutated`]).
//!    Starting inside the format, they reach code past the first check. Half
//!    the time a text seed only has its values changed. Otherwise, half the
//!    time, every change keeps each byte in place (a splice aside), so a
//!    format of lengths and counts keeps its shape.
//! 5. Bytes at random, some behind a seed's opening bytes to pass a magic.
//!
//! The fuzz tests are ignored by `test-all` and run on their own:
//!
//! ```text
//! cargo +esp195 fuzz-all
//! ```
//!
//! A run is the same on every machine, and a failure prints its input in
//! hex. For a longer run by hand, `FUZZ_SCALE` multiplies every target's
//! mutations and `FUZZ_SEED` moves the generator's start:
//!
//! ```text
//! FUZZ_SCALE=50 cargo +esp195 fuzz-all
//! ```
//!
//! Each target runs on its own thread; an input still running after
//! [`STALL`] fails the test as a hang (on a unit, the watchdog's reset).
//!
//! Included by path, so every crate's tests share one generator.

use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long one input may run before it counts as a hang: far past any
/// input's time in a debug build.
const STALL: Duration = Duration::from_secs(20);

/// Lengths a seed is cut to, at most: every length of a shorter seed, this
/// many spread across a longer one.
const CUTS: usize = 512;

/// Integers at the edges of a reader's arithmetic: around the limits of a
/// byte, `u16`, `u32` and `u64` and of small counts, and the sompi supply
/// and one over.
const INTEGERS: [u64; 36] = [
    0,
    1,
    2,
    7,
    8,
    15,
    16,
    31,
    32,
    33,
    63,
    64,
    65,
    127,
    128,
    255,
    256,
    257,
    1024,
    0x7FFF,
    0x8000,
    0xFFFF,
    0x1_0000,
    0x7FFF_FFFF,
    0x8000_0000,
    0xFFFF_FFFF,
    0x1_0000_0000,
    MAX_SOMPI / 2 + 1,
    MAX_SOMPI,
    MAX_SOMPI + 1,
    u64::MAX / 7 + 1,
    0x7FFF_FFFF_FFFF_FFFF,
    0x8000_0000_0000_0000,
    u64::MAX / 2 + 1,
    u64::MAX - 1,
    u64::MAX,
];

/// Kaspa's supply in sompi (29 billion KAS), written here because not every
/// crate including this file depends on `kassigner-kaspa`.
const MAX_SOMPI: u64 = 29_000_000_000 * 100_000_000;

/// Numbers as text, at the same edges, and shapes of a number in JSON or a
/// path that a reader may not expect.
const NUMBERS: [&[u8]; 24] = [
    b"0",
    b"1",
    b"-1",
    b"-0",
    b"00",
    b"0.5",
    b"1e400",
    b"255",
    b"256",
    b"65535",
    b"65536",
    b"2147483648",
    b"4294967295",
    b"4294967296",
    b"2900000000000000000",
    b"2900000000000000001",
    b"9223372036854775807",
    b"9223372036854775808",
    b"18446744073709551615",
    b"18446744073709551616",
    b"99999999999999999999999999999999",
    b"2147483647'",
    b"2147483648'",
    b"4294967295'",
];

/// Pieces of text a reader of JSON, paths or words gives meaning to.
const TOKENS: [&[u8]; 20] = [
    b"\"", b"{", b"}", b"[", b"]", b",", b":", b"\\", b"\\u0000", b"\\ud800", b"null", b"true",
    b"-", b"'", b"/", b"m/", b" ", b"\n", b"\r\n", b"\0",
];

/// Bytes a reader branches on: none, one, the ends of a signed and an
/// unsigned byte, a space, a digit, a letter.
const BYTES: [u8; 12] = [
    0x00, 0x01, 0x02, 0x1B, 0x20, 0x30, 0x41, 0x7F, 0x80, 0xC0, 0xFE, 0xFF,
];

/// Run `target` over the seeds and `rounds` mutations of them (the inputs
/// the module doc lists), failing on the first input that panics or hangs.
///
/// `target` is a plain function so its thread borrows nothing from the test
/// and can be left behind if it hangs.
pub fn run(name: &'static str, rounds: usize, seeds: Vec<Vec<u8>>, target: fn(&[u8])) {
    assert!(!seeds.is_empty(), "{name}: no seeds");
    let scale = var("FUZZ_SCALE").unwrap_or(1).max(1) as usize;
    let start = var("FUZZ_SEED").unwrap_or(0x9E37_79B9_7F4A_7C15) ^ fnv(name.as_bytes());
    let rounds = rounds.saturating_mul(scale);

    let current = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicUsize::new(0));
    let finished = Arc::new(AtomicBool::new(false));
    let failed: Arc<Mutex<Option<(usize, String)>>> = Arc::new(Mutex::new(None));

    let worker = {
        let (current, done, finished, failed) = (
            Arc::clone(&current),
            Arc::clone(&done),
            Arc::clone(&finished),
            Arc::clone(&failed),
        );
        std::thread::spawn(move || {
            let mut inputs = Inputs::new(seeds, rounds, start);
            let mut n = 0;
            while let Some(input) = inputs.next() {
                current.lock().unwrap().clone_from(&input);
                if let Err(e) = panic::catch_unwind(AssertUnwindSafe(|| target(&input))) {
                    *failed.lock().unwrap() = Some((n, message(&e)));
                    break;
                }
                n += 1;
                done.store(n, Ordering::Release);
            }
            finished.store(true, Ordering::Release);
        })
    };

    let mut seen = 0;
    let mut since = Instant::now();
    while !finished.load(Ordering::Acquire) {
        std::thread::sleep(Duration::from_millis(20));
        let now = done.load(Ordering::Acquire);
        if now != seen {
            seen = now;
            since = Instant::now();
        } else if since.elapsed() > STALL {
            let input = current.lock().unwrap().clone();
            panic!(
                "{name}: input {seen} still running after {STALL:?}, {} bytes: {}",
                input.len(),
                hex(&input)
            );
        }
    }
    worker.join().unwrap();
    let failure = failed.lock().unwrap().take();
    if let Some((n, why)) = failure {
        let input = current.lock().unwrap().clone();
        panic!(
            "{name}: input {n} panicked ({why}), {} bytes: {}",
            input.len(),
            hex(&input)
        );
    }
}

/// The inputs of one run, in the module doc's order.
struct Inputs {
    seeds: Vec<Vec<u8>>,
    /// The text seeds' values changed one at a time ([`values`]).
    values: Vec<Vec<u8>>,
    rng: u64,
    /// Which phase, and how far into it.
    phase: Phase,
    rounds: usize,
    /// The longest seed: how long random inputs grow.
    longest: usize,
}

#[derive(Clone, Copy)]
enum Phase {
    Whole(usize),
    Cut { seed: usize, at: usize },
    Values(usize),
    Mutated(usize),
    Random(usize),
}

impl Inputs {
    fn new(seeds: Vec<Vec<u8>>, rounds: usize, start: u64) -> Self {
        let longest = seeds.iter().map(Vec::len).max().unwrap_or(0);
        let values = seeds
            .iter()
            .filter(|s| text(s))
            .flat_map(|s| values(s))
            .collect();
        Self {
            seeds,
            values,
            rng: start | 1,
            phase: Phase::Whole(0),
            rounds,
            longest,
        }
    }

    fn next(&mut self) -> Option<Vec<u8>> {
        loop {
            match self.phase {
                Phase::Whole(i) => {
                    if i < self.seeds.len() {
                        self.phase = Phase::Whole(i + 1);
                        return Some(self.seeds[i].clone());
                    }
                    self.phase = Phase::Cut { seed: 0, at: 0 };
                }
                Phase::Cut { seed, at } => {
                    let Some(s) = self.seeds.get(seed) else {
                        self.phase = Phase::Values(0);
                        continue;
                    };
                    let points = s.len().min(CUTS);
                    if at >= points {
                        self.phase = Phase::Cut {
                            seed: seed + 1,
                            at: 0,
                        };
                        continue;
                    }
                    self.phase = Phase::Cut { seed, at: at + 1 };
                    // Every length of a short seed; across a long one, evenly
                    // spread from empty to one byte short of the whole.
                    let len = if s.len() <= CUTS {
                        at
                    } else {
                        at * (s.len() - 1) / (CUTS - 1)
                    };
                    return Some(s[..len].to_vec());
                }
                Phase::Values(i) => {
                    if let Some(v) = self.values.get(i) {
                        self.phase = Phase::Values(i + 1);
                        return Some(v.clone());
                    }
                    self.phase = Phase::Mutated(0);
                }
                Phase::Mutated(i) => {
                    if i < self.rounds {
                        self.phase = Phase::Mutated(i + 1);
                        return Some(self.mutated());
                    }
                    self.phase = Phase::Random(0);
                }
                Phase::Random(i) => {
                    if i < self.rounds / 16 + 16 {
                        self.phase = Phase::Random(i + 1);
                        return Some(self.random());
                    }
                    return None;
                }
            }
        }
    }

    /// xorshift64*: enough to spread inputs, and the same on every machine.
    fn u64(&mut self) -> u64 {
        self.rng ^= self.rng >> 12;
        self.rng ^= self.rng << 25;
        self.rng ^= self.rng >> 27;
        self.rng.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A number below `n`, which is not zero.
    fn below(&mut self, n: usize) -> usize {
        (self.u64() % n as u64) as usize
    }

    fn seed(&mut self) -> Vec<u8> {
        let i = self.below(self.seeds.len());
        self.seeds[i].clone()
    }

    fn mutated(&mut self) -> Vec<u8> {
        let mut b = if !self.values.is_empty() && self.below(2) == 0 {
            let i = self.below(self.values.len());
            self.values[i].clone()
        } else {
            self.seed()
        };
        if text(&b) && self.below(2) == 0 {
            for _ in 0..1 + self.below(3) {
                self.revalue(&mut b);
            }
            return b;
        }
        // A splice now and then: the head of one seed, the tail of another.
        if self.below(8) == 0 {
            let other = self.seed();
            let at = self.below(b.len() + 1);
            let from = self.below(other.len() + 1);
            b.truncate(at);
            b.extend_from_slice(&other[from..]);
        }
        let times = if self.below(4) == 0 {
            1 + self.below(16)
        } else {
            1 + self.below(4)
        };
        // Half the time, only changes that move no byte (see the module doc).
        let in_place = self.below(2) == 0;
        for _ in 0..times {
            self.mutate(&mut b, in_place);
        }
        b
    }

    fn mutate(&mut self, b: &mut Vec<u8>, in_place: bool) {
        /// The changes below that move no byte.
        const IN_PLACE: [usize; 7] = [0, 1, 2, 3, 4, 9, 14];
        let len = b.len();
        let change = if in_place {
            IN_PLACE[self.below(IN_PLACE.len())]
        } else {
            self.below(16)
        };
        match change {
            // A bit flipped.
            0 if len > 0 => {
                let i = self.below(len);
                b[i] ^= 1 << self.below(8);
            }
            // A byte changed, to anything or to one readers branch on.
            1 if len > 0 => {
                let i = self.below(len);
                b[i] = self.u64() as u8;
            }
            2 if len > 0 => {
                let i = self.below(len);
                b[i] = BYTES[self.below(BYTES.len())];
            }
            // A byte moved a little: a length or a count one off, or a few.
            3 if len > 0 => {
                let i = self.below(len);
                let d = 1 + self.below(16) as u8;
                b[i] = if self.below(2) == 0 {
                    b[i].wrapping_add(d)
                } else {
                    b[i].wrapping_sub(d)
                };
            }
            // An integer at a limit written over 2, 4 or 8 bytes, either order.
            4 if len > 0 => {
                let width = [2, 4, 8][self.below(3)];
                let v = INTEGERS[self.below(INTEGERS.len())];
                let bytes = if self.below(2) == 0 {
                    v.to_le_bytes()
                } else {
                    v.to_be_bytes()
                };
                let bytes = if self.below(2) == 0 {
                    &bytes[..width]
                } else {
                    &bytes[8 - width..]
                };
                let i = self.below(len);
                let n = bytes.len().min(len - i);
                b[i..i + n].copy_from_slice(&bytes[..n]);
            }
            // Bytes inserted, at random or a run of one byte.
            5 => {
                let i = self.below(len + 1);
                let n = 1 + self.below(16);
                let ins: Vec<u8> = (0..n).map(|_| self.u64() as u8).collect();
                b.splice(i..i, ins);
            }
            6 => {
                let i = self.below(len + 1);
                let n = 1 + self.below(256);
                let byte = [0x00, 0xFF, b'a', b'0', b' '][self.below(5)];
                b.splice(i..i, std::iter::repeat_n(byte, n));
            }
            // A range deleted.
            7 if len > 0 => {
                let i = self.below(len);
                let n = 1 + self.below((len - i).min(64));
                b.drain(i..i + n);
            }
            // A range repeated: a record, a key or a field twice.
            8 if len > 0 => {
                let i = self.below(len);
                let n = 1 + self.below((len - i).min(128));
                let copy = b[i..i + n].to_vec();
                let at = self.below(len + 1);
                b.splice(at..at, copy);
            }
            // A range written over with another part of the input.
            9 if len > 1 => {
                let from = self.below(len);
                let to = self.below(len);
                let n = 1 + self.below((len - from).min(len - to).min(64));
                b.copy_within(from..from + n, to);
            }
            // A number in text replaced with one at a limit.
            10 => {
                let number = NUMBERS[self.below(NUMBERS.len())];
                match digits(b, self.below(len + 1)) {
                    Some((i, n)) => {
                        b.splice(i..i + n, number.iter().copied());
                    }
                    None => {
                        let i = self.below(len + 1);
                        b.splice(i..i, number.iter().copied());
                    }
                }
            }
            // A token from `TOKENS` inserted.
            11 => {
                let token = TOKENS[self.below(TOKENS.len())];
                let i = self.below(len + 1);
                b.splice(i..i, token.iter().copied());
            }
            // A hex digit changed to another: hex text that stays hex.
            12 if len > 0 => {
                let i = self.below(len);
                if b[i].is_ascii_hexdigit() {
                    b[i] = b"0123456789abcdefABCDEF"[self.below(22)];
                } else {
                    b[i] ^= 0x20;
                }
            }
            // Cut short.
            13 => {
                let at = self.below(len + 1);
                b.truncate(at);
            }
            // Two bytes swapped.
            14 if len > 1 => {
                let i = self.below(len);
                let j = self.below(len);
                b.swap(i, j);
            }
            // A piece of another seed dropped in.
            15 => {
                let other = self.seed();
                if !other.is_empty() {
                    let from = self.below(other.len());
                    let n = 1 + self.below((other.len() - from).min(64));
                    let at = self.below(len + 1);
                    b.splice(at..at, other[from..from + n].iter().copied());
                }
            }
            _ => {
                let i = self.below(len + 1);
                b.insert(i, self.u64() as u8);
            }
        }
    }

    /// One value of a text changed, its shape kept: a digit, a hex digit in
    /// a hex string, or a number replaced with one at a limit.
    fn revalue(&mut self, b: &mut Vec<u8>) {
        let len = b.len();
        if len == 0 {
            return;
        }
        let from = self.below(len);
        match self.below(3) {
            0 => {
                if let Some((i, n)) = digits(b, from) {
                    let k = i + self.below(n);
                    b[k] = b'0' + self.below(10) as u8;
                }
            }
            1 => {
                if let Some((i, n)) = hex_run(b, from) {
                    let k = i + self.below(n);
                    b[k] = b"0123456789abcdef"[self.below(16)];
                }
            }
            _ => {
                if let Some((i, n)) = digits(b, from) {
                    let number = NUMBERS[self.below(NUMBERS.len())];
                    b.splice(i..i + n, number.iter().copied());
                }
            }
        }
    }

    /// Bytes at random, half the time behind a seed's first few bytes to pass
    /// a magic or a tag.
    fn random(&mut self) -> Vec<u8> {
        let mut b = Vec::new();
        if self.below(2) == 0 {
            let s = self.seed();
            let keep = self.below(s.len().min(8) + 1);
            b.extend_from_slice(&s[..keep]);
        }
        let n = self.below(self.longest + 17);
        b.extend((0..n).map(|_| self.u64() as u8));
        b
    }
}

/// Whether `b` is text: printable ASCII, spaces and line breaks.
fn text(b: &[u8]) -> bool {
    !b.is_empty()
        && b.iter()
            .all(|&c| c.is_ascii_graphic() || c == b' ' || c == b'\n' || c == b'\r' || c == b'\t')
}

/// Hex strings shorter than this are words (`fee`, `cafe`), not values.
const HEX_RUN: usize = 8;

/// Numbers each run of digits is replaced with in [`values`], taken in turn
/// from [`NUMBERS`], so a long text meets them all without a variant for
/// every pair.
const PER_NUMBER: usize = 6;

/// A text's values changed one at a time: each run of digits replaced with
/// numbers at a limit, each long hex string emptied, cut by a byte and by a
/// character, and doubled.
fn values(b: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut numbers = 0;
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_hexdigit() && (i == 0 || !b[i - 1].is_ascii_alphanumeric()) {
            let n = b[i..].iter().take_while(|c| c.is_ascii_hexdigit()).count();
            let ends = b.get(i + n).is_none_or(|c| !c.is_ascii_alphanumeric());
            if ends && n >= HEX_RUN {
                let run = &b[i..i + n];
                let mut doubled = run.to_vec();
                doubled.extend_from_slice(run);
                for new in [&[][..], &run[..n - 2], &run[..n - 1], &doubled[..]] {
                    let mut v = b[..i].to_vec();
                    v.extend_from_slice(new);
                    v.extend_from_slice(&b[i + n..]);
                    out.push(v);
                }
            }
            if ends && b[i..i + n].iter().all(u8::is_ascii_digit) {
                for k in 0..PER_NUMBER {
                    let number = NUMBERS[(numbers * PER_NUMBER + k) % NUMBERS.len()];
                    let mut v = b[..i].to_vec();
                    v.extend_from_slice(number);
                    v.extend_from_slice(&b[i + n..]);
                    out.push(v);
                }
                numbers += 1;
            }
            i += n;
        } else {
            i += 1;
        }
    }
    out
}

/// The hex string of at least [`HEX_RUN`] characters found first from
/// `from`, wrapping round: its start and length.
fn hex_run(b: &[u8], from: usize) -> Option<(usize, usize)> {
    let len = b.len();
    let mut k = 0;
    while k < len {
        let i = (from + k) % len;
        if b[i].is_ascii_hexdigit() && (i == 0 || !b[i - 1].is_ascii_hexdigit()) {
            let n = b[i..].iter().take_while(|c| c.is_ascii_hexdigit()).count();
            if n >= HEX_RUN {
                return Some((i, n));
            }
        }
        k += 1;
    }
    None
}

/// The run of ASCII digits found first from `from`, wrapping round: its start
/// and length.
fn digits(b: &[u8], from: usize) -> Option<(usize, usize)> {
    let len = b.len();
    (0..len)
        .map(|k| (from + k) % len)
        .find(|&i| b[i].is_ascii_digit())
        .map(|i| {
            let start = (0..=i)
                .rev()
                .take_while(|&j| b[j].is_ascii_digit())
                .last()
                .unwrap_or(i);
            let end = (i..len)
                .take_while(|&j| b[j].is_ascii_digit())
                .last()
                .unwrap_or(i);
            (start, end + 1 - start)
        })
}

fn var(name: &str) -> Option<u64> {
    std::env::var(name).ok()?.parse().ok()
}

/// FNV-1a, to give each target its own start from the same seed.
fn fnv(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xCBF2_9CE4_8422_2325, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01B3)
    })
}

fn message(e: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = e.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = e.downcast_ref::<String>() {
        s.clone()
    } else {
        "a panic".to_string()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
