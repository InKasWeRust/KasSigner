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

//! The generator on the host, over sources built to fail in set ways: what
//! it does with a source that passes and with one that stops.
//! `tests/entropy.rs` covers what a board's source must reject.

use kassigner_hal::drbg::chacha20::{self, ChaCha20, BLOCK};
use kassigner_hal::drbg::generator::{DOMAIN, KEY, OUT, RESEED_INTERVAL, SEED_BYTES};
use kassigner_hal::drbg::{Drbg, DrbgError};
use kassigner_hal::entropy::{Entropy, Error};
use sha2::{Digest, Sha256};

/// Xorshift32, deterministic but well distributed, a word at a time as a
/// board's source hands words over.
struct Xorshift(u32);

impl Xorshift {
    fn word(&mut self) -> u32 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.0 = x;
        x
    }
}

impl Entropy for Xorshift {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        for chunk in out.chunks_mut(4) {
            let w = self.word().to_le_bytes();
            chunk.copy_from_slice(&w[..chunk.len()]);
        }
        Ok(())
    }
}

/// Good for `good` fills, then what a board's source reports when its tests
/// trip: `Unhealthy`, the buffer zeroed.
struct Dies {
    inner: Xorshift,
    good: u32,
}

impl Entropy for Dies {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        if self.good > 0 {
            self.good -= 1;
            self.inner.fill(out)
        } else {
            out.fill(0);
            Err(Error::Unhealthy)
        }
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

/// A source that answers, with every bit set.
struct AllOnes;

impl Entropy for AllOnes {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        out.fill(0xFF);
        Ok(())
    }
}

#[test]
fn chacha20_rfc8439_vector() {
    assert!(chacha20::known_answer());
}

#[test]
fn chacha20_counter_advances() {
    let mut c = ChaCha20::new(&[7u8; 32]);
    let mut a = [0u8; 64];
    let mut b = [0u8; 64];
    c.block(&mut a);
    c.block(&mut b);
    assert_ne!(a, b);
}

#[test]
fn drbg_seeds_and_generates() {
    let mut d = Drbg::new(Xorshift(0xdead_beef)).unwrap();
    assert_eq!(d.poisoned(), None);
    let mut a = [0u8; 64];
    let mut b = [0u8; 64];
    d.fill(&mut a).unwrap();
    d.fill(&mut b).unwrap();
    assert_ne!(a, b);
    assert!(a.iter().any(|&x| x != 0));
}

#[test]
fn drbg_reseed_changes_stream() {
    let mut d = Drbg::new(Xorshift(42)).unwrap();
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    d.fill(&mut a).unwrap();
    d.reseed_now().unwrap();
    d.fill(&mut b).unwrap();
    assert_ne!(a, b);
}

#[test]
fn drbg_different_seeds_differ() {
    let mut d1 = Drbg::new(Xorshift(1)).unwrap();
    let mut d2 = Drbg::new(Xorshift(2)).unwrap();
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    d1.fill(&mut a).unwrap();
    d2.fill(&mut b).unwrap();
    assert_ne!(a, b);
}

/// A source that dies after the first seed poisons the generator at the
/// automatic reseed, and the poison is the source's verdict.
#[test]
fn drbg_poisons_when_source_dies_at_reseed() {
    let mut d = Drbg::new(Dies {
        inner: Xorshift(9),
        good: 1,
    })
    .unwrap();
    assert_eq!(d.poisoned(), None);
    let mut buf = [0u8; RESEED_INTERVAL as usize + 1];
    let r = d.fill(&mut buf);
    assert_eq!(r, Err(DrbgError::Source(Error::Unhealthy)));
    assert_eq!(d.poisoned(), Some(DrbgError::Source(Error::Unhealthy)));
    // Nothing from the failing call either: what it wrote before the reseed
    // is zeroed.
    assert!(buf.iter().all(|&b| b == 0), "output zeroed on the failure");
    // And it stays dead: no more bytes, and the buffer is zeroed.
    let mut again = [0xFFu8; 16];
    assert_eq!(d.fill(&mut again), Err(DrbgError::Source(Error::Unhealthy)));
    assert_eq!(again, [0u8; 16]);
}

/// **One long call reseeds at every interval, not only at its end.** A
/// source good for two seeds, the first and one reseed, dies at the second
/// reseed that a call of two intervals and a byte needs.
#[test]
fn drbg_reseeds_inside_a_long_call() {
    let mut d = Drbg::new(Dies {
        inner: Xorshift(9),
        good: 2,
    })
    .unwrap();
    let mut buf = [0u8; 2 * RESEED_INTERVAL as usize + 1];
    assert_eq!(d.fill(&mut buf), Err(DrbgError::Source(Error::Unhealthy)));
    assert!(buf.iter().all(|&b| b == 0), "output zeroed on the failure");

    // One interval in a call is one reseed, at its end.
    let mut d = Drbg::new(Dies {
        inner: Xorshift(9),
        good: 2,
    })
    .unwrap();
    let mut one = [0u8; RESEED_INTERVAL as usize];
    assert!(d.fill(&mut one).is_ok());
}

/// A source that refuses the first seed gives a generator that exists and
/// refuses, so a board can hold it and fail closed.
#[test]
fn drbg_over_a_dead_source_is_born_poisoned() {
    let mut d = Drbg::new(Absent).unwrap();
    assert_eq!(d.poisoned(), Some(DrbgError::Source(Error::Unavailable)));
    let mut out = [0xFFu8; 8];
    assert_eq!(d.fill(&mut out), Err(DrbgError::Source(Error::Unavailable)));
    assert_eq!(out, [0u8; 8]);
    assert_eq!(d.reseed_now(), Err(DrbgError::Source(Error::Unavailable)));

    let mut d = Drbg::new(AllOnes).unwrap();
    assert_eq!(d.poisoned(), Some(DrbgError::SeedDegenerate));
    assert!(d.next_u32().is_err());
}

/// The generator is an [`Entropy`] to the flow, failing with `Unavailable`
/// for no source and `Unhealthy` for a source that tripped its tests or a
/// degenerate seed; `aux` refuses like `fill`.
#[test]
fn drbg_is_an_entropy_source_to_the_flow() {
    fn draw<E: Entropy>(e: &mut E) -> Result<[u8; 32], Error> {
        e.aux()
    }

    let mut live = Drbg::new(Xorshift(5)).unwrap();
    let a = draw(&mut live).unwrap();
    let b = draw(&mut live).unwrap();
    assert_ne!(a, b);

    assert_eq!(
        draw(&mut Drbg::new(Absent).unwrap()),
        Err(Error::Unavailable)
    );
    assert_eq!(
        draw(&mut Drbg::new(AllOnes).unwrap()),
        Err(Error::Unhealthy)
    );
    let mut dies = Drbg::new(Dies {
        inner: Xorshift(9),
        good: 1,
    })
    .unwrap();
    let mut past = [0u8; RESEED_INTERVAL as usize + 1];
    assert!(Entropy::fill(&mut dies, &mut past).is_err());
    assert_eq!(draw(&mut dies), Err(Error::Unhealthy));
}

#[test]
fn drbg_next_u64_uses_8_bytes() {
    let mut d = Drbg::new(Xorshift(3)).unwrap();
    let a = d.next_u64().unwrap();
    let b = d.next_u64().unwrap();
    assert_ne!(a, b);
}

#[test]
fn drbg_output_is_balanced() {
    // Gross-breakage check only; ChaCha20 would pass this from any seed.
    let mut d = Drbg::new(Xorshift(77)).unwrap();
    let mut buf = [0u8; 4096];
    d.fill(&mut buf).unwrap();
    let ones: u32 = buf.iter().map(|b| b.count_ones()).sum();
    let pct = ones * 100 / (4096 * 8);
    assert!((45..=55).contains(&pct), "ones = {pct}%");
    let mut seen = [false; 256];
    for &b in &buf {
        seen[b as usize] = true;
    }
    assert!(seen.iter().all(|&s| s));
}

/// The raw source stays reachable underneath, for the entropy capture.
#[test]
fn the_source_is_reachable_beneath_the_generator() {
    let mut d = Drbg::new(Xorshift(11)).unwrap();
    let mut shadow = Xorshift(11);
    let mut skip = [0u8; SEED_BYTES];
    shadow.fill(&mut skip).unwrap();
    let mut from_source = [0u8; 16];
    let mut from_shadow = [0u8; 16];
    d.source().fill(&mut from_source).unwrap();
    shadow.fill(&mut from_shadow).unwrap();
    assert_eq!(
        from_source, from_shadow,
        "the words the board produced, unconditioned"
    );
}

/// The key a seeding makes: SHA-256 over the domain tag, the carry and the
/// raw seed.
fn conditioned(carry: &[u8], raw: &[u8]) -> [u8; KEY] {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(carry);
    h.update(raw);
    h.finalize().into()
}

/// A block under `key`, split as the generator splits it: the next key,
/// then the output.
fn step(key: &[u8; KEY]) -> ([u8; KEY], [u8; OUT]) {
    let mut block = [0u8; BLOCK];
    ChaCha20::new(key).block(&mut block);
    let mut next = [0u8; KEY];
    let mut out = [0u8; OUT];
    next.copy_from_slice(&block[..KEY]);
    out.copy_from_slice(&block[KEY..]);
    (next, out)
}

/// **The generator is exactly its documented construction**, recomputed
/// from the RFC-checked `ChaCha20` block and `sha2` over a second copy of
/// the source: the conditioned seed, each block split into next key and
/// output, and a reseed carrying a block of the old key into the new one.
#[test]
fn drbg_is_its_construction() {
    let mut d = Drbg::new(Xorshift(0x1234_5678)).unwrap();
    let mut raw_source = Xorshift(0x1234_5678);

    // First seeding: the cipher starts keyed with zeros, so the carry is the
    // first block of the all-zero key.
    let mut raw = [0u8; SEED_BYTES];
    raw_source.fill(&mut raw).unwrap();
    let (zero_carry, _) = step(&[0u8; KEY]);
    let mut key = conditioned(&zero_carry, &raw);

    // Three blocks of output, each from the key the one before it made.
    let mut want = [0u8; 3 * OUT];
    for chunk in want.chunks_exact_mut(OUT) {
        let (next, out) = step(&key);
        chunk.copy_from_slice(&out);
        key = next;
    }
    let mut got = [0u8; 3 * OUT];
    d.fill(&mut got).unwrap();
    assert_eq!(got, want, "seeding and fast key erasure");

    // A reseed: the carry is the next block under the current key; its
    // first 32 bytes go into the new key with the new seed.
    d.reseed_now().unwrap();
    raw_source.fill(&mut raw).unwrap();
    let (carry, _) = step(&key);
    let key = conditioned(&carry, &raw);
    let (_, want) = step(&key);
    let mut got = [0u8; OUT];
    d.fill(&mut got).unwrap();
    assert_eq!(got, want, "reseed carries the old key forward");
}
