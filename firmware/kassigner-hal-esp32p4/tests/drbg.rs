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

//! Host tests of the P4's health wrapper and of the generator seeded through
//! it. The generator itself is tested in `kassigner-hal`'s `tests/drbg.rs`.

use kassigner_hal::drbg::generator::{RESEED_INTERVAL, SEED_BYTES};
use kassigner_hal_esp32p4::drbg::{
    health::{Guarded, HealthError, APT_CUTOFF, RCT_CUTOFF, STARTUP_SAMPLES},
    Drbg, DrbgError, Entropy,
};

// ---------------------------------------------------------------------------
// Mock sources

/// Deterministic but well-distributed: xorshift32. Enough to pass RCT/APT.
struct Xorshift(u32);
impl Entropy for Xorshift {
    type Error = ();
    fn sample(&mut self) -> Result<u32, ()> {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.0 = x;
        Ok(x)
    }
}

/// Good for `good` samples, then stuck on one value forever.
struct Dies {
    inner: Xorshift,
    good: u32,
}
impl Entropy for Dies {
    type Error = ();
    fn sample(&mut self) -> Result<u32, ()> {
        if self.good > 0 {
            self.good -= 1;
            self.inner.sample()
        } else {
            Ok(0x5A5A_5A5A)
        }
    }
}

/// Good for `good` samples, then returns Err.
struct Errs {
    inner: Xorshift,
    good: u32,
}
impl Entropy for Errs {
    type Error = ();
    fn sample(&mut self) -> Result<u32, ()> {
        if self.good > 0 {
            self.good -= 1;
            self.inner.sample()
        } else {
            Err(())
        }
    }
}

/// Never repeats consecutively, but one byte value appears far too often.
struct Skewed {
    n: u32,
}
impl Entropy for Skewed {
    type Error = ();
    fn sample(&mut self) -> Result<u32, ()> {
        self.n = self.n.wrapping_add(1);
        // bytes: 0x11, k, 0x11, k+1 ... alternating so RCT never trips.
        let k = (self.n & 0xff) as u8;
        let k2 = k.wrapping_add(1);
        Ok(u32::from_le_bytes([0x11, k, 0x11, k2]))
    }
}

// ---------------------------------------------------------------------------
// Health tests

#[test]
fn startup_consumes_1024_bytes() {
    let mut g = Guarded::new(Xorshift(1));
    g.startup().unwrap();
    assert_eq!(g.total(), STARTUP_SAMPLES);
}

#[test]
fn rct_trips_on_stuck_source() {
    let mut g = Guarded::new(Dies {
        inner: Xorshift(1),
        good: 10,
    });
    g.startup().unwrap_err();
    assert_eq!(g.poisoned(), Some(HealthError::Repetition));
}

#[test]
fn rct_cutoff_is_exact() {
    // A byte repeated RCT_CUTOFF-1 times must pass; RCT_CUTOFF must fail.
    struct Rep(u32, u32);
    impl Entropy for Rep {
        type Error = ();
        fn sample(&mut self) -> Result<u32, ()> {
            // Emit `self.1` copies of 0xAA one byte at a time, then varied.
            let mut b = [0u8; 4];
            for x in &mut b {
                if self.0 < self.1 {
                    *x = 0xAA;
                    self.0 += 1;
                } else {
                    self.0 += 1;
                    *x = (self.0 * 37).to_le_bytes()[0]; // varied, never 0xAA twice
                }
            }
            Ok(u32::from_le_bytes(b))
        }
    }
    let mut g = Guarded::new(Rep(0, RCT_CUTOFF - 1));
    for _ in 0..64 {
        g.next_byte().unwrap();
    }
    let mut g = Guarded::new(Rep(0, RCT_CUTOFF));
    let r = (0..64).map(|_| g.next_byte()).find(Result::is_err);
    assert_eq!(r, Some(Err(HealthError::Repetition)));
}

#[test]
fn apt_trips_on_skewed_source() {
    let mut g = Guarded::new(Skewed { n: 0 });
    let r = g.startup();
    assert_eq!(r, Err(HealthError::Proportion));
    // 0x11 is every other byte, so it hits APT_CUTOFF well inside a window.
    assert!(g.total() < 2 * APT_CUTOFF + 2);
}

/// The APT cutoff is SP 800-90B's formula at the measured entropy:
/// `1 + CRITBINOM(512, 2^-7.26, 1 - 2^-20)`, the smallest count whose
/// binomial tail is under alpha, plus the reference sample itself. Worked
/// out here in floating point, term by term.
#[test]
fn apt_cutoff_is_the_standards_formula_at_the_measured_entropy() {
    const H: f64 = 7.26;
    const W: u32 = 512;
    let p = (-H).exp2();
    let alpha = (-20f64).exp2();
    let (mut term, mut sum, mut c) = ((1.0 - p).powi(W as i32), 0.0, 0u32);
    loop {
        sum += term;
        if sum >= 1.0 - alpha {
            break;
        }
        term *= f64::from(W - c) / f64::from(c + 1) * p / (1.0 - p);
        c += 1;
    }
    assert_eq!(APT_CUTOFF, 1 + c);
    assert_eq!(APT_CUTOFF, 16);
}

#[test]
fn apt_cutoff_is_exact() {
    // The window's first byte, 0xAA, is the reference. It comes `again` more
    // times, on every other byte so RCT never trips; the rest of the window
    // varies and is never 0xAA.
    struct Prop {
        n: u32,
        again: u32,
    }
    impl Entropy for Prop {
        type Error = ();
        fn sample(&mut self) -> Result<u32, ()> {
            let mut b = [0u8; 4];
            for x in &mut b {
                let i = self.n;
                self.n += 1;
                *x = if i == 0 || (i.is_multiple_of(2) && i / 2 <= self.again) {
                    0xAA
                } else {
                    // 1..=0xA9 and back: never 0xAA, never twice running.
                    (i % 0xA9 + 1) as u8
                };
            }
            Ok(u32::from_le_bytes(b))
        }
    }
    // One short of the cutoff passes the whole window.
    let mut g = Guarded::new(Prop {
        n: 0,
        again: APT_CUTOFF - 2,
    });
    for _ in 0..512 {
        g.next_byte().unwrap();
    }
    // At the cutoff it fails, on the byte that reaches it.
    let mut g = Guarded::new(Prop {
        n: 0,
        again: APT_CUTOFF - 1,
    });
    let r = (0..512).map(|_| g.next_byte()).position(|r| r.is_err());
    assert_eq!(r, Some(2 * (APT_CUTOFF as usize - 1)));
    assert_eq!(g.poisoned(), Some(HealthError::Proportion));
}

#[test]
fn source_error_poisons() {
    let mut g = Guarded::new(Errs {
        inner: Xorshift(1),
        good: 5,
    });
    assert_eq!(g.startup(), Err(HealthError::Source));
    assert_eq!(g.next_byte(), Err(HealthError::Source));
}

#[test]
fn poison_is_sticky() {
    let mut g = Guarded::new(Dies {
        inner: Xorshift(1),
        good: 10,
    });
    let _ = g.startup();
    for _ in 0..10 {
        assert!(g.next_byte().is_err());
    }
}

// ---------------------------------------------------------------------------
// DRBG

/// The generator seeded through the health wrapper, as `unit::bring_up`
/// builds it: the start-up test first, then the seed.
fn seeded<E: Entropy>(source: E) -> Drbg<Guarded<E>> {
    let mut g = Guarded::new(source);
    g.startup().unwrap();
    let d = Drbg::new(g).unwrap();
    assert_eq!(d.poisoned(), None);
    d
}

#[test]
fn drbg_seeds_through_the_health_wrapper() {
    let mut d = seeded(Xorshift(0xdead_beef));
    let mut a = [0u8; 64];
    let mut b = [0u8; 64];
    d.fill(&mut a).unwrap();
    d.fill(&mut b).unwrap();
    assert_ne!(a, b);
    assert!(a.iter().any(|&x| x != 0));
    assert_eq!(
        d.source().total(),
        STARTUP_SAMPLES + SEED_BYTES as u32,
        "two fills of the generator draw nothing more from the source"
    );
}

/// A source that dies past the start-up test and the first seed poisons the
/// generator at the automatic reseed, through the wrapper's verdict.
#[test]
fn drbg_poisons_when_source_dies_at_reseed() {
    let good_words = (STARTUP_SAMPLES + SEED_BYTES as u32) / 4 + 1;
    let mut d = seeded(Dies {
        inner: Xorshift(9),
        good: good_words,
    });
    let mut buf = [0u8; RESEED_INTERVAL as usize + 1];
    let r = d.fill(&mut buf);
    assert_eq!(
        r,
        Err(DrbgError::Source(kassigner_hal::entropy::Error::Unhealthy)),
        "{r:?}"
    );
    assert_eq!(d.source().poisoned(), Some(HealthError::Repetition));
    // And it stays dead: no more bytes, and the buffer is zeroed.
    let mut again = [0xFFu8; 16];
    assert!(d.fill(&mut again).is_err());
    assert_eq!(again, [0u8; 16]);
}

/// A source that errors is `Unavailable` to the generator; a source whose
/// tests trip is `Unhealthy`. What the flow sees is the wrapper's verdict.
#[test]
fn the_wrapper_reports_as_the_hal_trait_asks() {
    use kassigner_hal::entropy::{Entropy as Hal, Error};

    let mut g = Guarded::new(Errs {
        inner: Xorshift(1),
        good: 0,
    });
    let mut out = [0xFFu8; 8];
    assert_eq!(Hal::fill(&mut g, &mut out), Err(Error::Unavailable));
    assert_eq!(out, [0u8; 8], "nothing partial is handed over");

    let mut g = Guarded::new(Dies {
        inner: Xorshift(1),
        good: 10,
    });
    let _ = g.startup();
    let mut out = [0xFFu8; 8];
    assert_eq!(Hal::fill(&mut g, &mut out), Err(Error::Unhealthy));
    assert_eq!(out, [0u8; 8]);
}
