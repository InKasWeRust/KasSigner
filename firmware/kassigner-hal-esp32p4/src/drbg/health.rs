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

//! SP 800-90B section 4.4 continuous health tests.
//!
//! The standard requires two tests to run **continuously on the device**
//! over every sample the DRBG consumes, as a source assessed well offline
//! can still fail in the field: a cold ADC, a clobbered LDO, a dead REGI2C
//! write.
//!
//! * **Repetition Count Test (RCT)** catches a stuck source: it fails when
//!   the same byte comes `C` times in a row.
//! * **Adaptive Proportion Test (APT)** catches a collapsed distribution: it
//!   fails when a window's first byte occurs `C` times among the window's
//!   `W = 512` bytes.
//!
//! ## Cutoffs
//!
//! Both follow the standard's formulae at `alpha = 2^-20` and `H = 7.26`
//! bits per 8-bit sample: 7.269, assessed at the generator's read gap,
//! rounded down. A later assessment with ESP-IDF's analog start-up
//! (`entropy`) gave 7.31; the lower figure stays, and both give the same
//! cutoffs. The tests run per byte, the unit the assessments measured.
//!
//! ```text
//! RCT: C = 1 + ceil(20 / H)                          = 1 + ceil(2.75) = 4
//! APT: C = 1 + CRITBINOM(W, 2^-H, 1 - alpha), W = 512                 = 16
//! ```
//!
//! The APT cutoff is the formula at H itself, as `tests/drbg.rs` checks; H
//! rounded down to 7 would give 18, which detects less. At H = 7.26 a
//! window expects the reference byte about 3.3 times, and a source that
//! good still reaches 16 about once in 2^19 windows. A boot checks two or
//! three windows, so a sound unit started ten times a day refuses its
//! generator by chance about once in forty years; a reset clears it. H = 8
//! would give 13, too close to that tail: about twice a year. If a new
//! assessment changes H, recompute both.
//!
//! ## What a failure means
//!
//! [`Guarded`] does not retry: the first failure poisons the source for this
//! boot, the DRBG above it refuses to reseed, and its own poison then
//! refuses to generate. Only a reset, re-running the entropy bring-up and
//! the start-up test, recovers.

use crate::drbg::Entropy;

/// RCT cutoff. See module docs.
pub const RCT_CUTOFF: u32 = 4;
/// APT window, from the standard.
pub const APT_WINDOW: u32 = 512;
/// APT cutoff. See module docs.
pub const APT_CUTOFF: u32 = 16;

/// Samples the start-up test runs through both tests before the source is
/// trusted: the standard's minimum before the first output is used.
pub const STARTUP_SAMPLES: u32 = 1024;

/// Why the source was poisoned.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HealthError {
    /// The underlying source returned an error.
    Source,
    /// A byte value came [`RCT_CUTOFF`] times in a row.
    Repetition,
    /// A window's first byte occurred [`APT_CUTOFF`] times in the window.
    Proportion,
}

/// An [`Entropy`] source wrapped in the two continuous tests.
pub struct Guarded<E: Entropy> {
    inner: E,
    poisoned: Option<HealthError>,
    // RCT state
    rct_last: u8,
    rct_count: u32,
    // APT state
    apt_ref: u8,
    apt_count: u32,
    apt_seen: u32,
    // Bytes not yet handed out from the last 32-bit sample.
    pending: [u8; 4],
    pending_len: u8,
    total: u32,
}

impl<E: Entropy> Guarded<E> {
    /// Wrap `inner`. Call [`startup`](Self::startup) before drawing.
    pub fn new(inner: E) -> Self {
        Self {
            inner,
            poisoned: None,
            rct_last: 0,
            rct_count: 0,
            apt_ref: 0,
            apt_count: 0,
            apt_seen: 0,
            pending: [0; 4],
            pending_len: 0,
            total: 0,
        }
    }

    /// Run [`STARTUP_SAMPLES`] bytes through both tests and discard them.
    ///
    /// The first conversions after a cold start are the least trustworthy,
    /// so this doubles as the ADC warm-up, with every read checked.
    ///
    /// # Errors
    /// The first health-test failure; the source is then poisoned.
    pub fn startup(&mut self) -> Result<(), HealthError> {
        for _ in 0..STARTUP_SAMPLES {
            self.next_byte()?;
        }
        Ok(())
    }

    /// Has this source failed a test? Sticky.
    pub fn poisoned(&self) -> Option<HealthError> {
        self.poisoned
    }

    /// Bytes checked so far, including startup.
    pub fn total(&self) -> u32 {
        self.total
    }

    fn poison(&mut self, e: HealthError) -> HealthError {
        if self.poisoned.is_none() {
            self.poisoned = Some(e);
        }
        e
    }

    /// One tested byte.
    ///
    /// # Errors
    /// The poisoning reason, on this call or any earlier one.
    pub fn next_byte(&mut self) -> Result<u8, HealthError> {
        if let Some(e) = self.poisoned {
            return Err(e);
        }
        if self.pending_len == 0 {
            let Ok(w) = self.inner.sample() else {
                return Err(self.poison(HealthError::Source));
            };
            self.pending = w.to_le_bytes();
            self.pending_len = 4;
        }
        self.pending_len -= 1;
        let b = self.pending[3 - self.pending_len as usize];
        self.check(b)?;
        Ok(b)
    }

    /// Fill `dst` with tested bytes.
    ///
    /// # Errors
    /// As [`next_byte`](Self::next_byte).
    pub fn fill(&mut self, dst: &mut [u8]) -> Result<(), HealthError> {
        for d in dst.iter_mut() {
            *d = self.next_byte()?;
        }
        Ok(())
    }

    fn check(&mut self, b: u8) -> Result<(), HealthError> {
        self.total = self.total.wrapping_add(1);

        // ---- RCT ---------------------------------------------------------
        if self.total == 1 {
            self.rct_last = b;
            self.rct_count = 1;
        } else if b == self.rct_last {
            self.rct_count += 1;
            if self.rct_count >= RCT_CUTOFF {
                return Err(self.poison(HealthError::Repetition));
            }
        } else {
            self.rct_last = b;
            self.rct_count = 1;
        }

        // ---- APT ---------------------------------------------------------
        if self.apt_seen == 0 {
            // First sample of a window becomes the reference.
            self.apt_ref = b;
            self.apt_count = 1;
            self.apt_seen = 1;
        } else {
            self.apt_seen += 1;
            if b == self.apt_ref {
                self.apt_count += 1;
                if self.apt_count >= APT_CUTOFF {
                    return Err(self.poison(HealthError::Proportion));
                }
            }
            if self.apt_seen >= APT_WINDOW {
                self.apt_seen = 0;
            }
        }
        Ok(())
    }

    /// Access the wrapped source, e.g. to read hardware status registers.
    pub fn inner(&mut self) -> &mut E {
        &mut self.inner
    }
}

/// Wipes the raw source bytes held here, as every entropy buffer is wiped:
/// the last sample's four bytes (up to three not yet handed out), and the
/// last byte and the window's reference the tests keep.
impl<E: Entropy> Drop for Guarded<E> {
    fn drop(&mut self) {
        for b in self
            .pending
            .iter_mut()
            .chain([&mut self.rct_last, &mut self.apt_ref])
        {
            // SAFETY: `b` is a `&mut u8` into this value, valid and aligned;
            // volatile so the store is not dropped as dead.
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        self.pending_len = 0;
    }
}

/// The tested source as `kassigner-hal` sees it: what the generator seeds
/// from, and what the entropy capture reads under the generator. Tested
/// and raw, as that trait requires; conditioning is the generator's.
///
/// A failed sample is `Unavailable`; a tripped test, or the poison from one,
/// is `Unhealthy`. Either zeroes the buffer, as [`Guarded::fill`] stops at
/// the failing byte.
impl<E: Entropy> kassigner_hal::entropy::Entropy for Guarded<E> {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), kassigner_hal::entropy::Error> {
        match Guarded::fill(self, out) {
            Ok(()) => Ok(()),
            Err(e) => {
                out.fill(0);
                Err(match e {
                    HealthError::Source => kassigner_hal::entropy::Error::Unavailable,
                    HealthError::Repetition | HealthError::Proportion => {
                        kassigner_hal::entropy::Error::Unhealthy
                    }
                })
            }
        }
    }
}
