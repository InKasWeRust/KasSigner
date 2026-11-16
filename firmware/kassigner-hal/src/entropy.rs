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

//! The entropy source.
//!
//! A signer with a dead entropy source is broken, not degraded, which is why
//! `kassigner_crypto::sign` takes its auxiliary randomness with no default.
//!
//! A trait, not a registered global: a caller holds the source it draws, and
//! a test can supply one that is dead, stuck or biased and check that the
//! code above refuses rather than carries on.
//!
//! # What an implementor must guarantee
//!
//! Fill the whole buffer or return an error: never part of it, never bytes
//! it does not trust. Never substitute a weaker source when the primary
//! fails: a timer and a serial number are no basis for a signing nonce, and
//! something plausible is how a degraded source goes unnoticed.
//!
//! Test the draw before returning it, so a source that has stopped is
//! detected, not hashed: thirty-two zero words from an RNG read at the
//! wrong address hash to a respectable-looking digest. The tests are the
//! implementor's obligation, not something each caller might remember.
//!
//! # Sources are raw; [`crate::drbg`] conditions
//!
//! A board's source returns what the hardware produced, tested but not
//! conditioned: a hash is what lets a dead source pass for a live one, so a
//! source tests and does nothing else.
//!
//! The health tests say a source has not stopped and is not stuck, not how
//! much entropy it carries. The balance band is wide, so a source alive but
//! biased passes, and a biased byte harms an ECIES ephemeral scalar or a GCM
//! nonce that must never repeat (BIP340's `aux_rand` is hashed by the
//! specification and does not care).
//!
//! So the flow draws from [`crate::drbg::Drbg`] wrapped around the source,
//! built at every board's bring-up and itself an [`Entropy`]. The source's
//! tests stay between the hardware and the seed, so a stopped source still
//! poisons the generator; the output is uniform whatever the source's bias,
//! and forgets its past block by block.
//!
//! The seed pool in `kassigner-fw` credits the generator nothing: a seed's
//! entropy is counted from the camera, the motion sensor, the touches and
//! the dice.

/// Why a draw failed. Coarse on purpose: the only correct response to
/// either is to refuse whatever needed the randomness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No source: on a device, the hardware is absent or was not started.
    /// A configuration fault, not a transient one.
    Unavailable,
    /// The draw failed the source's health test: a source can be present,
    /// answer promptly, and be dead.
    Unhealthy,
}

/// A source of random bytes.
pub trait Entropy {
    /// Fill `out` entirely, or fail.
    ///
    /// # Errors
    ///
    /// `Unavailable` if there is no source, `Unhealthy` if the draw failed
    /// its health test. Either leaves `out` zeroed, so a caller that ignores
    /// the result has nothing that looks like randomness.
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error>;

    /// Draw the 32 bytes of auxiliary randomness a BIP340 signature needs.
    ///
    /// `kassigner_crypto::sign` takes `aux` with no default: a signer that
    /// quietly falls back to a deterministic nonce is the differential-fault
    /// case.
    ///
    /// # Errors
    ///
    /// As [`Entropy::fill`].
    fn aux(&mut self) -> Result<[u8; 32], Error> {
        let mut out = [0u8; 32];
        self.fill(&mut out)?;
        Ok(out)
    }
}

/// Health tests an implementor can use on a window of drawn words, offered
/// because they are easy to get wrong. Each returns `true` when the window
/// looks alive.
pub mod health {
    /// No two consecutive words identical: for a live 32-bit source a repeat
    /// is a 2^-32 event per pair, so one means the source stalled.
    pub fn no_repeats(words: &[u32]) -> bool {
        !words.windows(2).any(|w| w[0] == w[1])
    }

    /// Every word distinct: catches a stuck pattern with a period longer
    /// than one, which [`no_repeats`] misses.
    pub fn all_distinct(words: &[u32]) -> bool {
        words
            .iter()
            .enumerate()
            .all(|(i, w)| !words[..i].contains(w))
    }

    /// No bit position constant across the window: for a live source each is
    /// a fair coin per word, so one constant over 32 words is a 2^-31 event.
    ///
    /// Catches a counter, such as a timer read in place of a dead register.
    /// [`no_repeats`], [`all_distinct`] and [`balanced`] detect a stuck or
    /// dead source, not structure, and a counter can pass all three, but its
    /// bits below its stride and above its range never move.
    pub fn no_stuck_bits(words: &[u32]) -> bool {
        if words.is_empty() {
            return false;
        }
        let first = words[0];
        let mut constant: u32 = u32::MAX;
        for w in words {
            constant &= !(w ^ first);
        }
        constant == 0
    }

    /// Steps do not nearly all go one way: the other half of catching a
    /// counter. A window with one reversal still fails, so a counter that
    /// wraps inside it is caught.
    ///
    /// Under five words passes, too short to judge: three or four words
    /// cannot give two steps each way. The S3s' windows are 32 words.
    pub fn not_monotonic(words: &[u32]) -> bool {
        if words.len() < 5 {
            return true;
        }
        let ups = words.windows(2).filter(|w| w[1] > w[0]).count();
        let steps = words.len() - 1;
        ups + 1 < steps && ups > 1
    }

    /// Set bits within 30% to 70%: wide on purpose, a "has the source died"
    /// test, not a randomness test. A window this small says nothing about
    /// quality, and a narrow band gives false alarms on healthy hardware
    /// (256-sample windows measured 49.6% to 50.6% on real devices).
    pub fn balanced(words: &[u32]) -> bool {
        if words.is_empty() {
            return false;
        }
        let ones: u32 = words.iter().map(|w| w.count_ones()).sum();
        let total = words.len() as u32 * 32;
        let low = total * 30 / 100;
        let high = total * 70 / 100;
        (low..=high).contains(&ones)
    }

    /// Every test above.
    pub fn all(words: &[u32]) -> bool {
        no_repeats(words)
            && all_distinct(words)
            && no_stuck_bits(words)
            && not_monotonic(words)
            && balanced(words)
    }
}
