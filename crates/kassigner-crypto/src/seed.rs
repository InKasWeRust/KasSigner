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

//! A seed from collected randomness, two ways. Its sources and how much is
//! enough are level 3's (`kassigner_fw::seed`); this is here because key
//! material passes through it.
//!
//! The pool: one SHA-256 under a domain tag absorbs every sample, framed by
//! its source tag and both lengths; the seed is the digest's first 16 or 32
//! bytes. The result is unpredictable if any one input was (a lying
//! generator cannot weaken a camera), and the framing keeps different inputs
//! from absorbing to the same bytes; XOR or sums give neither. An empty pool
//! is refused: it would hash to one fixed mnemonic.
//!
//! Dice: SHA-256 over the ASCII digits as typed, so anyone can reproduce
//! the seed with another tool. A roll is `log2(6)` = 2.585 bits: 50 rolls
//! carry 129 and 99 carry 255.9, the two floors.
//!
//! `sha2`'s hasher, with its `zeroize` feature, wipes state and buffered
//! input on drop, finished or abandoned (`tests/seed.rs` checks the type).
//! The digest is zeroized after use and the mnemonic wipes itself. A hasher
//! moved by value leaves its old bytes on the stack, for the seed flow's
//! scrub at level 3.

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::bip39::{self, Bip39Error, Mnemonic, ENTROPY_12, ENTROPY_24};

/// The domain tag every pool starts with.
pub const DOMAIN: &[u8] = b"kassigner/seed/v1";

/// Fewest rolls for twelve words: 129 bits by arithmetic.
pub const DICE_ROLLS_12: usize = 50;

/// Fewest rolls for twenty-four words: 255.9 bits by arithmetic.
pub const DICE_ROLLS_24: usize = 99;

/// A face seen no more than `rolls / DICE_RARE_FACE_DIVISOR` times (integer
/// division) is a degenerate sequence: at 99 rolls a face seen at most once,
/// at 50 a face never seen.
///
/// A refusal, so set where honest dice almost never land: a face at most
/// once in 99 fair rolls about twice in a million, absent from 50 about
/// seven times in ten thousand. It catches sequences never rolled (all
/// ones, `12345` repeated, a stuck key), not bias.
pub const DICE_RARE_FACE_DIVISOR: usize = 60;

/// The same face this many times in a row is a degenerate sequence: a fair
/// die does it in 99 rolls about eight times in a million.
pub const DICE_MAX_RUN: usize = 10;

/// How long a mnemonic to make.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Words {
    Twelve,
    TwentyFour,
}

impl Words {
    /// Bytes of entropy behind that many words.
    pub const fn entropy_len(self) -> usize {
        match self {
            Words::Twelve => ENTROPY_12,
            Words::TwentyFour => ENTROPY_24,
        }
    }

    /// Fewest dice rolls for that many words.
    pub const fn dice_rolls(self) -> usize {
        match self {
            Words::Twelve => DICE_ROLLS_12,
            Words::TwentyFour => DICE_ROLLS_24,
        }
    }
}

/// Why a seed was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeedError {
    /// Nothing was absorbed.
    Empty,
    /// A roll that is not `1` to `6`, at that position.
    BadRoll {
        position: usize,
    },
    /// Fewer rolls than the word count needs.
    TooFewRolls {
        have: usize,
        need: usize,
    },
    /// The rolls do not look like dice. See [`Degenerate`].
    Degenerate(Degenerate),
    Bip39(Bip39Error),
}

/// Why a roll sequence was refused as typed rather than rolled. An honest
/// roller who trips one rolls again; the alternative is a seed whose entropy
/// is that of a pattern.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Degenerate {
    /// `face` (`1` to `6`) was seen `count` times, under
    /// [`DICE_RARE_FACE_DIVISOR`]'s floor for this many rolls.
    RareFace { face: u8, count: usize },
    /// `face` repeated `length` times in a row, at or past [`DICE_MAX_RUN`].
    LongRun { face: u8, length: usize },
}

impl From<Bip39Error> for SeedError {
    fn from(e: Bip39Error) -> Self {
        SeedError::Bip39(e)
    }
}

/// Collected randomness on its way to becoming a seed. Wipes itself on
/// drop, finished or not: the running state is the seed in the making.
pub struct Pool {
    hasher: Sha256,
    samples: u32,
}

impl core::fmt::Debug for Pool {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Pool({} samples, redacted)", self.samples)
    }
}

impl Default for Pool {
    fn default() -> Self {
        Self::new()
    }
}

impl Pool {
    /// An empty pool, already carrying the domain tag.
    pub fn new() -> Self {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN);
        Self { hasher, samples: 0 }
    }

    /// Absorb one sample from one source.
    ///
    /// `tag` names the source, under 256 bytes. The tag's length, the tag,
    /// the sample's length and the sample go in, in that order. An empty
    /// sample counts as one.
    pub fn absorb(&mut self, tag: &[u8], bytes: &[u8]) {
        // A tag past 255 bytes is cut there, so its length byte stays true
        // and the framing holds whatever a caller passes.
        let tag = &tag[..tag.len().min(usize::from(u8::MAX))];
        let tag_len = u8::try_from(tag.len()).unwrap_or(u8::MAX);
        self.hasher.update([tag_len]);
        self.hasher.update(tag);
        self.hasher.update((bytes.len() as u32).to_le_bytes());
        self.hasher.update(bytes);
        self.samples = self.samples.saturating_add(1);
    }

    /// Samples absorbed so far.
    pub const fn samples(&self) -> u32 {
        self.samples
    }

    /// The mnemonic, and the end of the pool.
    ///
    /// # Errors
    ///
    /// `Empty` if nothing was absorbed.
    pub fn finish(self, words: Words) -> Result<Mnemonic, SeedError> {
        if self.samples == 0 {
            return Err(SeedError::Empty);
        }
        let mut digest = [0u8; 32];
        self.hasher.finalize_into((&mut digest).into());
        let m = bip39::from_entropy(&digest[..words.entropy_len()]);
        digest.zeroize();
        Ok(m?)
    }
}

/// A seed from dice rolls alone.
///
/// `rolls` is the digits as typed, `1` to `6`. The entropy is SHA-256 over
/// them: all of it for twenty-four words, the first sixteen bytes for twelve.
///
/// # Errors
///
/// `BadRoll` for a byte that is not a die face, `TooFewRolls` under
/// [`Words::dice_rolls`], `Degenerate` (see [`Degenerate`]), in that order,
/// so the first error names the first thing to fix.
pub fn from_dice(rolls: &[u8], words: Words) -> Result<Mnemonic, SeedError> {
    if let Some(position) = rolls.iter().position(|r| !(b'1'..=b'6').contains(r)) {
        return Err(SeedError::BadRoll { position });
    }
    let need = words.dice_rolls();
    if rolls.len() < need {
        return Err(SeedError::TooFewRolls {
            have: rolls.len(),
            need,
        });
    }
    if let Some(d) = degenerate(rolls) {
        return Err(SeedError::Degenerate(d));
    }
    let mut hasher = Sha256::new();
    hasher.update(rolls);
    let mut digest = [0u8; 32];
    hasher.finalize_into((&mut digest).into());
    let m = bip39::from_entropy(&digest[..words.entropy_len()]);
    digest.zeroize();
    Ok(m?)
}

/// The two degenerate-sequence tests, on rolls already known to be faces:
/// faces first, in face order, then runs, so the verdict is deterministic.
fn degenerate(rolls: &[u8]) -> Option<Degenerate> {
    let mut counts = [0usize; 6];
    for &r in rolls {
        counts[usize::from(r - b'1')] += 1;
    }
    let floor = rolls.len() / DICE_RARE_FACE_DIVISOR;
    if let Some((i, &count)) = counts.iter().enumerate().find(|&(_, &c)| c <= floor) {
        return Some(Degenerate::RareFace {
            face: b'1' + i as u8,
            count,
        });
    }
    let mut run = 0usize;
    let mut last = 0u8;
    for &r in rolls {
        run = if r == last { run + 1 } else { 1 };
        last = r;
        if run >= DICE_MAX_RUN {
            return Some(Degenerate::LongRun {
                face: r,
                length: run,
            });
        }
    }
    None
}
