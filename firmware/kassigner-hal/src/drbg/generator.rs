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

//! The random number generator the flow uses, on every board.
//!
//! **Nothing above this draws a board's raw source directly.** Even tested,
//! a raw hardware RNG gives no backtracking resistance, no prediction
//! resistance between reseeds, and lets a partial failure leak straight
//! into keys. A DRBG fixes all three: the source seeds it, and everything
//! else draws from it.
//!
//! ## Seed sizing and conditioning
//!
//! The seed is [`SEED_BYTES`], 64. SP 800-90B measured the P4's SAR ADC
//! (rev1.3, ROM ECO2), read 56 µs apart, at 7.269 bits per byte, so 64 bytes
//! carry at least 465 bits: margin over a key's 256 even if a later
//! measurement is materially lower. The S3's WDEV register is closer to a
//! full byte, and a smaller seed there would buy nothing.
//!
//! The raw bytes are unpredictable but not uniform, so SHA-256 (the pinned
//! `sha2`) conditions them:
//!
//! ```text
//!   key = SHA-256( DOMAIN || carry || raw seed )
//! ```
//!
//! `carry` is 32 bytes of a block made under the current key, so a reseed
//! keeps what the old key held: a source that weakens between reseeds can
//! only add to the key. At the first seeding the key is zeros, `carry` is
//! public, and the raw seed carries everything.
//!
//! ## Fast key erasure
//!
//! Each `ChaCha20` block's first 32 bytes become the next key at once; only
//! the other 32 are handed out. So the key in memory reveals nothing already
//! produced, where a plain stream cipher would give whoever read one key
//! everything since the last reseed. One block per key is also what makes
//! the fixed nonce safe. (See "Fast-key-erasure random-number generators".)
//!
//! ## Failure model
//!
//! If the source dies the generator stops: it never runs on a stale key
//! with no signal. Every draw is a `Result`.
//! A reseed failure poisons the generator, as does a source failing its own
//! tests (an [`Error`] on its fill), and a poisoned generator refuses every
//! draw for the rest of the boot. Key and keystream buffer are zeroed on
//! drop, and each key as soon as its one block is made.
//!
//! A source that fails the first seeding gives a generator poisoned from
//! the start, not no generator, so a board's bring-up holds one whatever
//! the source did, reports the failure on its verification screen and
//! fails closed from there. [`Drbg::new`] fails only for a cipher that
//! fails its known-answer test: a broken build, not a broken board.
//!
//! ## Why `ChaCha20` and not HMAC-DRBG
//!
//! Simple enough to check by eye, fast on a 32-bit core without useful AES
//! acceleration, and well analysed. HMAC-DRBG would serve a FIPS
//! certificate behind the same interface.

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::drbg::chacha20::{self, ChaCha20, BLOCK};
use crate::entropy::{Entropy, Error};

/// Bytes drawn from the board's source per seed.
pub const SEED_BYTES: usize = 64;
/// Bit count of a seed, for the degenerate-seed check.
const SEED_BITS: u32 = 512;
const _: () = assert!(SEED_BITS as usize == SEED_BYTES * 8);

/// The domain tag the key derivation starts with.
pub const DOMAIN: &[u8] = b"kassigner/drbg/v1";

/// A `ChaCha20` key's length: the part of each block that becomes the next.
pub const KEY: usize = 32;

/// Bytes each block hands out: the part that does not become the next key.
pub const OUT: usize = BLOCK - KEY;

/// At most this many bytes pass between automatic reseeds, within one call
/// as across calls, so a long call cannot run on one key chain. Not a
/// security need for `ChaCha20` at these volumes: cheap insurance that
/// keeps a long-running device folding in fresh entropy.
pub const RESEED_INTERVAL: u32 = 4096;

/// Why the generator refused.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DrbgError {
    /// The `ChaCha20` core failed its known-answer test: a broken build,
    /// whose output cannot be trusted.
    CipherBroken,
    /// The board's source refused a draw: absent, or failed its own tests.
    Source(Error),
    /// The seed was all zeros or all ones: the source died between its
    /// tests and the seed read. A backstop: the source's own tests catch this
    /// first in practice.
    SeedDegenerate,
}

/// Cryptographic RNG for the firmware, over a board's tested raw source.
pub struct Drbg<E: Entropy> {
    source: E,
    chacha: ChaCha20,
    buf: [u8; OUT],
    pos: usize,
    since_reseed: u32,
    poisoned: Option<DrbgError>,
}

impl<E: Entropy> Drbg<E> {
    /// Verify the cipher and seed from `source`, which must already be
    /// started and through the board's start-up tests.
    ///
    /// # Errors
    ///
    /// `CipherBroken` if the known-answer test fails. A source that refuses
    /// the first seed or gives a degenerate one leaves the generator
    /// [`poisoned`](Self::poisoned) with that reason instead.
    pub fn new(source: E) -> Result<Self, DrbgError> {
        // The cipher first: a broken core's output passes every other check.
        if !chacha20::known_answer() {
            return Err(DrbgError::CipherBroken);
        }
        let mut d = Self {
            source,
            chacha: ChaCha20::new(&[0u8; 32]),
            buf: [0u8; OUT],
            pos: OUT,
            since_reseed: 0,
            poisoned: None,
        };
        // A failure here has poisoned `d`, which is what the caller gets.
        let _ = d.reseed();
        Ok(d)
    }

    /// Is this generator dead? Sticky.
    pub fn poisoned(&self) -> Option<DrbgError> {
        self.poisoned
    }

    /// The board's source, for diagnostics and the entropy capture, which
    /// must see the raw words, not this generator's output.
    pub fn source(&mut self) -> &mut E {
        &mut self.source
    }

    fn poison(&mut self, e: DrbgError) -> DrbgError {
        if self.poisoned.is_none() {
            self.poisoned = Some(e);
        }
        // Do not leave a usable stream behind.
        self.buf.zeroize();
        self.pos = OUT;
        e
    }

    /// Draw a fresh seed and rekey.
    fn reseed(&mut self) -> Result<(), DrbgError> {
        if let Some(e) = self.poisoned {
            return Err(e);
        }
        let mut seed = [0u8; SEED_BYTES];
        if let Err(e) = self.source.fill(&mut seed) {
            seed.zeroize();
            return Err(self.poison(DrbgError::Source(e)));
        }
        let ones: u32 = seed.iter().map(|b| b.count_ones()).sum();
        if ones == 0 || ones == SEED_BITS {
            seed.zeroize();
            return Err(self.poison(DrbgError::SeedDegenerate));
        }
        // What the current key holds, carried forward as a block it makes,
        // not as the key itself; that key is replaced below either way.
        let mut carry = [0u8; BLOCK];
        self.chacha.block(&mut carry);
        let mut key = [0u8; KEY];
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN);
        hasher.update(&carry[..KEY]);
        hasher.update(seed);
        hasher.finalize_into((&mut key).into());
        // The assignment drops the old cipher, whose `Drop` zeroes its state.
        self.chacha = ChaCha20::new(&key);
        key.zeroize();
        carry.zeroize();
        seed.zeroize();
        self.buf.zeroize();
        self.pos = OUT;
        self.since_reseed = 0;
        Ok(())
    }

    /// Force a reseed, besides the automatic ones every
    /// [`RESEED_INTERVAL`] bytes.
    ///
    /// The unit calls it once at boot, before any draw (`kassigner-signer`'s
    /// `main`): moved by value out of the board's bring-up, the generator
    /// left copies of its key in stack frames, each predicting every byte
    /// until the first reseed. No reseed is needed before a seed is made: a
    /// seed credits the generator nothing (`kassigner_fw::seed`), so no key
    /// the unit keeps rests on it, and the rest it gives is single-use: a
    /// sealed file's salt and nonce, or a signature's randomness.
    ///
    /// # Errors
    ///
    /// Any source failure; the generator is then poisoned.
    pub fn reseed_now(&mut self) -> Result<(), DrbgError> {
        self.reseed()
    }

    /// One block: the first [`KEY`] bytes rekey the cipher at once, the
    /// other [`OUT`] are the next output ("Fast key erasure" above).
    fn refill(&mut self) {
        let mut block = [0u8; BLOCK];
        self.chacha.block(&mut block);
        let mut key = [0u8; KEY];
        key.copy_from_slice(&block[..KEY]);
        // The assignment drops the old cipher, whose `Drop` zeroes its state.
        self.chacha = ChaCha20::new(&key);
        key.zeroize();
        self.buf.copy_from_slice(&block[KEY..]);
        block.zeroize();
        self.pos = 0;
    }

    /// Fill `dst` with random bytes, or fail closed: on `Err`, `dst` is
    /// zeroed, never part-filled by a generator that then died.
    ///
    /// # Errors
    ///
    /// The failure that poisoned the generator, if one already has;
    /// otherwise that of the automatic reseed this call triggered.
    pub fn fill(&mut self, dst: &mut [u8]) -> Result<(), DrbgError> {
        if let Some(e) = self.poisoned {
            dst.zeroize();
            return Err(e);
        }
        for i in 0..dst.len() {
            if self.pos >= OUT {
                self.refill();
            }
            dst[i] = self.buf[self.pos];
            // Cleared as consumed, so a snapshot of `buf` holds only bytes
            // not yet handed out.
            self.buf[self.pos] = 0;
            self.pos += 1;
            self.since_reseed = self.since_reseed.saturating_add(1);
            // At the interval, in the middle of a call or at its end.
            if self.since_reseed >= RESEED_INTERVAL {
                // The bytes written so far came from a good key, but an
                // error means no output: zeroed.
                if let Err(e) = self.reseed() {
                    dst.zeroize();
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Random `u32`.
    ///
    /// # Errors
    ///
    /// As [`fill`](Self::fill).
    pub fn next_u32(&mut self) -> Result<u32, DrbgError> {
        let mut b = [0u8; 4];
        self.fill(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    /// Random `u64`.
    ///
    /// # Errors
    ///
    /// As [`fill`](Self::fill).
    pub fn next_u64(&mut self) -> Result<u64, DrbgError> {
        let mut b = [0u8; 8];
        self.fill(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
}

/// The generator as the flow sees it: the [`Entropy`] it draws.
///
/// A failure is the source's own verdict when that killed the generator,
/// `Unhealthy` otherwise, so the flow's refusal reads the same whichever
/// layer failed.
impl<E: Entropy> Entropy for Drbg<E> {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        Drbg::fill(self, out).map_err(|e| match e {
            DrbgError::Source(source) => source,
            DrbgError::CipherBroken | DrbgError::SeedDegenerate => Error::Unhealthy,
        })
    }
}

impl<E: Entropy> Drop for Drbg<E> {
    fn drop(&mut self) {
        self.buf.zeroize();
        // `chacha` zeroes its own state in its Drop.
    }
}
