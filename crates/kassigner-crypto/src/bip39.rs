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

//! BIP39: entropy to mnemonic, mnemonic to seed, as the BIP is written;
//! Kaspa adopts it unchanged.
//!
//! A mnemonic is the secret in another encoding: twelve 11-bit word indices
//! are 128 bits of entropy and 4 of checksum. So [`Mnemonic`] wipes itself on
//! drop and gives out its words one at a time, never as a list. It holds
//! indices, which a `Drop` can clear, not `&'static str`s into the binary's
//! read-only data.
//!
//! `from_entropy` takes bytes; where they come from is level 3's hardware
//! question.

use hmac::Hmac;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

use crate::wordlist::WORDLIST;

/// Words in the shorter mnemonic.
pub const WORDS_12: usize = 12;
/// Words in the longer mnemonic.
pub const WORDS_24: usize = 24;
/// Bytes of entropy behind a 12-word mnemonic.
pub const ENTROPY_12: usize = 16;
/// Bytes of entropy behind a 24-word mnemonic.
pub const ENTROPY_24: usize = 32;
/// Length of a BIP39 seed.
pub const SEED_LEN: usize = 64;

/// PBKDF2 rounds, from the specification.
const PBKDF2_ROUNDS: u32 = 2048;
/// The salt is this, then the passphrase.
pub const SALT_PREFIX: &[u8] = b"mnemonic";

/// Bytes of scratch [`to_seed`] needs for a passphrase of `n` bytes.
///
/// No maximum: BIP39 sets none, and a passphrase never crosses the air gap.
/// The caller's buffer and the device's keyboard are the limits.
pub const fn scratch_for(passphrase_len: usize) -> usize {
    SALT_PREFIX.len() + passphrase_len
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bip39Error {
    /// Not 12 or 24 words.
    BadWordCount(usize),
    /// A word not in the list, by position, so no string that outlives the
    /// mnemonic is handed back.
    UnknownWord { position: usize },
    /// The checksum does not match the entropy: usually one word mistyped as
    /// another in the list, which is what the checksum is for.
    BadChecksum,
    /// The caller's buffer is too small; from [`to_seed`], for the salt and
    /// passphrase. Never a truncation: a shortened passphrase silently
    /// derives a seed no other wallet reproduces.
    BufferTooSmall,
}

/// A mnemonic, held as word indices. Zeroizes on drop: the indices are the
/// entropy.
#[derive(Clone)]
pub struct Mnemonic {
    /// Only the first `len` are meaningful; sized for 24 so one type covers
    /// both lengths without an allocation.
    words: [u16; WORDS_24],
    len: usize,
}

impl core::fmt::Debug for Mnemonic {
    /// Redacted: the word count only. A derived `Debug` would print the
    /// indices, the whole wallet in one stray `{:?}`. Kept rather than
    /// omitted so the type can appear in an assertion or an error.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Mnemonic({} words, redacted)", self.len)
    }
}

impl Drop for Mnemonic {
    fn drop(&mut self) {
        // The whole array, whatever `len` says.
        self.words.zeroize();
        self.len = 0;
    }
}

impl Mnemonic {
    /// Words in this mnemonic: 12 or 24, or none once it has been taken.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether this has been taken from: [`Mnemonic::take`] leaves an empty
    /// one behind.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Bytes of entropy behind it, or none once it has been taken.
    pub const fn entropy_len(&self) -> usize {
        match self.len {
            WORDS_12 => ENTROPY_12,
            WORDS_24 => ENTROPY_24,
            _ => 0,
        }
    }

    /// The word at `i`, or `None` past the end. One at a time: a whole list
    /// would hand a caller 24 `&'static str` that no `Drop` clears.
    pub fn word(&self, i: usize) -> Option<&'static str> {
        if i >= self.len {
            return None;
        }
        WORDLIST.get(self.words[i] as usize).copied()
    }

    /// The index at `i`, or `None` past the end.
    pub fn index(&self, i: usize) -> Option<u16> {
        if i >= self.len {
            return None;
        }
        Some(self.words[i])
    }

    /// Copy this mnemonic out and wipe the original: a plain move leaves the
    /// words in the source's frame, with no `Drop`. This closes one hand-off;
    /// running the flow below a frame scrubbed afterwards closes the rest.
    pub fn take(&mut self) -> Self {
        let taken = Self {
            words: self.words,
            len: self.len,
        };
        self.words.zeroize();
        self.len = 0;
        taken
    }

    /// Recover the entropy into `out`, returning how many bytes were written.
    ///
    /// # Errors
    ///
    /// `BufferTooSmall` if `out` is shorter than [`Self::entropy_len`];
    /// `BadWordCount(0)` for a mnemonic taken from.
    pub fn entropy(&self, out: &mut [u8]) -> Result<usize, Bip39Error> {
        let n = self.entropy_len();
        if n == 0 {
            return Err(Bip39Error::BadWordCount(0));
        }
        if out.len() < n {
            return Err(Bip39Error::BufferTooSmall);
        }
        let bits = self.len * 11;
        let entropy_bits = bits - bits / 33;

        out[..n].fill(0);
        for (i, &w) in self.words[..self.len].iter().enumerate() {
            for b in 0..11 {
                let bit = (w >> (10 - b)) & 1;
                let pos = i * 11 + b;
                if pos < entropy_bits && bit == 1 {
                    out[pos / 8] |= 1 << (7 - (pos % 8));
                }
            }
        }
        Ok(n)
    }
}

/// A BIP39 seed. Zeroizes on drop.
#[derive(Clone)]
pub struct Seed([u8; SEED_LEN]);

impl core::fmt::Debug for Seed {
    /// Redacted, for the reason above.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Seed(64 bytes, redacted)")
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Seed {
    /// The seed bytes, the one way to them. No `Deref`: `*seed` would copy
    /// all 64 bytes into an array nothing wipes, and a seed would pass where
    /// bytes are asked without its name in the call.
    pub const fn as_bytes(&self) -> &[u8; SEED_LEN] {
        &self.0
    }
}

/// Build a mnemonic from entropy: 16 bytes give 12 words, 32 give 24.
///
/// # Errors
///
/// `BadWordCount` for any other length, carrying the word count that length
/// would imply.
pub fn from_entropy(entropy: &[u8]) -> Result<Mnemonic, Bip39Error> {
    let words = match entropy.len() {
        ENTROPY_12 => WORDS_12,
        ENTROPY_24 => WORDS_24,
        // Words are 11 bits of entropy plus checksum, the checksum a 32nd of
        // the entropy: `(8n + 8n / 32) / 11`, which is `3n / 4`.
        n => return Err(Bip39Error::BadWordCount(n * 3 / 4)),
    };

    // The checksum, appended: the first `entropy_bits / 32` bits of SHA-256
    // over the entropy, 4 for 128, 8 for 256. A hash of the secret, so wiped.
    let mut digest = Sha256::digest(entropy);
    let checksum_bits = entropy.len() * 8 / 32;

    let mut m = Mnemonic {
        words: [0u16; WORDS_24],
        len: words,
    };
    for i in 0..words {
        let mut w = 0u16;
        for b in 0..11 {
            let pos = i * 11 + b;
            let bit = if pos < entropy.len() * 8 {
                (entropy[pos / 8] >> (7 - (pos % 8))) & 1
            } else {
                let c = pos - entropy.len() * 8;
                debug_assert!(c < checksum_bits);
                (digest[c / 8] >> (7 - (c % 8))) & 1
            };
            w = (w << 1) | bit as u16;
        }
        m.words[i] = w;
    }
    digest.zeroize();
    Ok(m)
}

/// Look up one word.
///
/// # Errors
///
/// `UnknownWord` at position zero, as a single lookup has none;
/// [`from_words`] reports the real one.
pub fn word_to_index(word: &str) -> Result<u16, Bip39Error> {
    // A binary search of the sorted list: the same number of comparisons for
    // every word, which a linear scan is not.
    WORDLIST
        .binary_search(&word)
        .map(|i| i as u16)
        .map_err(|_| Bip39Error::UnknownWord { position: 0 })
}

/// The word at an index, or `None` past the end of the list.
pub fn index_to_word(index: u16) -> Option<&'static str> {
    WORDLIST.get(index as usize).copied()
}

/// Build a mnemonic from words, checking the checksum.
///
/// # Errors
///
/// `BadWordCount` for anything but 12 or 24, `UnknownWord` with the position,
/// `BadChecksum` when every word is valid but the phrase is not.
pub fn from_words<'a, I>(words: I) -> Result<Mnemonic, Bip39Error>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut m = Mnemonic {
        words: [0u16; WORDS_24],
        len: 0,
    };
    for (position, w) in words.into_iter().enumerate() {
        if position >= WORDS_24 {
            return Err(Bip39Error::BadWordCount(position + 1));
        }
        m.words[position] = word_to_index(w).map_err(|_| Bip39Error::UnknownWord { position })?;
        m.len = position + 1;
    }
    if m.len != WORDS_12 && m.len != WORDS_24 {
        return Err(Bip39Error::BadWordCount(m.len));
    }
    validate(&m)?;
    Ok(m)
}

/// Build a mnemonic from word indices, checking the checksum: what a person
/// typing words one by one has.
///
/// # Errors
///
/// `BadWordCount` for anything but 12 or 24, `UnknownWord` with the position
/// for an index past the list, `BadChecksum` when the phrase is not one.
pub fn from_indices(indices: &[u16]) -> Result<Mnemonic, Bip39Error> {
    if indices.len() != WORDS_12 && indices.len() != WORDS_24 {
        return Err(Bip39Error::BadWordCount(indices.len()));
    }
    let mut m = Mnemonic {
        words: [0u16; WORDS_24],
        len: indices.len(),
    };
    for (position, &i) in indices.iter().enumerate() {
        if usize::from(i) >= WORDLIST.len() {
            return Err(Bip39Error::UnknownWord { position });
        }
        m.words[position] = i;
    }
    validate(&m)?;
    Ok(m)
}

/// How many last words complete `first` words, 11 or 23 of them: the last
/// word's bits not taken by the checksum are free. 128 for a 12-word phrase
/// (7 free bits and 4 of checksum), 8 for 24 (3 and 8).
pub const fn last_word_choices(first: usize) -> Option<u16> {
    match first {
        11 => Some(1 << 7),
        23 => Some(1 << 3),
        _ => None,
    }
}

/// The `choice`th of the last words that complete `first` (11 or 23 word
/// indices) into a valid phrase, in the list's order: the free bits are
/// `choice`, the checksum bits what the entropy then makes them.
///
/// # Errors
///
/// `BadWordCount` for `first` not 11 or 23 long; `UnknownWord` for an index
/// past the list or a `choice` past [`last_word_choices`].
pub fn last_word(first: &[u16], choice: u16) -> Result<u16, Bip39Error> {
    let (entropy_len, choices) = match (first.len(), last_word_choices(first.len())) {
        (11, Some(c)) => (ENTROPY_12, c),
        (23, Some(c)) => (ENTROPY_24, c),
        (n, _) => return Err(Bip39Error::BadWordCount(n + 1)),
    };
    if choice >= choices {
        return Err(Bip39Error::UnknownWord {
            position: first.len(),
        });
    }
    let checksum_bits = entropy_len / 4;
    let free_bits = 11 - checksum_bits;
    // The first words' bits, then the free bits: the whole entropy.
    let mut entropy = [0u8; ENTROPY_24];
    let mut bit = 0usize;
    let mut push = |value: u16, width: usize, entropy: &mut [u8; ENTROPY_24]| {
        for k in (0..width).rev() {
            if value >> k & 1 == 1 {
                entropy[bit / 8] |= 0x80 >> (bit % 8);
            }
            bit += 1;
        }
    };
    for (position, &i) in first.iter().enumerate() {
        if usize::from(i) >= WORDLIST.len() {
            entropy.zeroize();
            return Err(Bip39Error::UnknownWord { position });
        }
        push(i, 11, &mut entropy);
    }
    push(choice, free_bits, &mut entropy);
    let mut hash = Sha256::digest(&entropy[..entropy_len]);
    let checksum = u16::from(hash[0]) >> (8 - checksum_bits);
    hash.zeroize();
    entropy.zeroize();
    Ok(choice << checksum_bits | checksum)
}

/// Check a mnemonic's checksum.
///
/// # Errors
///
/// `BadChecksum` if the words do not agree with the entropy they encode;
/// `BadWordCount(0)` for a mnemonic taken from.
pub fn validate(m: &Mnemonic) -> Result<(), Bip39Error> {
    let mut entropy = [0u8; ENTROPY_24];
    let n = m.entropy(&mut entropy)?;
    let rebuilt = from_entropy(&entropy[..n])?;
    // Every word compared, the differences ORed: a slice `==` stops at the
    // first that differs, and its time would tell how many matched. Both
    // are `m.len` long.
    let diff = rebuilt.words[..m.len]
        .iter()
        .zip(&m.words[..m.len])
        .fold(0u16, |d, (x, y)| d | (x ^ y));
    let ok = diff == 0;
    entropy.zeroize();
    if ok {
        Ok(())
    } else {
        Err(Bip39Error::BadChecksum)
    }
}

/// Derive the seed from a mnemonic and a passphrase: PBKDF2-HMAC-SHA512,
/// 2048 rounds, salt `"mnemonic"` then the passphrase. The passphrase is
/// part of the seed, not a lock on it, so there is no wrong-passphrase error.
///
/// `scratch` holds the salt, so the caller's buffer is the only limit on a
/// passphrase; size it with [`scratch_for`]. It is wiped either way.
///
/// # The passphrase is not normalised
///
/// BIP39 puts the mnemonic and passphrase through Unicode NFKD before
/// PBKDF2; this uses the passphrase's bytes as given. [`WORDLIST`] is ASCII,
/// which NFKD leaves unchanged, and the firmware's keyboard types printable
/// ASCII only, so on those units the two agree.
///
/// **A caller whose input can produce non-ASCII text owns this**: a board
/// that widens its keyboard brings normalisation or keeps to ASCII. The
/// failure is silent: an unnormalised passphrase derives a valid wallet that
/// the same words and passphrase do not restore in other software.
/// Normalising here would cost about 108 KB of flash and an allocator, for
/// input the keyboard cannot produce.
///
/// # Errors
///
/// `BufferTooSmall` if `scratch` cannot hold the salt and passphrase;
/// `BadWordCount(0)` for a mnemonic taken from, whose seed would be the
/// empty phrase's, a wallet nobody can restore.
pub fn to_seed(m: &Mnemonic, passphrase: &str, scratch: &mut [u8]) -> Result<Seed, Bip39Error> {
    if m.is_empty() {
        return Err(Bip39Error::BadWordCount(0));
    }
    // The phrase rebuilt as bytes in one buffer that can be wiped.
    let mut phrase = [0u8; WORDS_24 * 9]; // longest BIP39 word is 8, plus a space
    let mut n = 0usize;
    for i in 0..m.len {
        if i > 0 {
            phrase[n] = b' ';
            n += 1;
        }
        let w = WORDLIST[m.words[i] as usize].as_bytes();
        phrase[n..n + w.len()].copy_from_slice(w);
        n += w.len();
    }

    let need = scratch_for(passphrase.len());
    if scratch.len() < need {
        phrase.zeroize();
        return Err(Bip39Error::BufferTooSmall);
    }
    let salt = &mut scratch[..need];
    salt[..SALT_PREFIX.len()].copy_from_slice(SALT_PREFIX);
    salt[SALT_PREFIX.len()..].copy_from_slice(passphrase.as_bytes());

    let mut out = [0u8; SEED_LEN];
    pbkdf2::pbkdf2::<Hmac<Sha512>>(&phrase[..n], salt, PBKDF2_ROUNDS, &mut out)
        .expect("SEED_LEN is a valid PBKDF2 output length");

    phrase.zeroize();
    salt.zeroize();
    // `out` is `Copy`: `Seed(out)` copies it, so the local is wiped too, as
    // in `bip32`.
    let seed = Seed(out);
    out.zeroize();
    Ok(seed)
}
