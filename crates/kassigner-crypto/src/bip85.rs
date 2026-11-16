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

//! BIP85 deterministic entropy, application `39'` (BIP39 mnemonics): a
//! child mnemonic is a standalone wallet, reproducible from the parent seed,
//! revealing neither the parent nor any sibling.
//!
//! ```text
//! m/83696968'/39'/language'/words'/index'
//! ```
//!
//! Every level is hardened, so this needs an [`ExtendedPrivateKey`]. The
//! child's entropy is the first 16 or 32 bytes of
//! `HMAC-SHA512(key = "bip-entropy-from-k", message = private key at path)`.
//!
//! The caller names the index: no counter is kept, as levels 0 to 2 hold no
//! state.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha512;
use zeroize::Zeroize;

use kassigner_kaspa::bip32_public::{ChildNumber, HARDENED_OFFSET};

use crate::bip32::{Bip32Error, ExtendedPrivateKey};
use crate::bip39::{self, Bip39Error, Mnemonic, ENTROPY_12, ENTROPY_24, WORDS_12, WORDS_24};

/// BIP85's purpose number.
pub const PURPOSE: u32 = 83_696_968;
/// The BIP39 application.
pub const APPLICATION_BIP39: u32 = 39;
/// English. The only language this crate has a word list for.
pub const LANGUAGE_ENGLISH: u32 = 0;

/// The HMAC key, from the specification.
const ENTROPY_KEY: &[u8] = b"bip-entropy-from-k";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bip85Error {
    /// A word count other than 12 or 24.
    BadWordCount(u32),
    /// An index at or above the hardened offset. This adds the offset
    /// itself, so an index already carrying it is a mistake.
    IndexTooLarge(u32),
    /// A key that is not a master key, with its depth. BIP85 derives from
    /// `m`; a lower node would give a child no one can remake from the seed
    /// by BIP85's path.
    NotMaster(u8),
    /// A fault while deriving.
    Bip32(Bip32Error),
    /// A fault while building the mnemonic.
    Bip39(Bip39Error),
}

impl From<Bip32Error> for Bip85Error {
    fn from(e: Bip32Error) -> Self {
        Bip85Error::Bip32(e)
    }
}

impl From<Bip39Error> for Bip85Error {
    fn from(e: Bip39Error) -> Self {
        Bip85Error::Bip39(e)
    }
}

/// Derive a child mnemonic. `words` is 12 or 24; `index` is plain, and `0`
/// gives `0'`.
///
/// # Errors
///
/// `BadWordCount` for anything but 12 or 24, `IndexTooLarge` for an index
/// that already carries the hardened bit, `NotMaster` for a key at any depth
/// but 0, and whatever derivation returns.
pub fn derive_mnemonic(
    master: &ExtendedPrivateKey,
    words: u32,
    index: u32,
) -> Result<Mnemonic, Bip85Error> {
    let entropy_len = match words as usize {
        WORDS_12 => ENTROPY_12,
        WORDS_24 => ENTROPY_24,
        _ => return Err(Bip85Error::BadWordCount(words)),
    };
    // From `path_for`, so a path shown and the path derived cannot differ.
    // Its word-count check repeats the one above.
    let path = path_for(words, index)?;
    // Depth 0 is enough: a depth-0 key naming a parent or a child number is
    // refused where it is built (`Bip32Error::NotAMaster`).
    if master.depth() != 0 {
        return Err(Bip85Error::NotMaster(master.depth()));
    }
    let node = master.derive_path(&path)?;

    let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(ENTROPY_KEY)
        .expect("HMAC accepts a key of any length");
    mac.update(node.private_key());
    let mut i = mac.finalize().into_bytes();

    // The HMAC output is a wallet: wiped once the entropy is taken, before
    // the mnemonic is built, so a failure there does not leave it.
    let mut entropy = [0u8; ENTROPY_24];
    entropy[..entropy_len].copy_from_slice(&i[..entropy_len]);
    i.zeroize();

    let result = bip39::from_entropy(&entropy[..entropy_len]);
    entropy.zeroize();

    Ok(result?)
}

/// The derivation path for a child, for a caller that shows it. The one
/// place the five levels are written: [`derive_mnemonic`] derives from it.
///
/// # Errors
///
/// `BadWordCount` and `IndexTooLarge`, as [`derive_mnemonic`]. Each level
/// adds [`HARDENED_OFFSET`] (`2^31`), so a hardened index would overflow: a
/// panic where overflow checks are on, as in the firmware, a wrong path
/// where they are off.
pub fn path_for(words: u32, index: u32) -> Result<[ChildNumber; 5], Bip85Error> {
    if words as usize != WORDS_12 && words as usize != WORDS_24 {
        return Err(Bip85Error::BadWordCount(words));
    }
    if index >= HARDENED_OFFSET {
        return Err(Bip85Error::IndexTooLarge(index));
    }
    Ok([
        ChildNumber(PURPOSE + HARDENED_OFFSET),
        ChildNumber(APPLICATION_BIP39 + HARDENED_OFFSET),
        ChildNumber(LANGUAGE_ENGLISH + HARDENED_OFFSET),
        ChildNumber(words + HARDENED_OFFSET),
        ChildNumber(index + HARDENED_OFFSET),
    ])
}
