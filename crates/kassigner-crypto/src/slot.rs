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

//! Seed slots: what the device holds a key for.
//!
//! A slot lives in RAM only and is wiped at power-off; nothing here writes
//! to flash or a card. Persistence is the encrypted container
//! ([`crate::container`]) a person chooses to make.
//!
//! [`Slot`] is an enum, so a mnemonic, an xprv and a raw key cannot be read
//! as one another, and every payload wipes itself on drop, so a slot copied
//! to the stack is cleared when the copy goes. A new mnemonic is
//! [`bip39::from_entropy`] over the board's entropy, not made here.
//!
//! # SeedQR
//!
//! SeedSigner's format, here because it moves a mnemonic: where a secret
//! goes, its handling goes. Standard: each word index as four decimal
//! digits. Compact: the entropy bytes, the checksum word recomputed on the
//! way in.
//!
//! # Fingerprints
//!
//! BIP32's, as other wallets show them: the first four bytes of
//! `RIPEMD160(SHA256(public key))` of the highest key the slot holds: a
//! mnemonic's master key `m` (the fingerprint in a key origin,
//! `[fingerprint/path]`), an xprv's own key, or a raw key.
//!
//! A master key exists only after the BIP39 stretch, so [`Slots`] reports
//! no fingerprint until a wallet has derived and recorded it. It is not
//! computed from the words, which would make the display a passphrase oracle
//! that skips the stretch.

use zeroize::Zeroize;

use crate::bip32::{compressed_public_key, Bip32Error, ExtendedPrivateKey, PRIVATE_KEY_SIZE};
use crate::bip39::{self, Bip39Error, Mnemonic, ENTROPY_24, WORDS_12, WORDS_24};
use crate::sign;
use kassigner_kaspa::bip32_public::PUBLIC_KEY_SIZE;

/// Bytes a stored passphrase can take: the fixed size a crate with no
/// allocator needs, not a BIP39 rule (it sets none). A keyboard that allows
/// more is the case to revisit.
pub const PASSPHRASE_MAX: usize = 64;

/// Bytes of a fingerprint.
pub const FINGERPRINT_LEN: usize = 4;

/// Characters of a standard SeedQR.
pub const SEEDQR_MAX: usize = WORDS_24 * 4;

/// Why a slot operation was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotError {
    /// Every slot is taken.
    Full,
    /// No slot at that index.
    NoSuchSlot {
        index: usize,
    },
    /// The slot at that index is empty.
    Empty {
        index: usize,
    },
    /// The passphrase is longer than [`PASSPHRASE_MAX`].
    PassphraseTooLong {
        len: usize,
    },
    /// The passphrase has a byte outside printable ASCII, at `at`.
    PassphraseCharacter {
        at: usize,
    },
    /// A raw key that is zero or past the curve order, or `Slot::Empty`
    /// given to [`Slots::store`].
    InvalidKey,
    /// Not 48 or 96 decimal digits, or an index past the word list.
    SeedQr,
    Bip39(Bip39Error),
    Bip32(Bip32Error),
}

impl From<Bip39Error> for SlotError {
    fn from(e: Bip39Error) -> Self {
        SlotError::Bip39(e)
    }
}
impl From<Bip32Error> for SlotError {
    fn from(e: Bip32Error) -> Self {
        SlotError::Bip32(e)
    }
}

/// A BIP39 passphrase. Zeroizes on drop.
///
/// Printable ASCII only, `0x20` to `0x7E`, the keyboard's whole alphabet:
/// BIP39's NFKD normalization, not implemented here, leaves ASCII unchanged,
/// so the seed is the one every other wallet derives. Anything else is
/// refused rather than derived into a wallet nobody else would open.
#[derive(Clone)]
pub struct Passphrase {
    bytes: [u8; PASSPHRASE_MAX],
    len: u8,
}

impl core::fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Not even its length, which a `Slot` printed for debugging would
        // show.
        f.write_str("Passphrase(redacted)")
    }
}

impl Drop for Passphrase {
    fn drop(&mut self) {
        self.bytes.zeroize();
        self.len = 0;
    }
}

impl Passphrase {
    /// No passphrase.
    pub const fn none() -> Self {
        Self {
            bytes: [0; PASSPHRASE_MAX],
            len: 0,
        }
    }

    /// A passphrase from its bytes.
    ///
    /// # Errors
    ///
    /// `PassphraseTooLong` past [`PASSPHRASE_MAX`], and
    /// `PassphraseCharacter` at the first byte outside printable ASCII.
    pub fn new(p: &[u8]) -> Result<Self, SlotError> {
        if p.len() > PASSPHRASE_MAX {
            return Err(SlotError::PassphraseTooLong { len: p.len() });
        }
        if let Some(at) = p.iter().position(|b| !(0x20..=0x7E).contains(b)) {
            return Err(SlotError::PassphraseCharacter { at });
        }
        let mut bytes = [0u8; PASSPHRASE_MAX];
        bytes[..p.len()].copy_from_slice(p);
        // Built from a copy of the local, which is wiped after, as in
        // `bip32`.
        let passphrase = Self {
            bytes,
            len: p.len() as u8,
        };
        bytes.zeroize();
        Ok(passphrase)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// The passphrase as text, for BIP39. Never fails: [`Passphrase::new`]
    /// admits only ASCII, and ASCII is UTF-8.
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).expect("ASCII by construction")
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// A raw private key. Zeroizes on drop.
#[derive(Clone)]
pub struct RawKey([u8; PRIVATE_KEY_SIZE]);

impl core::fmt::Debug for RawKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "RawKey(redacted)")
    }
}

impl Drop for RawKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl RawKey {
    /// A key from its bytes.
    ///
    /// # Errors
    ///
    /// `InvalidKey` if it is zero or past the curve order, which
    /// [`sign::public_key`] checks.
    pub fn new(key: &[u8; PRIVATE_KEY_SIZE]) -> Result<Self, SlotError> {
        sign::public_key(key).map_err(|_| SlotError::InvalidKey)?;
        Ok(Self(*key))
    }

    pub const fn as_bytes(&self) -> &[u8; PRIVATE_KEY_SIZE] {
        &self.0
    }

    /// This key's BIP32 fingerprint, over its public key.
    pub fn fingerprint(&self) -> [u8; FINGERPRINT_LEN] {
        let public = compressed_public_key(&self.0).expect("checked on construction");
        fingerprint_of(&public)
    }
}

/// What a slot holds.
#[derive(Clone, Debug)]
pub enum Slot {
    Empty,
    /// Twelve or twenty-four words and a passphrase, empty or not.
    Mnemonic {
        mnemonic: Mnemonic,
        passphrase: Passphrase,
    },
    /// An imported extended private key: some node of some tree, with its
    /// chain code, so children can be derived but no parent.
    Xprv(ExtendedPrivateKey),
    /// One private key, no tree.
    RawKey(RawKey),
}

impl Slot {
    /// A mnemonic slot.
    ///
    /// # Errors
    ///
    /// `PassphraseTooLong`, `PassphraseCharacter`; `Bip39(BadWordCount(0))`
    /// for a mnemonic taken from, which would open as the empty phrase's
    /// wallet.
    pub fn mnemonic(mnemonic: Mnemonic, passphrase: &[u8]) -> Result<Self, SlotError> {
        if mnemonic.is_empty() {
            return Err(SlotError::Bip39(Bip39Error::BadWordCount(0)));
        }
        Ok(Slot::Mnemonic {
            mnemonic,
            passphrase: Passphrase::new(passphrase)?,
        })
    }

    pub const fn is_empty(&self) -> bool {
        matches!(self, Slot::Empty)
    }

    /// What kind of slot, as one word, for a screen.
    pub const fn kind(&self) -> &'static str {
        match self {
            Slot::Empty => "empty",
            Slot::Mnemonic { .. } => "mnemonic",
            Slot::Xprv(_) => "xprv",
            Slot::RawKey(_) => "key",
        }
    }

    /// True when both slots hold the same secret, in constant time over the
    /// secret bytes. Used to refuse storing a slot twice.
    fn same_as(&self, other: &Slot) -> bool {
        match (self, other) {
            (
                Slot::Mnemonic {
                    mnemonic: a,
                    passphrase: pa,
                },
                Slot::Mnemonic {
                    mnemonic: b,
                    passphrase: pb,
                },
            ) => {
                // Counts and lengths folded in, and all twenty-four
                // positions compared (past a mnemonic's words both read as
                // zero): an early return would tell, by its time, whether
                // two passphrases are the same length.
                let mut diff = (a.len() ^ b.len()) | usize::from(pa.len ^ pb.len);
                for i in 0..WORDS_24 {
                    diff |= usize::from(a.index(i).unwrap_or(0) ^ b.index(i).unwrap_or(0));
                }
                // `&`, not `&&`: both halves are compared whatever the first
                // says, so the time does not tell whether the words matched.
                let words = diff == 0;
                let passphrase = ct_eq(&pa.bytes, &pb.bytes);
                words & passphrase
            }
            (Slot::Xprv(a), Slot::Xprv(b)) => {
                // Both compared, as above.
                let key = ct_eq(a.private_key(), b.private_key());
                let chain = ct_eq(a.chain_code(), b.chain_code());
                key & chain
            }
            (Slot::RawKey(a), Slot::RawKey(b)) => ct_eq(&a.0, &b.0),
            _ => false,
        }
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// A BIP32 fingerprint: the first four bytes of `RIPEMD160(SHA256(key))`
/// over a compressed public key, upstream's rule
/// (`wallet/bip32/src/public_key.rs`), from the level-0 crate.
pub fn fingerprint_of(public_key: &[u8; PUBLIC_KEY_SIZE]) -> [u8; FINGERPRINT_LEN] {
    kassigner_kaspa::bip32_public::fingerprint(public_key)
}

/// Slots, and which one is active. `N`, how many seeds a device holds, is
/// the caller's choice. Wipes every slot on drop.
pub struct Slots<const N: usize> {
    slots: [Slot; N],
    fingerprints: [Option<[u8; FINGERPRINT_LEN]>; N],
    active: Option<usize>,
}

impl<const N: usize> Default for Slots<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Drop for Slots<N> {
    fn drop(&mut self) {
        self.wipe_all();
    }
}

impl<const N: usize> Slots<N> {
    pub fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| Slot::Empty),
            fingerprints: [None; N],
            active: None,
        }
    }

    /// Put a mnemonic in, and wipe the caller's copy: a move would leave the
    /// words in the caller's frame, as its source gets no `Drop`. Copies made
    /// on the way here are the caller's, cleared by running the flow below a
    /// frame scrubbed afterwards (`kassigner_fw::wipe`). Nothing is wiped
    /// unless the store succeeds.
    ///
    /// # Errors
    ///
    /// `Full`, `PassphraseTooLong`, `PassphraseCharacter`;
    /// `Bip39(BadWordCount(0))` for a mnemonic already taken from.
    pub fn store_mnemonic(
        &mut self,
        mnemonic: &mut Mnemonic,
        passphrase: &[u8],
    ) -> Result<usize, SlotError> {
        // The error `Slot::mnemonic` gives an emptied mnemonic.
        if mnemonic.is_empty() {
            return Err(SlotError::Bip39(Bip39Error::BadWordCount(0)));
        }
        // The clone is stored, or wiped if already in a slot; the caller's
        // copy is cleared only once the index is in hand.
        let slot = Slot::mnemonic(mnemonic.clone(), passphrase)?;
        let index = self.store(slot)?;
        drop(mnemonic.take());
        Ok(index)
    }

    /// Put a slot in, or find it already there: for a secret already stored,
    /// that slot's index. A raw key's fingerprint is recorded at once; the
    /// others' by whoever derives them.
    ///
    /// # Errors
    ///
    /// `Full`; `InvalidKey` for `Slot::Empty`, as there is nothing to store.
    pub fn store(&mut self, slot: Slot) -> Result<usize, SlotError> {
        if slot.is_empty() {
            return Err(SlotError::InvalidKey);
        }
        if let Some(i) = self.slots.iter().position(|s| s.same_as(&slot)) {
            return Ok(i);
        }
        let i = self
            .slots
            .iter()
            .position(Slot::is_empty)
            .ok_or(SlotError::Full)?;
        self.fingerprints[i] = match &slot {
            Slot::RawKey(k) => Some(k.fingerprint()),
            _ => None,
        };
        self.slots[i] = slot;
        Ok(i)
    }

    /// Make a slot the active one.
    ///
    /// # Errors
    ///
    /// `NoSuchSlot`, `Empty`.
    pub fn activate(&mut self, index: usize) -> Result<(), SlotError> {
        self.get(index)?;
        self.active = Some(index);
        Ok(())
    }

    /// The active slot, if one is.
    pub fn active(&self) -> Option<(usize, &Slot)> {
        let i = self.active?;
        Some((i, &self.slots[i]))
    }

    /// The slot at `index`.
    ///
    /// # Errors
    ///
    /// `NoSuchSlot`, `Empty`.
    pub fn get(&self, index: usize) -> Result<&Slot, SlotError> {
        let s = self
            .slots
            .get(index)
            .ok_or(SlotError::NoSuchSlot { index })?;
        if s.is_empty() {
            return Err(SlotError::Empty { index });
        }
        Ok(s)
    }

    /// Wipe one slot, deactivating it if it was active. A missing index is
    /// ignored.
    pub fn delete(&mut self, index: usize) {
        if let Some(s) = self.slots.get_mut(index) {
            *s = Slot::Empty;
            self.fingerprints[index] = None;
            if self.active == Some(index) {
                self.active = None;
            }
        }
    }

    /// Wipe every slot.
    pub fn wipe_all(&mut self) {
        for s in &mut self.slots {
            *s = Slot::Empty;
        }
        self.fingerprints = [None; N];
        self.active = None;
    }

    /// Slots in use.
    pub fn count(&self) -> usize {
        self.slots.iter().filter(|s| !s.is_empty()).count()
    }

    /// The fingerprint recorded for a slot, if one has been.
    pub fn fingerprint(&self, index: usize) -> Option<[u8; FINGERPRINT_LEN]> {
        self.fingerprints.get(index).copied().flatten()
    }

    /// Record a slot's fingerprint, once a wallet has derived its key.
    ///
    /// # Errors
    ///
    /// `NoSuchSlot`, `Empty`.
    pub fn set_fingerprint(
        &mut self,
        index: usize,
        fp: [u8; FINGERPRINT_LEN],
    ) -> Result<(), SlotError> {
        self.get(index)?;
        self.fingerprints[index] = Some(fp);
        Ok(())
    }

    /// The slot with this fingerprint, if one has it recorded.
    pub fn find_by_fingerprint(&self, fp: &[u8; FINGERPRINT_LEN]) -> Option<usize> {
        self.fingerprints
            .iter()
            .position(|f| f.is_some_and(|f| ct_eq(&f, fp)))
    }
}

// ── SeedQR ──────────────────────────────────────────────────────────────────

/// Read a standard SeedQR: 48 or 96 decimal digits, four per word index.
///
/// # Errors
///
/// `SeedQr` for the wrong length, a non-digit, or an index of 2048 or more.
/// `Bip39` for a checksum that does not agree with the words.
pub fn from_seedqr(digits: &[u8]) -> Result<Mnemonic, SlotError> {
    let words = match digits.len() {
        n if n == WORDS_12 * 4 => WORDS_12,
        n if n == WORDS_24 * 4 => WORDS_24,
        _ => return Err(SlotError::SeedQr),
    };
    if !digits.iter().all(u8::is_ascii_digit) {
        return Err(SlotError::SeedQr);
    }
    let mut indices = [0u16; WORDS_24];
    for (w, chunk) in indices[..words].iter_mut().zip(digits.chunks_exact(4)) {
        let v = chunk
            .iter()
            .fold(0u16, |v, &c| v * 10 + u16::from(c - b'0'));
        if v >= 2048 {
            indices.zeroize();
            return Err(SlotError::SeedQr);
        }
        *w = v;
    }
    let m = bip39::from_indices(&indices[..words]);
    indices.zeroize();
    Ok(m?)
}

/// Write a standard SeedQR. Returns the digits written: 48 or 96, none
/// for a mnemonic taken from.
pub fn to_seedqr(m: &Mnemonic, out: &mut [u8; SEEDQR_MAX]) -> usize {
    for i in 0..m.len() {
        let idx = m.index(i).unwrap_or(0);
        out[i * 4] = b'0' + ((idx / 1000) % 10) as u8;
        out[i * 4 + 1] = b'0' + ((idx / 100) % 10) as u8;
        out[i * 4 + 2] = b'0' + ((idx / 10) % 10) as u8;
        out[i * 4 + 3] = b'0' + (idx % 10) as u8;
    }
    m.len() * 4
}

/// Read a compact SeedQR: the entropy bytes, 16 or 32.
///
/// # Errors
///
/// `Bip39` for any other length.
pub fn from_compact_seedqr(entropy: &[u8]) -> Result<Mnemonic, SlotError> {
    Ok(bip39::from_entropy(entropy)?)
}

/// Write a compact SeedQR. Returns the bytes written: 16 or 32, none for a
/// mnemonic taken from.
pub fn to_compact_seedqr(m: &Mnemonic, out: &mut [u8; ENTROPY_24]) -> usize {
    m.entropy(out).unwrap_or(0)
}
