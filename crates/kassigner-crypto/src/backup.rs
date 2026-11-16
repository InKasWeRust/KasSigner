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

//! A slot to a card and back: a backup's plaintext, in v1.0.7's format; the
//! container around it is [`crate::container`]. The plaintext is a secret,
//! so its format is here rather than at level 1, as SeedQR is in
//! [`crate::slot`].
//!
//! - A mnemonic: the word indices, two little-endian bytes each, under
//!   purpose `Seed`. The BIP39 passphrase is typed again, not stored, so a
//!   card and its password are not the whole wallet.
//! - An xprv: its `kprv...` text under purpose `Xprv`. A unit opens these
//!   but does not write them; sealing stays for tests.
//! - A raw key is not backed up (purpose `Raw` holds a stego hint).

use zeroize::Zeroize;

use crate::bip32::{ExtendedPrivateKey, PrivatePrefix, XPRV_TEXT_MAX};
use crate::bip39::{self, Bip39Error, Mnemonic, WORDS_24};
use crate::container::{
    open, open_with_key, seal, seal_with_key, Argon2Block, OpenError, SealKdf, SealingKey, KEY_SIZE,
};
use crate::password::{self, Weakness};
use crate::slot::{Slot, SlotError};
use kassigner_kaspa::derivation::{ACCOUNT_LEVELS, SINGLE_ACCOUNT};
use kassigner_protocol::container::{file_size, Purpose, NONCE_SIZE, SALT_SIZE};
use kassigner_protocol::container::{parse, Kdf};

/// Bytes of the largest seed plaintext.
pub const SEED_PLAINTEXT_MAX: usize = WORDS_24 * 2;

/// Bytes of the largest seed backup file.
pub const SEED_FILE_MAX: usize = file_size(SEED_PLAINTEXT_MAX);

/// Bytes of the largest xprv backup file.
pub const XPRV_FILE_MAX: usize = file_size(XPRV_TEXT_MAX);

/// Bytes of the largest backup file of either kind.
pub const FILE_MAX: usize = if SEED_FILE_MAX > XPRV_FILE_MAX {
    SEED_FILE_MAX
} else {
    XPRV_FILE_MAX
};

/// Why a backup was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackupError {
    /// A raw-key slot cannot be backed up.
    NotBackedUp,
    /// The container is not a seed or xprv backup.
    WrongPurpose(Purpose),
    /// Seed plaintext that is not 24 or 48 bytes, holds an index past the
    /// word list, or fails the BIP39 checksum; or xprv plaintext that is not
    /// a mainnet key's text.
    Malformed,
    Container(OpenError),
    Slot(SlotError),
    /// The password does not meet [`crate::password`]'s policy. Sealing
    /// only: a card opens under whatever it was sealed with.
    WeakPassword(Weakness),
    /// An xprv neither a master key (depth 0) nor an account node (depth
    /// 3); see [`crate::wallet::WalletError::XprvDepth`].
    XprvDepth {
        depth: u8,
    },
    /// An xprv at the account's depth but not account `0'`; see
    /// [`crate::wallet::WalletError::XprvAccount`].
    XprvAccount {
        child: u32,
    },
}

impl From<OpenError> for BackupError {
    fn from(e: OpenError) -> Self {
        BackupError::Container(e)
    }
}
impl From<SlotError> for BackupError {
    fn from(e: SlotError) -> Self {
        BackupError::Slot(e)
    }
}

/// Write the seed plaintext for a mnemonic. Returns bytes written.
pub fn seed_plaintext(m: &Mnemonic, out: &mut [u8; SEED_PLAINTEXT_MAX]) -> usize {
    for i in 0..m.len() {
        out[i * 2..i * 2 + 2].copy_from_slice(&m.index(i).unwrap_or(0).to_le_bytes());
    }
    m.len() * 2
}

/// Read a mnemonic back from seed plaintext.
///
/// # Errors
///
/// `Malformed`.
pub fn mnemonic_from_plaintext(bytes: &[u8]) -> Result<Mnemonic, BackupError> {
    let words = bytes.len() / 2;
    if !bytes.len().is_multiple_of(2) || (words != 12 && words != WORDS_24) {
        return Err(BackupError::Malformed);
    }
    let mut indices = [0u16; WORDS_24];
    for (w, pair) in indices[..words].iter_mut().zip(bytes.chunks_exact(2)) {
        *w = u16::from_le_bytes([pair[0], pair[1]]);
    }
    // An index past the list or a bad checksum: a malformed backup.
    let m = bip39::from_indices(&indices[..words]);
    indices.zeroize();
    m.map_err(|_| BackupError::Malformed)
}

/// Seal a slot into a backup file. Returns bytes written.
///
/// `salt` and `nonce` must be fresh. `kdf` is the board's: Argon2id where
/// it has the memory, PBKDF2 for a card another board must read.
///
/// # Errors
///
/// `WeakPassword` ([`crate::password`]) before any plaintext exists;
/// `NotBackedUp` for a raw-key or empty slot; `Slot` for a mnemonic with no
/// words; `Container` for a short `out`, which needs [`FILE_MAX`], or for
/// Argon2id memory shorter than [`crate::container::ARGON2_BLOCKS`].
pub fn seal_slot(
    slot: &Slot,
    password: &[u8],
    salt: &[u8; SALT_SIZE],
    nonce: &[u8; NONCE_SIZE],
    kdf: SealKdf<'_>,
    out: &mut [u8],
) -> Result<usize, BackupError> {
    password::check(password).map_err(BackupError::WeakPassword)?;
    let mut plain = [0u8; XPRV_TEXT_MAX];
    let (purpose, n) = plaintext(slot, &mut plain)?;
    let r = seal(purpose, &plain[..n], password, salt, nonce, kdf, out);
    plain.zeroize();
    Ok(r?)
}

/// What [`seal_slot`] seals a slot as: its purpose, and its plaintext in
/// `plain`, the length returned.
fn plaintext(
    slot: &Slot,
    plain: &mut [u8; XPRV_TEXT_MAX],
) -> Result<(Purpose, usize), BackupError> {
    match slot {
        // An empty mnemonic would restore nothing. `Slot::mnemonic` refuses
        // one; this covers a slot built any other way.
        Slot::Mnemonic { mnemonic, .. } if mnemonic.is_empty() => Err(BackupError::Slot(
            SlotError::Bip39(Bip39Error::BadWordCount(0)),
        )),
        Slot::Mnemonic { mnemonic, .. } => {
            let mut seed = [0u8; SEED_PLAINTEXT_MAX];
            let n = seed_plaintext(mnemonic, &mut seed);
            plain[..n].copy_from_slice(&seed[..n]);
            seed.zeroize();
            Ok((Purpose::Seed, n))
        }
        Slot::Xprv(k) => {
            let n = k
                .to_text(PrivatePrefix::Kprv, plain)
                .expect("the buffer is sized for it");
            Ok((Purpose::Xprv, n))
        }
        Slot::RawKey(_) | Slot::Empty => Err(BackupError::NotBackedUp),
    }
}

/// The purpose a slot is sealed under, for deriving its key in steps
/// ([`crate::container::Pbkdf2Steps::sealing`]).
///
/// # Errors
///
/// `NotBackedUp` for a raw-key or empty slot.
pub fn purpose_of(slot: &Slot) -> Result<Purpose, BackupError> {
    match slot {
        Slot::Mnemonic { .. } => Ok(Purpose::Seed),
        Slot::Xprv(_) => Ok(Purpose::Xprv),
        Slot::RawKey(_) | Slot::Empty => Err(BackupError::NotBackedUp),
    }
}

/// [`seal_slot`] under PBKDF2 with the key derived in steps by
/// [`crate::container::Pbkdf2Steps::sealing`]. Only that makes a
/// [`SealingKey`], after holding the password to the policy, so this cannot
/// seal under a password `seal_slot` refuses. The key must match the salt
/// and the slot's purpose, or the file opens under no password.
///
/// # Errors
///
/// As [`seal_slot`] but `WeakPassword`, which the steps refused.
pub fn seal_slot_with_key(
    slot: &Slot,
    key: &SealingKey,
    salt: &[u8; SALT_SIZE],
    nonce: &[u8; NONCE_SIZE],
    out: &mut [u8],
) -> Result<usize, BackupError> {
    let mut plain = [0u8; XPRV_TEXT_MAX];
    let (purpose, n) = plaintext(slot, &mut plain)?;
    let r = seal_with_key(
        purpose,
        &plain[..n],
        key,
        Kdf::Pbkdf2Sha256,
        salt,
        nonce,
        out,
    );
    plain.zeroize();
    Ok(r?)
}

/// Open a backup file into a slot. `passphrase` is what the person typed,
/// ignored for an xprv. `memory` is Argon2id's working memory; without it,
/// an Argon2id card gives `Container(KdfMemory)`.
///
/// # Errors
///
/// `Container` for a bad file or password; `WrongPurpose` for a container
/// that is neither seed nor xprv; `Malformed` for plaintext that is not a
/// mnemonic or a mainnet xprv; `XprvDepth` or `XprvAccount` for an xprv
/// that is neither a master key nor account `0'`; `Slot` for a passphrase
/// too long or outside printable ASCII.
pub fn open_slot(
    file: &[u8],
    password: &[u8],
    passphrase: &[u8],
    memory: Option<&mut [Argon2Block]>,
) -> Result<Slot, BackupError> {
    let mut plain = [0u8; XPRV_TEXT_MAX];
    let opened = open(file, password, &mut plain, memory);
    let r = opened
        .map_err(BackupError::from)
        .and_then(|o| slot_from(o.purpose, &plain[..o.len], passphrase));
    plain.zeroize();
    r
}

/// [`open_slot`] for a PBKDF2 backup, its key derived in steps
/// ([`crate::container::Pbkdf2Steps`]) from what [`backup_kdf`] gives.
///
/// # Errors
///
/// As [`open_slot`].
pub fn open_slot_with_key(
    file: &[u8],
    key: &[u8; KEY_SIZE],
    passphrase: &[u8],
) -> Result<Slot, BackupError> {
    let c = parse(file).map_err(|e| BackupError::Container(OpenError::Framing(e)))?;
    let mut plain = [0u8; XPRV_TEXT_MAX];
    let r = open_with_key(&c, key, &mut plain)
        .map_err(BackupError::from)
        .and_then(|o| slot_from(o.purpose, &plain[..o.len], passphrase));
    plain.zeroize();
    r
}

/// How a backup's key is derived, from its header: what a board needs
/// before asking for the password or deriving in steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackupKdf {
    /// PBKDF2 under this salt, for this purpose: every board opens it.
    Pbkdf2 {
        salt: [u8; SALT_SIZE],
        purpose: Purpose,
    },
    /// Argon2id: only a board with its memory, the P4, opens it.
    Argon2id,
}

/// A seed or xprv backup's derivation, from its header.
///
/// # Errors
///
/// `Container(Framing(..))` for a file that is not a container, or names an
/// unknown derivation (`UnsupportedKdf`); `WrongPurpose` for a container
/// that is neither seed nor xprv, the saltless layout included (`parse`
/// reads it as a transaction's); `Malformed` for a derivation and a salt
/// that do not go together.
pub fn backup_kdf(file: &[u8]) -> Result<BackupKdf, BackupError> {
    let c = parse(file).map_err(|e| BackupError::Container(OpenError::Framing(e)))?;
    if !matches!(c.purpose, Purpose::Seed | Purpose::Xprv) {
        return Err(BackupError::WrongPurpose(c.purpose));
    }
    match (c.kdf, c.salt) {
        (Kdf::Pbkdf2Sha256, Some(salt)) => Ok(BackupKdf::Pbkdf2 {
            salt: *salt,
            purpose: c.purpose,
        }),
        (Kdf::Argon2id, Some(_)) => Ok(BackupKdf::Argon2id),
        _ => Err(BackupError::Malformed),
    }
}

/// What a backup's plaintext is, as a slot: a seed with the passphrase
/// typed, or an xprv.
fn slot_from(purpose: Purpose, plain: &[u8], passphrase: &[u8]) -> Result<Slot, BackupError> {
    match purpose {
        Purpose::Seed => {
            mnemonic_from_plaintext(plain).and_then(|m| Ok(Slot::mnemonic(m, passphrase)?))
        }
        Purpose::Xprv => match ExtendedPrivateKey::from_text(plain) {
            // A master key or account `0'`, what a wallet can open: refused
            // at import, not stored as a slot that then fails to open.
            Ok((PrivatePrefix::Kprv, k)) => match k.depth() {
                0 => Ok(Slot::Xprv(k)),
                d if usize::from(d) == ACCOUNT_LEVELS
                    && k.child_number() == SINGLE_ACCOUNT[ACCOUNT_LEVELS - 1] =>
                {
                    Ok(Slot::Xprv(k))
                }
                d if usize::from(d) == ACCOUNT_LEVELS => Err(BackupError::XprvAccount {
                    child: k.child_number().0,
                }),
                depth => Err(BackupError::XprvDepth { depth }),
            },
            _ => Err(BackupError::Malformed),
        },
        other => Err(BackupError::WrongPurpose(other)),
    }
}
