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

//! Sealing and opening a steganography backup, and the walk key.
//!
//! The descriptor is the password: a caption-like line, in plain sight in
//! the photo (Descriptor carrier) or nowhere (Picture carrier). The key
//! comes from it, so it is handled here; level 1 only writes it as a
//! caption. No strength rule applies: it can be public by design.
//!
//! The words and the recovery hint share one container under
//! [`Purpose::Stego`], so an import derives one key. Always PBKDF2, the P4
//! included: a photo should outlive devices, and every unit opens PBKDF2.
//!
//! # The plaintext
//!
//! ```text
//! [words: u8][index: u16 LE] x words [hint: ASCII, 0 to 64 bytes]
//! ```
//!
//! The hint is whatever follows the indices: no separator, and an empty
//! hint is no bytes.
//!
//! v1.0.7 sealed the seed ([`Purpose::Seed`]) and an optional hint
//! ([`Purpose::Raw`]) apart, each with its own salt and so its own key:
//! [`open_legacy_seed`] and [`open_legacy_hint`] open what level 1 rebuilds
//! from the photo.

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use kassigner_protocol::container::{parse, Kdf, Purpose, NONCE_SIZE, SALT_SIZE};
use kassigner_protocol::stego::walk::{KEY_LABEL, KEY_SIZE as WALK_KEY_SIZE};

use crate::backup::{mnemonic_from_plaintext, seed_plaintext, SEED_PLAINTEXT_MAX};
use crate::bip39::{Mnemonic, WORDS_24};
use crate::container::{
    self, open, open_with_key, seal, seal_with_key, OpenError, Pbkdf2Steps, SealKdf, SealingKey,
    KEY_SIZE,
};

/// Longest recovery hint, v1.0.7's.
pub const HINT_MAX: usize = 64;

/// Longest plaintext: the count, 24 indices, the hint.
pub const PLAINTEXT_MAX: usize = 1 + SEED_PLAINTEXT_MAX + HINT_MAX;

/// Bytes a sealed stego container takes at most.
pub const CONTAINER_MAX: usize = kassigner_protocol::container::file_size(PLAINTEXT_MAX);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StegoError {
    Container(OpenError),
    /// The container is not a stego backup, nor, for the legacy functions,
    /// the seed or hint container they expect.
    WrongPurpose(Purpose),
    /// A hint longer than [`HINT_MAX`], or outside printable ASCII.
    Hint,
    /// Plaintext that is not a word count, that many indices in the list
    /// with a good checksum, and an ASCII hint.
    Malformed,
}

impl From<OpenError> for StegoError {
    fn from(e: OpenError) -> Self {
        StegoError::Container(e)
    }
}

/// The Picture carrier's walk key for a descriptor: `SHA-256(label ||
/// descriptor)`, v1.0.7's, so its photos are read with the same walk.
pub fn walk_key(descriptor: &[u8]) -> [u8; WALK_KEY_SIZE] {
    let mut h = Sha256::new();
    h.update(KEY_LABEL);
    h.update(descriptor);
    h.finalize().into()
}

/// Whether a hint can be sealed: its length and characters.
pub fn hint_ok(hint: &[u8]) -> bool {
    hint.len() <= HINT_MAX && hint.iter().all(|&c| (0x20..=0x7E).contains(&c))
}

/// The plaintext for a mnemonic and a hint, into `out`; its length.
fn plaintext(
    m: &Mnemonic,
    hint: &[u8],
    out: &mut [u8; PLAINTEXT_MAX],
) -> Result<usize, StegoError> {
    if !hint_ok(hint) {
        return Err(StegoError::Hint);
    }
    if m.is_empty() {
        return Err(StegoError::Malformed);
    }
    out[0] = m.len() as u8;
    let mut seed = [0u8; SEED_PLAINTEXT_MAX];
    let n = seed_plaintext(m, &mut seed);
    out[1..1 + n].copy_from_slice(&seed[..n]);
    seed.zeroize();
    out[1 + n..1 + n + hint.len()].copy_from_slice(hint);
    Ok(1 + n + hint.len())
}

/// A mnemonic and the hint's length from an opened plaintext, the hint
/// copied into `hint`.
fn unpack(plain: &[u8], hint: &mut [u8; HINT_MAX]) -> Result<(Mnemonic, usize), StegoError> {
    let words = usize::from(*plain.first().ok_or(StegoError::Malformed)?);
    if words > WORDS_24 || plain.len() < 1 + words * 2 {
        return Err(StegoError::Malformed);
    }
    let m = mnemonic_from_plaintext(&plain[1..1 + words * 2]).map_err(|_| StegoError::Malformed)?;
    let h = &plain[1 + words * 2..];
    if !hint_ok(h) {
        return Err(StegoError::Malformed);
    }
    hint[..h.len()].copy_from_slice(h);
    Ok((m, h.len()))
}

/// Seal a mnemonic and a hint under the descriptor, PBKDF2, into `out`:
/// the container level 1 strips for the photo. Returns bytes written.
///
/// # Errors
///
/// `Hint`; `Malformed` for an empty mnemonic; `Container` for a short
/// `out` (needs [`CONTAINER_MAX`]) or a zero salt or nonce.
pub fn seal_backup(
    m: &Mnemonic,
    hint: &[u8],
    descriptor: &[u8],
    salt: &[u8; SALT_SIZE],
    nonce: &[u8; NONCE_SIZE],
    out: &mut [u8],
) -> Result<usize, StegoError> {
    let mut plain = [0u8; PLAINTEXT_MAX];
    let n = plaintext(m, hint, &mut plain)?;
    let r = seal(
        Purpose::Stego,
        &plain[..n],
        descriptor,
        salt,
        nonce,
        SealKdf::Pbkdf2Sha256,
        out,
    );
    plain.zeroize();
    Ok(r?)
}

/// The derivation for a stego backup in steps, for a progress bar:
/// [`Pbkdf2Steps::sealing`] with the descriptor, the salt and
/// [`Purpose::Stego`]. [`container::policy`] never refuses a descriptor, so
/// this cannot fail.
pub fn steps(descriptor: &[u8], salt: &[u8; SALT_SIZE]) -> Pbkdf2Steps {
    Pbkdf2Steps::stego(descriptor, salt)
}

/// [`seal_backup`] with the key already derived by [`steps`] for the same
/// salt: its [`Pbkdf2Steps::sealing_key`].
pub fn seal_backup_with_key(
    m: &Mnemonic,
    hint: &[u8],
    key: &SealingKey,
    salt: &[u8; SALT_SIZE],
    nonce: &[u8; NONCE_SIZE],
    out: &mut [u8],
) -> Result<usize, StegoError> {
    let mut plain = [0u8; PLAINTEXT_MAX];
    let n = plaintext(m, hint, &mut plain)?;
    let r = seal_with_key(
        Purpose::Stego,
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

/// Open a stego container under the descriptor: the mnemonic, and the hint
/// into `hint`, its length returned.
///
/// # Errors
///
/// `WrongPurpose` for any other container, before any derivation;
/// `Container(Authentication)` for a wrong descriptor; `Malformed`.
pub fn open_backup(
    file: &[u8],
    descriptor: &[u8],
    hint: &mut [u8; HINT_MAX],
) -> Result<(Mnemonic, usize), StegoError> {
    let c = parse(file).map_err(OpenError::Framing)?;
    if c.purpose != Purpose::Stego {
        return Err(StegoError::WrongPurpose(c.purpose));
    }
    let mut plain = [0u8; PLAINTEXT_MAX];
    let r = open(file, descriptor, &mut plain, None)
        .map_err(StegoError::from)
        .and_then(|o| unpack(&plain[..o.len], hint));
    plain.zeroize();
    r
}

/// [`open_backup`] with the key already derived by [`steps`] from the
/// file's salt.
pub fn open_backup_with_key(
    file: &[u8],
    key: &[u8; KEY_SIZE],
    hint: &mut [u8; HINT_MAX],
) -> Result<(Mnemonic, usize), StegoError> {
    let c = parse(file).map_err(OpenError::Framing)?;
    if c.purpose != Purpose::Stego {
        return Err(StegoError::WrongPurpose(c.purpose));
    }
    let mut plain = [0u8; PLAINTEXT_MAX];
    let r = open_with_key(&c, key, &mut plain)
        .map_err(StegoError::from)
        .and_then(|o| unpack(&plain[..o.len], hint));
    plain.zeroize();
    r
}

/// Whether `key`, derived by [`steps`] from the file's salt, is the
/// descriptor a stego backup ([`Purpose::Stego`]) or a v1.0.7 seed
/// ([`Purpose::Seed`]) was sealed under, before hiding a backup over it.
/// The tag is checked in place, so no seed or hint reaches a buffer, and
/// [`container::check_with_key`] leaves the ciphertext wiped: pass a copy.
///
/// # Errors
///
/// `WrongPurpose` for any other container, before the check;
/// `Container(Authentication)` for another descriptor; `Container` for a
/// malformed file.
pub fn check_backup_with_key(file: &mut [u8], key: &[u8; KEY_SIZE]) -> Result<(), StegoError> {
    let c = parse(file).map_err(OpenError::Framing)?;
    if !matches!(c.purpose, Purpose::Stego | Purpose::Seed) {
        return Err(StegoError::WrongPurpose(c.purpose));
    }
    container::check_with_key(file, key)?;
    Ok(())
}

/// The salt and purpose of a stego backup or a legacy seed or hint, for
/// [`Pbkdf2Steps::new`].
///
/// # Errors
///
/// `Container(Framing(..))` for a file that is not a container or not
/// under PBKDF2; `WrongPurpose` for one that is none of the three, the
/// saltless layout included (read as a transaction's).
pub fn kdf_of(file: &[u8]) -> Result<([u8; SALT_SIZE], Purpose), StegoError> {
    let c = parse(file).map_err(OpenError::Framing)?;
    if !matches!(c.purpose, Purpose::Stego | Purpose::Seed | Purpose::Raw) {
        return Err(StegoError::WrongPurpose(c.purpose));
    }
    if c.kdf != Kdf::Pbkdf2Sha256 {
        return Err(StegoError::Container(OpenError::Framing(
            kassigner_protocol::container::ContainerError::UnsupportedKdf(c.kdf as u8),
        )));
    }
    let salt = c.salt.ok_or(StegoError::Malformed)?;
    Ok((*salt, c.purpose))
}

/// Open a v1.0.7 seed container, [`Purpose::Seed`], under the descriptor.
///
/// # Errors
///
/// `WrongPurpose`; `Container`; `Malformed`.
pub fn open_legacy_seed(file: &[u8], descriptor: &[u8]) -> Result<Mnemonic, StegoError> {
    let c = parse(file).map_err(OpenError::Framing)?;
    if c.purpose != Purpose::Seed {
        return Err(StegoError::WrongPurpose(c.purpose));
    }
    let mut plain = [0u8; SEED_PLAINTEXT_MAX];
    let r = open(file, descriptor, &mut plain, None)
        .map_err(StegoError::from)
        .and_then(|o| mnemonic_from_plaintext(&plain[..o.len]).map_err(|_| StegoError::Malformed));
    plain.zeroize();
    r
}

/// [`open_legacy_seed`] with the key already derived.
pub fn open_legacy_seed_with_key(
    file: &[u8],
    key: &[u8; KEY_SIZE],
) -> Result<Mnemonic, StegoError> {
    let c = parse(file).map_err(OpenError::Framing)?;
    if c.purpose != Purpose::Seed {
        return Err(StegoError::WrongPurpose(c.purpose));
    }
    let mut plain = [0u8; SEED_PLAINTEXT_MAX];
    let r = open_with_key(&c, key, &mut plain)
        .map_err(StegoError::from)
        .and_then(|o| mnemonic_from_plaintext(&plain[..o.len]).map_err(|_| StegoError::Malformed));
    plain.zeroize();
    r
}

/// Open a v1.0.7 hint container, [`Purpose::Raw`], under the descriptor,
/// into `hint`; its length. A hint that does not open is no hint: the seed
/// stands alone and the caller shows none.
///
/// # Errors
///
/// `WrongPurpose`; `Container`; `Malformed` for a hint past [`HINT_MAX`]
/// or outside ASCII.
pub fn open_legacy_hint(
    file: &[u8],
    descriptor: &[u8],
    hint: &mut [u8; HINT_MAX],
) -> Result<usize, StegoError> {
    let c = parse(file).map_err(OpenError::Framing)?;
    if c.purpose != Purpose::Raw {
        return Err(StegoError::WrongPurpose(c.purpose));
    }
    if c.len > HINT_MAX {
        return Err(StegoError::Malformed);
    }
    let mut plain = [0u8; HINT_MAX];
    let r = open(file, descriptor, &mut plain, None)
        .map_err(StegoError::from)
        .and_then(|o| hint_bytes(&plain[..o.len], hint));
    plain.zeroize();
    r
}

/// [`open_legacy_hint`] with the key already derived.
pub fn open_legacy_hint_with_key(
    file: &[u8],
    key: &[u8; KEY_SIZE],
    hint: &mut [u8; HINT_MAX],
) -> Result<usize, StegoError> {
    let c = parse(file).map_err(OpenError::Framing)?;
    if c.purpose != Purpose::Raw {
        return Err(StegoError::WrongPurpose(c.purpose));
    }
    if c.len > HINT_MAX {
        return Err(StegoError::Malformed);
    }
    let mut plain = [0u8; HINT_MAX];
    let r = open_with_key(&c, key, &mut plain)
        .map_err(StegoError::from)
        .and_then(|o| hint_bytes(&plain[..o.len], hint));
    plain.zeroize();
    r
}

fn hint_bytes(plain: &[u8], hint: &mut [u8; HINT_MAX]) -> Result<usize, StegoError> {
    if !hint_ok(plain) {
        return Err(StegoError::Malformed);
    }
    hint[..plain.len()].copy_from_slice(plain);
    Ok(plain.len())
}
