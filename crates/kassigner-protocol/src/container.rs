// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The encrypted container: a cleartext header saying what it is and how
//! its key is derived, which is the AAD, then a nonce, the ciphertext and a
//! tag.
//!
//! Unlike every other format here, no [`Profile`](crate::profile::Profile)
//! bounds it: a card outlives the device that wrote it and moves between
//! devices, so every device must read every card.
//!
//! `V1`, magic `KAS\x06`, is written; two older layouts are only read.
//!
//! | magic | carries | length | salt |
//! |---|---|---|---|
//! | `KAS\x06` | anything | `u16` | per file, 16 bytes |
//! | `KAS\x04` | seed, xprv, raw | `u8` | per file, 16 bytes |
//! | `KAS\x03` | transactions and exports | `u16` | none |
//!
//! Every offset after the length field differs between them, so the layout
//! is resolved once from the magic.
//!
//! `KAS\x03` has no salt: its key is PBKDF2 over `"KasSigner-KSPT-v1"`
//! (`kassigner-crypto`'s `FIXED_SALT`) in every file, so one table of
//! guessed passwords opens them all; the newer layouts carry a per-file
//! salt. It held four kinds of file, a multisig descriptor among them: a
//! secret with no on-chain record and no recovery.
//!
//! Magic bytes taken: `\x01` seed and `\x02` xprv and raw (no longer read),
//! `\x03`, `\x04`, `\x06`. `\x05` stays unused, as it is easily confused with
//! KSPT's `0x05` version; the next free magic is `\x07`.
//!
//! No key derivation or encryption, which need a passphrase and belong to
//! the crate holding key material: this checks the framing and hands back
//! the AAD, salt, nonce, ciphertext and tag.

/// What a container carries. Bound into the AAD and into the key, so a
/// container of one purpose cannot produce the key of another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Purpose {
    Seed = 1,
    Xprv = 2,
    Raw = 3,
    Kspt = 4,
    /// Sign Message's signed messages, sealed: never offered by a list of
    /// kpub files, which looks for KSPT.
    Text = 5,
    /// A multisig cosigner's kpub, `m/45'/111111'/0'`: a unit's sealed
    /// `.K45` file. Readable before the password, so a group takes only a key
    /// marked as a cosigner's, never a watch-only `44'` kpub (KSPT's).
    Cosigner = 6,
    /// A multisig group's descriptor: a unit's sealed `MDnnnn.TXT`.
    /// Readable before the password, so the descriptor import takes only a
    /// file marked as one.
    Descriptor = 7,
    /// A steganography backup, the seed's words and recovery hint, hidden in
    /// a photo by [`crate::stego`]. Its own purpose, so it and a card backup
    /// never open as each other. Always PBKDF2, even on the P4, so any unit
    /// opens it.
    Stego = 8,
}

impl Purpose {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Purpose::Seed),
            2 => Some(Purpose::Xprv),
            3 => Some(Purpose::Raw),
            4 => Some(Purpose::Kspt),
            5 => Some(Purpose::Text),
            6 => Some(Purpose::Cosigner),
            7 => Some(Purpose::Descriptor),
            8 => Some(Purpose::Stego),
            _ => None,
        }
    }
}

/// Which key-derivation function produced the key: a field, so a stronger
/// one can be added without a new format.
///
/// Every reader recognises every value, so a card it cannot open, such as
/// [`Kdf::Argon2id`] on a board without the memory, is refused by name at
/// level 2, not reported as damage. A value's parameters, fixed at level 2,
/// are part of its meaning: a stronger setting is a new value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kdf {
    /// PBKDF2-HMAC-SHA256, 100,000 iterations, over the per-file salt.
    Pbkdf2Sha256 = 1,
    /// Argon2id, RFC 9106, over the per-file salt. Memory-hard: a guess
    /// costs memory, not only time. Written by boards with the memory, the
    /// ESP32-P4; a board without it refuses the card.
    Argon2id = 2,
    /// PBKDF2-HMAC-SHA256, 100,000 iterations, over a fixed salt. No
    /// `kdf_id`: implied by [`Layout::LegacyNoSalt`], which has no field for
    /// one. Never written.
    Pbkdf2Sha256Fixed = 0xFE,
}

impl Kdf {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Kdf::Pbkdf2Sha256),
            2 => Some(Kdf::Argon2id),
            _ => None,
        }
    }
}

/// Which layout a container uses.
///
/// `KAS\x01` and `KAS\x02`, the seed and xprv backups of v1.0.5 and
/// earlier under one fixed salt, are refused as [`ContainerError::BadMagic`].
/// Such a card is opened on v1.0.7 and saved again, or its seed restored
/// from its words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    /// `KAS\x06`, a two-byte length and a per-file salt. The one written.
    V1,
    /// `KAS\x04`, a one-byte length and a per-file salt. Read, never written.
    Legacy,
    /// `KAS\x03`, a two-byte length and no salt. Read, never written. Its
    /// key uses one salt fixed for every file, and the length follows the
    /// magic: no version, purpose or KDF byte.
    LegacyNoSalt,
}

/// Magic of the current layout.
pub const MAGIC_V1: [u8; 4] = [b'K', b'A', b'S', 0x06];
/// Magic of the legacy layout.
pub const MAGIC_LEGACY: [u8; 4] = [b'K', b'A', b'S', 0x04];
/// Magic of the oldest layout, which carries no salt.
pub const MAGIC_LEGACY_NO_SALT: [u8; 4] = [b'K', b'A', b'S', 0x03];

/// Per-file salt length.
pub const SALT_SIZE: usize = 16;
/// AES-GCM nonce length.
pub const NONCE_SIZE: usize = 12;
/// AES-GCM tag length.
pub const TAG_SIZE: usize = 16;

impl Layout {
    const fn from_magic(m: &[u8]) -> Option<Self> {
        if m.len() < 4 {
            return None;
        }
        let m4 = [m[0], m[1], m[2], m[3]];
        if eq4(m4, MAGIC_V1) {
            Some(Layout::V1)
        } else if eq4(m4, MAGIC_LEGACY) {
            Some(Layout::Legacy)
        } else if eq4(m4, MAGIC_LEGACY_NO_SALT) {
            Some(Layout::LegacyNoSalt)
        } else {
            None
        }
    }

    /// Width of the length field, in bytes.
    const fn len_width(self) -> usize {
        match self {
            Layout::V1 | Layout::LegacyNoSalt => 2,
            Layout::Legacy => 1,
        }
    }

    /// Whether this layout carries a per-file salt.
    pub const fn has_salt(self) -> bool {
        !matches!(self, Layout::LegacyNoSalt)
    }

    /// Offset of the length field.
    const fn len_offset(self) -> usize {
        match self {
            // magic, version, purpose, kdf_id
            Layout::V1 | Layout::Legacy => 7,
            // magic only: this layout has no version, purpose or kdf byte
            Layout::LegacyNoSalt => 4,
        }
    }

    /// Offset of the salt. The AAD is the whole header through the salt, one
    /// slice, so no caller can assemble it in the wrong order.
    const fn salt_offset(self) -> usize {
        self.len_offset() + self.len_width()
    }

    /// Bytes the header occupies, salt included where there is one.
    pub const fn header_size(self) -> usize {
        match self {
            Layout::LegacyNoSalt => self.salt_offset(),
            _ => self.salt_offset() + SALT_SIZE,
        }
    }

    /// Bytes a container adds to its plaintext.
    pub const fn overhead(self) -> usize {
        self.header_size() + NONCE_SIZE + TAG_SIZE
    }
}

const fn eq4(a: [u8; 4], b: [u8; 4]) -> bool {
    a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContainerError {
    /// Shorter than the header, or than the length field claims.
    Truncated { at: usize },
    /// Not a container of any layout this reader knows.
    BadMagic,
    /// A version byte this layout does not define.
    BadVersion(u8),
    /// A purpose byte with no meaning.
    BadPurpose(u8),
    /// A key-derivation function this reader does not implement: the file
    /// is probably valid and the reader too old, not a corrupt file.
    UnsupportedKdf(u8),
    /// The declared plaintext length disagrees with the file size.
    LengthMismatch { declared: usize, available: usize },
    /// The caller's buffer cannot hold the plaintext.
    BufferTooSmall,
}

/// A container's framing, its parts borrowed from the file. No key and no
/// decryption: `aad`, `salt`, `nonce`, `ciphertext` and `tag` go to the
/// caller's cipher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Container<'a> {
    pub layout: Layout,
    pub version: u8,
    pub purpose: Purpose,
    pub kdf: Kdf,
    /// Declared plaintext length, checked equal to `ciphertext.len()`.
    pub len: usize,
    /// The whole header through the salt. Authenticated, not encrypted.
    pub aad: &'a [u8],
    /// `None` on [`Layout::LegacyNoSalt`], which has no per-file salt.
    pub salt: Option<&'a [u8; SALT_SIZE]>,
    pub nonce: &'a [u8; NONCE_SIZE],
    pub ciphertext: &'a [u8],
    pub tag: &'a [u8; TAG_SIZE],
}

/// Parse a container's framing.
///
/// # Errors
///
/// The first fault found, left to right. Nothing here authenticates: a
/// container that parses may still fail its tag, which whoever holds the key
/// checks.
pub fn parse(file: &[u8]) -> Result<Container<'_>, ContainerError> {
    let layout = Layout::from_magic(file).ok_or(ContainerError::BadMagic)?;
    let header_size = layout.header_size();
    if file.len() < header_size + NONCE_SIZE + TAG_SIZE {
        return Err(ContainerError::Truncated { at: file.len() });
    }

    // The oldest layout is the magic and a length, with no version, purpose
    // or KDF byte. Its purpose is read as KSPT whatever it holds, of the
    // four kinds v1.0.7 sealed in it: what a file holds is known only once
    // it is opened. The card's kpub list finds v1.0.7's sealed kpubs by it.
    let (version, purpose, kdf) = match layout {
        Layout::LegacyNoSalt => (0u8, Purpose::Kspt, Kdf::Pbkdf2Sha256Fixed),
        _ => {
            let version = file[4];
            let expected_version = match layout {
                Layout::V1 => 1,
                _ => 3,
            };
            if version != expected_version {
                return Err(ContainerError::BadVersion(version));
            }
            let purpose = Purpose::from_u8(file[5]).ok_or(ContainerError::BadPurpose(file[5]))?;
            let kdf = Kdf::from_u8(file[6]).ok_or(ContainerError::UnsupportedKdf(file[6]))?;
            (version, purpose, kdf)
        }
    };

    let lo = layout.len_offset();
    let len = match layout.len_width() {
        1 => file[lo] as usize,
        _ => u16::from_le_bytes([file[lo], file[lo + 1]]) as usize,
    };

    let salt_off = layout.salt_offset();
    let nonce_off = header_size;
    let ct_off = nonce_off + NONCE_SIZE;

    // GCM ciphertext is as long as its plaintext, so the declared length must
    // equal what is there.
    let available = file
        .len()
        .checked_sub(ct_off + TAG_SIZE)
        .ok_or(ContainerError::Truncated { at: ct_off })?;
    if len != available {
        return Err(ContainerError::LengthMismatch {
            declared: len,
            available,
        });
    }

    let aad = &file[..header_size];
    // `None` on the oldest layout, whose salt is fixed for every file.
    let salt: Option<&[u8; SALT_SIZE]> = if layout.has_salt() {
        Some(
            file[salt_off..salt_off + SALT_SIZE]
                .try_into()
                .map_err(|_| ContainerError::Truncated { at: salt_off })?,
        )
    } else {
        None
    };
    let nonce: &[u8; NONCE_SIZE] = file[nonce_off..nonce_off + NONCE_SIZE]
        .try_into()
        .map_err(|_| ContainerError::Truncated { at: nonce_off })?;
    let ciphertext = &file[ct_off..ct_off + len];
    let tag: &[u8; TAG_SIZE] = file[ct_off + len..ct_off + len + TAG_SIZE]
        .try_into()
        .map_err(|_| ContainerError::Truncated { at: ct_off + len })?;

    Ok(Container {
        layout,
        version,
        purpose,
        kdf,
        len,
        aad,
        salt,
        nonce,
        ciphertext,
        tag,
    })
}

/// Bytes a `V1` container of `plaintext_len` occupies.
pub const fn file_size(plaintext_len: usize) -> usize {
    Layout::V1.overhead() + plaintext_len
}

/// Write a `V1` header, the only layout written, into `out` and return it:
/// the AAD, so the bytes authenticated are the bytes written. The caller
/// places the nonce, ciphertext and tag after it.
///
/// # Errors
///
/// `BufferTooSmall` if `out` cannot hold the header; `UnsupportedKdf` for
/// [`Kdf::Pbkdf2Sha256Fixed`], which has no `kdf_id` a reader takes back;
/// `LengthMismatch` for a plaintext longer than the `u16` length can say.
pub fn write_header<'a>(
    purpose: Purpose,
    kdf: Kdf,
    plaintext_len: usize,
    salt: &[u8; SALT_SIZE],
    out: &'a mut [u8],
) -> Result<&'a [u8], ContainerError> {
    let n = Layout::V1.header_size();
    if out.len() < n {
        return Err(ContainerError::BufferTooSmall);
    }
    if Kdf::from_u8(kdf as u8).is_none() {
        return Err(ContainerError::UnsupportedKdf(kdf as u8));
    }
    if plaintext_len > u16::MAX as usize {
        return Err(ContainerError::LengthMismatch {
            declared: plaintext_len,
            available: u16::MAX as usize,
        });
    }
    out[0..4].copy_from_slice(&MAGIC_V1);
    out[4] = 1;
    out[5] = purpose as u8;
    out[6] = kdf as u8;
    out[7..9].copy_from_slice(&(plaintext_len as u16).to_le_bytes());
    out[9..9 + SALT_SIZE].copy_from_slice(salt);
    Ok(&out[..n])
}
