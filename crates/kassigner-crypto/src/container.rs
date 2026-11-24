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

//! Opening and sealing an encrypted container.
//!
//! The other half of `kassigner_protocol::container`, which parses the file
//! into AAD, salt, nonce, ciphertext and tag, all public on a card, at level
//! one. This half holds the password, the key and the plaintext, so it is
//! here. A container password only wraps the seed, unlike a BIP39
//! passphrase, but is still a secret.
//!
//! [`open`] writes into a caller's buffer and returns a length, not an owned
//! secret: a `Vec` needs an allocator, and a fixed array would size every
//! build for one board's largest container. Wiping it is the caller's job.

use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use kassigner_protocol::container::{
    parse, write_header, Container, ContainerError, Kdf, Layout, Purpose, NONCE_SIZE, SALT_SIZE,
    TAG_SIZE,
};

use crate::password::{self, Weakness};

/// PBKDF2 iterations for [`Kdf::Pbkdf2Sha256`].
///
/// Part of what `kdf_id = 1` means: changing it makes every existing card
/// unreadable. A stronger derivation gets a new `kdf_id`.
pub const PBKDF2_ITERATIONS: u32 = 100_000;

/// One 1 KiB block of Argon2id working memory.
///
/// A [`Kdf::Argon2id`] open or seal takes [`ARGON2_BLOCKS`] of these from the
/// caller (no allocator here; PSRAM on the ESP32-P4). They hold
/// password-derived state, which [`derive_key`] wipes before it returns.
pub type Argon2Block = argon2::Block;

/// Argon2id memory, in 1 KiB blocks: 16 MiB.
///
/// Part of what `kdf_id = 2` means: a card written with one memory cost
/// cannot be opened with another. Half the P4 module's 32 MB PSRAM.
pub const ARGON2_M_COST_KIB: u32 = 16 * 1024;

/// Argon2id passes over the memory: four. Part of `kdf_id = 2`.
///
/// Four passes over 16 MiB move 64 MiB per guess, which sets a
/// bandwidth-bound GPU's rate; RFC 9106 recommends at least three where
/// memory is constrained.
pub const ARGON2_T_COST: u32 = 4;

/// Argon2id lanes: one, as one core derives it. Part of `kdf_id = 2`.
pub const ARGON2_P_COST: u32 = 1;

/// The number of [`Argon2Block`]s a caller must pass for [`Kdf::Argon2id`].
pub const ARGON2_BLOCKS: usize = ARGON2_M_COST_KIB as usize;

/// The fixed salt of [`Kdf::Pbkdf2Sha256Fixed`].
///
/// The same on every device, so one precomputed table opens every file
/// under it. Read-only: nothing in this crate seals under it.
pub const FIXED_SALT: &[u8] = b"KasSigner-KSPT-v1";

/// Length of a derived key.
pub const KEY_SIZE: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// The file's framing is wrong.
    Framing(ContainerError),
    /// The tag did not verify: a wrong password, a corrupted file or an
    /// edited header. Not told apart, as telling a person which tells an
    /// attacker too.
    Authentication,
    /// The caller's buffer cannot hold the result: the plaintext when
    /// opening, the file when sealing. Reported before any derivation or
    /// decryption, so it costs and leaks nothing.
    BufferTooSmall { needed: usize },
    /// The derivation needs working memory the caller did not pass, or not
    /// enough: `needed` is in [`Argon2Block`]s.
    ///
    /// A board without the RAM (an ESP32-S3 reading a card an ESP32-P4
    /// wrote), not a bad password, so the person can be told to open the
    /// card on the board that made it, or from the words. Reported before
    /// any derivation.
    KdfMemory { needed: usize },
    /// A seal's salt or nonce is all zeros, what a stopped generator gives:
    /// refused, so a dead generator fails closed. Sealing only.
    ZeroSaltOrNonce,
    /// The password fails [`crate::password`]'s policy. Sealing only, before
    /// anything is derived; never for a stego backup, whose descriptor is
    /// not a password a person chose.
    WeakPassword(Weakness),
}

impl From<ContainerError> for OpenError {
    fn from(e: ContainerError) -> Self {
        OpenError::Framing(e)
    }
}

/// What a successful open produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opened {
    /// Bytes written into the caller's buffer.
    pub len: usize,
    /// What the container says it carries. Authenticated, as part of the
    /// AAD: a rewritten `purpose` fails the tag rather than delivering a seed
    /// labelled as a transaction.
    pub purpose: Purpose,
    /// Which layout the file used.
    pub layout: Layout,
}

/// A key-derivation function together with what it derives from.
///
/// One value, so a derivation and its salt cannot disagree: no salted
/// derivation without a salt, which would drop the per-file salt and the
/// purpose byte, and no fixed one given a salt its key would ignore.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KdfParams<'a> {
    /// `kdf_id = 1`: PBKDF2-HMAC-SHA256 over `salt || purpose`.
    Pbkdf2Sha256 { salt: &'a [u8; SALT_SIZE] },
    /// PBKDF2-HMAC-SHA256 over [`FIXED_SALT`], with no purpose byte: opening
    /// the oldest layout only, which has no salt field.
    Pbkdf2Sha256Fixed,
    /// `kdf_id = 2`: Argon2id over `salt || purpose`, with
    /// [`ARGON2_M_COST_KIB`], [`ARGON2_T_COST`] and [`ARGON2_P_COST`]. Needs
    /// [`ARGON2_BLOCKS`] of working memory from the caller.
    Argon2id { salt: &'a [u8; SALT_SIZE] },
}

impl<'a> KdfParams<'a> {
    /// The parameters a parsed container calls for.
    ///
    /// # Errors
    ///
    /// `Framing` for a derivation and a salt that do not go together, which
    /// [`parse`] never gives: returned rather than assumed, and matched
    /// without a wildcard so a new derivation stops compiling here.
    pub fn of(c: &Container<'a>) -> Result<Self, OpenError> {
        match (c.kdf, c.salt) {
            (Kdf::Pbkdf2Sha256, Some(salt)) => Ok(Self::Pbkdf2Sha256 { salt }),
            (Kdf::Argon2id, Some(salt)) => Ok(Self::Argon2id { salt }),
            (Kdf::Pbkdf2Sha256Fixed, None) => Ok(Self::Pbkdf2Sha256Fixed),
            (Kdf::Pbkdf2Sha256, None)
            | (Kdf::Argon2id, None)
            | (Kdf::Pbkdf2Sha256Fixed, Some(_)) => Err(OpenError::Framing(
                ContainerError::UnsupportedKdf(c.kdf as u8),
            )),
        }
    }

    /// The `kdf_id` a header records for these parameters.
    pub const fn id(self) -> Kdf {
        match self {
            KdfParams::Pbkdf2Sha256 { .. } => Kdf::Pbkdf2Sha256,
            KdfParams::Pbkdf2Sha256Fixed => Kdf::Pbkdf2Sha256Fixed,
            KdfParams::Argon2id { .. } => Kdf::Argon2id,
        }
    }

    /// The [`Argon2Block`]s these parameters need from the caller: none for
    /// PBKDF2, [`ARGON2_BLOCKS`] for Argon2id.
    pub const fn memory_needed(self) -> usize {
        match self {
            KdfParams::Pbkdf2Sha256 { .. } | KdfParams::Pbkdf2Sha256Fixed => 0,
            KdfParams::Argon2id { .. } => ARGON2_BLOCKS,
        }
    }
}

/// Which derivation to seal a new container under.
///
/// Not [`KdfParams`]: the fixed-salt derivation only opens, so it has no
/// value here, and Argon2id carries its working memory so the two cannot
/// disagree.
pub enum SealKdf<'m> {
    /// `kdf_id = 1`: PBKDF2-HMAC-SHA256, 100,000 iterations. Every board
    /// can open it.
    Pbkdf2Sha256,
    /// `kdf_id = 2`: Argon2id over the [`ARGON2_BLOCKS`] passed here. Only a
    /// board with the memory, the ESP32-P4, can open it.
    Argon2id(&'m mut [Argon2Block]),
}

/// Derive the wrapping key from a password, a salt and a purpose.
///
/// **The salt is `salt || purpose`, seventeen bytes**, for PBKDF2 and
/// Argon2id alike. The purpose byte is in the key as well as the AAD, so a
/// container of one kind cannot produce another's key: rewriting the byte
/// breaks both.
///
/// Separate from [`open`] so containers sharing a salt and purpose, as every
/// file of the oldest layout does, cost one slow derivation.
///
/// `memory` is the Argon2id working memory, ignored by PBKDF2 and wiped
/// before returning: password-derived state, in PSRAM nothing else scrubs.
///
/// The returned key is a secret; it wipes itself when dropped.
///
/// # Errors
///
/// `KdfMemory`, with nothing derived, when the parameters need memory and
/// `memory` is `None` or shorter than [`ARGON2_BLOCKS`].
pub fn derive_key(
    params: KdfParams<'_>,
    password: &[u8],
    purpose: Purpose,
    memory: Option<&mut [Argon2Block]>,
) -> Result<Zeroizing<[u8; KEY_SIZE]>, OpenError> {
    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    match params {
        KdfParams::Pbkdf2Sha256 { salt } => {
            let mut kdf_salt = [0u8; SALT_SIZE + 1];
            kdf_salt[..SALT_SIZE].copy_from_slice(salt);
            kdf_salt[SALT_SIZE] = purpose as u8;
            pbkdf2::pbkdf2::<Hmac<Sha256>>(password, &kdf_salt, PBKDF2_ITERATIONS, &mut key[..])
                .expect("KEY_SIZE is a valid PBKDF2 output length");
            kdf_salt.zeroize();
        }
        // The oldest layout: a fixed salt, and no purpose byte, as the format
        // has no field for one.
        KdfParams::Pbkdf2Sha256Fixed => {
            pbkdf2::pbkdf2::<Hmac<Sha256>>(password, FIXED_SALT, PBKDF2_ITERATIONS, &mut key[..])
                .expect("KEY_SIZE is a valid PBKDF2 output length");
        }
        KdfParams::Argon2id { salt } => {
            let needed = ARGON2_BLOCKS;
            let blocks = match memory {
                Some(m) if m.len() >= needed => &mut m[..needed],
                _ => return Err(OpenError::KdfMemory { needed }),
            };
            let mut kdf_salt = [0u8; SALT_SIZE + 1];
            kdf_salt[..SALT_SIZE].copy_from_slice(salt);
            kdf_salt[SALT_SIZE] = purpose as u8;
            let argon = Params::new(
                ARGON2_M_COST_KIB,
                ARGON2_T_COST,
                ARGON2_P_COST,
                Some(KEY_SIZE),
            )
            .expect("the Argon2id constants are valid parameters");
            let r = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon)
                .hash_password_into_with_memory(password, &kdf_salt, &mut key[..], &mut *blocks);
            // Wiped whatever happened: password-derived state in the caller's
            // memory.
            for b in blocks.iter_mut() {
                b.zeroize();
            }
            kdf_salt.zeroize();
            // Memory, salt and output lengths are checked above; nothing else
            // fails with these constants.
            r.expect("Argon2id inputs are checked before the call");
        }
    }
    Ok(key)
}

/// Open a container with a password: derive the key, then decrypt.
///
/// `out` receives the plaintext, a secret the caller must wipe. `memory` is
/// the Argon2id working memory, needed only for a [`Kdf::Argon2id`] card; a
/// board without it passes `None` and gets `KdfMemory` for such a card.
///
/// # Errors
///
/// `Framing` for a malformed file, `BufferTooSmall` and `KdfMemory` before
/// any derivation, `Authentication` if the tag does not verify.
pub fn open(
    file: &[u8],
    password: &[u8],
    out: &mut [u8],
    memory: Option<&mut [Argon2Block]>,
) -> Result<Opened, OpenError> {
    let c = parse(file)?;
    if out.len() < c.len {
        return Err(OpenError::BufferTooSmall { needed: c.len });
    }
    let key = derive_key(KdfParams::of(&c)?, password, c.purpose, memory)?;
    open_with_key(&c, &key, out)
}

/// Open a container with a key already derived for its salt and purpose
/// (see [`derive_key`]).
///
/// # Errors
///
/// `BufferTooSmall` before any decryption, `Authentication` if the tag does
/// not verify.
pub fn open_with_key(
    c: &Container<'_>,
    key: &[u8; KEY_SIZE],
    out: &mut [u8],
) -> Result<Opened, OpenError> {
    if out.len() < c.len {
        return Err(OpenError::BufferTooSmall { needed: c.len });
    }
    let buf = &mut out[..c.len];
    buf.copy_from_slice(c.ciphertext);

    let cipher = Aes256Gcm::new(key.into());
    let tag = aes_gcm::Tag::from(*c.tag);
    // The AAD is level 1's slice of the header, not the fields reassembled,
    // so the two halves cannot disagree on what is authenticated.
    match cipher.decrypt_inout_detached(&Nonce::from(*c.nonce), c.aad, (&mut *buf).into(), &tag) {
        Ok(()) => Ok(Opened {
            len: c.len,
            purpose: c.purpose,
            layout: c.layout,
        }),
        Err(_) => {
            // aes-gcm 0.11 checks the tag before decrypting, so `buf` holds
            // the ciphertext, not a wrong plaintext. Wiped anyway: a caller
            // ignoring the error finds zeros, whatever a later aes-gcm does.
            buf.zeroize();
            Err(OpenError::Authentication)
        }
    }
}

/// Whether a key opens the container `file` holds, decrypted in `file`
/// itself: for a unit checking a sealed file's password before writing over
/// or deleting it, with no second buffer the size of a signed transaction.
///
/// The ciphertext is wiped either way, so `file` no longer opens; header,
/// nonce and tag are left for the caller to wipe. The key must be derived
/// for this container's salt and purpose (see [`derive_key`]).
///
/// # Errors
///
/// `Framing` for a malformed file, `Authentication` if the tag does not
/// verify.
pub fn check_with_key(file: &mut [u8], key: &[u8; KEY_SIZE]) -> Result<Opened, OpenError> {
    let c = parse(file)?;
    let opened = Opened {
        len: c.len,
        purpose: c.purpose,
        layout: c.layout,
    };
    let nonce = Nonce::from(*c.nonce);
    let tag = aes_gcm::Tag::from(*c.tag);
    // Every layout is the header (the AAD), nonce, ciphertext and tag, and
    // `parse` has checked their lengths add up to the file's.
    let (aad, body) = file.split_at_mut(c.layout.header_size());
    let ct = &mut body[NONCE_SIZE..NONCE_SIZE + opened.len];
    let r = Aes256Gcm::new(key.into()).decrypt_inout_detached(&nonce, aad, ct.into(), &tag);
    // The plaintext, or under a wrong key the untouched ciphertext (aes-gcm
    // checks the tag first): wiped either way, as in `open_with_key`.
    ct.zeroize();
    r.map(|()| opened).map_err(|_| OpenError::Authentication)
}

/// Refuse an all-zero salt or nonce: not a randomness test, but the one
/// value a stopped generator is sure to give, checked on every seal.
fn fresh(salt: &[u8; SALT_SIZE], nonce: &[u8; NONCE_SIZE]) -> Result<(), OpenError> {
    if salt.iter().all(|&b| b == 0) || nonce.iter().all(|&b| b == 0) {
        return Err(OpenError::ZeroSaltOrNonce);
    }
    Ok(())
}

/// Seal a plaintext into a container, returning the file length.
///
/// `salt` and `nonce` come from the caller, as this crate has no entropy
/// source, and must be fresh per file: a repeated salt lets one precomputed
/// table open every card sharing a password, and a repeated nonce under one
/// key breaks AES-GCM outright.
///
/// Only the current layout is written, so [`SealKdf`] has no fixed-salt
/// value. The password is held to [`policy`] first.
///
/// # Errors
///
/// `WeakPassword` first; then, before any derivation, `ZeroSaltOrNonce`,
/// `BufferTooSmall` if `out` cannot hold the file and `Framing` for a
/// plaintext past what the length field can say; `KdfMemory` if the
/// Argon2id memory is shorter than [`ARGON2_BLOCKS`].
pub fn seal(
    purpose: Purpose,
    plaintext: &[u8],
    password: &[u8],
    salt: &[u8; SALT_SIZE],
    nonce: &[u8; NONCE_SIZE],
    kdf: SealKdf<'_>,
    out: &mut [u8],
) -> Result<usize, OpenError> {
    policy(purpose, password).map_err(OpenError::WeakPassword)?;
    seal_past_policy(purpose, plaintext, password, salt, nonce, kdf, out)
}

/// [`seal`] past [`policy`], for [`crate::backup`] alone: a seed's backup
/// holds its password to a rule of its own, which lets a seed that has a
/// passphrase be sealed under no password
/// ([`crate::backup::passphrase_guards`]). Nothing else may skip the policy,
/// so this does not leave the crate.
///
/// # Errors
///
/// As [`seal`] but `WeakPassword`.
pub(crate) fn seal_past_policy(
    purpose: Purpose,
    plaintext: &[u8],
    password: &[u8],
    salt: &[u8; SALT_SIZE],
    nonce: &[u8; NONCE_SIZE],
    kdf: SealKdf<'_>,
    out: &mut [u8],
) -> Result<usize, OpenError> {
    fresh(salt, nonce)?;
    // Before the derivation, seconds of PBKDF2 or 16 MiB of Argon2id, so a
    // file that will not fit costs nothing.
    fits(plaintext.len(), out.len())?;
    let (params, memory) = match kdf {
        SealKdf::Pbkdf2Sha256 => (KdfParams::Pbkdf2Sha256 { salt }, None),
        SealKdf::Argon2id(memory) => (KdfParams::Argon2id { salt }, Some(memory)),
    };
    let key = SealingKey(*derive_key(params, password, purpose, memory)?);
    seal_with_key(purpose, plaintext, &key, params.id(), salt, nonce, out)
}

/// The password policy as sealing applies it: [`password::check`] for
/// every purpose but [`Purpose::Stego`], whose "password" is the stego
/// descriptor, public in the Descriptor carrier by design. Applied where the
/// secret is sealed, so no caller can skip it: in [`seal`] and
/// [`Pbkdf2Steps::sealing`], whose [`SealingKey`] is all
/// [`seal_with_key`] takes.
///
/// One seal answers to another rule: a seed's backup, in [`crate::backup`],
/// takes no password at all when the seed has a passphrase, and this policy
/// for any password it does take.
///
/// # Errors
///
/// Why the password was refused.
pub fn policy(purpose: Purpose, password: &[u8]) -> Result<(), Weakness> {
    if purpose == Purpose::Stego {
        return Ok(());
    }
    password::check(password).map(|_| ())
}

/// A key to seal with. Outside this crate only [`seal`],
/// [`Pbkdf2Steps::sealing`] and [`crate::backup::sealing_steps`] make one:
/// the first two from a password [`policy`] accepted, the last from one a
/// backup's own rule accepted. So whatever [`seal_with_key`] writes is under
/// such a password. Wiped on drop.
pub struct SealingKey([u8; KEY_SIZE]);

impl Drop for SealingKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl core::fmt::Debug for SealingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SealingKey(redacted)")
    }
}

impl SealingKey {
    /// A fixed key for the boot known answer only
    /// ([`crate::kat::container`]), which seals a test vector's words under
    /// that vector's key. Crate-private, so nothing outside this crate seals
    /// without a password [`policy`] passed.
    pub(crate) fn known_answer(key: [u8; KEY_SIZE]) -> Self {
        Self(key)
    }
}

/// The PBKDF2 derivation a batch of rounds at a time, so a board can draw a
/// progress bar: 100,000 rounds take seconds on an ESP32-S3.
///
/// Its key is [`derive_key`]'s for [`KdfParams::Pbkdf2Sha256`]: one 32-byte
/// block, `U1 = HMAC(password, salt || purpose || 1)`, each next round the
/// HMAC of the last, all XORed. [`Pbkdf2Steps::fixed`] gives the
/// [`KdfParams::Pbkdf2Sha256Fixed`] key; [`Pbkdf2Steps::sealing`] gives a
/// [`SealingKey`]. Everything held between steps is wiped on drop.
pub struct Pbkdf2Steps {
    mac: Hmac<Sha256>,
    last: [u8; KEY_SIZE],
    sum: [u8; KEY_SIZE],
    done: u32,
    /// Made to seal: by [`Pbkdf2Steps::sealing`], after the policy, or for a
    /// stego backup.
    sealing: bool,
}

impl Pbkdf2Steps {
    /// The first round, for `password` under `salt` and `purpose`, to open
    /// with.
    pub fn new(password: &[u8], salt: &[u8; SALT_SIZE], purpose: Purpose) -> Self {
        Self::start(password, &[salt, &[purpose as u8]])
    }

    /// The first round, to seal with: the password held to [`policy`] first.
    ///
    /// # Errors
    ///
    /// Why the policy refused the password.
    pub fn sealing(
        password: &[u8],
        salt: &[u8; SALT_SIZE],
        purpose: Purpose,
    ) -> Result<Self, Weakness> {
        policy(purpose, password)?;
        let mut steps = Self::new(password, salt, purpose);
        steps.sealing = true;
        Ok(steps)
    }

    /// [`Pbkdf2Steps::sealing`] past [`policy`], for
    /// [`crate::backup::sealing_steps`] alone, which has held the password
    /// to a backup's own rule.
    pub(crate) fn sealing_past_policy(
        password: &[u8],
        salt: &[u8; SALT_SIZE],
        purpose: Purpose,
    ) -> Self {
        let mut steps = Self::new(password, salt, purpose);
        steps.sealing = true;
        steps
    }

    /// [`Pbkdf2Steps::sealing`] for a stego backup, which the policy never
    /// refuses: its descriptor under `salt` and [`Purpose::Stego`].
    pub(crate) fn stego(descriptor: &[u8], salt: &[u8; SALT_SIZE]) -> Self {
        let mut steps = Self::new(descriptor, salt, Purpose::Stego);
        steps.sealing = true;
        steps
    }

    /// The first round for the oldest layout, `KAS\x03`: `password` under
    /// [`FIXED_SALT`] alone, as the format has no purpose field. Opens only.
    pub fn fixed(password: &[u8]) -> Self {
        Self::start(password, &[FIXED_SALT])
    }

    /// The first round, the salt given in parts.
    fn start(password: &[u8], salt: &[&[u8]]) -> Self {
        let mac = <Hmac<Sha256> as KeyInit>::new_from_slice(password)
            .expect("HMAC takes a key of any length");
        let mut first = mac.clone();
        for part in salt {
            first.update(part);
        }
        first.update(&1u32.to_be_bytes());
        // U1 is bound so it can be wiped, and `last` is wiped once copied
        // into the steps, as in `bip32`: with the password's HMAC state, U1
        // gives the key.
        let mut block = first.finalize().into_bytes();
        let mut last = [0u8; KEY_SIZE];
        last.copy_from_slice(&block);
        block.zeroize();
        let steps = Self {
            mac,
            last,
            sum: last,
            done: 1,
            sealing: false,
        };
        last.zeroize();
        steps
    }

    /// Up to `rounds` more; returns the rounds done and the total.
    pub fn step(&mut self, rounds: u32) -> (u32, u32) {
        let end = self.done.saturating_add(rounds).min(PBKDF2_ITERATIONS);
        while self.done < end {
            let mut next = self.mac.clone();
            next.update(&self.last);
            // Each block bound and wiped, and `last` zipped by reference: a
            // temporary or a by-value copy would stay in this frame unwiped.
            let mut block = next.finalize().into_bytes();
            self.last.copy_from_slice(&block);
            block.zeroize();
            for (s, l) in self.sum.iter_mut().zip(self.last.iter()) {
                *s ^= *l;
            }
            self.done += 1;
        }
        (self.done, PBKDF2_ITERATIONS)
    }

    /// The key, once every round is done. A secret; it wipes itself when
    /// dropped.
    pub fn key(&self) -> Option<Zeroizing<[u8; KEY_SIZE]>> {
        (self.done == PBKDF2_ITERATIONS).then(|| Zeroizing::new(self.sum))
    }

    /// The key to seal with, once every round is done, for steps made by
    /// [`Pbkdf2Steps::sealing`]; `None` for steps made to open with.
    pub fn sealing_key(&self) -> Option<SealingKey> {
        (self.sealing && self.done == PBKDF2_ITERATIONS).then_some(SealingKey(self.sum))
    }
}

impl Drop for Pbkdf2Steps {
    fn drop(&mut self) {
        self.last.zeroize();
        self.sum.zeroize();
    }
}

/// The length of a sealed file of `plaintext_len` bytes, if it fits
/// `out_len` and its length field can say it; else `BufferTooSmall`, or
/// `Framing` past `u16::MAX`.
fn fits(plaintext_len: usize, out_len: usize) -> Result<usize, OpenError> {
    let total = Layout::V1.header_size() + NONCE_SIZE + plaintext_len + TAG_SIZE;
    if out_len < total {
        return Err(OpenError::BufferTooSmall { needed: total });
    }
    if plaintext_len > usize::from(u16::MAX) {
        return Err(OpenError::Framing(ContainerError::LengthMismatch {
            declared: plaintext_len,
            available: usize::from(u16::MAX),
        }));
    }
    Ok(total)
}

/// Seal with a key already derived, by [`Pbkdf2Steps::sealing`]: a
/// [`SealingKey`], so its password went through [`policy`].
///
/// `kdf` is written into the header and must be the derivation the key came
/// from; the header is authenticated, so a mismatch gives a file that opens
/// under no password rather than under the wrong one.
///
/// # Errors
///
/// As [`seal`], without `WeakPassword` and `KdfMemory`; `Framing` also for
/// [`Kdf::Pbkdf2Sha256Fixed`], which the layout written cannot record.
pub fn seal_with_key(
    purpose: Purpose,
    plaintext: &[u8],
    key: &SealingKey,
    kdf: Kdf,
    salt: &[u8; SALT_SIZE],
    nonce: &[u8; NONCE_SIZE],
    out: &mut [u8],
) -> Result<usize, OpenError> {
    fresh(salt, nonce)?;
    if kdf == Kdf::Pbkdf2Sha256Fixed {
        return Err(OpenError::Framing(ContainerError::UnsupportedKdf(
            kdf as u8,
        )));
    }
    let header_len = Layout::V1.header_size();
    let total = fits(plaintext.len(), out.len())?;

    // The header's own slice is the AAD, so the bytes authenticated are the
    // bytes written; rebuilt here, the layout would be described twice.
    let aad_len = {
        let aad = write_header(purpose, kdf, plaintext.len(), salt, out)?;
        aad.len()
    };
    debug_assert_eq!(aad_len, header_len);

    out[header_len..header_len + NONCE_SIZE].copy_from_slice(nonce);
    let ct_at = header_len + NONCE_SIZE;
    out[ct_at..ct_at + plaintext.len()].copy_from_slice(plaintext);

    let cipher = Aes256Gcm::new((&key.0).into());
    let (head, body) = out.split_at_mut(header_len);
    let aad = &head[..header_len];
    let ct = &mut body[NONCE_SIZE..NONCE_SIZE + plaintext.len()];

    // The plaintext is encrypted in place, so a failure wipes it. aes-gcm
    // fails only past its 2^36-byte limit, far above what `fits` allows.
    let tag = match cipher.encrypt_inout_detached(&Nonce::from(*nonce), aad, (&mut *ct).into()) {
        Ok(tag) => tag,
        Err(_) => {
            ct.zeroize();
            return Err(OpenError::Authentication);
        }
    };

    let tag_at = ct_at + plaintext.len();
    out[tag_at..tag_at + TAG_SIZE].copy_from_slice(&tag);
    Ok(total)
}
