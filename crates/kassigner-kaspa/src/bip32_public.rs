// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! BIP32 public derivation (upstream: `wallet/bip32/src/xpublic_key.rs`,
//! `public_key.rs`, `prefix.rs`).
//!
//! Child public keys from an extended public key, and nothing private: no
//! input holds key material. An integrator deriving receive addresses needs
//! exactly this, never `CKDpriv`, which lives in the device-only crate.
//! Hardened derivation needs the private key and is refused.
//!
//! `kpub` (mainnet) and `ktub` (testnet) have different version bytes under
//! the checksum, so a key from one network cannot be read as another.

use core::fmt;

/// Length of a chain code.
pub const CHAIN_CODE_SIZE: usize = 32;
/// Length of a compressed public key.
pub const PUBLIC_KEY_SIZE: usize = 33;
/// Length of a key fingerprint.
pub const FINGERPRINT_SIZE: usize = 4;
/// Length of a serialized extended key, before its checksum.
pub const EXTENDED_KEY_SIZE: usize = 78;

/// The most characters [`ExtendedPublicKey::to_text`] writes, by
/// [`crate::base58::encoded_max`]: a bound, as a kpub is 111.
pub const TEXT_MAX: usize = crate::base58::encoded_max(EXTENDED_KEY_SIZE);

/// Version bytes for a serialized extended public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prefix {
    /// Mainnet extended public key.
    Kpub,
    /// Testnet extended public key.
    Ktub,
}

impl Prefix {
    pub const fn version(self) -> u32 {
        match self {
            Prefix::Kpub => 0x038f_332e,
            Prefix::Ktub => 0x0390_a241,
        }
    }

    pub const fn from_version(v: u32) -> Option<Self> {
        match v {
            0x038f_332e => Some(Prefix::Kpub),
            0x0390_a241 => Some(Prefix::Ktub),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Prefix::Kpub => "kpub",
            Prefix::Ktub => "ktub",
        }
    }
}

/// A child index; at or above [`HARDENED_OFFSET`] it is hardened.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChildNumber(pub u32);

/// Where hardened indices begin.
pub const HARDENED_OFFSET: u32 = 0x8000_0000;

impl ChildNumber {
    pub const fn is_hardened(self) -> bool {
        self.0 >= HARDENED_OFFSET
    }
    pub const fn to_be_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bip32Error {
    /// Hardened derivation, impossible from a public key.
    HardenedFromPublic,
    /// Depth would exceed what a serialized extended key can express.
    DepthOverflow,
    /// The tweak is not a valid scalar, or the child is the identity; BIP32
    /// has the caller skip to the next index. Also a malformed path.
    InvalidChild,
    /// The public key bytes are not a point on the curve.
    InvalidPublicKey,
    /// The caller's buffer is too small.
    BufferTooSmall,
}

/// Parse a derivation path as upstream writes it: `m`, then `/<n>` per level,
/// `'` after a hardened one (`wallet/bip32/src/derivation_path.rs`). `m`
/// alone is the empty path.
///
/// A number reads as `str::parse::<u32>` reads it, leading zeros and one `+`
/// allowed (`m/01` and `m/+1` are `m/1`): upstream never writes those, but
/// it reads them.
///
/// # Errors
///
/// `InvalidChild` for anything else: a missing `m`, an empty level, or a
/// number of 2^31 or more. `BufferTooSmall` past `out.len()` levels.
pub fn parse_path(text: &[u8], out: &mut [ChildNumber]) -> Result<usize, Bip32Error> {
    parse_path_chars(text.iter().copied(), out)
}

/// [`parse_path`] over characters as they come: a bundle's path, decoded
/// from its escapes through [`ascii`](crate::pskb::lexer::ascii).
///
/// # Errors
///
/// As [`parse_path`].
pub fn parse_path_chars(
    text: impl IntoIterator<Item = u8>,
    out: &mut [ChildNumber],
) -> Result<usize, Bip32Error> {
    each_level(text, |n, child| {
        *out.get_mut(n).ok_or(Bip32Error::BufferTooSmall)? = child;
        Ok(())
    })
}

/// Whether `text` is a path [`parse_path`] reads, at any depth.
pub(crate) fn is_path(text: impl IntoIterator<Item = u8>) -> bool {
    each_level(text, |_, _| Ok(())).is_ok()
}

/// Read `text` as [`parse_path`] does, one character at a time, handing each
/// level and its index to `f`; the number of levels. A level is an optional
/// `+`, digits, and an optional `'`, below the hardened offset.
fn each_level(
    text: impl IntoIterator<Item = u8>,
    mut f: impl FnMut(usize, ChildNumber) -> Result<(), Bip32Error>,
) -> Result<usize, Bip32Error> {
    let bad = Bip32Error::InvalidChild;
    let mut chars = text.into_iter();
    if chars.next() != Some(b'm') {
        return Err(bad);
    }
    match chars.next() {
        None => return Ok(0),
        Some(b'/') => {}
        Some(_) => return Err(bad),
    }
    let mut n = 0usize;
    // The level being read: its number, its digits, its `+` and its `'`.
    let (mut v, mut digits, mut plus, mut hardened) = (0u32, 0usize, false, false);
    loop {
        let c = chars.next();
        match c {
            Some(b'/') | None => {
                if digits == 0 || v >= HARDENED_OFFSET {
                    return Err(bad);
                }
                f(
                    n,
                    ChildNumber(if hardened { v | HARDENED_OFFSET } else { v }),
                )?;
                n += 1;
                if c.is_none() {
                    return Ok(n);
                }
                (v, digits, plus, hardened) = (0, 0, false, false);
            }
            // Nothing follows a `'` in its level.
            Some(_) if hardened => return Err(bad),
            Some(b'\'') => hardened = true,
            Some(b'+') if digits == 0 && !plus => plus = true,
            Some(d @ b'0'..=b'9') => {
                v = v
                    .checked_mul(10)
                    .and_then(|v| v.checked_add(u32::from(d - b'0')))
                    .ok_or(bad)?;
                digits += 1;
            }
            Some(_) => return Err(bad),
        }
    }
}

/// An extended public key: a point, a chain code, and where it sits in the tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtendedPublicKey {
    pub public_key: [u8; PUBLIC_KEY_SIZE],
    pub chain_code: [u8; CHAIN_CODE_SIZE],
    pub depth: u8,
    pub parent_fingerprint: [u8; FINGERPRINT_SIZE],
    pub child_number: ChildNumber,
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The four-byte fingerprint of a public key: `RIPEMD160(SHA256(key))[..4]`.
pub fn fingerprint(public_key: &[u8; PUBLIC_KEY_SIZE]) -> [u8; FINGERPRINT_SIZE] {
    use ripemd::Ripemd160;
    use sha2::{Digest, Sha256};
    let sha = Sha256::digest(public_key);
    let rip = Ripemd160::digest(sha);
    let mut out = [0u8; FINGERPRINT_SIZE];
    out.copy_from_slice(&rip[..FINGERPRINT_SIZE]);
    out
}

impl ExtendedPublicKey {
    /// Fingerprint of this key, which becomes a child's parent fingerprint.
    pub fn fingerprint(&self) -> [u8; FINGERPRINT_SIZE] {
        fingerprint(&self.public_key)
    }

    /// Derive a non-hardened child. `I` is HMAC-SHA512 of the key and index
    /// under the chain code; the child is the parent plus `I_L` times the
    /// generator, `I_R` its chain code. Hardened indices are refused.
    pub fn derive_child(&self, child_number: ChildNumber) -> Result<Self, Bip32Error> {
        use hmac::{Hmac, KeyInit, Mac};
        use k256::elliptic_curve::sec1::ToSec1Point;
        use k256::ProjectivePoint;
        use sha2::Sha512;

        if child_number.is_hardened() {
            return Err(Bip32Error::HardenedFromPublic);
        }
        let depth = self.depth.checked_add(1).ok_or(Bip32Error::DepthOverflow)?;

        let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(&self.chain_code)
            .map_err(|_| Bip32Error::InvalidChild)?;
        mac.update(&self.public_key);
        mac.update(&child_number.to_be_bytes());
        let i = mac.finalize().into_bytes();
        let (il, ir) = i.split_at(32);

        // I_L must be a valid scalar; skipping to the next index is the
        // caller's call. `il` is half of a 64-byte output: 32 bytes.
        let mut il_bytes = [0u8; 32];
        il_bytes.copy_from_slice(il);
        let tweak = tweak_of(&il_bytes).ok_or(Bip32Error::InvalidChild)?;

        let parent = point(&self.public_key).ok_or(Bip32Error::InvalidPublicKey)?;

        let child = ProjectivePoint::from(parent) + (ProjectivePoint::GENERATOR * tweak);
        // BIP32 refuses the point at infinity.
        if bool::from(<ProjectivePoint as k256::elliptic_curve::group::Group>::is_identity(&child))
        {
            return Err(Bip32Error::InvalidChild);
        }
        let child_affine = child.to_affine();

        let encoded = child_affine.to_sec1_point(true);
        let mut public_key = [0u8; PUBLIC_KEY_SIZE];
        public_key.copy_from_slice(encoded.as_bytes());

        let mut chain_code = [0u8; CHAIN_CODE_SIZE];
        chain_code.copy_from_slice(ir);

        Ok(Self {
            public_key,
            chain_code,
            depth,
            parent_fingerprint: self.fingerprint(),
            child_number,
        })
    }

    /// Serialize to the 78-byte extended key body, without the checksum.
    pub fn serialize(&self, prefix: Prefix, out: &mut [u8]) -> Result<usize, Bip32Error> {
        if out.len() < EXTENDED_KEY_SIZE {
            return Err(Bip32Error::BufferTooSmall);
        }
        out[0..4].copy_from_slice(&prefix.version().to_be_bytes());
        out[4] = self.depth;
        out[5..9].copy_from_slice(&self.parent_fingerprint);
        out[9..13].copy_from_slice(&self.child_number.to_be_bytes());
        out[13..45].copy_from_slice(&self.chain_code);
        out[45..78].copy_from_slice(&self.public_key);
        Ok(EXTENDED_KEY_SIZE)
    }

    /// The key as a watch-only wallet reads it, `kpub...` on mainnet: base58
    /// over the body and its checksum. Returns the characters written, 111.
    ///
    /// # Errors
    ///
    /// `BufferTooSmall` if `out` cannot hold [`TEXT_MAX`].
    pub fn to_text(&self, prefix: Prefix, out: &mut [u8]) -> Result<usize, Bip32Error> {
        let mut body = [0u8; EXTENDED_KEY_SIZE];
        self.serialize(prefix, &mut body)?;
        let mut scratch = [0u8; EXTENDED_KEY_SIZE + 4];
        crate::base58::encode_check(&body, &mut scratch, out)
            .map_err(|_| Bip32Error::BufferTooSmall)
    }

    /// Read a key as [`Self::to_text`] writes it.
    ///
    /// # Errors
    ///
    /// `InvalidPublicKey` for text that is not one: longer than [`TEXT_MAX`],
    /// not base58, a bad checksum, a body not exactly 78 bytes (as upstream's
    /// `FromStr`), or as [`Self::deserialize`].
    pub fn from_text(text: &[u8]) -> Result<(Prefix, Self), Bip32Error> {
        if text.len() > TEXT_MAX {
            return Err(Bip32Error::InvalidPublicKey);
        }
        let mut raw = [0u8; crate::base58::decoded_max(TEXT_MAX)];
        match crate::base58::decode_check(text, &mut raw) {
            Ok(EXTENDED_KEY_SIZE) => Self::deserialize(&raw[..EXTENDED_KEY_SIZE]),
            _ => Err(Bip32Error::InvalidPublicKey),
        }
    }

    /// Parse a 78-byte extended key body.
    ///
    /// # Errors
    ///
    /// `BufferTooSmall` for fewer than 78 bytes. `InvalidPublicKey` for a
    /// version not a public key's, or a key off the curve, as upstream's
    /// `ExtendedPublicKey::try_from` (`secp256k1::PublicKey::from_slice`).
    pub fn deserialize(bytes: &[u8]) -> Result<(Prefix, Self), Bip32Error> {
        if bytes.len() < EXTENDED_KEY_SIZE {
            return Err(Bip32Error::BufferTooSmall);
        }
        let mut v = [0u8; 4];
        v.copy_from_slice(&bytes[0..4]);
        let prefix =
            Prefix::from_version(u32::from_be_bytes(v)).ok_or(Bip32Error::InvalidPublicKey)?;

        let mut parent_fingerprint = [0u8; FINGERPRINT_SIZE];
        parent_fingerprint.copy_from_slice(&bytes[5..9]);
        let mut cn = [0u8; 4];
        cn.copy_from_slice(&bytes[9..13]);
        let mut chain_code = [0u8; CHAIN_CODE_SIZE];
        chain_code.copy_from_slice(&bytes[13..45]);
        let mut public_key = [0u8; PUBLIC_KEY_SIZE];
        public_key.copy_from_slice(&bytes[45..78]);
        if point(&public_key).is_none() {
            return Err(Bip32Error::InvalidPublicKey);
        }

        Ok((
            prefix,
            Self {
                public_key,
                chain_code,
                depth: bytes[4],
                parent_fingerprint,
                child_number: ChildNumber(u32::from_be_bytes(cn)),
            },
        ))
    }
}

/// The point a compressed key encodes: tag 2 or 3, then an x below the field
/// prime with a y on the curve; `None` otherwise, as secp256k1. The tag is
/// checked here because k256 also reads tag 5 (SEC1 compact), which
/// secp256k1 refuses.
fn point(public_key: &[u8; PUBLIC_KEY_SIZE]) -> Option<k256::AffinePoint> {
    use k256::elliptic_curve::group::GroupEncoding;
    if !matches!(public_key[0], 2 | 3) {
        return None;
    }
    Option::from(k256::AffinePoint::from_bytes(&(*public_key).into()))
}

/// Whether `bytes` are a public key as `secp256k1::PublicKey::from_slice`
/// reads one: 33 bytes compressed, or 65 uncompressed, tag 4, or hybrid,
/// tag 6 or 7 with the tag's parity of y; a point on the curve each way.
pub(crate) fn is_public_key(bytes: &[u8]) -> bool {
    use k256::elliptic_curve::sec1::FromSec1Point;
    if let Ok(key) = <&[u8; PUBLIC_KEY_SIZE]>::try_from(bytes) {
        return point(key).is_some();
    }
    match bytes {
        [tag @ (4 | 6 | 7), xy @ ..] if xy.len() == 64 => {
            // Hybrid: the tag says y's parity, and has to be right.
            if *tag != 4 && (xy[63] & 1 == 1) != (*tag == 7) {
                return false;
            }
            let mut plain = [0u8; 65];
            plain[0] = 4;
            plain[1..].copy_from_slice(xy);
            k256::AffinePoint::from_sec1_bytes(&plain).is_ok()
        }
        _ => false,
    }
}

/// Whether `text` is an extended public key as upstream's
/// `ExtendedPublicKey::from_str` reads one, in a bundle's `xpubs` map: wider
/// than [`ExtendedPublicKey::from_text`]. The prefix is any four letters
/// ending `pub` or `tub`, not compared with the version bytes, and the key
/// must be a point.
pub(crate) fn is_xpub_text(text: &[u8]) -> bool {
    let mut raw = [0u8; EXTENDED_KEY_SIZE + 4];
    if crate::base58::decode_check(text, &mut raw) != Ok(EXTENDED_KEY_SIZE) {
        return false;
    }
    let Some(prefix) = text.get(..4) else {
        return false;
    };
    prefix.iter().all(u8::is_ascii_alphabetic)
        && matches!(&prefix[1..], b"pub" | b"tub")
        && is_public_key(&raw[45..EXTENDED_KEY_SIZE])
}

/// BIP32's `I_L` as a scalar: `None` at or past the curve order. Zero is
/// valid, the child then its parent's point, as upstream's `add_exp_tweak`
/// takes it; no known HMAC output gives it, so the test is of this alone.
fn tweak_of(il: &[u8; 32]) -> Option<k256::Scalar> {
    Option::from(<k256::Scalar as k256::elliptic_curve::PrimeField>::from_repr((*il).into()))
}

#[cfg(test)]
mod tests {
    use super::tweak_of;

    /// Zero is a tweak; the curve's order and past it are not.
    #[test]
    fn a_zero_tweak_is_valid_and_the_order_is_not() {
        assert_eq!(tweak_of(&[0u8; 32]), Some(k256::Scalar::ZERO));
        let order: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x41, 0x41,
        ];
        assert_eq!(tweak_of(&order), None);
        assert_eq!(tweak_of(&[0xFF; 32]), None);
        let mut below = order;
        below[31] -= 1;
        assert!(tweak_of(&below).is_some());
    }
}
