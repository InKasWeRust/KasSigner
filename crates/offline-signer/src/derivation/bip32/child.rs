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

use k256::{
    elliptic_curve::{
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Group, ScalarPrimitive,
    },
    AffinePoint, EncodedPoint, ProjectivePoint, Scalar, Secp256k1,
};

use crate::derivation::hmac::{hmac_sha512, zeroize_buf};

use super::{
    constants::{BITCOIN_SEED, HARDENED_BIT},
    error::Bip32Error,
    extended_private::ExtendedPrivKey,
    extended_public::ExtendedPubKey,
    scalar::{is_less_than_order, is_valid_secret_scalar, is_zero, scalar_add_mod_n},
};

// ─── Master Key Generation ────────────────────────────────────────────

/// Generate the master extended private key from a BIP39 seed.
///
/// BIP32 spec:
///   I = HMAC-SHA512(key="Bitcoin seed", data=seed)
///   IL = first 32 bytes → master private key
///   IR = last 32 bytes → master chain code
///
/// The private key must be: 0 < IL < n (secp256k1 curve order)
/// If IL >= n or IL == 0, the seed is invalid (probability ~2^-128).
pub fn master_key_from_seed(seed: &[u8; 64]) -> Result<ExtendedPrivKey, Bip32Error> {
    let i = hmac_sha512(BITCOIN_SEED, seed);

    let mut key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    key.copy_from_slice(&i[..32]);
    chain_code.copy_from_slice(&i[32..]);

    // Validate that the key is a valid scalar (0 < key < n)
    if !is_valid_secret_scalar(&key) {
        zeroize_buf(&mut key);
        zeroize_buf(&mut chain_code);
        return Err(Bip32Error::InvalidKey);
    }

    // is_valid_secret_scalar() already proves 0 < key < n, exactly the
    // secp256k1 SecretKey scalar invariant; a second library parse could not
    // fail and only created an unreachable coverage branch.

    Ok(ExtendedPrivKey {
        key,
        chain_code,
        depth: 0,
    })
}

// ─── Child Key Derivation ─────────────────────────────────────────────

/// Derive a child key from an extended private key.
///
/// BIP32 child key derivation:
///
/// **Hardened** (index >= 0x80000000):
///   data = 0x00 || parent_key || index_BE
///   I = HMAC-SHA512(key=parent_chain_code, data=data)
///
/// **Normal** (index < 0x80000000):
///   data = parent_pubkey_compressed || index_BE
///   I = HMAC-SHA512(key=parent_chain_code, data=data)
///
/// child_key = (IL + parent_key) mod n
/// child_chain_code = IR
pub fn derive_child(parent: &ExtendedPrivKey, index: u32) -> Result<ExtendedPrivKey, Bip32Error> {
    let is_hardened = index & HARDENED_BIT != 0;

    // Build data for HMAC
    // Hardened: 0x00 + key(32) + index(4) = 37 bytes
    // Normal: pubkey(33) + index(4) = 37 bytes
    let mut data = [0u8; 37];

    if is_hardened {
        // data = 0x00 || parent_key || ser32(index)
        data[0] = 0x00;
        data[1..33].copy_from_slice(&parent.key);
    } else {
        // data = ser_P(parent_pubkey) || ser32(index)
        let pubkey = parent.public_key_compressed()?;
        data[..33].copy_from_slice(&pubkey);
    }
    // Append index as big-endian u32
    data[33..37].copy_from_slice(&index.to_be_bytes());

    // I = HMAC-SHA512(key=chain_code, data=data)
    let i = hmac_sha512(&parent.chain_code, &data);

    let mut il = [0u8; 32];
    let mut child_chain_code = [0u8; 32];
    il.copy_from_slice(&i[..32]);
    child_chain_code.copy_from_slice(&i[32..]);

    // Validar IL
    if !is_less_than_order(&il) {
        zeroize_buf(&mut il);
        zeroize_buf(&mut child_chain_code);
        zeroize_buf(&mut data);
        return Err(Bip32Error::InvalidKey);
    }

    // child_key = (IL + parent_key) mod n
    let mut child_key = scalar_add_mod_n(&il, &parent.key);

    // Zeroize IL — no longer needed
    zeroize_buf(&mut il);
    zeroize_buf(&mut data);

    // child_key cannot be zero
    if is_zero(&child_key) {
        zeroize_buf(&mut child_key);
        zeroize_buf(&mut child_chain_code);
        return Err(Bip32Error::InvalidKey);
    }

    // scalar_add_mod_n() returns a value below n and the zero case was just
    // rejected, so the child already satisfies the secp256k1 secret-scalar
    // invariant. Re-parsing it cannot add a reachable failure mode.

    Ok(ExtendedPrivKey {
        key: child_key,
        chain_code: child_chain_code,
        depth: parent.depth.saturating_add(1),
    })
}

// ─── Public-key BIP32 child derivation (no private key required) ────
//
// This is the cryptographic primitive for HD multisig: given just a
// cosigner's account-level xpub (public key + chain code), derive the
// child pubkey at m/.../0/index without access to the private key.
// Used by the multisig script builder so each address index yields a
// fresh per-cosigner pubkey, matching the BIP32 / BIP48 behavior of
// hardware wallets like Coldcard, Ledger, Trezor.
//
// Formula (from BIP32, normal non-hardened child):
//   data         = ser_P(parent_pubkey) || ser32(index)   (37 bytes)
//   I            = HMAC-SHA512(key = parent_chain_code, data = data)
//   IL, IR       = I[0..32], I[32..64]
//   if IL >= n (secp256k1 order): fail
//   child_point  = IL * G + parent_point   (secp256k1 point addition)
//   if child_point is identity (point at infinity): fail
//   child_pubkey = compressed encoding of child_point
//   child_cc     = IR
//
// Hardened indices (index >= 0x80000000) are NOT supported here —
// public-only derivation cannot produce them (by design, per BIP32).

/// Derive a child extended public key at a normal (non-hardened) index.
///
/// Returns `Bip32Error::InvalidKey` for hardened indices, for IL >= n,
/// or if the resulting point is the identity. The result is a public
/// key that corresponds to the private child that the holder of the
/// parent xprv would derive via `derive_child(parent_xprv, index)`.
pub fn derive_child_pub(parent: &ExtendedPubKey, index: u32) -> Result<ExtendedPubKey, Bip32Error> {
    if index & HARDENED_BIT != 0 {
        return Err(Bip32Error::InvalidKey);
    }
    let (il_scalar, mut child_chain_code) = child_public_scalar(parent, index)?;
    let parent_point = decode_parent_point(parent, &mut child_chain_code)?;
    let child_point = ProjectivePoint::GENERATOR * il_scalar + parent_point;
    validate_child_point(&child_point, &mut child_chain_code)?;
    let child_pubkey = encode_child_point(&child_point, &mut child_chain_code)?;
    Ok(ExtendedPubKey {
        pubkey: child_pubkey,
        chain_code: child_chain_code,
        depth: parent.depth.saturating_add(1),
    })
}

fn child_public_scalar(
    parent: &ExtendedPubKey,
    index: u32,
) -> Result<(Scalar, [u8; 32]), Bip32Error> {
    let mut data = [0u8; 37];
    data[..33].copy_from_slice(&parent.pubkey);
    data[33..37].copy_from_slice(&index.to_be_bytes());
    let digest = hmac_sha512(&parent.chain_code, &data);
    zeroize_buf(&mut data);
    scalar_and_chain_code(&digest)
}

fn scalar_and_chain_code(digest: &[u8; 64]) -> Result<(Scalar, [u8; 32]), Bip32Error> {
    let mut il = [0u8; 32];
    let mut chain_code = [0u8; 32];
    il.copy_from_slice(&digest[..32]);
    chain_code.copy_from_slice(&digest[32..]);
    if !is_less_than_order(&il) {
        zeroize_buf(&mut il);
        zeroize_buf(&mut chain_code);
        return Err(Bip32Error::InvalidKey);
    }
    let primitive =
        ScalarPrimitive::<Secp256k1>::from_slice(&il).map_err(|_| Bip32Error::InvalidKey);
    zeroize_buf(&mut il);
    match primitive {
        Ok(value) => Ok((Scalar::from(&value), chain_code)),
        Err(error) => {
            zeroize_buf(&mut chain_code);
            Err(error)
        }
    }
}

fn decode_parent_point(
    parent: &ExtendedPubKey,
    child_chain_code: &mut [u8; 32],
) -> Result<ProjectivePoint, Bip32Error> {
    let encoded = match EncodedPoint::from_bytes(parent.pubkey) {
        Ok(encoded) => encoded,
        Err(_) => {
            zeroize_buf(child_chain_code);
            return Err(Bip32Error::CurveError);
        }
    };
    let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded));
    match affine {
        Some(point) => Ok(ProjectivePoint::from(point)),
        None => {
            zeroize_buf(child_chain_code);
            Err(Bip32Error::CurveError)
        }
    }
}

pub(super) fn validate_child_point(
    child_point: &ProjectivePoint,
    child_chain_code: &mut [u8; 32],
) -> Result<(), Bip32Error> {
    if bool::from(child_point.is_identity()) {
        zeroize_buf(child_chain_code);
        Err(Bip32Error::InvalidKey)
    } else {
        Ok(())
    }
}

fn encode_child_point(
    child_point: &ProjectivePoint,
    child_chain_code: &mut [u8; 32],
) -> Result<[u8; 33], Bip32Error> {
    let encoded = child_point.to_affine().to_encoded_point(true);
    let bytes = encoded.as_bytes();
    if bytes.len() != 33 {
        zeroize_buf(child_chain_code);
        return Err(Bip32Error::CurveError);
    }
    let mut pubkey = [0u8; 33];
    pubkey.copy_from_slice(bytes);
    Ok(pubkey)
}
