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

//! BIP340 Schnorr signing, as BIP340 writes it. Verifying needs no secret
//! and is in `kassigner_kaspa::bip340`, at level 0.
//!
//! `aux_rand` is a required argument, with no overload that omits it: a
//! signer that quietly falls back to a deterministic nonce is the
//! differential-fault case, where two signatures of one message on a
//! glitched device yield the key. A fixed value is legal, which makes the
//! published vectors checkable.
//!
//! The nonce is BIP340's, not v1.0.7's HMAC under a KasSigner tag: both
//! verify, but only BIP340's is reproducible by another implementation
//! given the same aux.
//!
//! A signature is verified against its own public key before release: a
//! fault during the arithmetic can give one that leaks the key.
//!
//! The key and the nonce, as bytes and as [`Scalar`], are wiped at their
//! last use. `Scalar` is `Copy`, so compiler copies are out of reach: this
//! shortens the window for an attacker who can read memory; it does not
//! close it.

use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::subtle::ConditionallyNegatable;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use kassigner_kaspa::bip340;

use crate::curve::scalar_of;

/// Length of a signature: `R.x || s`.
pub const SIGNATURE_SIZE: usize = 64;
/// Length of an x-only public key.
pub const XONLY_SIZE: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignError {
    /// The private key is zero or past the curve order.
    InvalidPrivateKey,
    /// A derived nonce was zero: negligible odds, not assumed away.
    InvalidNonce,
    /// The signature failed its own verification before release. Not
    /// reachable by valid inputs: on a device, likely an injected fault.
    VerificationFailed,
}

/// A BIP340 signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; SIGNATURE_SIZE]);

impl Signature {
    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.0
    }

    pub const fn from_bytes(b: [u8; SIGNATURE_SIZE]) -> Self {
        Self(b)
    }
}

impl core::fmt::Debug for Signature {
    /// Shown in full: a signature is public, on the wire for anyone.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Signature(")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

/// BIP340's tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || data)`.
fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut h = Sha256::new();
    h.update(tag_hash);
    h.update(tag_hash);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Reduce 32 bytes into a scalar, wrapping past the order: BIP340's
/// `int(hash) mod n`.
fn scalar_reduce(bytes: &[u8; 32]) -> Scalar {
    <Scalar as k256::elliptic_curve::ops::Reduce<k256::FieldBytes>>::reduce(&(*bytes).into())
}

/// The x coordinate of a point.
fn x_of(p: &AffinePoint) -> [u8; 32] {
    p.x().into()
}

/// The x-only public key for a private key.
///
/// # Errors
///
/// `InvalidPrivateKey` if the key is zero or past the curve order.
pub fn public_key(private_key: &[u8; 32]) -> Result<[u8; XONLY_SIZE], SignError> {
    let mut d = scalar_of(private_key).ok_or(SignError::InvalidPrivateKey)?;
    let point = (ProjectivePoint::GENERATOR * d).to_affine();
    d.zeroize();
    Ok(x_of(&point))
}

/// Sign a 32-byte message. `aux` is BIP340's `aux_rand`, with no default.
///
/// # Errors
///
/// `InvalidPrivateKey` for a key zero or past the curve order,
/// `InvalidNonce` for a zero nonce, `VerificationFailed` if the result does
/// not verify against its own public key.
pub fn sign(
    private_key: &[u8; 32],
    message: &[u8; 32],
    aux: &[u8; 32],
) -> Result<Signature, SignError> {
    let mut d0 = scalar_of(private_key).ok_or(SignError::InvalidPrivateKey)?;

    // P = d0*G. Keys are x-only, so if P has an odd y the key is negated.
    let p = (ProjectivePoint::GENERATOR * d0).to_affine();
    // A constant-time negation, not a branch on P's parity, whose timing
    // would depend on the key.
    let mut d = d0;
    d.conditional_negate(p.y_is_odd());
    let px = x_of(&p);
    // `d0` and `d` are the key: each wiped at its last use.
    d0.zeroize();

    // t = d XOR tagged_hash("BIP0340/aux", aux)
    //
    // The key masked, not hashed together with the aux, as BIP340 has it:
    // fewer operations touch the key itself, against power analysis.
    let mut t = d.to_bytes();
    let aux_hash = tagged_hash(b"BIP0340/aux", &[aux]);
    for (a, b) in t.iter_mut().zip(aux_hash.iter()) {
        *a ^= b;
    }

    // rand = tagged_hash("BIP0340/nonce", t || P.x || m), k0 = int(rand) mod n
    let mut rand = tagged_hash(b"BIP0340/nonce", &[&t, &px, message]);
    t.zeroize();

    let mut k0 = scalar_reduce(&rand);
    rand.zeroize();
    if bool::from(k0.is_zero()) {
        // The key is still held: wiped on this way out too.
        d.zeroize();
        return Err(SignError::InvalidNonce);
    }

    // R = k0*G, and k is negated if R has an odd y.
    let r = (ProjectivePoint::GENERATOR * k0).to_affine();
    // Constant time, as for the key: a branch on R's parity would leak a
    // bit of the nonce per signature.
    let mut k = k0;
    k.conditional_negate(r.y_is_odd());
    let rx = x_of(&r);
    // As secret as the key: `d = (s - k) * e^-1` recovers it from a
    // released signature.
    k0.zeroize();

    // e = int(tagged_hash("BIP0340/challenge", R.x || P.x || m)) mod n
    let e = scalar_reduce(&tagged_hash(b"BIP0340/challenge", &[&rx, &px, message]));

    // s = k + e*d
    let s = k + e * d;
    k.zeroize();
    d.zeroize();

    // `e` and `s` are not wiped: `e` hashes public values and `s` is half
    // the signature.
    let mut sig = [0u8; SIGNATURE_SIZE];
    sig[..32].copy_from_slice(&rx);
    sig[32..].copy_from_slice(&s.to_bytes());

    // Verify before releasing: a faulted signature is not merely invalid,
    // it can disclose the key. One verification.
    if !bip340::verify(&px, message, &sig) {
        sig.zeroize();
        return Err(SignError::VerificationFailed);
    }

    Ok(Signature(sig))
}
