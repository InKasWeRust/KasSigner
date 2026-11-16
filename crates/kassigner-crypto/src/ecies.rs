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

//! ECIES: encrypting to a public key.
//!
//! Not a standard: ECIES is a family (SEC1, ISO/IEC 18033-2, ANSI X9.63,
//! IEEE 1363a) with pluggable parts. The parts here are standard (secp256k1,
//! SEC2; Blake2b, RFC 7693; AES-GCM, NIST SP 800-38D; x-only keys, BIP340);
//! the recipe below is written down only here, and conformance is a
//! differential against v1.0.7.
//!
//! # The recipe
//!
//! ```text
//! shared      = ephemeral_scalar * recipient_point      (ECDH)
//! key         = Blake2b-256( "KasSigner-ECIES-v2"
//!                          || ephemeral_pubkey (33)
//!                          || recipient_xonly  (32)
//!                          || shared.x         (32) )
//! ciphertext  = AES-256-GCM(key, nonce, plaintext)
//! ```
//!
//! The tag is a domain separator: this derivation cannot collide with any
//! other use of the same shared point.
//!
//! The AAD is the 45-byte header, `eph_pub(33) || nonce(12)`, so the header
//! is authenticated as sent. It is part of the format: a message built
//! without it does not open on the other side. The nonce is not in the KDF
//! hash.
//!
//! The recipient is an x-only key, lifted to even y. Only `shared.x` feeds
//! the derivation and negation keeps x, so both sides agree whatever the
//! real key's parity.
//!
//! The ephemeral scalar and the nonce are arguments. Reusing either is
//! fatal: a repeated ephemeral key under one recipient gives two messages
//! one key, and a repeated nonce under one key breaks AES-GCM.
//!
//! The scalar (ephemeral or private), the shared point (in `SharedPoint`)
//! and the derived key are each wiped at their last use. Compiler copies on
//! the way (the projective product, what `to_affine` returns) are stack
//! below the call, left to the seed flow's frame scrub.

use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::{AffinePoint, ProjectivePoint};
use zeroize::{DefaultIsZeroes, Zeroize};

use kassigner_protocol::ecies::{
    ciphertext_offset, parse, wire_size, write_header, EciesError as WireError, EPHEMERAL_SIZE,
    NONCE_SIZE, OVERHEAD, TAG_SIZE,
};

use crate::curve::{lift_x, scalar_of};

type Blake2b256 = Blake2b<U32>;

/// The domain separator in the key derivation. Part of the format: changing
/// it makes every existing ciphertext undecryptable.
pub const DOMAIN: &[u8] = b"KasSigner-ECIES-v2";

/// Length of the derived key.
pub const KEY_SIZE: usize = 32;

/// Length of the additional authenticated data: the whole header.
pub const AAD_SIZE: usize = EPHEMERAL_SIZE + NONCE_SIZE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EciesError {
    /// The envelope's framing is wrong.
    Wire(WireError),
    /// The recipient's x is not a point on the curve.
    InvalidRecipient,
    /// The ephemeral key: encrypting, a scalar zero or past the curve order;
    /// decrypting, a valid prefix whose x is not on the curve.
    InvalidEphemeral,
    /// The nonce is all zeros, which no working generator gives; a sealed
    /// container refuses it too.
    ZeroNonce,
    /// The recipient's private key is zero or past the curve order.
    InvalidPrivateKey,
    /// The tag did not verify: a wrong key, a corrupted message or an edited
    /// ephemeral key, deliberately not told apart.
    Authentication,
    /// The caller's buffer is too small.
    BufferTooSmall { needed: usize },
}

impl From<WireError> for EciesError {
    fn from(e: WireError) -> Self {
        EciesError::Wire(e)
    }
}

/// Encrypt to a recipient named by an x-only public key.
///
/// `ephemeral` and `nonce` come from the caller and must both be fresh.
///
/// # Errors
///
/// `InvalidRecipient` or `InvalidEphemeral` for a bad key, `ZeroNonce` for a
/// nonce of zeros, `BufferTooSmall` if `out` cannot hold the envelope.
pub fn encrypt(
    recipient_x_only: &[u8; 32],
    plaintext: &[u8],
    ephemeral: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    out: &mut [u8],
) -> Result<usize, EciesError> {
    let needed = wire_size(plaintext.len());
    if out.len() < needed {
        return Err(EciesError::BufferTooSmall { needed });
    }
    if nonce.iter().all(|&b| b == 0) {
        return Err(EciesError::ZeroNonce);
    }

    let mut eph = scalar_of(ephemeral).ok_or(EciesError::InvalidEphemeral)?;
    // The scalar is held now, so this error path wipes it.
    let Some(recipient) = lift_x(recipient_x_only) else {
        eph.zeroize();
        return Err(EciesError::InvalidRecipient);
    };

    let eph_point = (ProjectivePoint::GENERATOR * eph).to_affine();
    let eph_encoded = eph_point.to_sec1_point(true);
    let mut eph_bytes = [0u8; EPHEMERAL_SIZE];
    eph_bytes.copy_from_slice(eph_encoded.as_bytes());

    let mut shared = SharedPoint((ProjectivePoint::from(recipient) * eph).to_affine());
    // With the envelope, the ephemeral scalar gives the shared point: it is
    // as good as the recipient's key for this message.
    eph.zeroize();
    let mut key = derive_key(&eph_bytes, recipient_x_only, &shared.0);
    shared.zeroize();

    // Sized at the top, so this does not fail; if it did, the key is wiped.
    if let Err(e) = write_header(&eph_bytes, nonce, plaintext.len(), out) {
        key.zeroize();
        return Err(e.into());
    }
    let ct_at = ciphertext_offset();
    out[ct_at..ct_at + plaintext.len()].copy_from_slice(plaintext);

    // The AAD comes from the header as written: what is authenticated is
    // what is sent.
    let mut aad = [0u8; AAD_SIZE];
    aad.copy_from_slice(&out[..AAD_SIZE]);

    // By reference: `key.into()` would copy the key into a temporary that
    // nothing wipes.
    let cipher = Aes256Gcm::new((&key).into());
    let ct = &mut out[ct_at..ct_at + plaintext.len()];
    let tag = cipher
        .encrypt_inout_detached(&Nonce::from(*nonce), &aad, ct.into())
        .map_err(|_| EciesError::Authentication);
    key.zeroize();
    // On a failure the plaintext copied in above is still there: wiped.
    // aes-gcm fails only for a plaintext past 2^36 bytes.
    let tag = match tag {
        Ok(tag) => tag,
        Err(e) => {
            out[ct_at..ct_at + plaintext.len()].zeroize();
            return Err(e);
        }
    };

    let tag_at = ct_at + plaintext.len();
    out[tag_at..tag_at + TAG_SIZE].copy_from_slice(&tag);
    Ok(needed)
}

/// Decrypt with the recipient's private key. `out` receives the plaintext,
/// a secret the caller wipes.
///
/// # Errors
///
/// `Wire` for a malformed envelope, `BufferTooSmall` before any decryption,
/// `InvalidPrivateKey` or `InvalidEphemeral` for a bad key,
/// `Authentication` if the tag does not verify.
pub fn decrypt(private_key: &[u8; 32], wire: &[u8], out: &mut [u8]) -> Result<usize, EciesError> {
    let env = parse(wire)?;
    if out.len() < env.ciphertext.len() {
        return Err(EciesError::BufferTooSmall {
            needed: env.ciphertext.len(),
        });
    }

    let mut d = scalar_of(private_key).ok_or(EciesError::InvalidPrivateKey)?;
    // The private scalar is held now, so this error path wipes it.
    let Some(eph_point) =
        Option::<AffinePoint>::from(AffinePoint::from_bytes(&(*env.ephemeral_key).into()))
    else {
        // `parse` checked the prefix: what fails here is an x off the curve.
        d.zeroize();
        return Err(EciesError::InvalidEphemeral);
    };

    // The recipient key in the hash is our own x-only key, recomputed: a
    // wrong private key gives a wrong hash as well as a wrong shared point.
    let our_point = (ProjectivePoint::GENERATOR * d).to_affine();
    let our_x: [u8; 32] = our_point.x().into();

    let mut shared = SharedPoint((ProjectivePoint::from(eph_point) * d).to_affine());
    d.zeroize();
    let mut key = derive_key(env.ephemeral_key, &our_x, &shared.0);
    shared.zeroize();

    let n = env.ciphertext.len();
    let buf = &mut out[..n];
    buf.copy_from_slice(env.ciphertext);

    let mut aad = [0u8; AAD_SIZE];
    aad[..EPHEMERAL_SIZE].copy_from_slice(env.ephemeral_key);
    aad[EPHEMERAL_SIZE..].copy_from_slice(env.nonce);

    // By reference, as in `encrypt`.
    let cipher = Aes256Gcm::new((&key).into());
    let tag = aes_gcm::Tag::from(*env.tag);
    let r = cipher.decrypt_inout_detached(&Nonce::from(*env.nonce), &aad, (&mut *buf).into(), &tag);
    key.zeroize();

    match r {
        Ok(()) => Ok(n),
        Err(_) => {
            // aes-gcm 0.11 checks the tag before decrypting, so this is
            // still ciphertext; wiped anyway, whatever a later version does.
            buf.zeroize();
            Err(EciesError::Authentication)
        }
    }
}

/// Bytes an envelope of `plaintext_len` occupies.
pub const fn encrypted_size(plaintext_len: usize) -> usize {
    OVERHEAD + plaintext_len
}

/// The key derivation, public so a differential harness can check it alone.
/// `shared` is the ECDH point; only its x is used.
pub fn derive_key(
    ephemeral_key: &[u8; EPHEMERAL_SIZE],
    recipient_x_only: &[u8; 32],
    shared: &AffinePoint,
) -> [u8; KEY_SIZE] {
    let mut shared_x: [u8; 32] = shared.x().into();
    let mut h = Blake2b256::new();
    h.update(DOMAIN);
    h.update(ephemeral_key);
    h.update(recipient_x_only);
    // As a slice: by value, the x would be copied into the call, out of
    // reach of the wipe below.
    h.update(shared_x.as_slice());
    // The x is the ECDH secret; `blake2`'s `zeroize` wipes the hasher.
    shared_x.zeroize();
    h.finalize().into()
}

/// The ECDH point, held so it can be wiped. `AffinePoint` has no
/// `Zeroize`, but it is `Copy + Default`, so through [`DefaultIsZeroes`]
/// `zeroize` overwrites the wrapper with the identity point by a volatile
/// write and a barrier, which this crate, forbidding `unsafe`, cannot write.
#[derive(Clone, Copy, Default)]
struct SharedPoint(AffinePoint);

impl DefaultIsZeroes for SharedPoint {}
