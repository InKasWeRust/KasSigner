// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! BIP340 Schnorr signature verification, which Kaspa uses unchanged with
//! the standard `BIP0340/challenge` tagged hash.
//!
//! Verification only: key material lives in one other crate, and no signing
//! type of the curve library is used, re-exported or reachable here.
//! Integrators need it, and a signer checking its own signature catches a
//! fault in its arithmetic before the signature leaves the device.
//!
//! A false [`verify`] does not say whether the signature, key or message was
//! wrong: a caller branching on the reason would build an oracle.

/// Length of an x-only public key.
pub const PUBLIC_KEY_SIZE: usize = 32;
/// Length of a signature.
pub const SIGNATURE_SIZE: usize = 64;
/// Length of the message digest a Kaspa signature covers.
pub const MESSAGE_SIZE: usize = 32;

/// Whether `public_key` is a BIP340 public key: an x below the field prime
/// on secp256k1, so `lift_x` succeeds. A script naming 32 bytes that fail
/// this can never be satisfied.
pub fn is_public_key(public_key: &[u8; PUBLIC_KEY_SIZE]) -> bool {
    k256::schnorr::VerifyingKey::from_slice(public_key).is_ok()
}

/// Verify a BIP340 signature over a 32-byte message: false for a malformed
/// key or signature too, the reason unreported.
pub fn verify(
    public_key: &[u8; PUBLIC_KEY_SIZE],
    message: &[u8; MESSAGE_SIZE],
    signature: &[u8; SIGNATURE_SIZE],
) -> bool {
    use k256::schnorr::signature::hazmat::PrehashVerifier;

    let Ok(key) = k256::schnorr::VerifyingKey::from_slice(public_key) else {
        return false;
    };
    let Ok(sig) = k256::schnorr::Signature::try_from(&signature[..]) else {
        return false;
    };
    key.verify_prehash(message, &sig).is_ok()
}
