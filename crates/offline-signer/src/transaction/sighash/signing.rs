// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Schnorr signing facade for transaction inputs.

use sha2::{Digest, Sha256};

use crate::transaction::model::{SigHashType, Transaction};

use super::calculate_sighash;

const AUX_DOMAIN: &[u8] = b"KasSigner/BIP340/input-aux/v1";

pub(super) fn input_aux_rand(
    signing_entropy: &[u8; 32],
    sighash: &[u8; 32],
    input_index: usize,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(AUX_DOMAIN);
    hasher.update(signing_entropy);
    hasher.update(sighash);
    hasher.update((input_index as u64).to_le_bytes());
    hasher.finalize().into()
}

/// Sign a Kaspa transaction input in deterministic BIP-340 mode.
///
/// This compatibility entry point is retained for host tools and standards
/// tests. Device firmware uses [`sign_input_with_entropy`] and refuses to sign
/// unless a healthy hardware-entropy sample is available.
pub fn sign_input(
    tx: &Transaction,
    input_index: usize,
    private_key: &[u8; 32],
    sighash_type: SigHashType,
) -> Result<crate::crypto::schnorr::SchnorrSignature, crate::crypto::schnorr::SchnorrError> {
    let sighash = calculate_sighash(tx, input_index, sighash_type);
    crate::crypto::schnorr::schnorr_sign(private_key, &sighash)
}

/// Sign one input using per-signature auxiliary randomness derived from a
/// health-checked 32-byte device entropy sample.
///
/// A distinct auxiliary value is derived for every input and message. The
/// caller must zeroize `signing_entropy` after the complete signing operation.
pub fn sign_input_with_entropy(
    tx: &Transaction,
    input_index: usize,
    private_key: &[u8; 32],
    sighash_type: SigHashType,
    signing_entropy: &[u8; 32],
) -> Result<crate::crypto::schnorr::SchnorrSignature, crate::crypto::schnorr::SchnorrError> {
    let sighash = calculate_sighash(tx, input_index, sighash_type);
    let mut aux_rand = input_aux_rand(signing_entropy, &sighash, input_index);
    let result =
        crate::crypto::schnorr::schnorr_sign_with_aux_rand(private_key, &sighash, &aux_rand);
    shared_signer::bytes::zeroize_bytes(&mut aux_rand);
    result
}
