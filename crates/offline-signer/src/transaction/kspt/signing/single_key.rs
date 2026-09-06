use crate::transaction::{
    model::{SigHashType, Transaction},
    sighash,
};

use super::super::{error::PsktError, kssn::SignedResponse, validation::validate_base_transaction};

fn sign_one(
    tx: &Transaction,
    input_index: usize,
    private_key: &[u8; 32],
    sighash_type: SigHashType,
    signing_entropy: Option<&[u8; 32]>,
) -> Result<crate::crypto::schnorr::SchnorrSignature, PsktError> {
    let result = match signing_entropy {
        Some(entropy) => {
            sighash::sign_input_with_entropy(tx, input_index, private_key, sighash_type, entropy)
        }
        None => sighash::sign_input(tx, input_index, private_key, sighash_type),
    };
    result.map_err(|_| PsktError::SigningFailed)
}

fn sign_transaction_impl(
    tx: &Transaction,
    private_key: &[u8; 32],
    sighash_type: SigHashType,
    signing_entropy: Option<&[u8; 32]>,
) -> Result<SignedResponse, PsktError> {
    validate_base_transaction(tx)?;
    let mut response = SignedResponse::new();
    for input_index in 0..tx.num_inputs {
        let signature = sign_one(tx, input_index, private_key, sighash_type, signing_entropy)?;
        response.add_signature(
            u32::try_from(input_index).map_err(|_| PsktError::InvalidInputIndex)?,
            sighash_type,
            &signature.bytes,
        )?;
    }
    Ok(response)
}

pub fn sign_transaction(
    tx: &Transaction,
    private_key: &[u8; 32],
    sighash_type: SigHashType,
) -> Result<SignedResponse, PsktError> {
    sign_transaction_impl(tx, private_key, sighash_type, None)
}

pub fn sign_transaction_with_entropy(
    tx: &Transaction,
    private_key: &[u8; 32],
    sighash_type: SigHashType,
    signing_entropy: &[u8; 32],
) -> Result<SignedResponse, PsktError> {
    sign_transaction_impl(tx, private_key, sighash_type, Some(signing_entropy))
}

fn sign_transaction_in_place_impl(
    tx: &mut Transaction,
    private_key: &[u8; 32],
    sighash_type: SigHashType,
    signing_entropy: Option<&[u8; 32]>,
) -> Result<usize, PsktError> {
    validate_base_transaction(tx)?;
    let compressed_public_key =
        crate::derivation::bip32::compressed_pubkey_from_raw_key(private_key)
            .map_err(|_| PsktError::SigningFailed)?;
    for input_index in 0..tx.num_inputs {
        let signature = sign_one(tx, input_index, private_key, sighash_type, signing_entropy)?;
        super::signature_state::set_single_signature(
            &mut tx.inputs[input_index],
            signature.bytes,
            sighash_type.to_byte(),
            0,
            compressed_public_key,
        );
    }
    Ok(tx.num_inputs)
}

pub fn sign_transaction_in_place(
    tx: &mut Transaction,
    private_key: &[u8; 32],
    sighash_type: SigHashType,
) -> Result<usize, PsktError> {
    sign_transaction_in_place_impl(tx, private_key, sighash_type, None)
}

pub fn sign_transaction_in_place_with_entropy(
    tx: &mut Transaction,
    private_key: &[u8; 32],
    sighash_type: SigHashType,
    signing_entropy: &[u8; 32],
) -> Result<usize, PsktError> {
    sign_transaction_in_place_impl(tx, private_key, sighash_type, Some(signing_entropy))
}

/// Sign one matching P2PK input with an imported raw private key.
pub fn sign_matching_input_in_place_with_entropy(
    tx: &mut Transaction,
    input_index: usize,
    private_key: &[u8; 32],
    sighash_type: SigHashType,
    signing_entropy: &[u8; 32],
) -> Result<bool, PsktError> {
    super::p2pk::checked_target(tx, input_index).and_then(|target| {
        sign_raw_target_with_entropy(
            tx,
            input_index,
            private_key,
            sighash_type,
            signing_entropy,
            target,
        )
    })
}

fn sign_raw_target_with_entropy(
    tx: &mut Transaction,
    input_index: usize,
    private_key: &[u8; 32],
    sighash_type: SigHashType,
    signing_entropy: &[u8; 32],
    target: Option<[u8; 32]>,
) -> Result<bool, PsktError> {
    let Some(target) = target else {
        return Ok(false);
    };
    crate::derivation::bip32::compressed_pubkey_from_raw_key(private_key)
        .map_err(|_| PsktError::SigningFailed)
        .and_then(|compressed| {
            sign_raw_if_matching(
                tx,
                input_index,
                private_key,
                sighash_type,
                signing_entropy,
                &target,
                compressed,
            )
        })
}

fn sign_raw_if_matching(
    tx: &mut Transaction,
    input_index: usize,
    private_key: &[u8; 32],
    sighash_type: SigHashType,
    signing_entropy: &[u8; 32],
    target: &[u8; 32],
    compressed_public_key: [u8; 33],
) -> Result<bool, PsktError> {
    if compressed_public_key[1..33] != target[..] {
        return Ok(false);
    }
    sign_one(
        tx,
        input_index,
        private_key,
        sighash_type,
        Some(signing_entropy),
    )
    .map(|signature| {
        super::signature_state::set_single_signature(
            &mut tx.inputs[input_index],
            signature.bytes,
            sighash_type.to_byte(),
            0,
            compressed_public_key,
        );
        true
    })
}

fn input_matches_xonly(tx: &Transaction, input_index: usize, xonly: &[u8]) -> bool {
    let script = &tx.inputs[input_index].utxo_entry.script_public_key;
    script.script_len == 34
        && script.script[0] == 0x20
        && script.script[33] == 0xac
        && &script.script[1..33] == xonly
}

fn sign_matching_input(
    tx: &mut Transaction,
    input_index: usize,
    private_key: &[u8; 32],
    sighash_type: SigHashType,
    signing_entropy: &[u8; 32],
    compressed_public_key: [u8; 33],
) -> Result<(), PsktError> {
    let signature = sign_one(
        tx,
        input_index,
        private_key,
        sighash_type,
        Some(signing_entropy),
    )?;
    super::signature_state::set_single_signature(
        &mut tx.inputs[input_index],
        signature.bytes,
        sighash_type.to_byte(),
        0,
        compressed_public_key,
    );
    Ok(())
}

/// Sign only P2PK inputs that match an imported raw private key.
pub fn sign_matching_inputs_in_place_with_entropy(
    tx: &mut Transaction,
    private_key: &[u8; 32],
    sighash_type: SigHashType,
    signing_entropy: &[u8; 32],
) -> Result<usize, PsktError> {
    validate_base_transaction(tx)?;
    let compressed_public_key =
        crate::derivation::bip32::compressed_pubkey_from_raw_key(private_key)
            .map_err(|_| PsktError::SigningFailed)?;
    let xonly = &compressed_public_key[1..33];
    let mut signed_count = 0usize;
    for input_index in 0..tx.num_inputs {
        if !input_matches_xonly(tx, input_index, xonly) {
            continue;
        }
        sign_matching_input(
            tx,
            input_index,
            private_key,
            sighash_type,
            signing_entropy,
            compressed_public_key,
        )?;
        signed_count += 1;
    }
    if signed_count == 0 {
        Err(PsktError::NoInputs)
    } else {
        Ok(signed_count)
    }
}
