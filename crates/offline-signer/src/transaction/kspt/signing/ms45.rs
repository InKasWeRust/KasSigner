//! Strict v1.0.6 45' multisig signing from untrusted derivation hints.

use shared_signer::bytes::zeroize_bytes;

use crate::transaction::{
    model::{Ms45Hint, MultisigInfo, SigHashType, Transaction},
    sighash,
};

use super::super::error::PsktError;
use super::{
    context::SigningContext,
    signature_state::{append_signature, has_pubkey_position},
};

pub(super) fn sign_input(
    tx: &mut Transaction,
    input_index: usize,
    multisig: &MultisigInfo,
    context: &SigningContext,
    sighash_type: SigHashType,
    signing_entropy: Option<&[u8; 32]>,
    hint: &Ms45Hint,
) -> Result<usize, PsktError> {
    let mut added = 0usize;
    for seed_index in 0..context.seed_count() {
        let Some(mut material) = context.ms45_material(seed_index, hint) else {
            continue;
        };
        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(&material.compressed_public_key[1..]);
        let Some(position) = multisig.pubkeys[..multisig.n as usize]
            .iter()
            .position(|candidate| *candidate == xonly)
        else {
            zeroize_bytes(&mut material.private_key);
            continue;
        };
        if has_pubkey_position(&tx.inputs[input_index], position as u8) {
            zeroize_bytes(&mut material.private_key);
            continue;
        }
        let signature = sign_with_optional_entropy(
            tx,
            input_index,
            &material.private_key,
            sighash_type,
            signing_entropy,
        )?;
        zeroize_bytes(&mut material.private_key);
        added += usize::from(append_signature(
            &mut tx.inputs[input_index],
            signature,
            sighash_type.to_byte(),
            position as u8,
            material.compressed_public_key,
        ));
    }
    Ok(added)
}

fn sign_with_optional_entropy(
    tx: &Transaction,
    input_index: usize,
    private_key: &[u8; 32],
    sighash_type: SigHashType,
    signing_entropy: Option<&[u8; 32]>,
) -> Result<[u8; 64], PsktError> {
    let result = match signing_entropy {
        Some(entropy) => {
            sighash::sign_input_with_entropy(tx, input_index, private_key, sighash_type, entropy)
        }
        None => sighash::sign_input(tx, input_index, private_key, sighash_type),
    };
    result
        .map(|signature| signature.bytes)
        .map_err(|_| PsktError::SigningFailed)
}
