use shared_signer::anti_klepto::{Commitment, NonceCommitment, SignatureProof, Signed};

use crate::protocol::{
    anti_klepto::verify_nonce_relation,
    schnorr::bip340_verify,
    transaction::sighash::{
        compute_full_sighash, FullSighashInput, FullSighashRequest, SighashContext, SighashOutput,
    },
};

use super::{
    kspt_bridge::{parse_compact_kspt_transaction, xonly_at_position},
    model::{CompactKsptInput, CompactKsptTransaction},
};

const MAX_SIGNATURES_PER_INPUT: usize = 5;

pub(crate) fn validate_host_commitment_wire(
    original_wire: &[u8],
    commitment: &Commitment<'_>,
) -> Result<(), String> {
    let original = parse_anti_klepto_transaction(original_wire)?;
    validate_host_commitment(&original, commitment)
}

pub(crate) fn verify_host_transcript_wire(
    original_wire: &[u8],
    signed_wire: &[u8],
    commitment: &Commitment<'_>,
    signed_message: &Signed<'_>,
    host_secret: &[u8; 32],
) -> Result<(), String> {
    let original = parse_anti_klepto_transaction(original_wire)?;
    let signed = parse_anti_klepto_transaction(signed_wire)?;
    verify_host_transcript(&original, &signed, commitment, signed_message, host_secret)
}

pub(crate) fn validate_anti_klepto_transaction_wire(data: &[u8]) -> Result<(), String> {
    parse_anti_klepto_transaction(data).map(|_| ())
}

fn parse_anti_klepto_transaction(data: &[u8]) -> Result<CompactKsptTransaction, String> {
    let transaction = parse_compact_kspt_transaction(data)?;
    if transaction.inputs.is_empty() {
        return Err("compact KSPT has no inputs".into());
    }
    if transaction.outputs.is_empty() {
        return Err("compact KSPT has no outputs".into());
    }
    if transaction.flags & !0x01 != 0 {
        return Err("compact KSPT contains unsupported flags".into());
    }
    Ok(transaction)
}

fn validate_host_commitment(
    original: &CompactKsptTransaction,
    commitment: &Commitment<'_>,
) -> Result<(), String> {
    let mut previous = None;
    for index in 0..commitment.len() {
        let record = commitment
            .record(index)
            .ok_or_else(|| "invalid anti-klepto proof".to_string())?;
        let position = (record.input_index, record.signature_slot);
        if previous.is_some_and(|value| value >= position) {
            return Err("anti-klepto commitments are not strictly ordered".into());
        }
        validate_commitment_record(original, &record)?;
        previous = Some(position);
    }
    Ok(())
}

fn validate_commitment_record(
    original: &CompactKsptTransaction,
    record: &NonceCommitment,
) -> Result<(), String> {
    let input_index = usize::try_from(record.input_index)
        .map_err(|_| "anti-klepto input index is out of range".to_string())?;
    let input = original
        .inputs
        .get(input_index)
        .ok_or_else(|| "anti-klepto input index is out of range".to_string())?;
    let slot = usize::from(record.signature_slot);
    if slot < input.signatures.len() || slot >= MAX_SIGNATURES_PER_INPUT {
        return Err("anti-klepto signature slot is invalid".into());
    }
    validate_canonical_commitment_points(record)?;
    if !pubkey_is_allowed_for_input(input, &record.public_key[1..]) {
        return Err("anti-klepto commitment uses an unexpected signing key".into());
    }
    Ok(())
}

fn validate_canonical_commitment_points(record: &NonceCommitment) -> Result<(), String> {
    if record.public_key[0] != 0x02 || record.nonce_point[0] != 0x02 {
        return Err("anti-klepto points must use even-Y compressed encoding".into());
    }
    k256::PublicKey::from_sec1_bytes(&record.public_key)
        .map_err(|_| "anti-klepto public key is invalid".to_string())?;
    k256::PublicKey::from_sec1_bytes(&record.nonce_point)
        .map_err(|_| "anti-klepto nonce point is invalid".to_string())?;
    Ok(())
}

fn pubkey_is_allowed_for_input(input: &CompactKsptInput, target_xonly: &[u8]) -> bool {
    let script = signing_script(input);
    (0..MAX_SIGNATURES_PER_INPUT).any(|position| {
        xonly_at_position(script, position as u8).is_some_and(|key| &key[..] == target_xonly)
    })
}

fn signing_script(input: &CompactKsptInput) -> &[u8] {
    if input.redeem_script.is_empty() {
        &input.script
    } else {
        &input.redeem_script
    }
}

fn verify_host_transcript(
    original: &CompactKsptTransaction,
    signed: &CompactKsptTransaction,
    commitment: &Commitment<'_>,
    signed_message: &Signed<'_>,
    host_secret: &[u8; 32],
) -> Result<(), String> {
    validate_host_commitment(original, commitment)?;
    if commitment.session_id != signed_message.session_id
        || commitment.transaction_digest != signed_message.transaction_digest
    {
        return Err("anti-klepto session binding changed".into());
    }
    if !same_transaction_body(original, signed)
        || commitment.len() != signed_message.proof_count()
        || added_signature_count(original, signed)? != commitment.len()
    {
        return Err("anti-klepto transaction body changed".into());
    }
    for index in 0..commitment.len() {
        verify_transcript_proof(
            original,
            signed,
            commitment,
            signed_message,
            host_secret,
            index,
        )?;
    }
    Ok(())
}

fn same_transaction_body(left: &CompactKsptTransaction, right: &CompactKsptTransaction) -> bool {
    same_transaction_header(left, right)
        && left.inputs.len() == right.inputs.len()
        && left.outputs == right.outputs
        && left
            .inputs
            .iter()
            .zip(&right.inputs)
            .all(|(left, right)| same_input_body(left, right))
}

fn same_transaction_header(left: &CompactKsptTransaction, right: &CompactKsptTransaction) -> bool {
    (
        left.generation,
        left.version,
        left.locktime,
        &left.subnetwork_id,
        left.gas,
        &left.payload,
        left.network,
        &left.stealth_tweak,
    ) == (
        right.generation,
        right.version,
        right.locktime,
        &right.subnetwork_id,
        right.gas,
        &right.payload,
        right.network,
        &right.stealth_tweak,
    )
}

fn same_input_body(left: &CompactKsptInput, right: &CompactKsptInput) -> bool {
    same_input_fields(left, right) && right.signatures.starts_with(&left.signatures)
}

fn same_input_fields(left: &CompactKsptInput, right: &CompactKsptInput) -> bool {
    (
        &left.previous_tx_id,
        left.previous_index,
        left.amount,
        left.sequence,
        left.sig_op_count,
        left.script_version,
        &left.script,
        &left.redeem_script,
        left.derivation,
        left.ms45_derivation,
    ) == (
        &right.previous_tx_id,
        right.previous_index,
        right.amount,
        right.sequence,
        right.sig_op_count,
        right.script_version,
        &right.script,
        &right.redeem_script,
        right.derivation,
        right.ms45_derivation,
    )
}

fn added_signature_count(
    original: &CompactKsptTransaction,
    signed: &CompactKsptTransaction,
) -> Result<usize, String> {
    if original.inputs.len() != signed.inputs.len() {
        return Err("anti-klepto input count changed".into());
    }
    original
        .inputs
        .iter()
        .zip(&signed.inputs)
        .try_fold(0usize, |total, (before, after)| {
            if after.signatures.len() < before.signatures.len() {
                return Err("anti-klepto signature count regressed".into());
            }
            total
                .checked_add(after.signatures.len() - before.signatures.len())
                .ok_or_else(|| "anti-klepto signature count overflow".to_string())
        })
}

fn verify_transcript_proof(
    original: &CompactKsptTransaction,
    signed: &CompactKsptTransaction,
    commitment: &Commitment<'_>,
    signed_message: &Signed<'_>,
    host_secret: &[u8; 32],
    proof_index: usize,
) -> Result<(), String> {
    let commitment_record = commitment
        .record(proof_index)
        .ok_or_else(|| "anti-klepto commitment proof is missing".to_string())?;
    let proof = signed_message
        .proof(proof_index)
        .ok_or_else(|| "anti-klepto signature proof is missing".to_string())?;
    let (input_index, slot) = validate_proof_position(signed, &commitment_record, &proof)?;
    let actual = &signed.inputs[input_index].signatures[slot];
    validate_signature_metadata(original, signed, input_index, &commitment_record, actual)?;
    verify_signature_and_nonce(
        signed,
        commitment,
        host_secret,
        input_index,
        &commitment_record,
        actual,
    )
}

fn validate_proof_position(
    signed: &CompactKsptTransaction,
    commitment: &NonceCommitment,
    proof: &SignatureProof,
) -> Result<(usize, usize), String> {
    if commitment.input_index != proof.input_index
        || commitment.signature_slot != proof.signature_slot
    {
        return Err("anti-klepto proof position does not match commitment".into());
    }
    let input_index = usize::try_from(proof.input_index)
        .map_err(|_| "anti-klepto proof input index is invalid".to_string())?;
    let slot = usize::from(proof.signature_slot);
    let input = signed
        .inputs
        .get(input_index)
        .ok_or_else(|| "anti-klepto proof input index is invalid".to_string())?;
    if slot >= input.signatures.len() {
        return Err("anti-klepto proof signature slot is invalid".into());
    }
    Ok((input_index, slot))
}

fn validate_signature_metadata(
    original: &CompactKsptTransaction,
    signed: &CompactKsptTransaction,
    input_index: usize,
    commitment: &NonceCommitment,
    actual: &super::model::CompactKsptSignature,
) -> Result<(), String> {
    let signed_input = &signed.inputs[input_index];
    let input_sighash = signed_input
        .signatures
        .first()
        .map(|signature| signature.sighash_type)
        .ok_or_else(|| "anti-klepto signed input has no signatures".to_string())?;
    if actual.sighash_type != input_sighash
        || actual.sighash_type != expected_added_sighash(&original.inputs[input_index])
    {
        return Err("anti-klepto sighash metadata changed".into());
    }
    let expected_xonly = signing_pubkey_xonly(signed_input, actual.pubkey_pos)
        .ok_or_else(|| "anti-klepto signing public key is invalid".to_string())?;
    if commitment.public_key[1..33] != expected_xonly[..] {
        return Err("anti-klepto commitment public key does not match signature".into());
    }
    Ok(())
}

fn expected_added_sighash(input: &CompactKsptInput) -> u8 {
    input
        .signatures
        .first()
        .map_or(0x01, |signature| signature.sighash_type)
}

fn signing_pubkey_xonly(input: &CompactKsptInput, pubkey_pos: u8) -> Option<[u8; 32]> {
    xonly_at_position(signing_script(input), pubkey_pos)
}

fn verify_signature_and_nonce(
    signed: &CompactKsptTransaction,
    commitment: &Commitment<'_>,
    host_secret: &[u8; 32],
    input_index: usize,
    commitment_record: &NonceCommitment,
    actual: &super::model::CompactKsptSignature,
) -> Result<(), String> {
    let expected_xonly = signing_pubkey_xonly(&signed.inputs[input_index], actual.pubkey_pos)
        .ok_or_else(|| "anti-klepto signing public key is invalid".to_string())?;
    let message = transaction_sighash(signed, input_index, actual.sighash_type)?;
    if !bip340_verify(&expected_xonly, &message, &actual.signature)? {
        return Err("anti-klepto final signature is invalid".into());
    }
    verify_nonce_relation(
        &commitment_record.nonce_point,
        &actual.signature,
        &commitment.session_id,
        host_secret,
        commitment_record.input_index,
        commitment_record.signature_slot,
        &commitment_record.public_key,
    )
}

pub(crate) fn compact_kspt_sighash_wire(data: &[u8]) -> Result<[u8; 32], String> {
    let transaction = parse_anti_klepto_transaction(data)?;
    if transaction.inputs.len() != 1 {
        return Err("Private Swap claim must contain exactly one input".into());
    }
    let sighash_type = expected_added_sighash(&transaction.inputs[0]);
    if sighash_type != 0x01 {
        return Err("Private Swap claim requires SIGHASH_ALL".into());
    }
    transaction_sighash(&transaction, 0, sighash_type)
}

pub(crate) fn transaction_sighash(
    transaction: &CompactKsptTransaction,
    input_index: usize,
    sighash_type: u8,
) -> Result<[u8; 32], String> {
    let inputs: Vec<_> = transaction
        .inputs
        .iter()
        .map(|input| FullSighashInput {
            transaction_id: &input.previous_tx_id,
            index: input.previous_index,
            amount: input.amount,
            sequence: input.sequence,
            sig_op_count: input.sig_op_count,
            spk_version: input.script_version,
            spk_script: &input.script,
        })
        .collect();
    let outputs: Vec<_> = transaction
        .outputs
        .iter()
        .map(|output| SighashOutput {
            value: output.value,
            spk_version: output.script_version,
            spk_script: output.script.clone(),
            covenant: output.covenant,
        })
        .collect();
    let context = SighashContext {
        subnetwork_id: &transaction.subnetwork_id,
        gas: transaction.gas,
        locktime: transaction.locktime,
        payload: &transaction.payload,
    };
    compute_full_sighash(FullSighashRequest {
        tx_version: transaction.version,
        inputs: &inputs,
        input_index,
        outputs: &outputs,
        context: &context,
        sighash_type,
    })
}

#[cfg(test)]
mod unit_tests;
