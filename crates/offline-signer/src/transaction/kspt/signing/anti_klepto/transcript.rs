use shared_signer::anti_klepto::{Commitment, NonceCommitment, SignatureProof, Signed};

use crate::{
    crypto::{
        anti_klepto as crypto,
        schnorr::{schnorr_verify, SchnorrSignature},
    },
    transaction::{
        model::{SigHashType, Transaction},
        sighash,
    },
};

use super::{
    commitment::validate_host_commitment, keys::signing_pubkey_xonly,
    transaction_body::same_transaction_body, AntiKleptoVerifyError,
};

pub fn verify_host_transcript(
    original: &Transaction,
    signed: &Transaction,
    commitment: &Commitment<'_>,
    signed_message: &Signed<'_>,
    host_secret: &[u8; 32],
) -> Result<(), AntiKleptoVerifyError> {
    validate_host_commitment(original, commitment)?;
    validate_transcript_binding(original, signed, commitment, signed_message)?;
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

fn validate_transcript_binding(
    original: &Transaction,
    signed: &Transaction,
    commitment: &Commitment<'_>,
    signed_message: &Signed<'_>,
) -> Result<(), AntiKleptoVerifyError> {
    if commitment.session_id != signed_message.session_id
        || commitment.transaction_digest != signed_message.transaction_digest
    {
        return Err(AntiKleptoVerifyError::SessionMismatch);
    }
    if !same_transaction_body(original, signed)
        || commitment.len() != signed_message.proof_count()
        || added_signature_count(original, signed)? != commitment.len()
    {
        return Err(AntiKleptoVerifyError::TransactionMismatch);
    }
    Ok(())
}

fn verify_transcript_proof(
    original: &Transaction,
    signed: &Transaction,
    commitment: &Commitment<'_>,
    signed_message: &Signed<'_>,
    host_secret: &[u8; 32],
    index: usize,
) -> Result<(), AntiKleptoVerifyError> {
    let commitment_record = commitment
        .record(index)
        .ok_or(AntiKleptoVerifyError::InvalidProof)?;
    let proof = signed_message
        .proof(index)
        .ok_or(AntiKleptoVerifyError::InvalidProof)?;
    validate_proof_position(signed, &commitment_record, &proof)?;
    let input_index =
        usize::try_from(proof.input_index).map_err(|_| AntiKleptoVerifyError::InvalidProof)?;
    let actual = &signed.inputs[input_index].sigs[usize::from(proof.signature_slot)];
    validate_proof_signature_metadata(original, signed, &commitment_record, &proof, actual)?;
    verify_proof_signature(
        signed,
        commitment,
        host_secret,
        &commitment_record,
        &proof,
        actual,
    )
}

pub(in crate::transaction::kspt::signing) fn validate_proof_position(
    signed: &Transaction,
    commitment: &NonceCommitment,
    proof: &SignatureProof,
) -> Result<(), AntiKleptoVerifyError> {
    let input_index =
        usize::try_from(proof.input_index).map_err(|_| AntiKleptoVerifyError::InvalidProof)?;
    let slot = usize::from(proof.signature_slot);
    if commitment.input_index != proof.input_index
        || commitment.signature_slot != proof.signature_slot
        || input_index >= signed.num_inputs
        || slot >= usize::from(signed.inputs[input_index].sig_count)
    {
        Err(AntiKleptoVerifyError::InvalidProof)
    } else {
        Ok(())
    }
}

fn validate_proof_signature_metadata(
    original: &Transaction,
    signed: &Transaction,
    commitment: &NonceCommitment,
    proof: &SignatureProof,
    actual: &crate::transaction::model::InputSig,
) -> Result<(), AntiKleptoVerifyError> {
    let input_index =
        usize::try_from(proof.input_index).map_err(|_| AntiKleptoVerifyError::InvalidProof)?;
    let expected_sighash = expected_added_sighash(original, input_index);
    if (actual.present, actual.sighash_type, actual.sighash_type)
        != (
            true,
            signed.inputs[input_index].sighash_type,
            expected_sighash,
        )
    {
        return Err(AntiKleptoVerifyError::InvalidProof);
    }
    let expected_xonly = signing_pubkey_xonly(signed, input_index, actual.pubkey_pos)?;
    if commitment.public_key[1..33] != expected_xonly {
        return Err(AntiKleptoVerifyError::InvalidPublicKey);
    }
    Ok(())
}

pub(in crate::transaction::kspt::signing) fn expected_added_sighash(
    original: &Transaction,
    input_index: usize,
) -> u8 {
    let input = &original.inputs[input_index];
    if input.sig_count == 0 {
        SigHashType::All.to_byte()
    } else {
        input.sighash_type
    }
}

fn verify_proof_signature(
    signed: &Transaction,
    commitment: &Commitment<'_>,
    host_secret: &[u8; 32],
    commitment_record: &NonceCommitment,
    proof: &SignatureProof,
    actual: &crate::transaction::model::InputSig,
) -> Result<(), AntiKleptoVerifyError> {
    let input_index =
        usize::try_from(proof.input_index).map_err(|_| AntiKleptoVerifyError::InvalidProof)?;
    let expected_xonly = signing_pubkey_xonly(signed, input_index, actual.pubkey_pos)?;
    let sighash_type = SigHashType::from_byte(actual.sighash_type)
        .ok_or(AntiKleptoVerifyError::InvalidSignature)?;
    let message = sighash::calculate_sighash(signed, input_index, sighash_type);
    let signature = SchnorrSignature {
        bytes: actual.signature,
    };
    schnorr_verify(&expected_xonly, &message, &signature)
        .map_err(|_| AntiKleptoVerifyError::InvalidSignature)?;
    crypto::verify_nonce_relation(
        &commitment_record.nonce_point,
        &signature,
        &commitment.session_id,
        host_secret,
        commitment_record.input_index,
        commitment_record.signature_slot,
        &commitment_record.public_key,
    )
    .map_err(|_| AntiKleptoVerifyError::InvalidNonceRelation)
}

pub(in crate::transaction::kspt::signing) fn added_signature_count(
    original: &Transaction,
    signed: &Transaction,
) -> Result<usize, AntiKleptoVerifyError> {
    if original.num_inputs != signed.num_inputs {
        return Err(AntiKleptoVerifyError::TransactionMismatch);
    }
    let mut added = 0usize;
    for input_index in 0..original.num_inputs {
        added = added
            .checked_add(added_signatures_for_input(original, signed, input_index)?)
            .ok_or(AntiKleptoVerifyError::TransactionMismatch)?;
    }
    Ok(added)
}

pub(in crate::transaction::kspt::signing) fn added_signatures_for_input(
    original: &Transaction,
    signed: &Transaction,
    input_index: usize,
) -> Result<usize, AntiKleptoVerifyError> {
    let before = usize::from(original.inputs[input_index].sig_count);
    let after = usize::from(signed.inputs[input_index].sig_count);
    let added = signed.inputs[input_index]
        .sigs
        .get(before..after)
        .ok_or(AntiKleptoVerifyError::TransactionMismatch)?;
    if added.iter().any(|slot| !slot.present) {
        return Err(AntiKleptoVerifyError::InvalidProof);
    }
    Ok(added.len())
}
