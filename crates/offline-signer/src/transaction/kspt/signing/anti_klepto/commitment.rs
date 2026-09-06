use shared_signer::anti_klepto::{Commitment, NonceCommitment};

use crate::transaction::model::Transaction;

use super::{keys::pubkey_is_allowed_for_input, AntiKleptoVerifyError};

pub fn validate_host_commitment(
    original: &Transaction,
    commitment: &Commitment<'_>,
) -> Result<(), AntiKleptoVerifyError> {
    let mut previous_position = None;
    for index in 0..commitment.len() {
        let record = commitment
            .record(index)
            .ok_or(AntiKleptoVerifyError::InvalidProof)?;
        validate_commitment_order(previous_position, &record)?;
        validate_commitment_record(original, &record)?;
        previous_position = Some((record.input_index, record.signature_slot));
    }
    Ok(())
}

fn validate_commitment_order(
    previous: Option<(u32, u8)>,
    record: &NonceCommitment,
) -> Result<(), AntiKleptoVerifyError> {
    let position = (record.input_index, record.signature_slot);
    if previous.is_some_and(|value| value >= position) {
        Err(AntiKleptoVerifyError::InvalidProof)
    } else {
        Ok(())
    }
}

fn validate_commitment_record(
    original: &Transaction,
    record: &NonceCommitment,
) -> Result<(), AntiKleptoVerifyError> {
    let input_index =
        usize::try_from(record.input_index).map_err(|_| AntiKleptoVerifyError::InvalidProof)?;
    let slot = usize::from(record.signature_slot);
    if !commitment_position_is_valid(original, input_index, slot)
        || !canonical_points_are_valid(record)
    {
        return Err(AntiKleptoVerifyError::InvalidProof);
    }
    if !pubkey_is_allowed_for_input(original, input_index, &record.public_key[1..33])? {
        return Err(AntiKleptoVerifyError::InvalidPublicKey);
    }
    Ok(())
}

pub(in crate::transaction::kspt::signing) fn commitment_position_is_valid(
    original: &Transaction,
    input_index: usize,
    slot: usize,
) -> bool {
    let Some(input) = original.inputs.get(input_index) else {
        return false;
    };
    if input_index >= original.num_inputs || slot < usize::from(input.sig_count) {
        return false;
    }
    input.sigs.get(slot).is_some()
}

fn canonical_points_are_valid(record: &NonceCommitment) -> bool {
    record.public_key[0] == 0x02
        && record.nonce_point[0] == 0x02
        && k256::PublicKey::from_sec1_bytes(&record.public_key).is_ok()
        && k256::PublicKey::from_sec1_bytes(&record.nonce_point).is_ok()
}
