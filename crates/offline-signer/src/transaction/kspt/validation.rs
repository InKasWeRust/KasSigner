use crate::transaction::model::{
    SigHashType, Transaction, TransactionAmountError, TransactionAmounts, MAX_INPUTS, MAX_OUTPUTS,
    MAX_PAYLOAD_SIZE, MAX_REDEEM_SIZE, MAX_SCRIPT_SIZE, MAX_SIGS_PER_INPUT, REDEEM_POOL_SIZE,
};

use super::error::PsktError;

fn map_amount_error(error: TransactionAmountError) -> PsktError {
    match error {
        TransactionAmountError::InputTotalOverflow => PsktError::InputAmountOverflow,
        TransactionAmountError::OutputTotalOverflow => PsktError::OutputAmountOverflow,
        TransactionAmountError::OutputsExceedInputs => PsktError::OutputsExceedInputs,
    }
}

pub fn transaction_amounts(tx: &Transaction) -> Result<TransactionAmounts, PsktError> {
    tx.checked_amounts().map_err(map_amount_error)
}

pub fn validate_transaction_for_review(tx: &Transaction) -> Result<(), PsktError> {
    validate_base_transaction(tx)
}

fn checked_pool_redeem_bytes(
    tx: &Transaction,
    start: usize,
    len: usize,
) -> Result<&[u8], PsktError> {
    let end = start.checked_add(len).ok_or(PsktError::InvalidModel)?;
    if tx.redeem_pool_used > REDEEM_POOL_SIZE || end > tx.redeem_pool_used {
        return Err(PsktError::InvalidModel);
    }
    if end > tx.redeem_pool.len() {
        return Err(PsktError::InvalidModel);
    }
    Ok(&tx.redeem_pool[start..end])
}

fn checked_inline_redeem_bytes(
    input: &crate::transaction::model::TransactionInput,
    len: usize,
) -> Result<&[u8], PsktError> {
    input
        .redeem_script
        .get(..len)
        .ok_or(PsktError::InvalidModel)
}

pub(crate) fn checked_redeem_bytes(
    tx: &Transaction,
    input_index: usize,
) -> Result<&[u8], PsktError> {
    if input_index >= tx.num_inputs || input_index >= tx.inputs.len() {
        return Err(PsktError::InvalidInputIndex);
    }
    let input = &tx.inputs[input_index];
    let len = input.redeem_script_len;
    if len == 0 {
        return Ok(&[]);
    }
    if len > MAX_REDEEM_SIZE {
        return Err(PsktError::ScriptTooLong);
    }
    if input.redeem_in_pool {
        return checked_pool_redeem_bytes(tx, input.redeem_script_offset as usize, len);
    }
    checked_inline_redeem_bytes(input, len)
}

fn validate_transaction_shape(tx: &Transaction) -> Result<(), PsktError> {
    if tx.num_inputs == 0 {
        return Err(PsktError::NoInputs);
    }
    if tx.num_inputs > MAX_INPUTS {
        return Err(PsktError::TooManyInputs);
    }
    if tx.num_inputs > tx.inputs.len() {
        return Err(PsktError::InvalidModel);
    }
    if tx.num_outputs == 0 {
        return Err(PsktError::NoOutputs);
    }
    if tx.num_outputs > MAX_OUTPUTS {
        return Err(PsktError::TooManyOutputs);
    }
    if tx.payload_len > MAX_PAYLOAD_SIZE {
        return Err(PsktError::PayloadTooLong);
    }
    if tx.redeem_pool_used > REDEEM_POOL_SIZE {
        return Err(PsktError::InvalidModel);
    }
    Ok(())
}

fn validate_inputs(tx: &Transaction) -> Result<(), PsktError> {
    for input_index in 0..tx.num_inputs {
        let input = &tx.inputs[input_index];
        if input.utxo_entry.script_public_key.script_len > MAX_SCRIPT_SIZE {
            return Err(PsktError::ScriptTooLong);
        }
        checked_redeem_bytes(tx, input_index)?;
    }
    Ok(())
}

fn validate_outputs(tx: &Transaction) -> Result<(), PsktError> {
    for output in &tx.outputs[..tx.num_outputs] {
        if output.script_public_key.script_len > MAX_SCRIPT_SIZE {
            return Err(PsktError::ScriptTooLong);
        }
        if output.has_covenant && output.covenant_auth_input as usize >= tx.num_inputs {
            return Err(PsktError::InvalidInputIndex);
        }
    }
    Ok(())
}

pub(crate) fn validate_base_transaction(tx: &Transaction) -> Result<(), PsktError> {
    validate_transaction_shape(tx)?;
    transaction_amounts(tx)?;
    validate_inputs(tx)?;
    validate_outputs(tx)
}

fn validate_signature_slots(
    input: &crate::transaction::model::TransactionInput,
) -> Result<(), PsktError> {
    let count = input.sig_count as usize;
    if count > MAX_SIGS_PER_INPUT {
        return Err(PsktError::TooManySignatures);
    }
    let mut seen_positions = [false; 256];
    for slot_index in 0..MAX_SIGS_PER_INPUT {
        let slot = &input.sigs[slot_index];
        if slot_index < count {
            validate_present_signature(slot, &mut seen_positions)?;
        } else if slot.present {
            return Err(PsktError::InvalidSignatureState);
        }
    }
    if count != 0 && input.sighash_type != input.sigs[0].sighash_type {
        return Err(PsktError::InvalidSignatureState);
    }
    Ok(())
}

fn validate_present_signature(
    slot: &crate::transaction::model::InputSig,
    seen_positions: &mut [bool; 256],
) -> Result<(), PsktError> {
    if !slot.present {
        return Err(PsktError::InvalidSignatureState);
    }
    if SigHashType::from_byte(slot.sighash_type).is_none() {
        return Err(PsktError::InvalidSigHashType);
    }
    let position = slot.pubkey_pos as usize;
    if seen_positions[position] {
        return Err(PsktError::InvalidSignatureState);
    }
    seen_positions[position] = true;
    Ok(())
}

pub(crate) fn validate_partial_signed(tx: &Transaction) -> Result<(), PsktError> {
    validate_base_transaction(tx)?;
    for input_index in 0..tx.num_inputs {
        validate_signature_slots(&tx.inputs[input_index])?;
        checked_redeem_bytes(tx, input_index)?;
    }
    Ok(())
}

#[cfg(test)]
mod unit_tests;
