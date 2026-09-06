use crate::transaction::model::{ScriptPublicKey, Transaction};

use super::super::{error::PsktError, validation::validate_base_transaction};

pub(super) fn xonly_from_script(script: &ScriptPublicKey) -> Option<[u8; 32]> {
    matches!(
        (script.script_len, script.script[0], script.script[33]),
        (34, 0x20, 0xac)
    )
    .then(|| {
        let mut target = [0u8; 32];
        target.copy_from_slice(&script.script[1..33]);
        target
    })
}

pub(super) fn checked_target(
    tx: &Transaction,
    input_index: usize,
) -> Result<Option<[u8; 32]>, PsktError> {
    validate_base_transaction(tx)?;
    ensure_input_index(tx, input_index)?;
    Ok(xonly_from_script(
        &tx.inputs[input_index].utxo_entry.script_public_key,
    ))
}

pub(super) fn ensure_input_index(tx: &Transaction, input_index: usize) -> Result<(), PsktError> {
    tx.inputs
        .get(input_index)
        .ok_or(PsktError::InvalidInputIndex)?;
    if input_index >= tx.num_inputs {
        return Err(PsktError::InvalidInputIndex);
    }
    Ok(())
}
