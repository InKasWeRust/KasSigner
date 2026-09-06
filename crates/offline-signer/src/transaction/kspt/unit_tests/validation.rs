use crate::transaction::{
    kspt::{
        error::PsktError,
        validation::{
            checked_redeem_bytes, validate_base_transaction, validate_partial_signed,
            validate_transaction_for_review,
        },
    },
    model::{
        MAX_OUTPUTS, MAX_PAYLOAD_SIZE, MAX_REDEEM_SIZE, MAX_SCRIPT_SIZE, MAX_SIGS_PER_INPUT,
        REDEEM_POOL_SIZE,
    },
};

use super::common::{add_single_signature, transaction};

#[test]
fn base_validation_classifies_transaction_shape_and_capacity_failures() {
    let mut tx = transaction();
    tx.num_inputs = 0;
    assert_eq!(validate_base_transaction(&tx), Err(PsktError::NoInputs));

    let mut tx = transaction();
    tx.num_inputs = tx.inputs.len() + 1;
    assert_eq!(validate_base_transaction(&tx), Err(PsktError::InvalidModel));

    let mut tx = transaction();
    tx.num_outputs = 0;
    assert_eq!(validate_base_transaction(&tx), Err(PsktError::NoOutputs));

    let mut tx = transaction();
    tx.num_outputs = MAX_OUTPUTS + 1;
    assert_eq!(
        validate_base_transaction(&tx),
        Err(PsktError::TooManyOutputs)
    );

    let mut tx = transaction();
    tx.payload_len = MAX_PAYLOAD_SIZE + 1;
    assert_eq!(
        validate_base_transaction(&tx),
        Err(PsktError::PayloadTooLong)
    );

    let mut tx = transaction();
    tx.redeem_pool_used = REDEEM_POOL_SIZE + 1;
    assert_eq!(validate_base_transaction(&tx), Err(PsktError::InvalidModel));
}

#[test]
fn base_validation_rejects_aggregate_monetary_overflow_and_negative_fee_shape() {
    let mut input_overflow = transaction();
    input_overflow
        .ensure_input_slots(2)
        .expect("second input slot");
    input_overflow.num_inputs = 2;
    input_overflow.inputs[0].utxo_entry.amount = u64::MAX;
    input_overflow.inputs[1] = input_overflow.inputs[0].clone();
    input_overflow.inputs[1].utxo_entry.amount = 1;
    input_overflow.outputs[0].value = u64::MAX;
    assert_eq!(
        validate_base_transaction(&input_overflow),
        Err(PsktError::InputAmountOverflow)
    );

    let mut output_overflow = transaction();
    output_overflow.num_outputs = 2;
    output_overflow.inputs[0].utxo_entry.amount = u64::MAX;
    output_overflow.outputs[0].value = u64::MAX;
    output_overflow.outputs[1] = output_overflow.outputs[0].clone();
    output_overflow.outputs[1].value = 1;
    assert_eq!(
        validate_base_transaction(&output_overflow),
        Err(PsktError::OutputAmountOverflow)
    );

    let mut negative_fee = transaction();
    negative_fee.outputs[0].value = negative_fee.inputs[0].utxo_entry.amount + 1;
    assert_eq!(
        validate_base_transaction(&negative_fee),
        Err(PsktError::OutputsExceedInputs)
    );

    let mut exact_max = transaction();
    exact_max.ensure_input_slots(2).expect("second input slot");
    exact_max.num_inputs = 2;
    exact_max.inputs[1] = exact_max.inputs[0].clone();
    exact_max.inputs[0].utxo_entry.amount = u64::MAX - 1;
    exact_max.inputs[1].utxo_entry.amount = 1;
    exact_max.outputs[0].value = u64::MAX;
    assert_eq!(validate_base_transaction(&exact_max), Ok(()));
}

#[test]
fn base_validation_rejects_oversized_scripts_and_invalid_covenant_links() {
    let mut input_script = transaction();
    input_script.inputs[0]
        .utxo_entry
        .script_public_key
        .script_len = MAX_SCRIPT_SIZE + 1;
    assert_eq!(
        validate_base_transaction(&input_script),
        Err(PsktError::ScriptTooLong)
    );

    let mut output_script = transaction();
    output_script.outputs[0].script_public_key.script_len = MAX_SCRIPT_SIZE + 1;
    assert_eq!(
        validate_base_transaction(&output_script),
        Err(PsktError::ScriptTooLong)
    );

    let mut covenant = transaction();
    covenant.outputs[0].has_covenant = true;
    covenant.outputs[0].covenant_auth_input = 1;
    assert_eq!(
        validate_base_transaction(&covenant),
        Err(PsktError::InvalidInputIndex)
    );
}

#[test]
fn redeem_script_validation_covers_inline_pool_and_index_boundaries() {
    let tx = transaction();
    assert_eq!(
        checked_redeem_bytes(&tx, 1),
        Err(PsktError::InvalidInputIndex)
    );
    assert_eq!(
        checked_redeem_bytes(&tx, tx.inputs.len()),
        Err(PsktError::InvalidInputIndex)
    );
    assert_eq!(checked_redeem_bytes(&tx, 0), Ok(&[][..]));

    let mut inline = transaction();
    inline.inputs[0].redeem_script[..3].copy_from_slice(b"abc");
    inline.inputs[0].redeem_script_len = 3;
    assert_eq!(checked_redeem_bytes(&inline, 0), Ok(&b"abc"[..]));

    let mut inline_too_long = transaction();
    inline_too_long.inputs[0].redeem_script_len = MAX_REDEEM_SIZE + 1;
    assert_eq!(
        checked_redeem_bytes(&inline_too_long, 0),
        Err(PsktError::ScriptTooLong)
    );

    let mut inline_out_of_bounds = transaction();
    inline_out_of_bounds.inputs[0].redeem_script_len = MAX_SCRIPT_SIZE + 1;
    assert_eq!(
        checked_redeem_bytes(&inline_out_of_bounds, 0),
        Err(PsktError::InvalidModel)
    );

    let mut pooled = transaction();
    pooled.redeem_pool[..3].copy_from_slice(b"xyz");
    pooled.redeem_pool_used = 3;
    pooled.inputs[0].redeem_in_pool = true;
    pooled.inputs[0].redeem_script_len = 3;
    assert_eq!(checked_redeem_bytes(&pooled, 0), Ok(&b"xyz"[..]));

    let mut pool_usage_short = transaction();
    pool_usage_short.inputs[0].redeem_in_pool = true;
    pool_usage_short.inputs[0].redeem_script_len = 3;
    pool_usage_short.redeem_pool_used = 2;
    assert_eq!(
        checked_redeem_bytes(&pool_usage_short, 0),
        Err(PsktError::InvalidModel)
    );

    let mut pool_slice_out_of_bounds = transaction();
    pool_slice_out_of_bounds.inputs[0].redeem_in_pool = true;
    pool_slice_out_of_bounds.inputs[0].redeem_script_offset = REDEEM_POOL_SIZE as u16;
    pool_slice_out_of_bounds.inputs[0].redeem_script_len = 1;
    pool_slice_out_of_bounds.redeem_pool_used = REDEEM_POOL_SIZE;
    assert_eq!(
        checked_redeem_bytes(&pool_slice_out_of_bounds, 0),
        Err(PsktError::InvalidModel)
    );
}

#[test]
fn partial_signature_validation_rejects_every_inconsistent_slot_state() {
    let mut too_many = transaction();
    too_many.inputs[0].sig_count = (MAX_SIGS_PER_INPUT + 1) as u8;
    assert_eq!(
        validate_partial_signed(&too_many),
        Err(PsktError::TooManySignatures)
    );

    let mut missing = transaction();
    missing.inputs[0].sig_count = 1;
    assert_eq!(
        validate_partial_signed(&missing),
        Err(PsktError::InvalidSignatureState)
    );

    let mut invalid_sighash = transaction();
    add_single_signature(&mut invalid_sighash, 0, [0x11; 64]);
    invalid_sighash.inputs[0].sigs[0].sighash_type = 0xff;
    invalid_sighash.inputs[0].sighash_type = 0xff;
    assert_eq!(
        validate_partial_signed(&invalid_sighash),
        Err(PsktError::InvalidSigHashType)
    );

    let mut duplicate_position = transaction();
    add_single_signature(&mut duplicate_position, 0, [0x22; 64]);
    duplicate_position.inputs[0].sig_count = 2;
    duplicate_position.inputs[0].sigs[1] = duplicate_position.inputs[0].sigs[0].clone();
    assert_eq!(
        validate_partial_signed(&duplicate_position),
        Err(PsktError::InvalidSignatureState)
    );

    let mut unexpected_slot = transaction();
    unexpected_slot.inputs[0].sigs[1].present = true;
    assert_eq!(
        validate_partial_signed(&unexpected_slot),
        Err(PsktError::InvalidSignatureState)
    );

    let mut mismatched_policy = transaction();
    add_single_signature(&mut mismatched_policy, 0, [0x33; 64]);
    mismatched_policy.inputs[0].sighash_type = 0x02;
    assert_eq!(
        validate_partial_signed(&mismatched_policy),
        Err(PsktError::InvalidSignatureState)
    );

    let mut valid = transaction();
    add_single_signature(&mut valid, 0, [0x44; 64]);
    assert_eq!(validate_partial_signed(&valid), Ok(()));
}

#[test]
fn validation_accepts_dynamic_inputs_and_fixed_output_boundaries() {
    const MANY_INPUTS: usize = 16;
    let mut tx = transaction();
    tx.ensure_input_slots(MANY_INPUTS)
        .expect("grow input model");
    tx.num_inputs = MANY_INPUTS;
    tx.num_outputs = MAX_OUTPUTS;
    tx.payload_len = MAX_PAYLOAD_SIZE;
    tx.redeem_pool_used = REDEEM_POOL_SIZE;
    for input in &mut tx.inputs[..MANY_INPUTS] {
        input.utxo_entry.script_public_key.script_len = MAX_SCRIPT_SIZE;
    }
    for output in &mut tx.outputs[..MAX_OUTPUTS] {
        output.script_public_key.script_len = MAX_SCRIPT_SIZE;
    }
    tx.outputs[0].has_covenant = true;
    tx.outputs[0].covenant_auth_input = (MANY_INPUTS - 1) as u16;
    assert_eq!(validate_base_transaction(&tx), Ok(()));

    let mut pooled = transaction();
    pooled.inputs[0].redeem_in_pool = true;
    pooled.inputs[0].redeem_script_offset = (REDEEM_POOL_SIZE - MAX_REDEEM_SIZE) as u16;
    pooled.inputs[0].redeem_script_len = MAX_REDEEM_SIZE;
    pooled.redeem_pool_used = REDEEM_POOL_SIZE;
    assert_eq!(
        checked_redeem_bytes(&pooled, 0).unwrap().len(),
        MAX_REDEEM_SIZE
    );

    let mut exact_signatures = transaction();
    exact_signatures.inputs[0].sig_count = MAX_SIGS_PER_INPUT as u8;
    exact_signatures.inputs[0].sighash_type = 1;
    for (position, slot) in exact_signatures.inputs[0].sigs.iter_mut().enumerate() {
        slot.present = true;
        slot.pubkey_pos = position as u8;
        slot.sighash_type = 1;
        slot.signature = [position as u8 + 1; 64];
    }
    assert_eq!(validate_partial_signed(&exact_signatures), Ok(()));
}

#[test]
fn public_review_validation_delegates_to_base_validation() {
    let tx = transaction();
    assert_eq!(
        validate_transaction_for_review(&tx),
        validate_base_transaction(&tx)
    );
    let mut empty = transaction();
    empty.num_inputs = 0;
    assert_eq!(
        validate_transaction_for_review(&empty),
        Err(PsktError::NoInputs)
    );
}
