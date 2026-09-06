use crate::transaction::model::Transaction;

pub(super) fn same_transaction_body(left: &Transaction, right: &Transaction) -> bool {
    same_transaction_header(left, right)
        && same_transaction_inputs(left, right)
        && same_transaction_outputs(left, right)
}

fn same_transaction_header(left: &Transaction, right: &Transaction) -> bool {
    (
        left.version,
        left.num_inputs,
        left.num_outputs,
        left.network,
        left.locktime,
        left.subnetwork_id,
        left.gas,
        left.payload_len,
        left.has_stealth_tweak,
        left.stealth_tweak,
    ) == (
        right.version,
        right.num_inputs,
        right.num_outputs,
        right.network,
        right.locktime,
        right.subnetwork_id,
        right.gas,
        right.payload_len,
        right.has_stealth_tweak,
        right.stealth_tweak,
    ) && left.payload[..left.payload_len] == right.payload[..right.payload_len]
}

fn same_transaction_inputs(left: &Transaction, right: &Transaction) -> bool {
    for index in 0..left.num_inputs {
        if !same_input_body(left, right, index) || !same_existing_signatures(left, right, index) {
            return false;
        }
    }
    true
}

fn same_input_body(left: &Transaction, right: &Transaction, index: usize) -> bool {
    let a = &left.inputs[index];
    let b = &right.inputs[index];
    (
        a.previous_outpoint.transaction_id,
        a.previous_outpoint.index,
        a.sequence,
        a.sig_op_count,
        a.utxo_entry.amount,
        a.utxo_entry.script_public_key.version,
        a.utxo_entry.script_public_key.script_len,
        a.has_derivation_hint,
        a.derivation_branch,
        a.derivation_index,
        a.ms45_hint,
    ) == (
        b.previous_outpoint.transaction_id,
        b.previous_outpoint.index,
        b.sequence,
        b.sig_op_count,
        b.utxo_entry.amount,
        b.utxo_entry.script_public_key.version,
        b.utxo_entry.script_public_key.script_len,
        b.has_derivation_hint,
        b.derivation_branch,
        b.derivation_index,
        b.ms45_hint,
    ) && a.utxo_entry.script_public_key.script[..a.utxo_entry.script_public_key.script_len]
        == b.utxo_entry.script_public_key.script[..b.utxo_entry.script_public_key.script_len]
        && left.redeem_bytes(index) == right.redeem_bytes(index)
        && b.sig_count >= a.sig_count
}

fn same_existing_signatures(left: &Transaction, right: &Transaction, input_index: usize) -> bool {
    let count = usize::from(left.inputs[input_index].sig_count);
    for slot in 0..count {
        if !same_signature_slot(
            &left.inputs[input_index].sigs[slot],
            &right.inputs[input_index].sigs[slot],
        ) {
            return false;
        }
    }
    true
}

fn same_signature_slot(
    left: &crate::transaction::model::InputSig,
    right: &crate::transaction::model::InputSig,
) -> bool {
    (
        left.present,
        left.signature,
        left.sighash_type,
        left.pubkey_pos,
    ) == (
        right.present,
        right.signature,
        right.sighash_type,
        right.pubkey_pos,
    )
}

fn same_transaction_outputs(left: &Transaction, right: &Transaction) -> bool {
    for index in 0..left.num_outputs {
        if !same_output_body(&left.outputs[index], &right.outputs[index]) {
            return false;
        }
    }
    true
}

fn same_output_body(
    left: &crate::transaction::model::TransactionOutput,
    right: &crate::transaction::model::TransactionOutput,
) -> bool {
    (
        left.value,
        left.script_public_key.version,
        left.script_public_key.script_len,
        left.has_covenant,
        left.covenant_auth_input,
        left.covenant_id,
        left.has_derivation_hint,
        left.derivation_branch,
        left.derivation_index,
        left.ms45_hint,
    ) == (
        right.value,
        right.script_public_key.version,
        right.script_public_key.script_len,
        right.has_covenant,
        right.covenant_auth_input,
        right.covenant_id,
        right.has_derivation_hint,
        right.derivation_branch,
        right.derivation_index,
        right.ms45_hint,
    ) && left.script_public_key.script[..left.script_public_key.script_len]
        == right.script_public_key.script[..right.script_public_key.script_len]
}
