use crate::transaction::model::{ScriptType, Transaction};

use super::super::script::analyze_input_script;

#[derive(Clone, Copy)]
enum SignatureRequirement {
    Count(u8),
    Unsupported,
}

fn requirement_for_input(tx: &Transaction, input_index: usize) -> SignatureRequirement {
    let (script_type, multisig) = analyze_input_script(tx, input_index);
    match (script_type, multisig) {
        (ScriptType::P2PK, _) => SignatureRequirement::Count(1),
        (ScriptType::Multisig | ScriptType::P2SH, Some(info)) => {
            SignatureRequirement::Count(info.m)
        }
        (ScriptType::P2SH, None) => SignatureRequirement::Count(1),
        _ => SignatureRequirement::Unsupported,
    }
}

fn present_for_input(tx: &Transaction, input_index: usize, required: u8) -> u8 {
    tx.inputs[input_index].sig_count.min(required)
}

pub fn is_fully_signed(tx: &Transaction) -> bool {
    if tx.num_inputs == 0 || tx.num_inputs > tx.inputs.len() {
        return false;
    }
    for input_index in 0..tx.num_inputs {
        let SignatureRequirement::Count(required) = requirement_for_input(tx, input_index) else {
            return false;
        };
        if present_for_input(tx, input_index, required) < required {
            return false;
        }
    }
    true
}

pub fn signature_status(tx: &Transaction) -> (u32, u32) {
    if tx.num_inputs > tx.inputs.len() {
        return (0, 0);
    }
    let mut present = 0u32;
    let mut required = 0u32;
    for input_index in 0..tx.num_inputs {
        match requirement_for_input(tx, input_index) {
            SignatureRequirement::Count(count) => {
                required = required.saturating_add(u32::from(count));
                present =
                    present.saturating_add(u32::from(present_for_input(tx, input_index, count)));
            }
            SignatureRequirement::Unsupported => required = required.saturating_add(1),
        }
    }
    (present, required)
}
