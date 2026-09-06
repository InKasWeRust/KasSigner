use crate::transaction::model::{
    detect_script_type, parse_multisig_script, MultisigInfo, ScriptType, Transaction,
};

use super::validation::checked_redeem_bytes;

/// Analyze the script controlling one input.
///
/// Invalid indexes or malformed externally constructed redeem metadata return
/// `ScriptType::Unknown` rather than panicking.
pub fn analyze_input_script(
    tx: &Transaction,
    input_index: usize,
) -> (ScriptType, Option<MultisigInfo>) {
    try_analyze_input_script(tx, input_index).unwrap_or((ScriptType::Unknown, None))
}

fn try_analyze_input_script(
    tx: &Transaction,
    input_index: usize,
) -> Option<(ScriptType, Option<MultisigInfo>)> {
    if input_index >= tx.num_inputs {
        return None;
    }
    let script = &tx.inputs[input_index].utxo_entry.script_public_key;
    let script_bytes = script.script.get(..script.script_len)?;
    let script_type = detect_script_type(script_bytes, script_bytes.len());

    if script_type == ScriptType::P2SH && tx.inputs[input_index].redeem_script_len != 0 {
        let redeem = checked_redeem_bytes(tx, input_index).ok()?;
        let redeem_type = detect_script_type(redeem, redeem.len());
        let multisig = if redeem_type == ScriptType::Multisig {
            parse_multisig_script(redeem, redeem.len())
        } else {
            None
        };
        return Some((ScriptType::P2SH, multisig));
    }

    let multisig = if script_type == ScriptType::Multisig {
        parse_multisig_script(script_bytes, script_bytes.len())
    } else {
        None
    };
    Some((script_type, multisig))
}
