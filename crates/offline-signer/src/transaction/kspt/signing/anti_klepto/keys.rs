use crate::transaction::{
    kspt::{script::analyze_input_script, signing::covenant::candidate_keys_for_input},
    model::{ScriptType, Transaction},
};

use super::AntiKleptoVerifyError;

pub(in crate::transaction::kspt::signing) fn pubkey_is_allowed_for_input(
    tx: &Transaction,
    input_index: usize,
    target_xonly: &[u8],
) -> Result<bool, AntiKleptoVerifyError> {
    let (script_type, multisig) = analyze_input_script(tx, input_index);
    match (script_type, multisig) {
        (ScriptType::P2PK, _) => {
            let script = &tx.inputs[input_index].utxo_entry.script_public_key;
            Ok(&script.script[1..33] == target_xonly)
        }
        (ScriptType::Multisig | ScriptType::P2SH, Some(info)) => Ok(info.pubkeys
            [..usize::from(info.n)]
            .iter()
            .any(|key| key.as_slice() == target_xonly)),
        (ScriptType::P2SH, None) => {
            let candidates = candidate_keys_for_input(tx, input_index)?;
            Ok(candidates.keys[..candidates.len]
                .iter()
                .any(|key| key.as_slice() == target_xonly))
        }
        _ => Ok(false),
    }
}

pub(in crate::transaction::kspt::signing) fn signing_pubkey_xonly(
    tx: &Transaction,
    input_index: usize,
    pubkey_pos: u8,
) -> Result<[u8; 32], AntiKleptoVerifyError> {
    let (script_type, multisig) = analyze_input_script(tx, input_index);
    match (script_type, multisig) {
        (ScriptType::P2PK, _) => p2pk_signing_key(tx, input_index),
        (ScriptType::Multisig | ScriptType::P2SH, Some(info)) => info
            .pubkeys
            .get(..usize::from(info.n))
            .and_then(|keys| keys.get(usize::from(pubkey_pos)))
            .copied()
            .ok_or(AntiKleptoVerifyError::InvalidPublicKey),
        (ScriptType::P2SH, None) => covenant_signing_key(tx, input_index, pubkey_pos),
        _ => Err(AntiKleptoVerifyError::InvalidPublicKey),
    }
}

fn p2pk_signing_key(
    tx: &Transaction,
    input_index: usize,
) -> Result<[u8; 32], AntiKleptoVerifyError> {
    let script = &tx.inputs[input_index].utxo_entry.script_public_key;
    let mut key = [0u8; 32];
    key.copy_from_slice(&script.script[1..33]);
    Ok(key)
}

fn covenant_signing_key(
    tx: &Transaction,
    input_index: usize,
    pubkey_pos: u8,
) -> Result<[u8; 32], AntiKleptoVerifyError> {
    let candidates = candidate_keys_for_input(tx, input_index)?;
    candidates.keys[..candidates.len]
        .get(usize::from(pubkey_pos))
        .copied()
        .ok_or(AntiKleptoVerifyError::InvalidPublicKey)
}
