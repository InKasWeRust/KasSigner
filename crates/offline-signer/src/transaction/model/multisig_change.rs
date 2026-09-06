//! Descriptor-backed 45' multisig change verification.

use super::{
    constants::{OP_BLAKE2B, OP_DATA_32, OP_EQUAL},
    multisig::MultisigConfig,
    transaction::Transaction,
};

/// Find the first 45' output change claim contradicted by a descriptor already
/// proven against one of this transaction's inputs. Unknown/unverifiable claims
/// are not called forged; only a trusted-descriptor mismatch is fatal.
#[must_use]
pub fn find_forged_change(tx: &Transaction, configs: &[MultisigConfig]) -> Option<usize> {
    let trusted = trusted_descriptor(tx, configs)?;
    for output_index in 0..tx.num_outputs {
        let output = &tx.outputs[output_index];
        if !output.ms45_hint.present {
            continue;
        }
        let Some(hash) =
            p2sh_hash(&output.script_public_key.script[..output.script_public_key.script_len])
        else {
            continue;
        };
        if matches_input_script(
            tx,
            &output.script_public_key.script[..output.script_public_key.script_len],
        ) {
            continue;
        }
        if !trusted.matches_at(&output.ms45_hint, &hash) {
            return Some(output_index);
        }
    }
    None
}

/// Return the trusted 45' chain for one multisig output after proving both the
/// transaction input and the output script against the same stored descriptor.
/// `0` is receive, `1` is change. Unhinted, legacy, same-input-script, malformed,
/// or otherwise unverifiable outputs return `None` rather than being guessed.
#[must_use]
pub fn trusted_multisig_output_chain(
    tx: &Transaction,
    configs: &[MultisigConfig],
    output_index: usize,
) -> Option<u8> {
    let trusted = trusted_descriptor(tx, configs)?;
    let output = tx.outputs.get(output_index)?;
    if output_index >= tx.num_outputs || !output.ms45_hint.present {
        return None;
    }
    let script = &output.script_public_key.script[..output.script_public_key.script_len];
    let hash = p2sh_hash(script)?;
    if matches_input_script(tx, script) || !trusted.matches_at(&output.ms45_hint, &hash) {
        return None;
    }
    u8::try_from(output.ms45_hint.chain)
        .ok()
        .filter(|chain| *chain <= 1)
}

fn trusted_descriptor<'a>(
    tx: &Transaction,
    configs: &'a [MultisigConfig],
) -> Option<&'a MultisigConfig> {
    for config in configs.iter().filter(|config| config.active && config.v45) {
        for input in tx.inputs.iter().take(tx.num_inputs) {
            let script = input.utxo_entry.script_public_key.script_bytes();
            let Some(hash) = p2sh_hash(script) else {
                continue;
            };
            if config.matches_at(&input.ms45_hint, &hash) {
                return Some(config);
            }
        }
    }
    None
}

fn matches_input_script(tx: &Transaction, candidate: &[u8]) -> bool {
    tx.inputs
        .iter()
        .take(tx.num_inputs)
        .any(|input| input.utxo_entry.script_public_key.script_bytes() == candidate)
}

fn p2sh_hash(script: &[u8]) -> Option<[u8; 32]> {
    if script.len() != 35
        || script[0] != OP_BLAKE2B
        || script[1] != OP_DATA_32
        || script[34] != OP_EQUAL
    {
        return None;
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&script[2..34]);
    Some(hash)
}
