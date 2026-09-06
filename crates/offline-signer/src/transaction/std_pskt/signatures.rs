//! PSKT signature merge and UI status helpers.

use crate::transaction::model::{Transaction, MAX_SIGS_PER_INPUT};

/// After `sign_transaction_multisig` or `sign_transaction_multi_addr`
/// has populated `inp.sigs[]` with new signatures tagged by
/// `pubkey_compressed`, promote them into `inp.incoming_partial_sigs[]`
/// ready for PSKT emission.
///
/// Merging rules:
///   - Existing entries in `incoming_partial_sigs` (from a PSKT that
///     arrived partially signed) are preserved.
///   - Each new entry from `sigs[]` with `present=true` and a non-zero
///     `pubkey_compressed` is inserted — unless a matching pubkey
///     already exists, in which case the existing entry wins (an
///     already-signed input shouldn't be resigned by this device).
///   - After insertion, the slot array is sorted by pubkey byte order
///     so emission matches `kaspa-wallet-pskt`'s BTreeMap iteration.
///
/// If the fixed signature capacity is already full, additional KSPT
/// signatures are not inserted. Existing PSKT signatures always retain
/// priority, and the complete retained set is sorted by public key.
///
/// Does not mutate `sigs[]` — KSPT emission on the same tx still works
/// if the caller picks that path instead. Designed to be idempotent:
/// calling this twice is a no-op on the second call.
fn incoming_contains_pubkey(
    input: &crate::transaction::model::TransactionInput,
    pubkey: [u8; 33],
) -> bool {
    input.incoming_partial_sigs[..input.incoming_partial_sigs_count as usize]
        .iter()
        .any(|entry| entry.pubkey == pubkey)
}

fn append_ksp_signatures(input: &mut crate::transaction::model::TransactionInput) {
    for slot_index in 0..input.sig_count as usize {
        let slot = input.sigs[slot_index].clone();
        if !slot.present || slot.pubkey_compressed == [0u8; 33] {
            continue;
        }
        if incoming_contains_pubkey(input, slot.pubkey_compressed) {
            continue;
        }
        let next = input.incoming_partial_sigs_count as usize;
        if next >= MAX_SIGS_PER_INPUT {
            break;
        }
        input.incoming_partial_sigs[next].pubkey = slot.pubkey_compressed;
        input.incoming_partial_sigs[next].signature = slot.signature;
        input.incoming_partial_sigs[next].present = true;
        input.incoming_partial_sigs_count = (next + 1) as u8;
    }
}

fn sort_incoming_signatures(input: &mut crate::transaction::model::TransactionInput) {
    let count = input.incoming_partial_sigs_count as usize;
    input.incoming_partial_sigs[..count].sort_unstable_by_key(|entry| entry.pubkey);
}

pub fn move_ksp_sigs_to_pskt(tx: &mut Transaction) {
    for input_index in 0..tx.num_inputs {
        let input = &mut tx.inputs[input_index];
        let base = input.incoming_partial_sigs_count;
        append_ksp_signatures(input);
        if input.incoming_partial_sigs_count != base {
            sort_incoming_signatures(input);
        }
    }
}

/// PSKT-aware sig counter for the UI. Mirrors
/// `crate::transaction::kspt::signature_status` but reads
/// `incoming_partial_sigs_count` instead of `sig_count`, and uses the
/// shared `analyze_input_script` to determine required M from the
/// redeem script.
///
/// Returns `(present, required)`. For P2PK inputs, `required` is 1 and
/// `present` is 1 if any incoming sig exists. For multisig, `required`
/// is M from the parsed redeem script and `present` is the count of
/// incoming partial sigs capped at M.
pub fn pskt_signature_status(tx: &Transaction) -> (u32, u32) {
    use crate::transaction::kspt::analyze_input_script;
    use crate::transaction::model::ScriptType;
    let mut present: u32 = 0;
    let mut required: u32 = 0;
    for i in 0..tx.num_inputs {
        let (script_type, ms_info) = analyze_input_script(tx, i);
        let incoming = tx.inputs[i].incoming_partial_sigs_count;
        match script_type {
            ScriptType::P2PK => {
                required += 1;
                if incoming > 0 {
                    present += 1;
                }
            }
            ScriptType::Multisig | ScriptType::P2SH => {
                if let Some(ref ms) = ms_info {
                    required += u32::from(ms.m);
                    present += u32::from(incoming.min(ms.m));
                }
            }
            ScriptType::Unknown => {
                required += 1;
            }
        }
    }
    (present, required)
}
