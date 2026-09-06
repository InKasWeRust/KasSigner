use crate::transaction::model::{TransactionInput, MAX_SIGS_PER_INPUT};

pub(super) fn has_pubkey_position(input: &TransactionInput, pubkey_position: u8) -> bool {
    input.sigs[..input.sig_count.min(MAX_SIGS_PER_INPUT as u8) as usize]
        .iter()
        .any(|slot| slot.present && slot.pubkey_pos == pubkey_position)
}

pub(super) fn set_single_signature(
    input: &mut TransactionInput,
    signature: [u8; 64],
    sighash_type: u8,
    pubkey_position: u8,
    compressed_public_key: [u8; 33],
) {
    input.sigs[0].signature = signature;
    input.sigs[0].sighash_type = sighash_type;
    input.sigs[0].pubkey_pos = pubkey_position;
    input.sigs[0].present = true;
    input.sigs[0].pubkey_compressed = compressed_public_key;
    for slot in &mut input.sigs[1..] {
        slot.present = false;
    }
    input.sig_count = 1;
    input.sighash_type = sighash_type;
}

pub(super) fn append_signature(
    input: &mut TransactionInput,
    signature: [u8; 64],
    sighash_type: u8,
    pubkey_position: u8,
    compressed_public_key: [u8; 33],
) -> bool {
    if has_pubkey_position(input, pubkey_position) {
        return false;
    }
    let slot_index = input.sig_count as usize;
    if slot_index >= MAX_SIGS_PER_INPUT {
        return false;
    }
    if input.sig_count == 0 {
        input.sighash_type = sighash_type;
    }
    let slot = &mut input.sigs[slot_index];
    slot.signature = signature;
    slot.sighash_type = sighash_type;
    slot.pubkey_pos = pubkey_position;
    slot.present = true;
    slot.pubkey_compressed = compressed_public_key;
    input.sig_count += 1;
    true
}
