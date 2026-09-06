use alloc::vec::Vec;
use crate::runtime::data::AppData;
use offline_signer::transaction::model::{SigHashType, Transaction};

#[derive(Clone, Copy)]
pub(in crate::runtime::workflow_tests::connected) enum WireFormat { CompactKspt, StandardPskt }

pub(in crate::runtime::workflow_tests::connected) fn install_wallet(ad: &mut AppData) -> bool {
    crate::services::wallet_session::install_workflow_backup_mnemonic_fixture(ad)
        && crate::runtime::signing::populate_active_pubkeys_with_checkpoint(ad, &mut || {}).is_ok()
}

pub(in crate::runtime::workflow_tests::connected) fn wire(ad: &AppData, format: WireFormat) -> Option<Vec<u8>> {
    let tx = transaction(ad)?;
    match format {
        WireFormat::CompactKspt =>
            offline_signer::transaction::kspt::serialize_compact_kspt_vec(&tx).ok(),
        WireFormat::StandardPskt =>
            offline_signer::transaction::std_pskt::serialize_pskt_vec(
                &tx,
                &shared_signer::PsktParsed::empty(),
                b"",
                shared_signer::TxInputFormat::PsktSingle,
            ).ok(),
    }
}

fn transaction(ad: &AppData) -> Option<Transaction> {
    if !ad.wallet.addresses.pubkeys_cached { return None; }
    let mut tx = Transaction::try_new().ok()?;
    tx.version = 0;
    tx.network = ad.wallet.seeds.seed_mgr.network().kaspa_network();
    tx.ensure_input_slots(2).ok()?;
    tx.num_inputs = 2;
    tx.num_outputs = 2;

    configure_input(&mut tx, 0, ad.wallet.addresses.pubkey_cache[0], [0x41; 32], 0, 100_000_000);
    configure_input(&mut tx, 1, ad.wallet.addresses.change_pubkey_cache[0], [0x42; 32], 1, 100_000_000);
    configure_output(&mut tx, 0, ad.wallet.addresses.pubkey_cache[2], 150_000_000, None);
    configure_output(&mut tx, 1, ad.wallet.addresses.change_pubkey_cache[1], 49_000_000, Some((1, 1)));
    Some(tx)
}

fn configure_input(
    tx: &mut Transaction,
    index: usize,
    pubkey: [u8; 32],
    txid: [u8; 32],
    outpoint: u32,
    amount: u64,
) {
    let input = &mut tx.inputs[index];
    input.previous_outpoint.transaction_id = txid;
    input.previous_outpoint.index = outpoint;
    input.utxo_entry.amount = amount;
    input.sequence = u64::MAX;
    input.sig_op_count = 1;
    input.sighash_type = SigHashType::All.to_byte();
    set_p2pk(&mut input.utxo_entry.script_public_key, pubkey);
}

fn configure_output(
    tx: &mut Transaction,
    index: usize,
    pubkey: [u8; 32],
    value: u64,
    hint: Option<(u8, u32)>,
) {
    let output = &mut tx.outputs[index];
    output.value = value;
    set_p2pk(&mut output.script_public_key, pubkey);
    if let Some((branch, derivation_index)) = hint {
        output.has_derivation_hint = true;
        output.derivation_branch = branch;
        output.derivation_index = derivation_index;
    }
}

fn set_p2pk(script: &mut offline_signer::transaction::model::ScriptPublicKey, pubkey: [u8; 32]) {
    script.version = 0;
    script.script[0] = 0x20;
    script.script[1..33].copy_from_slice(&pubkey);
    script.script[33] = 0xac;
    script.script_len = 34;
}
