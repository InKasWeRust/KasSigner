use crate::transaction::model::Transaction;

pub(super) fn transaction() -> Transaction {
    let mut tx = Transaction::try_new().expect("transaction test allocation");
    tx.version = 1;
    tx.network = crate::address::KaspaNetwork::Mainnet;
    tx.num_inputs = 1;
    tx.num_outputs = 1;
    tx.inputs[0].previous_outpoint.transaction_id = [0x11; 32];
    tx.inputs[0].previous_outpoint.index = 7;
    tx.inputs[0].utxo_entry.amount = 100_000;
    tx.inputs[0].sequence = u64::MAX;
    tx.inputs[0].sig_op_count = 1;
    {
        let script = &mut tx.inputs[0].utxo_entry.script_public_key;
        set_p2pk_script(&mut script.script, &mut script.script_len, 0x22);
    }

    tx.outputs[0].value = 99_000;
    {
        let script = &mut tx.outputs[0].script_public_key;
        set_p2pk_script(&mut script.script, &mut script.script_len, 0x33);
    }
    tx
}

fn set_p2pk_script(script: &mut [u8], len: &mut usize, key_byte: u8) {
    script[0] = 0x20;
    script[1..33].fill(key_byte);
    script[33] = 0xac;
    *len = 34;
}

pub(super) fn set_p2sh_script(tx: &mut Transaction, redeem: &[u8]) {
    let script = &mut tx.inputs[0].utxo_entry.script_public_key;
    script.script[0] = 0xaa;
    script.script[1] = 0x20;
    script.script[2..34].fill(0x44);
    script.script[34] = 0x87;
    script.script_len = 35;
    tx.store_redeem(0, redeem).expect("fixture redeem fits");
}

pub(super) fn add_single_signature(tx: &mut Transaction, pubkey_position: u8, signature: [u8; 64]) {
    let input = &mut tx.inputs[0];
    input.sigs[0].signature = signature;
    input.sigs[0].sighash_type = 0x01;
    input.sigs[0].pubkey_pos = pubkey_position;
    input.sigs[0].present = true;
    input.sigs[0].pubkey_compressed = [0x02; 33];
    input.sig_count = 1;
    input.sighash_type = 0x01;
}
