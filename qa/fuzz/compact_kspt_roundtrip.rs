#![no_main]

use libfuzzer_sys::fuzz_target;
use offline_signer::transaction::{
    kspt::{parse_compact_kspt, serialize_compact_kspt},
    model::Transaction,
};

fn p2pk(script: &mut [u8], key: u8) -> usize {
    script[0] = 0x20;
    script[1..33].fill(key);
    script[33] = 0xac;
    34
}

fuzz_target!(|data: &[u8]| {
    let byte = |index: usize| data.get(index).copied().unwrap_or(index as u8);
    let Ok(mut tx) = Transaction::try_new() else {
        return;
    };
    tx.version = u16::from_le_bytes([byte(0), byte(1)]);
    tx.network = offline_signer::address::KaspaNetwork::Mainnet;
    tx.num_inputs = 1;
    tx.num_outputs = 1;
    tx.inputs[0].previous_outpoint.transaction_id.fill(byte(2));
    tx.inputs[0].previous_outpoint.index = u32::from_le_bytes([byte(3), byte(4), byte(5), byte(6)]);
    tx.inputs[0].utxo_entry.amount = u64::from(byte(7)).saturating_add(1_000);
    tx.inputs[0].sequence = u64::MAX - u64::from(byte(8));
    tx.inputs[0].utxo_entry.script_public_key.script_len = p2pk(
        &mut tx.inputs[0].utxo_entry.script_public_key.script,
        byte(9),
    );
    tx.outputs[0].value = u64::from(byte(10));
    tx.outputs[0].script_public_key.script_len =
        p2pk(&mut tx.outputs[0].script_public_key.script, byte(11));
    tx.locktime = u64::from(byte(12));
    let payload = data.get(13..).unwrap_or_default();
    let payload_len = payload.len().min(tx.payload.len()).min(64);
    tx.payload[..payload_len].copy_from_slice(&payload[..payload_len]);
    tx.payload_len = payload_len;

    let mut encoded = [0u8; 8192];
    let written = serialize_compact_kspt(&tx, &mut encoded).expect("bounded transaction encodes");
    let Ok(mut parsed) = Transaction::try_new() else {
        return;
    };
    parse_compact_kspt(&encoded[..written], &mut parsed).expect("serialized transaction parses");
    assert_eq!(parsed.version, tx.version);
    assert_eq!(parsed.num_inputs, 1);
    assert_eq!(parsed.num_outputs, 1);
    assert_eq!(parsed.inputs[0].previous_outpoint.transaction_id, tx.inputs[0].previous_outpoint.transaction_id);
    assert_eq!(parsed.inputs[0].previous_outpoint.index, tx.inputs[0].previous_outpoint.index);
    assert_eq!(parsed.inputs[0].utxo_entry.amount, tx.inputs[0].utxo_entry.amount);
    assert_eq!(parsed.outputs[0].value, tx.outputs[0].value);
    assert_eq!(&parsed.payload[..parsed.payload_len], &tx.payload[..tx.payload_len]);

    let mut canonical = [0u8; 8192];
    let canonical_len = serialize_compact_kspt(&parsed, &mut canonical).expect("parsed transaction re-encodes");
    assert_eq!(&canonical[..canonical_len], &encoded[..written]);
});
