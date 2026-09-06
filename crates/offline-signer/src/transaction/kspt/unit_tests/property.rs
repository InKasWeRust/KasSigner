use crate::{
    derivation::bip32::{derive_account_key, derive_address_key, derive_change_key},
    transaction::{
        kspt::{parse_compact_kspt, serialize_compact_kspt, PsktError},
        model::Transaction,
    },
};

fn generated_seed(case: u8) -> [u8; 64] {
    let mut seed = [0u8; 64];
    for (index, byte) in seed.iter_mut().enumerate() {
        *byte = case
            .wrapping_mul(37)
            .wrapping_add(index as u8)
            .rotate_left((index % 7) as u32);
    }
    seed
}

fn p2pk_script(script: &mut [u8], value: u8) -> usize {
    script[0] = 0x20;
    script[1..33].fill(value);
    script[33] = 0xac;
    34
}

#[test]
fn key_derivation_is_deterministic_and_separates_receive_from_change() {
    for case in 0..64u8 {
        let seed = generated_seed(case);
        let first = derive_account_key(&seed).expect("generated seed derives");
        let second = derive_account_key(&seed).expect("same seed derives again");
        assert_eq!(first.private_key_bytes(), second.private_key_bytes());
        assert_eq!(first.chain_code_bytes(), second.chain_code_bytes());

        for index in [0u32, 1, 2, 7, 31, u32::from(u16::MAX)] {
            let receive = derive_address_key(&first, index).expect("receive child derives");
            let change = derive_change_key(&first, index).expect("change child derives");
            assert_ne!(receive.private_key_bytes(), change.private_key_bytes());
        }
    }
}

#[test]
fn compact_kspt_roundtrip_is_canonical_for_generated_transactions() {
    for case in 0..64u8 {
        let mut transaction = Transaction::try_new().expect("transaction test allocation");
        transaction.version = u16::from(case);
        transaction.network = crate::address::KaspaNetwork::Mainnet;
        transaction.num_inputs = 1;
        transaction.num_outputs = 1;
        transaction.inputs[0]
            .previous_outpoint
            .transaction_id
            .fill(case);
        transaction.inputs[0].previous_outpoint.index = u32::from(case);
        transaction.inputs[0].utxo_entry.amount = 10_000 + u64::from(case);
        transaction.inputs[0]
            .utxo_entry
            .script_public_key
            .script_len = p2pk_script(
            &mut transaction.inputs[0].utxo_entry.script_public_key.script,
            case.wrapping_add(1),
        );
        transaction.outputs[0].value = 9_000 + u64::from(case);
        transaction.outputs[0].script_public_key.script_len = p2pk_script(
            &mut transaction.outputs[0].script_public_key.script,
            case.wrapping_add(2),
        );
        transaction.locktime = u64::from(case) * 17;
        transaction.payload_len = usize::from(case % 17);
        for (index, byte) in transaction.payload[..transaction.payload_len]
            .iter_mut()
            .enumerate()
        {
            *byte = case.wrapping_add(index as u8);
        }

        let mut encoded = [0u8; 4096];
        let written = serialize_compact_kspt(&transaction, &mut encoded)
            .expect("generated transaction serializes");
        let mut recovered = Transaction::try_new().expect("transaction test allocation");
        parse_compact_kspt(&encoded[..written], &mut recovered)
            .expect("serialized transaction parses");
        let mut canonical = [0u8; 4096];
        let canonical_length = serialize_compact_kspt(&recovered, &mut canonical)
            .expect("parsed transaction reserializes");
        assert_eq!(&canonical[..canonical_length], &encoded[..written]);
        assert_eq!(
            recovered.inputs[0].utxo_entry.amount,
            transaction.inputs[0].utxo_entry.amount
        );
        assert_eq!(recovered.outputs[0].value, transaction.outputs[0].value);
    }
}

#[test]
fn compact_kspt_rejects_every_truncated_prefix_of_a_valid_message() {
    let mut transaction = Transaction::try_new().expect("transaction test allocation");
    transaction.network = crate::address::KaspaNetwork::Mainnet;
    transaction.num_inputs = 1;
    transaction.num_outputs = 1;
    transaction.inputs[0].utxo_entry.amount = 10_000;
    transaction.inputs[0]
        .utxo_entry
        .script_public_key
        .script_len = p2pk_script(
        &mut transaction.inputs[0].utxo_entry.script_public_key.script,
        0x11,
    );
    transaction.outputs[0].value = 9_000;
    transaction.outputs[0].script_public_key.script_len =
        p2pk_script(&mut transaction.outputs[0].script_public_key.script, 0x22);
    let mut encoded = [0u8; 4096];
    let written = serialize_compact_kspt(&transaction, &mut encoded).expect("fixture serializes");
    for length in 0..written {
        let mut parsed = Transaction::try_new().expect("transaction test allocation");
        assert!(
            parse_compact_kspt(&encoded[..length], &mut parsed).is_err(),
            "truncated prefix {length}/{written} was accepted"
        );
    }
    let mut invalid_magic = encoded;
    invalid_magic[0] ^= 0xff;
    let mut parsed = Transaction::try_new().expect("transaction test allocation");
    assert_eq!(
        parse_compact_kspt(&invalid_magic[..written], &mut parsed),
        Err(PsktError::InvalidMagic)
    );
}
