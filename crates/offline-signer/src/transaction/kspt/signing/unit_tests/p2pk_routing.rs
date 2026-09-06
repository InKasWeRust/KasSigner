use super::super::{
    p2pk::{checked_target, ensure_input_index, xonly_from_script},
    sign_matching_input_in_place_with_entropy,
};
use super::{set_p2pk, transaction};
use crate::{
    derivation::bip32::compressed_pubkey_from_raw_key,
    transaction::{kspt::PsktError, model::SigHashType},
};

#[test]
fn p2pk_script_extraction_requires_the_exact_canonical_shape() {
    let target = [0x42u8; 32];
    let mut tx = transaction();
    set_p2pk(&mut tx, &target);
    let script = &mut tx.inputs[0].utxo_entry.script_public_key;
    assert_eq!(xonly_from_script(script), Some(target));

    for variant in 0..4 {
        let mut candidate = script.clone();
        match variant {
            0 => candidate.script_len = 33,
            1 => candidate.script_len = 35,
            2 => candidate.script[0] = 0x21,
            3 => candidate.script[33] = 0xad,
            _ => unreachable!(),
        }
        assert_eq!(xonly_from_script(&candidate), None, "variant {variant}");
    }
}

#[test]
fn p2pk_checked_target_distinguishes_valid_malformed_and_input_boundaries() {
    let first = [0x31u8; 32];
    let second = [0x32u8; 32];
    let mut tx = transaction();
    tx.ensure_input_slots(2).expect("second input slot");
    tx.num_inputs = 2;
    tx.inputs[1] = tx.inputs[0].clone();
    set_p2pk(&mut tx, &first);
    {
        let script = &mut tx.inputs[1].utxo_entry.script_public_key;
        script.script[0] = 0x20;
        script.script[1..33].copy_from_slice(&second);
        script.script[33] = 0xac;
        script.script_len = 34;
    }

    assert_eq!(checked_target(&tx, 0), Ok(Some(first)));
    assert_eq!(checked_target(&tx, 1), Ok(Some(second)));
    assert_eq!(checked_target(&tx, 2), Err(PsktError::InvalidInputIndex));

    tx.inputs[1].utxo_entry.script_public_key.script_len = 33;
    assert_eq!(checked_target(&tx, 1), Ok(None));
}

#[test]
fn p2pk_index_guard_accepts_last_declared_slot_and_rejects_exact_next_slot() {
    let mut tx = transaction();
    let capacity = tx.inputs.len();
    tx.num_inputs = capacity;
    assert_eq!(ensure_input_index(&tx, capacity - 1), Ok(()));
    assert_eq!(
        ensure_input_index(&tx, capacity),
        Err(PsktError::InvalidInputIndex)
    );

    tx.num_inputs = capacity - 1;
    assert_eq!(ensure_input_index(&tx, capacity - 2), Ok(()));
    assert_eq!(
        ensure_input_index(&tx, capacity - 1),
        Err(PsktError::InvalidInputIndex)
    );

    // A malformed model can declare more inputs than its backing storage. The
    // backing-array boundary must still fail closed independently of num_inputs.
    tx.num_inputs = capacity + 1;
    assert_eq!(
        ensure_input_index(&tx, capacity),
        Err(PsktError::InvalidInputIndex)
    );
}

#[test]
fn p2pk_single_input_signing_rejects_wrong_key_without_mutation() {
    let right_key = [1u8; 32];
    let wrong_key = [2u8; 32];
    let compressed = compressed_pubkey_from_raw_key(&right_key).expect("right public key");
    let mut target = [0u8; 32];
    target.copy_from_slice(&compressed[1..33]);

    let mut wrong = transaction();
    set_p2pk(&mut wrong, &target);
    assert_eq!(
        sign_matching_input_in_place_with_entropy(
            &mut wrong,
            0,
            &wrong_key,
            SigHashType::All,
            &[0x71; 32],
        ),
        Ok(false),
    );
    assert_eq!(wrong.inputs[0].sig_count, 0);

    let mut valid = transaction();
    set_p2pk(&mut valid, &target);
    assert_eq!(
        sign_matching_input_in_place_with_entropy(
            &mut valid,
            0,
            &right_key,
            SigHashType::All,
            &[0x71; 32],
        ),
        Ok(true),
    );
    assert_eq!(valid.inputs[0].sig_count, 1);
    assert_eq!(valid.inputs[0].sigs[0].pubkey_compressed, compressed);
}
