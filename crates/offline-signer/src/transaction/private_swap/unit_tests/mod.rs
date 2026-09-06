use alloc::vec::Vec;

use super::*;
use super::{parse_private_swap_script, PrivateSwapError};
use crate::{address::KaspaNetwork, transaction::model::Transaction};

fn push_data(script: &mut Vec<u8>, data: &[u8]) {
    script.push(u8::try_from(data.len()).expect("fixture direct push"));
    script.extend_from_slice(data);
}

fn push_int(script: &mut Vec<u8>, value: u64) {
    if value == 0 {
        script.push(OP_0);
        return;
    }
    if value <= 16 {
        script.push(0x50 + value as u8);
        return;
    }
    let mut bytes = value.to_le_bytes().to_vec();
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    if bytes.last().is_some_and(|byte| byte & 0x80 != 0) {
        bytes.push(0);
    }
    push_data(script, &bytes);
}

fn canonical_script(
    owner: [u8; 32],
    claimer: [u8; 32],
    destination: &[u8],
    locktime: u64,
) -> Vec<u8> {
    let mut script = Vec::new();
    push_data(&mut script, &[0x42; 16]);
    script.extend_from_slice(&[OP_DROP, OP_IF]);
    push_data(&mut script, &claimer);
    script.extend_from_slice(&[
        OP_CHECKSIGVERIFY,
        OP_TX_INPUT_COUNT,
        OP_1,
        OP_NUMEQUALVERIFY,
        OP_TX_OUTPUT_COUNT,
        OP_1,
        OP_NUMEQUALVERIFY,
        OP_0,
        OP_TX_OUTPUT_SPK,
    ]);
    push_data(&mut script, destination);
    script.extend_from_slice(&[
        OP_EQUALVERIFY,
        OP_0,
        OP_TX_INPUT_AMOUNT,
        OP_DUP,
        OP_0,
        OP_TX_OUTPUT_AMOUNT,
        OP_GREATERTHANOREQUAL,
        OP_VERIFY,
        OP_0,
        OP_TX_OUTPUT_AMOUNT,
        OP_SUB,
    ]);
    push_int(&mut script, PRIVATE_SWAP_MAX_FEE_SOMPI);
    script.extend_from_slice(&[OP_LESSTHANOREQUAL, OP_VERIFY, OP_1, OP_ELSE]);
    push_data(&mut script, &owner);
    script.push(OP_CHECKSIGVERIFY);
    push_int(&mut script, locktime);
    script.extend_from_slice(&[OP_CHECKLOCKTIMEVERIFY, OP_1, OP_ENDIF]);
    script
}

fn claim_transaction() -> (Transaction, [u8; 32]) {
    let owner = [0x21; 32];
    let claimer = [0x31; 32];
    let mut tx = Transaction::try_new().expect("transaction test allocation");
    tx.version = 0;
    tx.network = KaspaNetwork::Mainnet;
    tx.num_inputs = 1;
    tx.num_outputs = 1;
    tx.inputs[0].previous_outpoint.transaction_id = [0x11; 32];
    tx.inputs[0].previous_outpoint.index = 3;
    tx.inputs[0].sequence = u64::MAX;
    tx.inputs[0].sig_op_count = 1;
    tx.inputs[0].sighash_type = 0x01;
    tx.inputs[0].utxo_entry.amount = 1_000_000_000;
    let input_spk = &mut tx.inputs[0].utxo_entry.script_public_key;
    input_spk.script[0] = 0xaa;
    input_spk.script[1] = 0x20;
    input_spk.script[2..34].fill(0x77);
    input_spk.script[34] = 0x87;
    input_spk.script_len = 35;

    let output_script = &mut tx.outputs[0].script_public_key;
    output_script.version = 0;
    output_script.script[0] = 0x20;
    output_script.script[1..33].fill(0x44);
    output_script.script[33] = 0xac;
    output_script.script_len = 34;
    tx.outputs[0].value = 999_999_000;

    let mut destination = Vec::from(output_script.version.to_le_bytes());
    destination.extend_from_slice(output_script.script_bytes());
    let redeem = canonical_script(owner, claimer, &destination, 50_000);
    tx.store_redeem(0, &redeem).expect("fixture redeem");
    (tx, claimer)
}

#[test]
fn canonical_private_swap_script_roundtrips_and_rejects_noncanonical_shapes() {
    let owner = [0x21; 32];
    let claimer = [0x31; 32];
    let destination = [0x00, 0x00, 0x20, 0x41, 0xac];
    let script = canonical_script(owner, claimer, &destination, 50_000);
    let parsed = parse_private_swap_script(&script).expect("canonical private swap");
    assert_eq!(parsed.salt, [0x42; 16]);
    assert_eq!(parsed.claimer_pubkey, claimer);
    assert_eq!(parsed.owner_pubkey, owner);
    assert_eq!(parsed.destination_spk, destination);
    assert_eq!(parsed.refund_locktime_daa, 50_000);

    let mut trailing = script.clone();
    trailing.push(OP_1);
    assert_eq!(
        parse_private_swap_script(&trailing),
        Err(PrivateSwapError::InvalidScript)
    );

    let zero_salt = canonical_script(owner, claimer, &destination, 50_000);
    let mut zero_salt = zero_salt;
    zero_salt[1..17].fill(0);
    assert_eq!(
        parse_private_swap_script(&zero_salt),
        Err(PrivateSwapError::InvalidScript)
    );

    let same_role = canonical_script(claimer, claimer, &destination, 50_000);
    assert_eq!(
        parse_private_swap_script(&same_role),
        Err(PrivateSwapError::InvalidScript)
    );

    let zero_timeout = canonical_script(owner, claimer, &destination, 0);
    assert_eq!(
        parse_private_swap_script(&zero_timeout),
        Err(PrivateSwapError::InvalidScript)
    );
    assert_eq!(
        parse_private_swap_script(&[0xa8, 0x20]),
        Err(PrivateSwapError::InvalidScript)
    );
}

#[test]
fn script_integer_and_direct_push_readers_reject_noncanonical_encodings() {
    assert!(is_canonical_positive_script_int(&[17]));
    assert!(is_canonical_positive_script_int(&[0x80, 0x00]));
    assert!(!is_canonical_positive_script_int(&[]));
    assert!(!is_canonical_positive_script_int(&[0x80]));
    assert!(!is_canonical_positive_script_int(&[1, 0]));

    let mut pos = 0;
    assert_eq!(read_script_int(&[OP_0], &mut pos), Ok(0));
    pos = 0;
    assert_eq!(read_script_int(&[OP_1], &mut pos), Ok(1));
    pos = 0;
    assert_eq!(read_script_int(&[1, 17], &mut pos), Ok(17));

    for bad in [
        &[1, 0][..],
        &[1, 0x80][..],
        &[1, 16][..],
        &[10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10][..],
    ] {
        let mut offset = 0;
        assert_eq!(
            read_script_int(bad, &mut offset),
            Err(PrivateSwapError::InvalidScript)
        );
    }

    let mut offset = 0;
    assert_eq!(
        read_bounded_direct_push(&[0], &mut offset, 1, 75),
        Err(PrivateSwapError::InvalidScript)
    );
    offset = 0;
    assert_eq!(
        read_bounded_direct_push(&[76], &mut offset, 1, 75),
        Err(PrivateSwapError::InvalidScript)
    );
    offset = 0;
    assert_eq!(
        read_bounded_direct_push(&[2, 1], &mut offset, 1, 75),
        Err(PrivateSwapError::InvalidScript)
    );

    let mut expect_pos = 0;
    assert_eq!(
        expect(&[OP_1], &mut expect_pos, OP_0),
        Err(PrivateSwapError::InvalidScript)
    );
    expect_pos = 0;
    assert_eq!(
        expect_sequence(&[OP_1], &mut expect_pos, &[OP_0]),
        Err(PrivateSwapError::InvalidScript)
    );
}

#[test]
fn claim_sighash_enforces_transaction_role_destination_and_fee_policy() {
    let (tx, claimer) = claim_transaction();
    let (digest, policy) = private_swap_claim_sighash(&tx, &claimer).expect("valid claim");
    assert_ne!(digest, [0; 32]);
    assert_eq!(policy.claimer_pubkey, claimer);

    let (mut wrong_shape, _) = claim_transaction();
    wrong_shape.num_outputs = 0;
    assert_eq!(
        private_swap_claim_sighash(&wrong_shape, &claimer),
        Err(PrivateSwapError::InvalidTransaction)
    );

    let (mut already_signed, _) = claim_transaction();
    already_signed.inputs[0].sig_count = 1;
    assert_eq!(
        private_swap_claim_sighash(&already_signed, &claimer),
        Err(PrivateSwapError::InvalidTransaction)
    );

    let (mut incoming_signed, _) = claim_transaction();
    incoming_signed.inputs[0].incoming_partial_sigs_count = 1;
    assert_eq!(
        private_swap_claim_sighash(&incoming_signed, &claimer),
        Err(PrivateSwapError::InvalidTransaction)
    );

    let (mut bad_sighash, _) = claim_transaction();
    bad_sighash.inputs[0].sighash_type = 0xff;
    assert_eq!(
        private_swap_claim_sighash(&bad_sighash, &claimer),
        Err(PrivateSwapError::InvalidSighash)
    );

    let (mut non_all_sighash, _) = claim_transaction();
    non_all_sighash.inputs[0].sighash_type = 0x02;
    assert_eq!(
        private_swap_claim_sighash(&non_all_sighash, &claimer),
        Err(PrivateSwapError::InvalidSighash)
    );

    let (mut no_redeem, _) = claim_transaction();
    no_redeem.inputs[0].redeem_script_len = 0;
    assert_eq!(
        private_swap_claim_sighash(&no_redeem, &claimer),
        Err(PrivateSwapError::InvalidScript)
    );

    let (wrong_claimer, _) = claim_transaction();
    assert_eq!(
        private_swap_claim_sighash(&wrong_claimer, &[0x99; 32]),
        Err(PrivateSwapError::WrongClaimer)
    );

    let (mut wrong_destination, _) = claim_transaction();
    wrong_destination.outputs[0].script_public_key.script[1] ^= 1;
    assert_eq!(
        private_swap_claim_sighash(&wrong_destination, &claimer),
        Err(PrivateSwapError::WrongDestination)
    );

    let (mut overspend, _) = claim_transaction();
    overspend.outputs[0].value = overspend.inputs[0].utxo_entry.amount + 1;
    assert_eq!(
        private_swap_claim_sighash(&overspend, &claimer),
        Err(PrivateSwapError::InvalidTransaction)
    );

    let (mut excessive_fee, _) = claim_transaction();
    excessive_fee.inputs[0].utxo_entry.amount = PRIVATE_SWAP_MAX_FEE_SOMPI + 10_000;
    excessive_fee.outputs[0].value = 9_999;
    assert_eq!(
        private_swap_claim_sighash(&excessive_fee, &claimer),
        Err(PrivateSwapError::FeeTooHigh)
    );
}
