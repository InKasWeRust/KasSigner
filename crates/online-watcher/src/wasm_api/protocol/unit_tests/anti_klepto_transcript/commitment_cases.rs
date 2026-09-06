use offline_signer::transaction::model::Transaction;

use super::fixture::{canonical_public_key, TranscriptFixture};

#[test]
fn commitments_are_strictly_ordered_and_each_record_is_independently_validated() {
    let fixture = TranscriptFixture::p2pk_two_inputs();
    assert!(fixture
        .accept_commitment(&fixture.commitment_records)
        .is_ok());

    let mut reversed = fixture.commitment_records.clone();
    reversed.swap(0, 1);
    assert_unsafe_commitment(
        &fixture,
        &reversed,
        "anti-klepto commitments are not strictly ordered",
    );

    let duplicate = vec![fixture.commitment_records[0], fixture.commitment_records[0]];
    assert_unsafe_commitment(
        &fixture,
        &duplicate,
        "anti-klepto commitments are not strictly ordered",
    );

    let mut invalid_slot = fixture.commitment_records.clone();
    invalid_slot[0].signature_slot = 5;
    assert_unsafe_commitment(
        &fixture,
        &invalid_slot,
        "anti-klepto signature slot is invalid",
    );

    let occupied = TranscriptFixture::p2sh_with_existing_none_signature();
    let mut occupied_slot = occupied.commitment_records.clone();
    occupied_slot[0].signature_slot = 0;
    assert_unsafe_commitment(
        &occupied,
        &occupied_slot,
        "anti-klepto signature slot is invalid",
    );

    let mut unexpected_key = fixture.commitment_records.clone();
    unexpected_key[0].public_key = canonical_public_key([2u8; 32]);
    assert_unsafe_commitment(
        &fixture,
        &unexpected_key,
        "anti-klepto commitment uses an unexpected signing key",
    );
}

#[test]
fn commitment_points_require_canonical_even_y_and_valid_curve_points() {
    let fixture = TranscriptFixture::p2pk_two_inputs();
    assert_eq!(fixture.commitment_records[0].public_key[0], 0x02);

    let mut odd_public_key = fixture.commitment_records.clone();
    odd_public_key[0].public_key[0] = 0x03;
    assert_unsafe_commitment(
        &fixture,
        &odd_public_key,
        "anti-klepto points must use even-Y compressed encoding",
    );

    let mut odd_nonce = fixture.commitment_records.clone();
    odd_nonce[0].nonce_point[0] = 0x03;
    assert_unsafe_commitment(
        &fixture,
        &odd_nonce,
        "anti-klepto points must use even-Y compressed encoding",
    );

    let mut invalid_public_key = fixture.commitment_records.clone();
    invalid_public_key[0].public_key = [0xff; 33];
    invalid_public_key[0].public_key[0] = 0x02;
    assert_unsafe_commitment(
        &fixture,
        &invalid_public_key,
        "anti-klepto public key is invalid",
    );

    let mut invalid_nonce = fixture.commitment_records.clone();
    invalid_nonce[0].nonce_point = [0xff; 33];
    invalid_nonce[0].nonce_point[0] = 0x02;
    assert_unsafe_commitment(
        &fixture,
        &invalid_nonce,
        "anti-klepto nonce point is invalid",
    );
}

#[test]
fn p2pk_commitment_validation_rejects_each_structural_script_boundary() {
    let fixture = TranscriptFixture::p2pk_two_inputs();
    for (label, mutation) in [
        ("short P2PK", short_p2pk as fn(&mut Transaction)),
        (
            "wrong P2PK push opcode",
            wrong_p2pk_push as fn(&mut Transaction),
        ),
        (
            "missing P2PK checksig",
            missing_p2pk_checksig as fn(&mut Transaction),
        ),
    ] {
        let wire = fixture.mutate_original_transaction(mutation);
        let error = fixture
            .validate_commitment_against(&wire, &fixture.commitment_records)
            .expect_err(label);
        assert_eq!(
            error, "anti-klepto commitment uses an unexpected signing key",
            "{label}"
        );
    }
}

#[test]
fn redeem_script_signing_keys_are_required_for_p2sh_commitments() {
    let fixture = TranscriptFixture::p2sh_multisig();
    assert!(fixture
        .accept_commitment(&fixture.commitment_records)
        .is_ok());
    assert!(fixture.verify_public().is_ok());

    let mut unexpected_key = fixture.commitment_records.clone();
    unexpected_key[0].public_key = canonical_public_key([3u8; 32]);
    assert_unsafe_commitment(
        &fixture,
        &unexpected_key,
        "anti-klepto commitment uses an unexpected signing key",
    );
}

fn assert_unsafe_commitment(
    fixture: &TranscriptFixture,
    records: &[shared_signer::anti_klepto::NonceCommitment],
    expected: &str,
) {
    let error = fixture
        .accept_commitment(records)
        .expect_err("unsafe commitment accepted");
    assert_eq!(error, format!("unsafe signer commitment: {expected}"));
}

fn short_p2pk(transaction: &mut Transaction) {
    transaction.inputs[0]
        .utxo_entry
        .script_public_key
        .script_len = 33;
}

fn wrong_p2pk_push(transaction: &mut Transaction) {
    transaction.inputs[0].utxo_entry.script_public_key.script[0] = 0x21;
}

fn missing_p2pk_checksig(transaction: &mut Transaction) {
    // OP_CHECKSIGVERIFY (0xad) is still a real signature-check opcode and is
    // intentionally recognized by covenant key scanning. Replace the terminal
    // opcode with OP_0 so this case genuinely removes signature authorization.
    transaction.inputs[0].utxo_entry.script_public_key.script[33] = 0x00;
}
