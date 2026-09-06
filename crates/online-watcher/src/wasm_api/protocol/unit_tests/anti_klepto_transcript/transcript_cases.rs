use offline_signer::transaction::model::Transaction;

use super::fixture::{canonical_public_key, TranscriptFixture};

type TransactionMutation = (&'static str, fn(&mut Transaction));

#[test]
fn every_bound_transaction_and_input_field_rejects_single_field_mutation() {
    let fixture = TranscriptFixture::p2pk_two_inputs();
    let mutations: &[TransactionMutation] = &[
        ("network", change_network),
        ("version", change_version),
        ("locktime", change_locktime),
        ("subnetwork", change_subnetwork),
        ("gas", change_gas),
        ("payload", change_payload),
        ("stealth tweak", change_stealth_tweak),
        ("input count", change_input_count),
        ("output", change_output),
        ("previous transaction id", change_previous_tx_id),
        ("previous index", change_previous_index),
        ("amount", change_amount),
        ("sequence", change_sequence),
        ("sig-op count", change_sig_op_count),
        ("script version", change_script_version),
        ("script bytes", change_script),
        ("redeem script", change_redeem_script),
    ];
    for (label, mutation) in mutations {
        let wire = fixture.mutate_signed_transaction(*mutation);
        let error = fixture
            .verify_public_with(&fixture.commitment_records, &fixture.proofs, &wire)
            .expect_err(label);
        assert_eq!(
            error, "anti-klepto verification failed: anti-klepto transaction body changed",
            "{label}",
        );
    }
}

#[test]
fn transcript_counts_and_each_proof_position_are_bound_independently() {
    let fixture = TranscriptFixture::p2pk_two_inputs();
    assert_eq!(fixture.proofs.len(), 2);

    let one_proof = vec![fixture.proofs[0]];
    assert_transaction_binding_error(&fixture, &one_proof, &fixture.signed_tx_wire);

    let mut extra_proof = fixture.proofs.clone();
    extra_proof.push(fixture.proofs[0]);
    assert_transaction_binding_error(&fixture, &extra_proof, &fixture.signed_tx_wire);

    assert_transaction_binding_error(&fixture, &fixture.proofs, fixture.original_transaction());

    let mut wrong_input = fixture.proofs.clone();
    wrong_input[0].input_index = 1;
    assert_proof_position_error(&fixture, &wrong_input);

    let mut wrong_slot = fixture.proofs.clone();
    wrong_slot[0].signature_slot = 1;
    assert_proof_position_error(&fixture, &wrong_slot);
}

#[test]
fn signature_metadata_binds_sighash_and_the_committed_signing_key() {
    let fixture = TranscriptFixture::p2pk_two_inputs();
    let changed_sighash = fixture.mutate_signed_transaction(change_signature_sighash);
    let error = fixture
        .verify_public_with(
            &fixture.commitment_records,
            &fixture.proofs,
            &changed_sighash,
        )
        .expect_err("changed sighash accepted");
    assert_eq!(
        error,
        "anti-klepto verification failed: anti-klepto sighash metadata changed",
    );

    let unexpected_default = TranscriptFixture::p2pk_unexpected_none_sighash();
    let error = unexpected_default
        .verify_public()
        .expect_err("new signature changed default SIGHASH_ALL");
    assert_eq!(
        error,
        "anti-klepto verification failed: anti-klepto sighash metadata changed",
    );

    let multisig = TranscriptFixture::p2sh_multisig();
    let mut different_allowed_key = multisig.commitment_records.clone();
    different_allowed_key[0].public_key = canonical_public_key([2u8; 32]);
    multisig
        .accept_commitment(&different_allowed_key)
        .expect("second multisig key is allowed by the input");
    let error = multisig
        .verify_public_with(
            &different_allowed_key,
            &multisig.proofs,
            &multisig.signed_tx_wire,
        )
        .expect_err("commitment/signature key mismatch accepted");
    assert_eq!(
        error,
        "anti-klepto verification failed: anti-klepto commitment public key does not match signature",
    );
}

#[test]
fn existing_signature_count_sighash_and_bytes_remain_bound_when_one_signature_is_added() {
    let fixture = TranscriptFixture::p2sh_with_existing_none_signature();
    assert_eq!(fixture.commitment_records.len(), 1);
    assert_eq!(fixture.commitment_records[0].signature_slot, 1);
    assert_eq!(fixture.proofs.len(), 1);
    assert_eq!(fixture.proofs[0].signature_slot, 1);
    assert_eq!(
        fixture
            .verify_public()
            .expect("existing-signature transcript"),
        hex::encode(&fixture.signed_tx_wire),
    );

    let changed_existing = fixture.mutate_signed_transaction(change_existing_signature);
    let error = fixture
        .verify_public_with(
            &fixture.commitment_records,
            &fixture.proofs,
            &changed_existing,
        )
        .expect_err("existing signature mutation accepted");
    assert_eq!(
        error,
        "anti-klepto verification failed: anti-klepto transaction body changed",
    );
}

#[test]
fn provisional_signature_is_valid_bip340_but_fails_the_host_nonce_relation() {
    let fixture = TranscriptFixture::p2pk_two_inputs();
    let error = fixture
        .verify_public_with(
            &fixture.commitment_records,
            &fixture.proofs,
            &fixture.provisional_tx_wire,
        )
        .expect_err("provisional signatures accepted as final");
    assert_eq!(
        error,
        "anti-klepto verification failed: anti-klepto final nonce does not include the host contribution",
    );
}

#[test]
fn session_and_transaction_digest_metadata_cannot_be_changed() {
    use shared_signer::anti_klepto;

    let fixture = TranscriptFixture::p2pk_two_inputs();
    let commitment_wire =
        hex::decode(fixture.commitment_hex(&fixture.commitment_records)).expect("commitment wire");
    let commitment = anti_klepto::parse_commitment(&commitment_wire).expect("commitment parse");
    let mut signed_wire =
        hex::decode(fixture.signed_message_hex(&fixture.proofs, &fixture.signed_tx_wire))
            .expect("signed response wire");

    signed_wire[6] ^= 1;
    let signed = anti_klepto::parse_signed(&signed_wire).expect("session-mutated response");
    assert_eq!(
        crate::protocol::pskt::verify_host_transcript_wire(
            fixture.original_transaction(),
            &fixture.signed_tx_wire,
            &commitment,
            &signed,
            &fixture.host_secret,
        )
        .unwrap_err(),
        "anti-klepto session binding changed",
    );

    let mut signed_wire =
        hex::decode(fixture.signed_message_hex(&fixture.proofs, &fixture.signed_tx_wire))
            .expect("signed response wire");
    signed_wire[22] ^= 1;
    let signed = anti_klepto::parse_signed(&signed_wire).expect("digest-mutated response");
    assert_eq!(
        crate::protocol::pskt::verify_host_transcript_wire(
            fixture.original_transaction(),
            &fixture.signed_tx_wire,
            &commitment,
            &signed,
            &fixture.host_secret,
        )
        .unwrap_err(),
        "anti-klepto session binding changed",
    );
}

fn assert_transaction_binding_error(
    fixture: &TranscriptFixture,
    proofs: &[shared_signer::anti_klepto::SignatureProof],
    transaction: &[u8],
) {
    let error = fixture
        .verify_public_with(&fixture.commitment_records, proofs, transaction)
        .expect_err("invalid transcript count accepted");
    assert_eq!(
        error,
        "anti-klepto verification failed: anti-klepto transaction body changed",
    );
}

fn assert_proof_position_error(
    fixture: &TranscriptFixture,
    proofs: &[shared_signer::anti_klepto::SignatureProof],
) {
    let error = fixture
        .verify_public_with(&fixture.commitment_records, proofs, &fixture.signed_tx_wire)
        .expect_err("invalid proof position accepted");
    assert_eq!(
        error,
        "anti-klepto verification failed: anti-klepto proof position does not match commitment",
    );
}

fn change_network(transaction: &mut Transaction) {
    transaction.network = offline_signer::address::KaspaNetwork::Testnet;
}

fn change_version(transaction: &mut Transaction) {
    transaction.version = transaction.version.wrapping_add(1);
}

fn change_locktime(transaction: &mut Transaction) {
    transaction.locktime = transaction.locktime.wrapping_add(1);
}

fn change_subnetwork(transaction: &mut Transaction) {
    transaction.subnetwork_id[0] ^= 1;
}

fn change_gas(transaction: &mut Transaction) {
    transaction.gas = transaction.gas.wrapping_add(1);
}

fn change_payload(transaction: &mut Transaction) {
    transaction.payload[0] = 0x51;
    transaction.payload_len = 1;
}

fn change_stealth_tweak(transaction: &mut Transaction) {
    transaction.stealth_tweak = [1u8; 32];
    transaction.has_stealth_tweak = true;
}

fn change_input_count(transaction: &mut Transaction) {
    transaction.num_inputs -= 1;
}

fn change_output(transaction: &mut Transaction) {
    transaction.outputs[0].value = transaction.outputs[0].value.wrapping_sub(1);
}

fn change_previous_tx_id(transaction: &mut Transaction) {
    transaction.inputs[0].previous_outpoint.transaction_id[0] ^= 1;
}

fn change_previous_index(transaction: &mut Transaction) {
    transaction.inputs[0].previous_outpoint.index = transaction.inputs[0]
        .previous_outpoint
        .index
        .wrapping_add(1);
}

fn change_amount(transaction: &mut Transaction) {
    transaction.inputs[0].utxo_entry.amount =
        transaction.inputs[0].utxo_entry.amount.wrapping_add(1);
}

fn change_sequence(transaction: &mut Transaction) {
    transaction.inputs[0].sequence = transaction.inputs[0].sequence.wrapping_sub(1);
}

fn change_sig_op_count(transaction: &mut Transaction) {
    transaction.inputs[0].sig_op_count = transaction.inputs[0].sig_op_count.wrapping_add(1);
}

fn change_script_version(transaction: &mut Transaction) {
    transaction.inputs[0].utxo_entry.script_public_key.version = 1;
}

fn change_script(transaction: &mut Transaction) {
    transaction.inputs[0].utxo_entry.script_public_key.script[1] ^= 1;
}

fn change_redeem_script(transaction: &mut Transaction) {
    transaction
        .store_redeem(0, &[0x51])
        .expect("redeem mutation");
}

fn change_signature_sighash(transaction: &mut Transaction) {
    transaction.inputs[0].sigs[0].sighash_type = 0x02;
    transaction.inputs[0].sighash_type = 0x02;
}

fn change_existing_signature(transaction: &mut Transaction) {
    transaction.inputs[0].sigs[0].signature[0] ^= 1;
}
