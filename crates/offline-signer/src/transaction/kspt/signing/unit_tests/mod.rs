use alloc::{vec, vec::Vec};

use crate::{
    derivation::bip32::{derive_account_key, derive_address_key},
    transaction::{
        kspt::PsktError,
        model::{SigHashType, Transaction},
    },
};

mod covenant_routing;
mod coverage_routes;
mod multi_address_routing;
mod multisig_routing;
mod p2pk_routing;
mod transcript_routing;

use super::{
    context::SigningContext,
    covenant::scan_candidate_keys,
    sign_transaction_multisig_with_entropy,
    signature_state::{append_signature, has_pubkey_position, set_single_signature},
};

fn transaction() -> Transaction {
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
    tx.outputs[0].value = 99_000;
    let output = &mut tx.outputs[0].script_public_key;
    output.script[0] = 0x20;
    output.script[1..33].fill(0x33);
    output.script[33] = 0xac;
    output.script_len = 34;
    tx
}

fn set_p2pk(tx: &mut Transaction, xonly: &[u8; 32]) {
    let script = &mut tx.inputs[0].utxo_entry.script_public_key;
    script.script[0] = 0x20;
    script.script[1..33].copy_from_slice(xonly);
    script.script[33] = 0xac;
    script.script_len = 34;
}

fn set_p2sh(tx: &mut Transaction, redeem: &[u8]) {
    let script = &mut tx.inputs[0].utxo_entry.script_public_key;
    script.script[0] = 0xaa;
    script.script[1] = 0x20;
    script.script[2..34].fill(0x44);
    script.script[34] = 0x87;
    script.script_len = 35;
    tx.store_redeem(0, redeem).expect("redeem script");
}

fn set_two_of_two_multisig(tx: &mut Transaction, first: &[u8; 32], second: &[u8; 32]) {
    let script = &mut tx.inputs[0].utxo_entry.script_public_key;
    script.script[0] = 0x52;
    script.script[1] = 0x20;
    script.script[2..34].copy_from_slice(first);
    script.script[34] = 0x20;
    script.script[35..67].copy_from_slice(second);
    script.script[67] = 0x52;
    script.script[68] = 0xae;
    script.script_len = 69;
}

#[test]
fn signing_context_resolves_account_direct_and_cached_material() {
    let seed = [0x31u8; 64];
    let absent = [0u8; 64];
    let seeds = [(seed, true), (absent, false)];
    let mut context = SigningContext::from_seeds(&seeds);
    assert_eq!(context.seed_count(), 2);
    assert!(context.account_xonly(0).is_some());
    assert!(context.account_xonly(1).is_none());
    assert!(context.account_material(0).is_some());
    assert!(context.account_material(1).is_none());

    let account = derive_account_key(&seed).expect("account key");
    let child = derive_address_key(&account, 3).expect("address child");
    let target = child.public_key_x_only().expect("address public key");
    let expected = child
        .public_key_compressed()
        .expect("compressed public key");

    assert_eq!(
        context
            .direct_address_material(0, &target)
            .expect("direct material")
            .compressed_public_key,
        expected,
    );
    assert_eq!(
        context
            .cached_address_material(0, &target)
            .expect("cached material")
            .compressed_public_key,
        expected,
    );
    assert!(context.cached_address_material(7, &target).is_none());
    assert!(context.cached_address_material(0, &[0xff; 32]).is_none());

    let change = crate::derivation::bip32::derive_change_key(&account, 4).expect("change child");
    let change_target = change.public_key_x_only().expect("change public key");
    assert_eq!(
        context
            .direct_address_material(0, &change_target)
            .expect("direct change material")
            .compressed_public_key,
        change
            .public_key_compressed()
            .expect("compressed change key"),
    );
    assert_eq!(
        context
            .cached_address_material(0, &change_target)
            .expect("cached change material")
            .compressed_public_key,
        change
            .public_key_compressed()
            .expect("compressed change key"),
    );

    let many = [([0u8; 64], false); 9];
    assert_eq!(SigningContext::from_seeds(&many).seed_count(), 8);
}

#[test]
fn covenant_key_scanner_handles_push_families_and_truncation() {
    let key = [0x42u8; 32];
    let mut script = [0u8; 256];
    let mut position = 0usize;

    script[position] = 1;
    script[position + 1] = 0xaa;
    position += 2;
    script[position] = 0x4c;
    script[position + 1] = 2;
    script[position + 2..position + 4].fill(0xbb);
    position += 4;
    script[position] = 0x4d;
    script[position + 1] = 2;
    script[position + 2] = 0;
    script[position + 3..position + 5].fill(0xcc);
    position += 5;
    script[position] = 0x4e;
    script[position + 1] = 2;
    script[position + 2..position + 5].fill(0);
    script[position + 5..position + 7].fill(0xdd);
    position += 7;
    script[position] = 0x20;
    script[position + 1..position + 33].copy_from_slice(&key);
    script[position + 33] = 0xac;
    position += 34;

    let candidates = scan_candidate_keys(&script[..position]).expect("scan");
    assert_eq!(candidates.len, 1);
    assert_eq!(candidates.keys[0], key);

    assert!(scan_candidate_keys(&[0x20, 0x01]).is_err());
    assert!(scan_candidate_keys(&[0x4c]).is_err());
    assert!(scan_candidate_keys(&[0x4d, 1]).is_err());
    assert!(scan_candidate_keys(&[0x4e, 1, 0, 0]).is_err());
}

#[test]
fn covenant_key_scanner_respects_push_lengths_checksig_offsets_and_candidate_limit() {
    let key = [0x41u8; 32];

    let mut delayed_checksig = vec![0x20];
    delayed_checksig.extend_from_slice(&key);
    delayed_checksig.extend_from_slice(&[0x51, 0xad]);
    let candidates = scan_candidate_keys(&delayed_checksig).expect("delayed checksig");
    assert_eq!(candidates.len, 1);
    assert_eq!(candidates.keys[0], key);

    let mut no_checksig = vec![0x20];
    no_checksig.extend_from_slice(&key);
    no_checksig.extend_from_slice(&[0x51, 0x52]);
    assert_eq!(
        scan_candidate_keys(&no_checksig).expect("no checksig").len,
        0
    );

    let mut pushdata2 = vec![0x4d, 0x02, 0x01];
    pushdata2.extend_from_slice(&vec![0x20; 258]);
    pushdata2.push(0x20);
    pushdata2.extend_from_slice(&key);
    pushdata2.push(0xac);
    let candidates = scan_candidate_keys(&pushdata2).expect("little-endian pushdata2 length");
    assert_eq!(candidates.len, 1);
    assert_eq!(candidates.keys[0], key);

    let mut pushdata4 = vec![0x4e, 0x00, 0x01, 0x00, 0x00];
    pushdata4.extend_from_slice(&vec![0x20; 256]);
    pushdata4.push(0x20);
    pushdata4.extend_from_slice(&key);
    pushdata4.push(0xad);
    let candidates = scan_candidate_keys(&pushdata4).expect("little-endian pushdata4 length");
    assert_eq!(candidates.len, 1);
    assert_eq!(candidates.keys[0], key);

    let mut nine = Vec::new();
    for value in 0u8..9 {
        nine.push(0x20);
        nine.extend_from_slice(&[value; 32]);
        nine.push(0xac);
    }
    let candidates = scan_candidate_keys(&nine).expect("candidate cap");
    assert_eq!(candidates.len, 8);
    assert_eq!(candidates.keys[0], [0; 32]);
    assert_eq!(candidates.keys[7], [7; 32]);
}

#[test]
fn multisig_signer_covers_p2pk_multisig_and_covenant_routes() {
    let seed = [0x31u8; 64];
    let seeds = [(seed, true)];
    let account = derive_account_key(&seed).expect("account key");
    let address_xonly = derive_address_key(&account, 0)
        .expect("address key")
        .public_key_x_only()
        .expect("address public key");
    let xonly = account.public_key_x_only().expect("account public key");
    let entropy = [0x5au8; 32];

    let mut p2pk = transaction();
    set_p2pk(&mut p2pk, &address_xonly);
    assert_eq!(
        sign_transaction_multisig_with_entropy(&mut p2pk, &seeds, SigHashType::All, None, &entropy,),
        Ok(1),
    );
    assert_eq!(p2pk.inputs[0].sig_count, 1);

    let mut multisig_redeem = [0u8; 36];
    multisig_redeem[0] = 0x51;
    multisig_redeem[1] = 0x20;
    multisig_redeem[2..34].copy_from_slice(&xonly);
    multisig_redeem[34] = 0x51;
    multisig_redeem[35] = 0xae;
    let mut multisig = transaction();
    set_p2sh(&mut multisig, &multisig_redeem);
    assert_eq!(
        sign_transaction_multisig_with_entropy(
            &mut multisig,
            &seeds,
            SigHashType::All,
            None,
            &entropy,
        ),
        Ok(1),
    );
    assert_eq!(multisig.inputs[0].sig_count, 1);

    let mut covenant_redeem = [0u8; 34];
    covenant_redeem[0] = 0x20;
    covenant_redeem[1..33].copy_from_slice(&xonly);
    covenant_redeem[33] = 0xac;
    let mut covenant = transaction();
    set_p2sh(&mut covenant, &covenant_redeem);
    assert_eq!(
        sign_transaction_multisig_with_entropy(
            &mut covenant,
            &seeds,
            SigHashType::All,
            Some(0),
            &entropy,
        ),
        Ok(1),
    );
    assert_eq!(covenant.inputs[0].sig_count, 1);
    assert_ne!(covenant.inputs[0].sigs[0].signature, [0u8; 64]);
    assert_ne!(covenant.inputs[0].sigs[0].signature, [1u8; 64]);

    let mut filtered = transaction();
    set_p2sh(&mut filtered, &covenant_redeem);
    assert_eq!(
        sign_transaction_multisig_with_entropy(
            &mut filtered,
            &seeds,
            SigHashType::All,
            Some(1),
            &entropy,
        ),
        Err(PsktError::NoInputs),
    );
}

#[test]
fn single_key_public_entry_points_cover_response_and_in_place_signing() {
    use super::{
        sign_transaction, sign_transaction_in_place, sign_transaction_in_place_with_entropy,
        sign_transaction_with_entropy,
    };

    let private_key = [1u8; 32];
    let entropy = [0x44u8; 32];

    let response = sign_transaction(&transaction(), &private_key, SigHashType::All)
        .expect("deterministic response");
    assert_eq!(response.signatures.len(), 1);

    let response =
        sign_transaction_with_entropy(&transaction(), &private_key, SigHashType::All, &entropy)
            .expect("entropy response");
    assert_eq!(response.signatures.len(), 1);

    let mut in_place = transaction();
    assert_eq!(
        sign_transaction_in_place(&mut in_place, &private_key, SigHashType::All),
        Ok(1)
    );
    assert_eq!(in_place.inputs[0].sig_count, 1);

    let mut in_place_entropy = transaction();
    assert_eq!(
        sign_transaction_in_place_with_entropy(
            &mut in_place_entropy,
            &private_key,
            SigHashType::All,
            &entropy,
        ),
        Ok(1)
    );
    assert_eq!(in_place_entropy.inputs[0].sig_count, 1);

    let mut empty = Transaction::try_new().expect("transaction test allocation");
    assert_eq!(
        sign_transaction_in_place(&mut empty, &private_key, SigHashType::All),
        Err(PsktError::NoInputs)
    );
}

#[test]
fn raw_account_context_and_public_multisig_wrappers_are_covered() {
    use super::{sign_transaction_multisig, sign_transaction_multisig_accounts_with_entropy};

    let seed = [0x31u8; 64];
    let account = derive_account_key(&seed).expect("account key");
    let raw = account.to_raw();
    let accounts = [(raw, true), ([0u8; 65], false)];
    let context = SigningContext::from_account_raw(&accounts);
    assert_eq!(context.seed_count(), 2);
    assert!(context.account_material(0).is_some());
    assert!(context.account_material(1).is_none());

    let address_xonly = derive_address_key(&account, 0)
        .expect("address key")
        .public_key_x_only()
        .expect("address public key");

    let mut seeded = transaction();
    set_p2pk(&mut seeded, &address_xonly);
    assert_eq!(
        sign_transaction_multisig(&mut seeded, &[(seed, true)], SigHashType::All, None,),
        Ok(1)
    );

    let mut imported = transaction();
    set_p2pk(&mut imported, &address_xonly);
    assert_eq!(
        sign_transaction_multisig_accounts_with_entropy(
            &mut imported,
            &accounts,
            SigHashType::All,
            None,
            &[0x66; 32],
        ),
        Ok(1)
    );
}

#[test]
fn covenant_scanner_distinguishes_unchecked_delayed_and_capacity_limited_keys() {
    let key = [0x24u8; 32];
    let mut unchecked = [0u8; 33];
    unchecked[0] = 0x20;
    unchecked[1..].copy_from_slice(&key);
    assert_eq!(scan_candidate_keys(&unchecked).expect("scan").len, 0);

    let mut delayed = [0u8; 35];
    delayed[0] = 0x20;
    delayed[1..33].copy_from_slice(&key);
    delayed[33] = 0x00;
    delayed[34] = 0xad;
    let delayed_candidates = scan_candidate_keys(&delayed).expect("delayed checksig scan");
    assert_eq!(delayed_candidates.len, 1);
    assert_eq!(delayed_candidates.keys[0], key);

    let mut many = [0u8; 9 * 34];
    for chunk in many.chunks_exact_mut(34) {
        chunk[0] = 0x20;
        chunk[1..33].copy_from_slice(&key);
        chunk[33] = 0xac;
    }
    assert_eq!(scan_candidate_keys(&many).expect("bounded scan").len, 8);
}

#[test]
fn first_appended_signature_initializes_input_sighash_state() {
    let mut input = transaction().inputs[0].clone();
    input.sighash_type = 0;
    assert_eq!(input.sig_count, 0);
    assert!(append_signature(
        &mut input,
        [0x6a; 64],
        SigHashType::Single.to_byte(),
        2,
        [0x03; 33],
    ));
    assert_eq!(input.sig_count, 1);
    assert_eq!(input.sighash_type, SigHashType::Single.to_byte());
    assert_eq!(input.sigs[0].sighash_type, SigHashType::Single.to_byte());
}

#[test]
fn signature_state_rejects_duplicates_and_capacity_overflow() {
    let mut input = transaction().inputs[0].clone();
    assert!(!has_pubkey_position(&input, 3));

    set_single_signature(&mut input, [0x11; 64], 0x01, 3, [0x02; 33]);
    assert!(has_pubkey_position(&input, 3));
    assert!(!append_signature(
        &mut input, [0x22; 64], 0x01, 3, [0x03; 33],
    ));

    for position in 4..8u8 {
        assert!(append_signature(
            &mut input,
            [position; 64],
            0x01,
            position,
            [0x02; 33],
        ));
    }
    assert_eq!(
        input.sig_count as usize,
        crate::transaction::model::MAX_SIGS_PER_INPUT
    );
    assert!(!append_signature(
        &mut input, [0x99; 64], 0x01, 9, [0x02; 33],
    ));
}

#[test]
fn signers_refuse_already_signed_and_malformed_p2pk_inputs() {
    use super::sign_matching_inputs_in_place_with_entropy;

    let seed = [0x31u8; 64];
    let seeds = [(seed, true)];
    let account = derive_account_key(&seed).expect("account key");
    let address_xonly = derive_address_key(&account, 0)
        .expect("address key")
        .public_key_x_only()
        .expect("address public key");
    let entropy = [0x5au8; 32];

    let mut already_signed = transaction();
    set_p2pk(&mut already_signed, &address_xonly);
    set_single_signature(
        &mut already_signed.inputs[0],
        [0x11; 64],
        SigHashType::All.to_byte(),
        0,
        [0x02; 33],
    );
    assert_eq!(
        sign_transaction_multisig_with_entropy(
            &mut already_signed,
            &seeds,
            SigHashType::All,
            None,
            &entropy,
        ),
        Err(PsktError::NoInputs),
    );

    let private_key = *derive_address_key(&account, 0)
        .expect("private address key")
        .private_key_bytes();
    let compressed = crate::derivation::bip32::compressed_pubkey_from_raw_key(&private_key)
        .expect("compressed key");
    let mut xonly = [0u8; 32];
    xonly.copy_from_slice(&compressed[1..]);

    for variant in 0..4 {
        let mut malformed = transaction();
        set_p2pk(&mut malformed, &xonly);
        match variant {
            0 => malformed.inputs[0].utxo_entry.script_public_key.script_len = 33,
            1 => malformed.inputs[0].utxo_entry.script_public_key.script[0] = 0x21,
            2 => malformed.inputs[0].utxo_entry.script_public_key.script[33] = 0xad,
            3 => malformed.inputs[0].utxo_entry.script_public_key.script[1] ^= 1,
            _ => unreachable!(),
        }
        assert_eq!(
            sign_matching_inputs_in_place_with_entropy(
                &mut malformed,
                &private_key,
                SigHashType::All,
                &entropy,
            ),
            Err(PsktError::NoInputs),
            "variant {variant}",
        );
    }
}

#[test]
fn already_signed_covenant_input_short_circuits_without_resigning() {
    let seed = [0x31u8; 64];
    let seeds = [(seed, true)];
    let account = derive_account_key(&seed).expect("account key");
    let xonly = account.public_key_x_only().expect("account public key");

    let mut redeem = [0u8; 34];
    redeem[0] = 0x20;
    redeem[1..33].copy_from_slice(&xonly);
    redeem[33] = 0xac;

    let mut tx = transaction();
    set_p2sh(&mut tx, &redeem);
    set_single_signature(
        &mut tx.inputs[0],
        [0x55; 64],
        SigHashType::All.to_byte(),
        0,
        [0x02; 33],
    );

    assert_eq!(
        sign_transaction_multisig_with_entropy(
            &mut tx,
            &seeds,
            SigHashType::All,
            Some(0),
            &[0x5a; 32],
        ),
        Err(PsktError::NoInputs),
    );
    assert_eq!(tx.inputs[0].sig_count, 1);
    assert_eq!(tx.inputs[0].sigs[0].signature, [0x55; 64]);
}

#[test]
fn anti_klepto_error_conversion_preserves_pskt_error() {
    use super::AntiKleptoVerifyError;

    assert_eq!(
        AntiKleptoVerifyError::from(PsktError::NoInputs),
        AntiKleptoVerifyError::Pskt(PsktError::NoInputs),
    );
}

fn anti_klepto_p2pk_transaction(private_key: &[u8; 32]) -> Transaction {
    let compressed = crate::derivation::bip32::compressed_pubkey_from_raw_key(private_key)
        .expect("compressed key");
    let mut xonly = [0u8; 32];
    xonly.copy_from_slice(&compressed[1..]);
    let mut tx = transaction();
    set_p2pk(&mut tx, &xonly);
    tx.inputs[0].sighash_type = SigHashType::All.to_byte();
    tx
}

#[test]
fn anti_klepto_transaction_round_trip_verifies_and_rejects_mutations() {
    use super::{
        finalize_raw_key_signatures, initial_signature_counts, nonce_commitment_records,
        proof_records, sign_transaction_in_place_with_entropy, validate_host_commitment,
        verify_host_transcript, AntiKleptoVerifyError,
    };
    use crate::transaction::kspt::{parse_compact_kspt, serialize_compact_kspt};
    use shared_signer::anti_klepto;

    let private_key = [1u8; 32];
    let host_secret = [0x51u8; 32];
    let original = anti_klepto_p2pk_transaction(&private_key);
    let mut signed = anti_klepto_p2pk_transaction(&private_key);
    let initial_counts = initial_signature_counts(&original);
    sign_transaction_in_place_with_entropy(
        &mut signed,
        &private_key,
        SigHashType::All,
        &[0x71u8; 32],
    )
    .expect("provisional signature");

    let records = nonce_commitment_records(&signed, &initial_counts).expect("nonce records");
    assert_eq!(records.len(), 1);

    let mut original_wire = [0u8; 2048];
    let original_len =
        serialize_compact_kspt(&original, &mut original_wire).expect("original wire");
    let digest = anti_klepto::transaction_digest(&original_wire[..original_len]);
    let host_commit = anti_klepto::host_commitment(&host_secret);
    let session = anti_klepto::session_id(&host_commit, &digest);

    let mut commitment_wire = [0u8; 256];
    let commitment_len =
        anti_klepto::encode_commitment(&session, &digest, &records, &mut commitment_wire)
            .expect("commitment wire");
    // Keep the valid commitment on immutable backing storage for the rest of
    // the transcript checks. `parse_commitment` returns a borrowed view, while
    // `commitment_wire` is deliberately reused below as scratch space for
    // malformed commitment cases.
    let commitment_wire_valid = commitment_wire;
    let commitment = anti_klepto::parse_commitment(&commitment_wire_valid[..commitment_len])
        .expect("commitment parse");
    validate_host_commitment(&original, &commitment).expect("safe commitment");

    finalize_raw_key_signatures(
        &mut signed,
        &private_key,
        &initial_counts,
        &session,
        &host_secret,
    )
    .expect("final anti-klepto signature");
    let proofs = proof_records(&signed, &initial_counts).expect("proof records");
    let mut signed_tx_wire = [0u8; 2048];
    let signed_tx_len =
        serialize_compact_kspt(&signed, &mut signed_tx_wire).expect("signed tx wire");
    let mut signed_message_wire = [0u8; 2304];
    let signed_message_len = anti_klepto::encode_signed(
        &session,
        &digest,
        &proofs,
        &signed_tx_wire[..signed_tx_len],
        &mut signed_message_wire,
    )
    .expect("signed message wire");
    let signed_message = anti_klepto::parse_signed(&signed_message_wire[..signed_message_len])
        .expect("signed message parse");

    verify_host_transcript(
        &original,
        &signed,
        &commitment,
        &signed_message,
        &host_secret,
    )
    .expect("verified transcript");

    // Compact unsigned KSPT does not serialize TransactionInput::sighash_type.
    // The verifier must therefore accept the normal unsigned -> SIGHASH_ALL transition
    // after parsing the request wire, while still rejecting signer-selected alternatives.
    let mut parsed_original = Transaction::try_new().expect("transaction test allocation");
    parse_compact_kspt(&original_wire[..original_len], &mut parsed_original)
        .expect("parse unsigned original");
    assert_eq!(parsed_original.inputs[0].sighash_type, 0);
    verify_host_transcript(
        &parsed_original,
        &signed,
        &commitment,
        &signed_message,
        &host_secret,
    )
    .expect("parsed unsigned transcript verifies");

    let mut changed_sighash = Transaction::try_new().expect("transaction test allocation");
    parse_compact_kspt(&signed_tx_wire[..signed_tx_len], &mut changed_sighash)
        .expect("parse signed for sighash mutation");
    changed_sighash.inputs[0].sighash_type = SigHashType::None.to_byte();
    changed_sighash.inputs[0].sigs[0].sighash_type = SigHashType::None.to_byte();
    assert_eq!(
        verify_host_transcript(
            &parsed_original,
            &changed_sighash,
            &commitment,
            &signed_message,
            &host_secret,
        ),
        Err(AntiKleptoVerifyError::InvalidProof),
    );
    assert_eq!(
        verify_host_transcript(
            &original,
            &signed,
            &commitment,
            &signed_message,
            &[0x52; 32]
        ),
        Err(AntiKleptoVerifyError::InvalidNonceRelation),
    );

    let mut changed_body = Transaction::try_new().expect("transaction test allocation");
    parse_compact_kspt(&signed_tx_wire[..signed_tx_len], &mut changed_body).expect("parse signed");
    changed_body.outputs[0].value += 1;
    assert_eq!(
        verify_host_transcript(
            &original,
            &changed_body,
            &commitment,
            &signed_message,
            &host_secret
        ),
        Err(AntiKleptoVerifyError::TransactionMismatch),
    );

    // Exercise every security-relevant body binding rather than only the output value.
    // Each mutation must fail before nonce proof validation can bless a different transaction.
    macro_rules! reject_body_mutation {
        ($label:literal, $mutation:expr) => {{
            let mut candidate = Transaction::try_new().expect("transaction test allocation");
            parse_compact_kspt(&signed_tx_wire[..signed_tx_len], &mut candidate)
                .expect("parse signed mutation baseline");
            ($mutation)(&mut candidate);
            assert_eq!(
                verify_host_transcript(
                    &original,
                    &candidate,
                    &commitment,
                    &signed_message,
                    &host_secret
                ),
                Err(AntiKleptoVerifyError::TransactionMismatch),
                $label,
            );
        }};
    }
    reject_body_mutation!("version", |tx: &mut Transaction| tx.version ^= 1);
    reject_body_mutation!("input count", |tx: &mut Transaction| tx.num_inputs = 0);
    reject_body_mutation!("output count", |tx: &mut Transaction| tx.num_outputs = 0);
    reject_body_mutation!("network", |tx: &mut Transaction| {
        tx.network = crate::address::KaspaNetwork::Testnet;
    });
    reject_body_mutation!("locktime", |tx: &mut Transaction| tx.locktime = 1);
    reject_body_mutation!("subnetwork", |tx: &mut Transaction| tx.subnetwork_id[0] ^=
        1);
    reject_body_mutation!("gas", |tx: &mut Transaction| tx.gas = 1);
    reject_body_mutation!("payload length", |tx: &mut Transaction| {
        tx.payload_len = 1;
        tx.payload[0] = 0x91;
    });
    reject_body_mutation!("stealth presence", |tx: &mut Transaction| tx
        .has_stealth_tweak =
        true);
    reject_body_mutation!("stealth tweak", |tx: &mut Transaction| tx.stealth_tweak
        [0] ^= 1);
    reject_body_mutation!("outpoint txid", |tx: &mut Transaction| tx.inputs[0]
        .previous_outpoint
        .transaction_id[0] ^=
        1);
    reject_body_mutation!("outpoint index", |tx: &mut Transaction| tx.inputs[0]
        .previous_outpoint
        .index ^= 1);
    reject_body_mutation!("sequence", |tx: &mut Transaction| tx.inputs[0].sequence ^=
        1);
    reject_body_mutation!("sigop", |tx: &mut Transaction| tx.inputs[0].sig_op_count ^=
        1);
    reject_body_mutation!("input amount", |tx: &mut Transaction| tx.inputs[0]
        .utxo_entry
        .amount += 1);
    reject_body_mutation!("input script version", |tx: &mut Transaction| tx.inputs
        [0]
    .utxo_entry
    .script_public_key
    .version ^= 1);
    reject_body_mutation!("input script length", |tx: &mut Transaction| tx.inputs
        [0]
    .utxo_entry
    .script_public_key
    .script_len -=
        1);
    reject_body_mutation!("input script bytes", |tx: &mut Transaction| tx.inputs[0]
        .utxo_entry
        .script_public_key
        .script[1] ^=
        1);
    reject_body_mutation!("output script version", |tx: &mut Transaction| tx
        .outputs[0]
        .script_public_key
        .version ^=
        1);
    reject_body_mutation!("output script length", |tx: &mut Transaction| tx.outputs
        [0]
    .script_public_key
    .script_len -=
        1);
    reject_body_mutation!("output script bytes", |tx: &mut Transaction| tx.outputs
        [0]
    .script_public_key
    .script[1] ^=
        1);
    reject_body_mutation!("covenant presence", |tx: &mut Transaction| tx.outputs[0]
        .has_covenant =
        true);
    reject_body_mutation!("covenant authorizer", |tx: &mut Transaction| tx.outputs
        [0]
    .covenant_auth_input =
        1);
    reject_body_mutation!("covenant id", |tx: &mut Transaction| tx.outputs[0]
        .covenant_id[0] ^=
        1);
    reject_body_mutation!("derivation presence", |tx: &mut Transaction| {
        tx.outputs[0].has_derivation_hint = true;
    });
    reject_body_mutation!("derivation branch", |tx: &mut Transaction| {
        tx.outputs[0].derivation_branch = 1;
    });
    reject_body_mutation!("derivation index", |tx: &mut Transaction| {
        tx.outputs[0].derivation_index = 1;
    });

    // New signatures are part of the proof, not the immutable body. Missing or
    // cryptographically modified proof material must fail with the exact class.
    let mut missing_signature = Transaction::try_new().expect("transaction test allocation");
    parse_compact_kspt(&signed_tx_wire[..signed_tx_len], &mut missing_signature)
        .expect("parse missing-signature baseline");
    missing_signature.inputs[0].sigs[0].present = false;
    assert_eq!(
        verify_host_transcript(
            &original,
            &missing_signature,
            &commitment,
            &signed_message,
            &host_secret
        ),
        Err(AntiKleptoVerifyError::InvalidProof),
    );
    let mut bad_signature = Transaction::try_new().expect("transaction test allocation");
    parse_compact_kspt(&signed_tx_wire[..signed_tx_len], &mut bad_signature)
        .expect("parse bad-signature baseline");
    bad_signature.inputs[0].sigs[0].signature[63] ^= 1;
    assert_eq!(
        verify_host_transcript(
            &original,
            &bad_signature,
            &commitment,
            &signed_message,
            &host_secret
        ),
        Err(AntiKleptoVerifyError::InvalidSignature),
    );

    // Commitment coordinates are untrusted host input. Exercise invalid
    // positions, non-canonical points and a valid-but-wrong signing key.
    for (label, record) in {
        let mut out_of_range = records[0];
        out_of_range.input_index = 1;
        let mut bad_slot = records[0];
        bad_slot.signature_slot = 8;
        let mut odd_pubkey = records[0];
        odd_pubkey.public_key[0] = 0x03;
        let mut odd_nonce = records[0];
        odd_nonce.nonce_point[0] = 0x03;
        [
            ("input", out_of_range),
            ("slot", bad_slot),
            ("pubkey", odd_pubkey),
            ("nonce", odd_nonce),
        ]
    } {
        let len =
            anti_klepto::encode_commitment(&session, &digest, &[record], &mut commitment_wire)
                .expect("mutated commitment wire");
        let parsed = anti_klepto::parse_commitment(&commitment_wire[..len])
            .expect("mutated commitment parse");
        assert_eq!(
            validate_host_commitment(&original, &parsed),
            Err(AntiKleptoVerifyError::InvalidProof),
            "{label}"
        );
    }
    let wrong_private_key = [2u8; 32];
    let mut wrong_key_record = records[0];
    wrong_key_record.public_key =
        crate::derivation::bip32::compressed_pubkey_from_raw_key(&wrong_private_key)
            .expect("wrong compressed public key");
    wrong_key_record.public_key[0] = 0x02;
    let wrong_key_len = anti_klepto::encode_commitment(
        &session,
        &digest,
        &[wrong_key_record],
        &mut commitment_wire,
    )
    .expect("wrong-key commitment wire");
    let wrong_key_commitment = anti_klepto::parse_commitment(&commitment_wire[..wrong_key_len])
        .expect("wrong-key commitment parse");
    assert_eq!(
        validate_host_commitment(&original, &wrong_key_commitment),
        Err(AntiKleptoVerifyError::InvalidPublicKey),
    );

    // Session, digest and proof cardinality/position are independently bound.
    let mut wrong_session = session;
    wrong_session[0] ^= 1;
    let wrong_session_len = anti_klepto::encode_signed(
        &wrong_session,
        &digest,
        &proofs,
        &signed_tx_wire[..signed_tx_len],
        &mut signed_message_wire,
    )
    .expect("wrong session message");
    let wrong_session_message =
        anti_klepto::parse_signed(&signed_message_wire[..wrong_session_len])
            .expect("wrong session parse");
    assert_eq!(
        verify_host_transcript(
            &original,
            &signed,
            &commitment,
            &wrong_session_message,
            &host_secret
        ),
        Err(AntiKleptoVerifyError::SessionMismatch),
    );
    let mut wrong_digest = digest;
    wrong_digest[0] ^= 1;
    let wrong_digest_len = anti_klepto::encode_signed(
        &session,
        &wrong_digest,
        &proofs,
        &signed_tx_wire[..signed_tx_len],
        &mut signed_message_wire,
    )
    .expect("wrong digest message");
    let wrong_digest_message = anti_klepto::parse_signed(&signed_message_wire[..wrong_digest_len])
        .expect("wrong digest parse");
    assert_eq!(
        verify_host_transcript(
            &original,
            &signed,
            &commitment,
            &wrong_digest_message,
            &host_secret
        ),
        Err(AntiKleptoVerifyError::SessionMismatch),
    );
    let duplicate_proofs = [proofs[0], proofs[0]];
    let too_many_proofs_len = anti_klepto::encode_signed(
        &session,
        &digest,
        &duplicate_proofs,
        &signed_tx_wire[..signed_tx_len],
        &mut signed_message_wire,
    )
    .expect("extra proof message");
    let too_many_proofs = anti_klepto::parse_signed(&signed_message_wire[..too_many_proofs_len])
        .expect("extra proof parse");
    assert_eq!(
        verify_host_transcript(
            &original,
            &signed,
            &commitment,
            &too_many_proofs,
            &host_secret
        ),
        Err(AntiKleptoVerifyError::TransactionMismatch),
    );
    let mut wrong_proof = proofs[0];
    wrong_proof.input_index = 1;
    let wrong_proof_len = anti_klepto::encode_signed(
        &session,
        &digest,
        &[wrong_proof],
        &signed_tx_wire[..signed_tx_len],
        &mut signed_message_wire,
    )
    .expect("wrong proof message");
    let wrong_proof_message = anti_klepto::parse_signed(&signed_message_wire[..wrong_proof_len])
        .expect("wrong proof parse");
    assert_eq!(
        verify_host_transcript(
            &original,
            &signed,
            &commitment,
            &wrong_proof_message,
            &host_secret
        ),
        Err(AntiKleptoVerifyError::InvalidProof),
    );

    let duplicate = [records[0], records[0]];
    let duplicate_len =
        anti_klepto::encode_commitment(&session, &digest, &duplicate, &mut commitment_wire)
            .expect("duplicate commitment wire");
    let duplicate_commitment = anti_klepto::parse_commitment(&commitment_wire[..duplicate_len])
        .expect("duplicate commitment parse");
    assert_eq!(
        validate_host_commitment(&original, &duplicate_commitment),
        Err(AntiKleptoVerifyError::InvalidProof),
    );
}

#[test]
fn anti_klepto_finalization_rejects_invalid_ranges_slots_sighashes_and_keys() {
    use super::{
        finalize_raw_key_signatures, initial_signature_counts,
        sign_transaction_in_place_with_entropy,
    };

    let private_key = [1u8; 32];
    let wrong_private_key = [2u8; 32];
    let session = [0x41u8; shared_signer::anti_klepto::SESSION_ID_LEN];
    let host_secret = [0x52u8; 32];

    let mut provisional = anti_klepto_p2pk_transaction(&private_key);
    let initial = initial_signature_counts(&provisional);
    sign_transaction_in_place_with_entropy(
        &mut provisional,
        &private_key,
        SigHashType::All,
        &[0x73; 32],
    )
    .expect("provisional signature");

    let mut start_after_end = provisional_from_wire(&provisional);
    assert_eq!(
        finalize_raw_key_signatures(
            &mut start_after_end,
            &private_key,
            &[2],
            &session,
            &host_secret,
        ),
        Err(PsktError::InvalidSignatureState),
    );

    let mut end_past_capacity = provisional_from_wire(&provisional);
    end_past_capacity.inputs[0].sig_count = 6;
    assert_eq!(
        finalize_raw_key_signatures(
            &mut end_past_capacity,
            &private_key,
            &initial,
            &session,
            &host_secret,
        ),
        Err(PsktError::InvalidSignatureState),
    );

    let mut absent = provisional_from_wire(&provisional);
    absent.inputs[0].sigs[0].present = false;
    assert_eq!(
        finalize_raw_key_signatures(&mut absent, &private_key, &initial, &session, &host_secret),
        Err(PsktError::InvalidSignatureState),
    );

    let mut missing_pubkey = provisional_from_wire(&provisional);
    missing_pubkey.inputs[0].sigs[0].pubkey_compressed[0] = 0;
    assert_eq!(
        finalize_raw_key_signatures(
            &mut missing_pubkey,
            &private_key,
            &initial,
            &session,
            &host_secret,
        ),
        Err(PsktError::InvalidSignatureState),
    );

    let mut wrong_key = provisional_from_wire(&provisional);
    assert_eq!(
        finalize_raw_key_signatures(
            &mut wrong_key,
            &wrong_private_key,
            &initial,
            &session,
            &host_secret,
        ),
        Err(PsktError::DerivationFailed),
    );

    let mut bad_sighash = provisional_from_wire(&provisional);
    bad_sighash.inputs[0].sigs[0].sighash_type = 0xff;
    assert_eq!(
        finalize_raw_key_signatures(
            &mut bad_sighash,
            &private_key,
            &initial,
            &session,
            &host_secret,
        ),
        Err(PsktError::InvalidSigHashType),
    );
}

fn provisional_from_wire(tx: &Transaction) -> Transaction {
    use crate::transaction::kspt::{parse_compact_kspt, serialize_compact_kspt};

    let mut wire = [0u8; 4096];
    let len = serialize_compact_kspt(tx, &mut wire).expect("serialize provisional transaction");
    let mut parsed = Transaction::try_new().expect("transaction test allocation");
    parse_compact_kspt(&wire[..len], &mut parsed).expect("parse provisional transaction");

    // Compact KSPT stores the signature's pubkey position, not the runtime-only
    // resolved compressed key. Restore that signing metadata so each mutation
    // below reaches the branch it is intended to exercise.
    for input_index in 0..parsed.num_inputs {
        let signature_count = usize::from(parsed.inputs[input_index].sig_count);
        for slot in 0..signature_count {
            parsed.inputs[input_index].sigs[slot].pubkey_compressed =
                tx.inputs[input_index].sigs[slot].pubkey_compressed;
        }
    }
    parsed
}

#[test]
fn anti_klepto_partial_multisig_preserves_existing_signature_and_sighash_binding() {
    use super::{
        finalize_account_set_signatures, initial_signature_counts, nonce_commitment_records,
        proof_records, validate_host_commitment, verify_host_transcript, AntiKleptoVerifyError,
    };
    use crate::transaction::kspt::{parse_compact_kspt, serialize_compact_kspt};
    use shared_signer::anti_klepto;

    let first_seed = [0x31u8; 64];
    let second_seed = [0x32u8; 64];
    let first_account = derive_account_key(&first_seed).expect("first account");
    let second_account = derive_account_key(&second_seed).expect("second account");
    let first_child = derive_address_key(&first_account, 0).expect("first child");
    let second_child = derive_address_key(&second_account, 0).expect("second child");
    let first_xonly = first_child.public_key_x_only().expect("first xonly");
    let second_xonly = second_child.public_key_x_only().expect("second xonly");
    let first_compressed = first_child
        .public_key_compressed()
        .expect("first compressed");

    let build_partial = || {
        let mut tx = transaction();
        set_two_of_two_multisig(&mut tx, &first_xonly, &second_xonly);
        tx.inputs[0].sighash_type = SigHashType::All.to_byte();
        set_single_signature(
            &mut tx.inputs[0],
            [0x5a; 64],
            SigHashType::All.to_byte(),
            0,
            first_compressed,
        );
        tx
    };

    let original = build_partial();
    let mut signed = build_partial();
    let initial = initial_signature_counts(&original);
    assert_eq!(&initial[..original.num_inputs], &[1]);
    assert_eq!(
        sign_transaction_multisig_with_entropy(
            &mut signed,
            &[(first_seed, true), (second_seed, true)],
            SigHashType::All,
            None,
            &[0x75; 32],
        ),
        Ok(1),
    );
    assert_eq!(signed.inputs[0].sig_count, 2);

    let records = nonce_commitment_records(&signed, &initial).expect("new nonce record");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].signature_slot, 1);

    let mut original_wire = [0u8; 4096];
    let original_len =
        serialize_compact_kspt(&original, &mut original_wire).expect("original wire");
    let digest = anti_klepto::transaction_digest(&original_wire[..original_len]);
    let host_secret = [0x61u8; 32];
    let session = anti_klepto::session_id(&anti_klepto::host_commitment(&host_secret), &digest);

    let mut commitment_wire = [0u8; 512];
    let commitment_len =
        anti_klepto::encode_commitment(&session, &digest, &records, &mut commitment_wire)
            .expect("commitment wire");
    let commitment = anti_klepto::parse_commitment(&commitment_wire[..commitment_len])
        .expect("commitment parse");
    validate_host_commitment(&original, &commitment).expect("partial commitment valid");

    let accounts = [
        (first_account.to_raw(), true),
        (second_account.to_raw(), true),
    ];
    assert_eq!(
        finalize_account_set_signatures(&mut signed, &accounts, &initial, &session, &host_secret),
        Ok(1),
    );
    let proofs = proof_records(&signed, &initial).expect("partial proofs");

    let mut signed_wire = [0u8; 4096];
    let signed_len = serialize_compact_kspt(&signed, &mut signed_wire).expect("signed wire");
    let mut signed_message_wire = [0u8; 4608];
    let signed_message_len = anti_klepto::encode_signed(
        &session,
        &digest,
        &proofs,
        &signed_wire[..signed_len],
        &mut signed_message_wire,
    )
    .expect("signed message");
    let signed_message = anti_klepto::parse_signed(&signed_message_wire[..signed_message_len])
        .expect("signed message parse");
    verify_host_transcript(
        &original,
        &signed,
        &commitment,
        &signed_message,
        &host_secret,
    )
    .expect("partial transcript verifies");

    let mut changed_existing = Transaction::try_new().expect("transaction test allocation");
    parse_compact_kspt(&signed_wire[..signed_len], &mut changed_existing)
        .expect("parse existing mutation");
    changed_existing.inputs[0].sigs[0].signature[0] ^= 1;
    assert_eq!(
        verify_host_transcript(
            &original,
            &changed_existing,
            &commitment,
            &signed_message,
            &host_secret,
        ),
        Err(AntiKleptoVerifyError::TransactionMismatch),
    );

    let mut removed_existing = Transaction::try_new().expect("transaction test allocation");
    parse_compact_kspt(&signed_wire[..signed_len], &mut removed_existing)
        .expect("parse count mutation");
    removed_existing.inputs[0].sig_count = 0;
    assert_eq!(
        verify_host_transcript(
            &original,
            &removed_existing,
            &commitment,
            &signed_message,
            &host_secret,
        ),
        Err(AntiKleptoVerifyError::TransactionMismatch),
    );

    let mut mismatched_sighash = Transaction::try_new().expect("transaction test allocation");
    parse_compact_kspt(&signed_wire[..signed_len], &mut mismatched_sighash)
        .expect("parse sighash mutation");
    mismatched_sighash.inputs[0].sigs[1].sighash_type = SigHashType::None.to_byte();
    assert_eq!(
        verify_host_transcript(
            &original,
            &mismatched_sighash,
            &commitment,
            &signed_message,
            &host_secret,
        ),
        Err(AntiKleptoVerifyError::InvalidProof),
    );
}

#[test]
fn anti_klepto_record_builders_reject_empty_and_invalid_signature_state() {
    use super::{initial_signature_counts, nonce_commitment_records, proof_records};

    let private_key = [1u8; 32];
    let mut unsigned = anti_klepto_p2pk_transaction(&private_key);
    let initial = initial_signature_counts(&unsigned);
    assert_eq!(
        nonce_commitment_records(&unsigned, &initial),
        Err(PsktError::NoInputs)
    );
    assert_eq!(proof_records(&unsigned, &initial), Err(PsktError::NoInputs));

    unsigned.inputs[0].sig_count = 6;
    assert_eq!(
        nonce_commitment_records(&unsigned, &initial),
        Err(PsktError::InvalidSignatureState),
    );
    assert_eq!(
        proof_records(&unsigned, &initial),
        Err(PsktError::InvalidSignatureState)
    );

    let mut provisional = anti_klepto_p2pk_transaction(&private_key);
    super::sign_transaction_in_place_with_entropy(
        &mut provisional,
        &private_key,
        SigHashType::All,
        &[0x74; 32],
    )
    .expect("provisional record");
    let provisional_initial = vec![0];

    provisional.inputs[0].sigs[0].present = false;
    assert_eq!(
        nonce_commitment_records(&provisional, &provisional_initial),
        Err(PsktError::InvalidSignatureState),
    );
    assert_eq!(
        proof_records(&provisional, &provisional_initial),
        Err(PsktError::InvalidSignatureState),
    );

    provisional.inputs[0].sigs[0].present = true;
    provisional.inputs[0].sigs[0].pubkey_compressed[0] = 0;
    assert_eq!(
        nonce_commitment_records(&provisional, &provisional_initial),
        Err(PsktError::InvalidSignatureState),
    );

    let mut missing_input_slot = anti_klepto_p2pk_transaction(&private_key);
    missing_input_slot.num_inputs = missing_input_slot.inputs.len() + 1;
    let counts = vec![0; missing_input_slot.num_inputs];
    assert_eq!(
        nonce_commitment_records(&missing_input_slot, &counts),
        Err(PsktError::InvalidSignatureState),
    );
    assert_eq!(
        proof_records(&missing_input_slot, &counts),
        Err(PsktError::InvalidSignatureState),
    );

    let missing_counts: Vec<u8> = Vec::new();
    let one_input = anti_klepto_p2pk_transaction(&private_key);
    assert_eq!(
        nonce_commitment_records(&one_input, &missing_counts),
        Err(PsktError::InvalidSignatureState),
    );
    assert_eq!(
        proof_records(&one_input, &missing_counts),
        Err(PsktError::InvalidSignatureState),
    );

    let mut invalid_range = anti_klepto_p2pk_transaction(&private_key);
    invalid_range.inputs[0].sig_count = 1;
    let after_end = vec![2];
    assert_eq!(
        nonce_commitment_records(&invalid_range, &after_end),
        Err(PsktError::InvalidSignatureState),
    );
    assert_eq!(
        proof_records(&invalid_range, &after_end),
        Err(PsktError::InvalidSignatureState),
    );
}

#[test]
fn anti_klepto_account_finalization_covers_stealth_material_resolution() {
    use super::{
        finalize_account_signatures, initial_signature_counts, nonce_commitment_records,
        sign_transaction_multi_addr_with_entropy,
    };
    use k256::elliptic_curve::{ops::Add, sec1::ToEncodedPoint, ScalarPrimitive};
    use k256::{ProjectivePoint, Scalar};

    let seed = [0x31u8; 64];
    let account = derive_account_key(&seed).expect("account");
    let primitive = ScalarPrimitive::<k256::Secp256k1>::from_slice(account.private_key_bytes())
        .expect("account scalar");
    let raw = Scalar::from(primitive);
    let account_point = (ProjectivePoint::GENERATOR * raw)
        .to_affine()
        .to_encoded_point(true);
    let normalized = if account_point.as_bytes()[0] == 0x03 {
        -raw
    } else {
        raw
    };
    let tweak_bytes = [1u8; 32];
    let tweak = ScalarPrimitive::<k256::Secp256k1>::from_slice(&tweak_bytes).expect("tweak");
    let combined = normalized.add(&Scalar::from(tweak));
    let combined_point = (ProjectivePoint::GENERATOR * combined)
        .to_affine()
        .to_encoded_point(true);
    let mut target = [0u8; 32];
    target.copy_from_slice(&combined_point.as_bytes()[1..33]);

    let mut signed = transaction();
    set_p2pk(&mut signed, &target);
    signed.inputs[0].sighash_type = SigHashType::All.to_byte();
    signed.has_stealth_tweak = true;
    signed.stealth_tweak = tweak_bytes;
    let initial = initial_signature_counts(&signed);
    sign_transaction_multi_addr_with_entropy(&mut signed, &seed, SigHashType::All, &[0x62; 32])
        .expect("provisional stealth signature");
    assert_eq!(
        nonce_commitment_records(&signed, &initial).unwrap().len(),
        1
    );

    finalize_account_signatures(
        &mut signed,
        &account,
        &initial,
        &[0x12; shared_signer::anti_klepto::SESSION_ID_LEN],
        &[0x34; 32],
    )
    .expect("final stealth signature");
}

#[test]
fn anti_klepto_error_mapping_covers_all_schnorr_error_variants() {
    use crate::crypto::{anti_klepto::AntiKleptoError, schnorr::SchnorrError};

    assert_eq!(
        AntiKleptoError::from(SchnorrError::InvalidPrivateKey),
        AntiKleptoError::InvalidPrivateKey,
    );
    assert_eq!(
        AntiKleptoError::from(SchnorrError::SigningFailed),
        AntiKleptoError::InvalidFinalSignature,
    );
    assert_eq!(
        AntiKleptoError::from(SchnorrError::InvalidSignature),
        AntiKleptoError::InvalidFinalSignature,
    );
}

#[test]
fn per_input_multisig_signing_rejects_out_of_range_index_without_mutation() {
    let seed = [0x31u8; 64];
    let account = derive_account_key(&seed).expect("account");
    let accounts = [(account.to_raw(), true)];
    let mut tx = transaction();
    let before = tx.inputs[0].sig_count;
    assert_eq!(
        super::sign_multisig_accounts_input_with_entropy(
            &mut tx,
            1,
            &accounts,
            SigHashType::All,
            None,
            &[0x7au8; 32],
        ),
        Err(PsktError::InvalidInputIndex),
    );
    assert_eq!(tx.inputs[0].sig_count, before);
}

#[test]
fn signing_context_stays_stack_light() {
    assert!(core::mem::size_of::<SigningContext>() <= 2_048);
}
