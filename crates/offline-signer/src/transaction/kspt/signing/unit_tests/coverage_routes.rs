use super::super::{
    context::SigningContext, finalize_account_signatures, initial_signature_counts,
    sign_matching_inputs_in_place_with_entropy, sign_transaction, sign_transaction_in_place,
    sign_transaction_in_place_with_entropy, sign_transaction_with_entropy,
};
use super::{set_p2pk, transaction};
use crate::{
    derivation::bip32::{
        compressed_pubkey_from_raw_key, derive_account_key, derive_address_key, derive_change_key,
    },
    transaction::{kspt::PsktError, model::SigHashType},
};

fn set_p2pk_at(
    tx: &mut crate::transaction::model::Transaction,
    input_index: usize,
    target: &[u8; 32],
) {
    let script = &mut tx.inputs[input_index].utxo_entry.script_public_key;
    script.script[0] = 0x20;
    script.script[1..33].copy_from_slice(target);
    script.script[33] = 0xac;
    script.script_len = 34;
}

#[test]
fn single_key_public_routes_cover_response_in_place_entropy_and_matching_scan() {
    let private_key = [1u8; 32];
    let compressed = compressed_pubkey_from_raw_key(&private_key).expect("raw key");
    let mut target = [0u8; 32];
    target.copy_from_slice(&compressed[1..33]);

    let tx = transaction();
    let response =
        sign_transaction(&tx, &private_key, SigHashType::All).expect("single-key response signing");
    assert_eq!(response.signatures.len(), 1);
    assert_eq!(response.signatures[0].input_index, 0);
    assert_eq!(response.signatures[0].sighash_type, SigHashType::All);

    let entropy_response =
        sign_transaction_with_entropy(&tx, &private_key, SigHashType::None, &[0x41; 32])
            .expect("entropy response signing");
    assert_eq!(entropy_response.signatures.len(), 1);
    assert_eq!(
        entropy_response.signatures[0].sighash_type,
        SigHashType::None
    );
    assert_ne!(
        response.signatures[0].signature,
        entropy_response.signatures[0].signature
    );

    let mut in_place = transaction();
    assert_eq!(
        sign_transaction_in_place(&mut in_place, &private_key, SigHashType::All),
        Ok(1),
    );
    assert_eq!(in_place.inputs[0].sig_count, 1);
    assert_eq!(in_place.inputs[0].sigs[0].pubkey_compressed, compressed);

    let mut entropy_in_place = transaction();
    assert_eq!(
        sign_transaction_in_place_with_entropy(
            &mut entropy_in_place,
            &private_key,
            SigHashType::Single,
            &[0x42; 32],
        ),
        Ok(1),
    );
    assert_eq!(entropy_in_place.inputs[0].sig_count, 1);
    assert_eq!(
        entropy_in_place.inputs[0].sigs[0].sighash_type,
        SigHashType::Single.to_byte()
    );

    let mut matching = transaction();
    matching.ensure_input_slots(2).expect("second input");
    matching.inputs[1] = matching.inputs[0].clone();
    matching.inputs[1].previous_outpoint.index = 8;
    matching.num_inputs = 2;
    set_p2pk_at(&mut matching, 0, &target);
    set_p2pk_at(&mut matching, 1, &[0x99; 32]);
    assert_eq!(
        sign_matching_inputs_in_place_with_entropy(
            &mut matching,
            &private_key,
            SigHashType::All,
            &[0x43; 32],
        ),
        Ok(1),
    );
    assert_eq!(matching.inputs[0].sig_count, 1);
    assert_eq!(matching.inputs[1].sig_count, 0);

    let mut no_match = transaction();
    set_p2pk(&mut no_match, &[0x98; 32]);
    assert_eq!(
        sign_matching_inputs_in_place_with_entropy(
            &mut no_match,
            &private_key,
            SigHashType::All,
            &[0x43; 32],
        ),
        Err(PsktError::NoInputs),
    );
}

#[test]
fn signing_context_raw_account_routes_make_account_receive_change_and_miss_observable() {
    let account = derive_account_key(&[0x31u8; 64]).expect("account key");
    let raw = account.to_raw();
    let receive = derive_address_key(&account, 3).expect("receive child");
    let change = derive_change_key(&account, 4).expect("change child");
    let account_target = account.public_key_x_only().expect("account xonly");
    let receive_target = receive.public_key_x_only().expect("receive xonly");
    let change_target = change.public_key_x_only().expect("change xonly");

    let mut context = SigningContext::from_account_raw(&[(raw, true), ([0u8; 65], false)]);
    assert_eq!(context.seed_count(), 2);
    assert_eq!(context.account_xonly(0), Some(account_target));
    assert_eq!(context.account_xonly(1), None);
    assert_eq!(
        context
            .account_material(0)
            .expect("account material")
            .compressed_public_key,
        account.public_key_compressed().expect("account compressed"),
    );
    assert!(context.account_material(1).is_none());

    assert_eq!(
        context
            .direct_address_material(0, &receive_target)
            .expect("direct receive")
            .compressed_public_key,
        receive.public_key_compressed().expect("receive compressed"),
    );
    assert_eq!(
        context
            .direct_address_material(0, &change_target)
            .expect("direct change")
            .compressed_public_key,
        change.public_key_compressed().expect("change compressed"),
    );
    assert_eq!(
        context
            .cached_address_material(0, &receive_target)
            .expect("cached receive")
            .compressed_public_key,
        receive.public_key_compressed().expect("receive compressed"),
    );
    assert_eq!(
        context
            .matching_material(&account_target)
            .expect("matching account")
            .compressed_public_key,
        account.public_key_compressed().expect("account compressed"),
    );
    assert_eq!(
        context
            .matching_material(&change_target)
            .expect("matching change")
            .compressed_public_key,
        change.public_key_compressed().expect("change compressed"),
    );
    assert!(context.matching_material(&[0xff; 32]).is_none());
    assert!(context
        .cached_address_material(7, &receive_target)
        .is_none());
}

#[test]
fn account_finalization_entry_points_cover_zero_addition_range_without_fabricating_progress() {
    let account = derive_account_key(&[0x31u8; 64]).expect("account key");
    let mut tx = transaction();
    let initial = initial_signature_counts(&tx);
    assert_eq!(&initial[..tx.num_inputs], &[0]);

    let session = [0x51u8; shared_signer::anti_klepto::SESSION_ID_LEN];
    assert_eq!(
        finalize_account_signatures(&mut tx, &account, &initial, &session, &[0x52; 32],),
        Err(PsktError::NoInputs),
    );
    assert_eq!(tx.inputs[0].sig_count, 0);
}

#[test]
fn signing_context_hd45_account_sets_cover_valid_and_rejected_hints() {
    use crate::transaction::model::Ms45Hint;

    let seed = [0x52u8; 64];
    let account = derive_account_key(&seed).expect("44' account");
    let ms45 =
        crate::derivation::bip32::derive_multisig_account_key(&seed, 0).expect("45' account");
    let accounts = [(account.to_raw(), true), ([0u8; 65], false)];
    let ms45_accounts = [(ms45.to_raw(), true), ([0u8; 65], false)];
    let context = SigningContext::from_account_sets(&accounts, &ms45_accounts);

    let hint = Ms45Hint {
        present: true,
        cosigner: 2,
        chain: 1,
        index: 7,
    };
    let expected =
        crate::derivation::bip32::derive_multisig_address_key(&ms45, 2, 1, 7).expect("45' child");
    let material = context
        .ms45_material(0, &hint)
        .expect("45' signing material");
    assert_eq!(material.private_key, *expected.private_key_bytes());
    assert_eq!(
        material.compressed_public_key,
        expected.public_key_compressed().expect("45' compressed"),
    );

    assert!(context.ms45_material(1, &hint).is_none());
    assert!(context.ms45_material(0, &Ms45Hint::none()).is_none());
    assert!(context
        .ms45_material(
            0,
            &Ms45Hint {
                present: true,
                cosigner: 0,
                chain: 2,
                index: 0
            },
        )
        .is_none());
}

#[test]
fn hd45_input_signing_covers_match_duplicate_miss_and_entropy_routes() {
    use super::super::ms45;
    use crate::transaction::model::{Ms45Hint, MultisigInfo};

    let seed = [0x73u8; 64];
    let account = derive_account_key(&seed).expect("44' account");
    let ms45_account =
        crate::derivation::bip32::derive_multisig_account_key(&seed, 0).expect("45' account");
    let context = SigningContext::from_account_sets(
        &[(account.to_raw(), true)],
        &[(ms45_account.to_raw(), true)],
    );
    let hint = Ms45Hint {
        present: true,
        cosigner: 1,
        chain: 0,
        index: 3,
    };
    let child = crate::derivation::bip32::derive_multisig_address_key(&ms45_account, 1, 0, 3)
        .expect("45' child");
    let child_xonly = child.public_key_x_only().expect("45' xonly");

    let mut info = MultisigInfo::new();
    info.m = 1;
    info.n = 2;
    info.pubkeys[0] = child_xonly;
    info.pubkeys[1] = [0x99; 32];

    let mut tx = transaction();
    assert_eq!(
        ms45::sign_input(&mut tx, 0, &info, &context, SigHashType::All, None, &hint),
        Ok(1),
    );
    assert_eq!(tx.inputs[0].sig_count, 1);
    assert_ne!(tx.inputs[0].sigs[0].signature, [0u8; 64]);
    assert_ne!(tx.inputs[0].sigs[0].signature, [1u8; 64]);
    assert_eq!(
        ms45::sign_input(&mut tx, 0, &info, &context, SigHashType::All, None, &hint),
        Ok(0),
    );

    let mut entropy_tx = transaction();
    assert_eq!(
        ms45::sign_input(
            &mut entropy_tx,
            0,
            &info,
            &context,
            SigHashType::Single,
            Some(&[0x74; 32]),
            &hint,
        ),
        Ok(1),
    );

    let mut miss_info = info.clone();
    miss_info.pubkeys[0] = [0x88; 32];
    let mut miss_tx = transaction();
    assert_eq!(
        ms45::sign_input(
            &mut miss_tx,
            0,
            &miss_info,
            &context,
            SigHashType::All,
            None,
            &hint
        ),
        Ok(0),
    );

    let absent_context =
        SigningContext::from_account_sets(&[([0u8; 65], false)], &[([0u8; 65], false)]);
    let mut absent_tx = transaction();
    assert_eq!(
        ms45::sign_input(
            &mut absent_tx,
            0,
            &info,
            &absent_context,
            SigHashType::All,
            None,
            &hint
        ),
        Ok(0),
    );
}

#[test]
fn signing_context_account_sets_reject_absent_and_out_of_range_hd45_slots() {
    use crate::transaction::model::Ms45Hint;

    let seed0 = [0x91u8; 64];
    let seed1 = [0x92u8; 64];
    let account0 = derive_account_key(&seed0).expect("account 0");
    let account1 = derive_account_key(&seed1).expect("account 1");
    let ms0 = crate::derivation::bip32::derive_multisig_account_key(&seed0, 0).expect("ms0");
    let ms1 = crate::derivation::bip32::derive_multisig_account_key(&seed1, 0).expect("ms1");
    let hint = Ms45Hint {
        present: true,
        cosigner: 0,
        chain: 0,
        index: 0,
    };

    let absent = SigningContext::from_account_sets(
        &[(account0.to_raw(), true), (account1.to_raw(), true)],
        &[(ms0.to_raw(), true), (ms1.to_raw(), false)],
    );
    assert!(absent.ms45_material(0, &hint).is_some());
    assert!(absent.ms45_material(1, &hint).is_none());

    let out_of_range = SigningContext::from_account_sets(
        &[(account0.to_raw(), true)],
        &[(ms0.to_raw(), true), (ms1.to_raw(), true)],
    );
    assert_eq!(out_of_range.seed_count(), 1);
    assert!(out_of_range.ms45_material(0, &hint).is_some());
    assert!(out_of_range.ms45_material(1, &hint).is_none());
}
