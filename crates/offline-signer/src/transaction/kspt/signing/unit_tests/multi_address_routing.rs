use super::super::{
    sign_account_input_with_entropy, sign_transaction_account_multi_addr_with_entropy,
    sign_transaction_multi_addr,
};
use super::{set_p2pk, transaction};
use crate::{
    derivation::bip32::{derive_account_key, derive_address_key, derive_change_key},
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

fn stealth_target(
    account: &crate::derivation::bip32::ExtendedPrivKey,
    tweak_bytes: [u8; 32],
) -> [u8; 32] {
    use k256::elliptic_curve::{ops::Add, sec1::ToEncodedPoint, ScalarPrimitive};
    use k256::{ProjectivePoint, Scalar};

    let primitive = ScalarPrimitive::<k256::Secp256k1>::from_slice(account.private_key_bytes())
        .expect("account scalar");
    let raw = Scalar::from(primitive);
    let point = (ProjectivePoint::GENERATOR * raw)
        .to_affine()
        .to_encoded_point(true);
    let normalized = if point.as_bytes()[0] == 0x03 {
        -raw
    } else {
        raw
    };
    let tweak = ScalarPrimitive::<k256::Secp256k1>::from_slice(&tweak_bytes).expect("tweak scalar");
    let combined = normalized.add(&Scalar::from(tweak));
    let encoded = (ProjectivePoint::GENERATOR * combined)
        .to_affine()
        .to_encoded_point(true);
    let mut target = [0u8; 32];
    target.copy_from_slice(&encoded.as_bytes()[1..33]);
    target
}

#[test]
fn account_input_route_distinguishes_receive_change_stealth_and_nonmatch() {
    let seed = [0x31u8; 64];
    let account = derive_account_key(&seed).expect("account");
    let entropy = [0x61u8; 32];

    for (target, expected_compressed) in [
        {
            let child = derive_address_key(&account, 0).expect("receive child");
            (
                child.public_key_x_only().unwrap(),
                child.public_key_compressed().unwrap(),
            )
        },
        {
            let child = derive_change_key(&account, 0).expect("change child");
            (
                child.public_key_x_only().unwrap(),
                child.public_key_compressed().unwrap(),
            )
        },
    ] {
        let mut tx = transaction();
        set_p2pk(&mut tx, &target);
        assert_eq!(
            sign_account_input_with_entropy(&mut tx, 0, &account, SigHashType::All, &entropy),
            Ok(true),
        );
        assert_eq!(tx.inputs[0].sig_count, 1);
        assert_eq!(tx.inputs[0].sigs[0].pubkey_compressed, expected_compressed);
    }

    let other = derive_account_key(&[0x32u8; 64]).unwrap();
    let other_target = derive_address_key(&other, 0)
        .unwrap()
        .public_key_x_only()
        .unwrap();
    let mut nonmatch = transaction();
    set_p2pk(&mut nonmatch, &other_target);
    assert_eq!(
        sign_account_input_with_entropy(&mut nonmatch, 0, &account, SigHashType::All, &entropy),
        Ok(false),
    );
    assert_eq!(nonmatch.inputs[0].sig_count, 0);

    let tweak = [1u8; 32];
    let target = stealth_target(&account, tweak);
    let mut stealth = transaction();
    set_p2pk(&mut stealth, &target);
    stealth.has_stealth_tweak = true;
    stealth.stealth_tweak = tweak;
    assert_eq!(
        sign_account_input_with_entropy(&mut stealth, 0, &account, SigHashType::All, &entropy),
        Ok(true),
    );
    assert_eq!(stealth.inputs[0].sig_count, 1);
    assert_eq!(&stealth.inputs[0].sigs[0].pubkey_compressed[1..33], &target);
}

#[test]
fn standard_input_derivation_hint_signs_beyond_legacy_scan_and_must_match_script() {
    let seed = [0x31u8; 64];
    let account = derive_account_key(&seed).expect("account");
    let child = derive_address_key(&account, 500).expect("far receive child");
    let target = child.public_key_x_only().expect("far receive public key");
    let entropy = [0x64u8; 32];

    let mut hinted = transaction();
    set_p2pk(&mut hinted, &target);
    hinted.inputs[0].has_derivation_hint = true;
    hinted.inputs[0].derivation_branch = 0;
    hinted.inputs[0].derivation_index = 500;
    assert_eq!(
        sign_account_input_with_entropy(&mut hinted, 0, &account, SigHashType::All, &entropy),
        Ok(true),
    );
    assert_eq!(
        hinted.inputs[0].sigs[0].pubkey_compressed,
        child.public_key_compressed().unwrap()
    );

    let mut wrong_hint = transaction();
    set_p2pk(&mut wrong_hint, &target);
    wrong_hint.inputs[0].has_derivation_hint = true;
    wrong_hint.inputs[0].derivation_branch = 0;
    wrong_hint.inputs[0].derivation_index = 499;
    assert_eq!(
        sign_account_input_with_entropy(&mut wrong_hint, 0, &account, SigHashType::All, &entropy),
        Ok(false),
    );
    assert_eq!(wrong_hint.inputs[0].sig_count, 0);
}

#[test]
fn multi_address_standard_match_wins_even_when_stealth_metadata_is_present() {
    let seed = [0x31u8; 64];
    let account = derive_account_key(&seed).expect("account");
    let receive = derive_address_key(&account, 0).expect("receive");
    let target = receive.public_key_x_only().unwrap();
    let mut tx = transaction();
    set_p2pk(&mut tx, &target);
    tx.has_stealth_tweak = true;
    tx.stealth_tweak = [1u8; 32];

    assert_eq!(
        sign_transaction_account_multi_addr_with_entropy(
            &mut tx,
            &account,
            SigHashType::All,
            &[0x62; 32],
        ),
        Ok(1),
    );
    assert_eq!(tx.inputs[0].sig_count, 1);
    assert_eq!(
        tx.inputs[0].sigs[0].pubkey_compressed,
        receive.public_key_compressed().unwrap()
    );
}

#[test]
fn multi_address_shape_filters_reject_each_independent_p2pk_malformation() {
    let seed = [0x31u8; 64];
    let account = derive_account_key(&seed).expect("account");
    let target = derive_address_key(&account, 0)
        .unwrap()
        .public_key_x_only()
        .unwrap();

    for variant in 0..3 {
        let mut tx = transaction();
        set_p2pk(&mut tx, &target);
        match variant {
            0 => tx.inputs[0].utxo_entry.script_public_key.script_len = 33,
            1 => tx.inputs[0].utxo_entry.script_public_key.script[0] = 0x21,
            2 => tx.inputs[0].utxo_entry.script_public_key.script[33] = 0xad,
            _ => unreachable!(),
        }
        assert_eq!(
            sign_transaction_account_multi_addr_with_entropy(
                &mut tx,
                &account,
                SigHashType::All,
                &[0x63; 32],
            ),
            Err(PsktError::NoInputs),
            "variant {variant}",
        );
        assert_eq!(tx.inputs[0].sig_count, 0);
    }
}

#[test]
fn multi_address_public_wrapper_reports_exact_number_of_signed_inputs() {
    let seed = [0x31u8; 64];
    let account = derive_account_key(&seed).expect("account");
    let receive = derive_address_key(&account, 0)
        .unwrap()
        .public_key_x_only()
        .unwrap();
    let change = derive_change_key(&account, 0)
        .unwrap()
        .public_key_x_only()
        .unwrap();

    let mut tx = transaction();
    tx.ensure_input_slots(2).unwrap();
    tx.inputs[1] = tx.inputs[0].clone();
    tx.inputs[1].previous_outpoint.index = 8;
    tx.num_inputs = 2;
    set_p2pk_at(&mut tx, 0, &receive);
    set_p2pk_at(&mut tx, 1, &change);
    assert_eq!(
        sign_transaction_multi_addr(&mut tx, &seed, SigHashType::All),
        Ok(2)
    );
    assert_eq!(tx.inputs[0].sig_count, 1);
    assert_eq!(tx.inputs[1].sig_count, 1);

    let other = derive_account_key(&[0x32u8; 64]).unwrap();
    let other_target = derive_address_key(&other, 0)
        .unwrap()
        .public_key_x_only()
        .unwrap();
    let mut none = transaction();
    set_p2pk(&mut none, &other_target);
    assert_eq!(
        sign_transaction_multi_addr(&mut none, &seed, SigHashType::All),
        Err(PsktError::NoInputs)
    );
}
