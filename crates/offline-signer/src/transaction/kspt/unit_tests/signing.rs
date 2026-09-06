use crate::{
    derivation::bip32::{compressed_pubkey_from_raw_key, derive_account_key, derive_address_key},
    transaction::{
        kspt::{
            sign_matching_inputs_in_place_with_entropy,
            sign_transaction_account_multi_addr_with_entropy, PsktError,
        },
        model::{SigHashType, Transaction},
    },
};

fn set_p2pk(tx: &mut Transaction, xonly: &[u8; 32]) {
    let script = &mut tx.inputs[0].utxo_entry.script_public_key;
    script.script[0] = 0x20;
    script.script[1..33].copy_from_slice(xonly);
    script.script[33] = 0xac;
    script.script_len = 34;
}

#[test]
fn imported_account_key_signs_receive_inputs() {
    let seed = [0x31u8; 64];
    let account = derive_account_key(&seed).expect("account derivation");
    let child = derive_address_key(&account, 7).expect("address derivation");
    let xonly = child.public_key_x_only().expect("child public key");
    let mut tx = super::common::transaction();
    set_p2pk(&mut tx, &xonly);

    let signed = sign_transaction_account_multi_addr_with_entropy(
        &mut tx,
        &account,
        SigHashType::All,
        &[0xA5; 32],
    )
    .expect("account input should sign");

    assert_eq!(signed, 1);
    assert_eq!(tx.inputs[0].sig_count, 1);
}

#[test]
fn raw_key_signer_rejects_nonmatching_inputs() {
    let private_key = [0x11u8; 32];
    let compressed = compressed_pubkey_from_raw_key(&private_key).expect("valid private key");
    let mut xonly = [0u8; 32];
    xonly.copy_from_slice(&compressed[1..33]);

    let mut matching = super::common::transaction();
    set_p2pk(&mut matching, &xonly);
    assert_eq!(
        sign_matching_inputs_in_place_with_entropy(
            &mut matching,
            &private_key,
            SigHashType::All,
            &[0x5A; 32],
        )
        .expect("matching raw-key input"),
        1,
    );

    let mut foreign = super::common::transaction();
    assert_eq!(
        sign_matching_inputs_in_place_with_entropy(
            &mut foreign,
            &private_key,
            SigHashType::All,
            &[0x5A; 32],
        ),
        Err(PsktError::NoInputs),
    );
}

#[test]
fn imported_account_signer_handles_stealth_tweaks_and_rejects_mismatches() {
    use k256::elliptic_curve::{ops::Add, sec1::ToEncodedPoint, ScalarPrimitive};
    use k256::{ProjectivePoint, Scalar};

    let seed = [0x41u8; 64];
    let account = derive_account_key(&seed).expect("account derivation");
    let account_primitive =
        ScalarPrimitive::<k256::Secp256k1>::from_slice(account.private_key_bytes())
            .expect("account scalar");
    let account_scalar = {
        let scalar = Scalar::from(account_primitive);
        let encoded = (ProjectivePoint::GENERATOR * scalar)
            .to_affine()
            .to_encoded_point(true);
        if encoded.as_bytes()[0] == 0x03 {
            -scalar
        } else {
            scalar
        }
    };
    let mut tweak_bytes = [0u8; 32];
    tweak_bytes[31] = 1;
    let tweak =
        ScalarPrimitive::<k256::Secp256k1>::from_slice(&tweak_bytes).expect("stealth tweak");
    let combined = account_scalar.add(&Scalar::from(tweak));
    let encoded = (ProjectivePoint::GENERATOR * combined)
        .to_affine()
        .to_encoded_point(true);
    let mut target = [0u8; 32];
    target.copy_from_slice(&encoded.as_bytes()[1..33]);

    let mut transaction = super::common::transaction();
    set_p2pk(&mut transaction, &target);
    transaction.has_stealth_tweak = true;
    transaction.stealth_tweak = tweak_bytes;
    assert_eq!(
        sign_transaction_account_multi_addr_with_entropy(
            &mut transaction,
            &account,
            SigHashType::All,
            &[0x7b; 32],
        ),
        Ok(1),
    );

    let mut mismatch = super::common::transaction();
    set_p2pk(&mut mismatch, &[0xff; 32]);
    mismatch.has_stealth_tweak = true;
    mismatch.stealth_tweak = tweak_bytes;
    assert_eq!(
        sign_transaction_account_multi_addr_with_entropy(
            &mut mismatch,
            &account,
            SigHashType::All,
            &[0x7b; 32],
        ),
        Err(PsktError::NoInputs),
    );
}

#[test]
fn seed_based_multi_address_public_wrappers_are_covered() {
    use crate::transaction::kspt::{
        sign_transaction_multi_addr, sign_transaction_multi_addr_with_entropy,
    };

    let seed = [0x51u8; 64];
    let account = derive_account_key(&seed).expect("account derivation");
    let child = derive_address_key(&account, 2).expect("address derivation");
    let xonly = child.public_key_x_only().expect("child public key");

    let mut deterministic = super::common::transaction();
    set_p2pk(&mut deterministic, &xonly);
    assert_eq!(
        sign_transaction_multi_addr(&mut deterministic, &seed, SigHashType::All),
        Ok(1)
    );

    let mut entropy = super::common::transaction();
    set_p2pk(&mut entropy, &xonly);
    assert_eq!(
        sign_transaction_multi_addr_with_entropy(
            &mut entropy,
            &seed,
            SigHashType::All,
            &[0x6a; 32],
        ),
        Ok(1)
    );
}
