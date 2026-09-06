use super::super::{
    sign_multisig_accounts_input_with_entropy, sign_transaction_multisig,
    sign_transaction_multisig_accounts_with_entropy,
};
use super::{set_p2pk, set_p2sh, set_two_of_two_multisig, transaction};
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

#[test]
fn per_input_account_route_distinguishes_two_signer_multisig_from_unknown_script() {
    let first = derive_account_key(&[0x31u8; 64]).unwrap();
    let second = derive_account_key(&[0x32u8; 64]).unwrap();
    let first_xonly = first.public_key_x_only().unwrap();
    let second_xonly = second.public_key_x_only().unwrap();
    let accounts = [(first.to_raw(), true), (second.to_raw(), true)];

    let mut multisig = transaction();
    set_two_of_two_multisig(&mut multisig, &first_xonly, &second_xonly);
    assert_eq!(
        sign_multisig_accounts_input_with_entropy(
            &mut multisig,
            0,
            &accounts,
            SigHashType::All,
            None,
            &[0x71; 32],
        ),
        Ok(2),
    );
    assert_eq!(multisig.inputs[0].sig_count, 2);
    assert_eq!(multisig.inputs[0].sigs[0].pubkey_pos, 0);
    assert_eq!(multisig.inputs[0].sigs[1].pubkey_pos, 1);

    let mut unknown = transaction();
    unknown.inputs[0].utxo_entry.script_public_key.script[0] = 0x51;
    unknown.inputs[0].utxo_entry.script_public_key.script_len = 1;
    assert_eq!(
        sign_multisig_accounts_input_with_entropy(
            &mut unknown,
            0,
            &accounts,
            SigHashType::All,
            None,
            &[0x71; 32],
        ),
        Ok(0),
    );
    assert_eq!(unknown.inputs[0].sig_count, 0);
}

#[test]
fn multisig_material_selection_observes_account_and_cached_child_routes() {
    let seed = [0x31u8; 64];
    let account = derive_account_key(&seed).unwrap();
    let other = derive_account_key(&[0x32u8; 64]).unwrap();
    let account_xonly = account.public_key_x_only().unwrap();
    let other_xonly = other.public_key_x_only().unwrap();
    let accounts = [(account.to_raw(), true)];

    let mut account_route = transaction();
    set_two_of_two_multisig(&mut account_route, &account_xonly, &other_xonly);
    assert_eq!(
        sign_multisig_accounts_input_with_entropy(
            &mut account_route,
            0,
            &accounts,
            SigHashType::All,
            None,
            &[0x72; 32],
        ),
        Ok(1),
    );
    assert_eq!(account_route.inputs[0].sigs[0].pubkey_pos, 0);
    assert_eq!(
        account_route.inputs[0].sigs[0].pubkey_compressed,
        account.public_key_compressed().unwrap(),
    );

    let child = derive_address_key(&account, 3).unwrap();
    let child_xonly = child.public_key_x_only().unwrap();
    let mut cached_route = transaction();
    set_two_of_two_multisig(&mut cached_route, &child_xonly, &other_xonly);
    assert_eq!(
        sign_multisig_accounts_input_with_entropy(
            &mut cached_route,
            0,
            &accounts,
            SigHashType::All,
            None,
            &[0x73; 32],
        ),
        Ok(1),
    );
    assert_eq!(cached_route.inputs[0].sigs[0].pubkey_pos, 0);
    assert_eq!(
        cached_route.inputs[0].sigs[0].pubkey_compressed,
        child.public_key_compressed().unwrap()
    );
}

#[test]
fn covenant_account_route_honors_active_account_selection() {
    let first = derive_account_key(&[0x31u8; 64]).unwrap();
    let second = derive_account_key(&[0x32u8; 64]).unwrap();
    let accounts = [(first.to_raw(), true), (second.to_raw(), true)];
    let second_xonly = second.public_key_x_only().unwrap();
    let mut redeem = [0u8; 34];
    redeem[0] = 0x20;
    redeem[1..33].copy_from_slice(&second_xonly);
    redeem[33] = 0xac;

    let mut filtered = transaction();
    set_p2sh(&mut filtered, &redeem);
    assert_eq!(
        sign_multisig_accounts_input_with_entropy(
            &mut filtered,
            0,
            &accounts,
            SigHashType::All,
            Some(0),
            &[0x74; 32],
        ),
        Ok(0),
    );
    assert_eq!(filtered.inputs[0].sig_count, 0);

    let mut selected = transaction();
    set_p2sh(&mut selected, &redeem);
    assert_eq!(
        sign_multisig_accounts_input_with_entropy(
            &mut selected,
            0,
            &accounts,
            SigHashType::All,
            Some(1),
            &[0x74; 32],
        ),
        Ok(1),
    );
    assert_eq!(selected.inputs[0].sig_count, 1);
    assert_eq!(
        selected.inputs[0].sigs[0].pubkey_compressed,
        second.public_key_compressed().unwrap()
    );
}

#[test]
fn multisig_public_wrappers_report_exact_two_input_progress() {
    let seed = [0x31u8; 64];
    let account = derive_account_key(&seed).unwrap();
    let receive = derive_address_key(&account, 0)
        .unwrap()
        .public_key_x_only()
        .unwrap();
    let change = derive_change_key(&account, 0)
        .unwrap()
        .public_key_x_only()
        .unwrap();

    let build = || {
        let mut tx = transaction();
        tx.ensure_input_slots(2).unwrap();
        tx.inputs[1] = tx.inputs[0].clone();
        tx.inputs[1].previous_outpoint.index = 8;
        tx.num_inputs = 2;
        set_p2pk_at(&mut tx, 0, &receive);
        set_p2pk_at(&mut tx, 1, &change);
        tx
    };

    let mut seeded = build();
    assert_eq!(
        sign_transaction_multisig(&mut seeded, &[(seed, true)], SigHashType::All, None),
        Ok(2),
    );
    assert_eq!(seeded.inputs[0].sig_count, 1);
    assert_eq!(seeded.inputs[1].sig_count, 1);

    let mut imported = build();
    assert_eq!(
        sign_transaction_multisig_accounts_with_entropy(
            &mut imported,
            &[(account.to_raw(), true)],
            SigHashType::All,
            None,
            &[0x75; 32],
        ),
        Ok(2),
    );
    assert_eq!(imported.inputs[0].sig_count, 1);
    assert_eq!(imported.inputs[1].sig_count, 1);

    let mut none = transaction();
    set_p2pk(&mut none, &[0x99; 32]);
    assert_eq!(
        sign_transaction_multisig_accounts_with_entropy(
            &mut none,
            &[(account.to_raw(), true)],
            SigHashType::All,
            None,
            &[0x75; 32],
        ),
        Err(PsktError::NoInputs),
    );
}

#[test]
fn hd45_account_set_public_entry_point_signs_the_hint_selected_child() {
    use crate::transaction::model::{
        Ms45Hint, OP_1, OP_BLAKE2B, OP_CHECKMULTISIG, OP_DATA_32, OP_EQUAL,
    };

    let seed = [0x75u8; 64];
    let ms45 =
        crate::derivation::bip32::derive_multisig_account_key(&seed, 0).expect("45' account");
    let hint = Ms45Hint {
        present: true,
        cosigner: 1,
        chain: 1,
        index: 4,
    };
    let child = crate::derivation::bip32::derive_multisig_address_key(
        &ms45,
        hint.cosigner,
        hint.chain,
        hint.index,
    )
    .expect("45' child");
    let xonly = child.public_key_x_only().expect("45' xonly");

    let mut redeem = [0u8; 36];
    redeem[0] = OP_1;
    redeem[1] = OP_DATA_32;
    redeem[2..34].copy_from_slice(&xonly);
    redeem[34] = OP_1;
    redeem[35] = OP_CHECKMULTISIG;

    let mut tx = super::transaction();
    tx.store_redeem(0, &redeem).expect("redeem");
    let hash = crate::transaction::sighash::blake2b_hash(&redeem);
    let outer = &mut tx.inputs[0].utxo_entry.script_public_key;
    outer.script[0] = OP_BLAKE2B;
    outer.script[1] = OP_DATA_32;
    outer.script[2..34].copy_from_slice(&hash);
    outer.script[34] = OP_EQUAL;
    outer.script_len = 35;
    tx.inputs[0].ms45_hint = hint;

    assert_eq!(
        super::super::sign_multisig_account_sets_input_with_entropy(
            &mut tx,
            0,
            &[([0u8; 65], false)],
            &[(ms45.to_raw(), true)],
            crate::transaction::model::SigHashType::All,
            None,
            &[0x76; 32],
        ),
        Ok(1),
    );
    assert_eq!(tx.inputs[0].sig_count, 1);
}

#[test]
fn hd45_account_set_signs_exact_two_local_members_of_two_of_three() {
    use crate::{
        derivation::{
            bip32::{derive_account_key, derive_multisig_account_key},
            xpub::derive_multisig_account_parts,
        },
        transaction::model::{Ms45Hint, MultisigConfig},
    };

    let first_seed = [0x81u8; 64];
    let second_seed = [0x82u8; 64];
    let external_seed = [0x83u8; 64];
    let first_parts = derive_multisig_account_parts(&first_seed, 0).expect("first 45' kpub");
    let second_parts = derive_multisig_account_parts(&second_seed, 0).expect("second 45' kpub");
    let external_parts =
        derive_multisig_account_parts(&external_seed, 0).expect("external 45' kpub");

    let mut config = MultisigConfig::new();
    config.m = 2;
    config.n = 3;
    config.v45 = true;
    assert!(config.set_cosigner(0, &first_parts));
    assert!(config.set_cosigner(1, &second_parts));
    assert!(config.set_cosigner(2, &external_parts));
    config.sort_cosigners();
    assert!(config.resolve_cosigner_index(&first_parts));
    config.chain = 0;
    config.addr_index = 4;
    let script_len = config.build_script();
    assert_ne!(script_len, 0);

    let mut tx = transaction();
    tx.inputs[0].sig_op_count = config.n;
    tx.inputs[0].ms45_hint = Ms45Hint {
        present: true,
        cosigner: u32::from(config.cosigner_index),
        chain: u32::from(config.chain),
        index: config.addr_index,
    };
    set_p2sh(&mut tx, &config.script[..script_len]);

    let first_account = derive_account_key(&first_seed).expect("first account");
    let second_account = derive_account_key(&second_seed).expect("second account");
    let first_ms45 = derive_multisig_account_key(&first_seed, 0).expect("first 45' account");
    let second_ms45 = derive_multisig_account_key(&second_seed, 0).expect("second 45' account");
    let accounts = [
        (first_account.to_raw(), true),
        (second_account.to_raw(), true),
    ];
    let ms45_accounts = [(first_ms45.to_raw(), true), (second_ms45.to_raw(), true)];

    let unsigned_wire =
        crate::transaction::kspt::serialize_compact_kspt_vec(&tx).expect("unsigned compact KSPT");
    let mut imported =
        crate::transaction::model::Transaction::try_new().expect("transaction test allocation");
    crate::transaction::kspt::parse_compact_kspt(&unsigned_wire, &mut imported)
        .expect("unsigned compact KSPT import");
    assert_eq!(imported.inputs[0].sig_count, 0);
    assert_eq!(imported.inputs[0].sighash_type, 0);

    assert_eq!(
        super::super::sign_multisig_account_sets_input_with_entropy(
            &mut imported,
            0,
            &accounts,
            &ms45_accounts,
            SigHashType::All,
            Some(0),
            &[0x84; 32],
        ),
        Ok(2),
    );
    assert_eq!(imported.inputs[0].sig_count, 2);
    assert_eq!(imported.inputs[0].sighash_type, SigHashType::All.to_byte());
    let mut positions = [
        imported.inputs[0].sigs[0].pubkey_pos,
        imported.inputs[0].sigs[1].pubkey_pos,
    ];
    positions.sort_unstable();
    assert_ne!(positions[0], positions[1]);

    let signed_wire = crate::transaction::kspt::serialize_compact_kspt_vec(&imported)
        .expect("signed compact KSPT");
    let mut reparsed =
        crate::transaction::model::Transaction::try_new().expect("transaction test allocation");
    crate::transaction::kspt::parse_compact_kspt(&signed_wire, &mut reparsed)
        .expect("signed compact KSPT re-import");
    assert_eq!(reparsed.inputs[0].sig_count, 2);
    assert_eq!(reparsed.inputs[0].sighash_type, SigHashType::All.to_byte());
    assert!(crate::transaction::kspt::is_fully_signed(&reparsed));
}
