use crate::transaction::model::{detect_script_type, parse_multisig_script, ScriptType};

use super::super::analyze_input_script;
use super::common::transaction;

#[test]
fn public_script_analysis_is_checked() {
    let tx = transaction();
    let (script_type, multisig) = analyze_input_script(&tx, tx.num_inputs);
    assert_eq!(script_type, ScriptType::Unknown);
    assert!(multisig.is_none());
}

#[test]
fn non_p2sh_input_ignores_unrelated_redeem_metadata() {
    let mut tx = transaction();
    tx.store_redeem(0, &[0x51]).expect("redeem metadata fits");
    let (script_type, multisig) = analyze_input_script(&tx, 0);
    assert_eq!(script_type, ScriptType::P2PK);
    assert!(multisig.is_none());
}

#[test]
fn script_detection_covers_standard_and_rejected_shapes() {
    let mut p2pk = [0u8; 34];
    p2pk[0] = 0x20;
    p2pk[33] = 0xac;
    assert_eq!(detect_script_type(&p2pk, p2pk.len()), ScriptType::P2PK);

    let mut p2sh = [0u8; 35];
    p2sh[0] = 0xaa;
    p2sh[1] = 0x20;
    p2sh[34] = 0x87;
    assert_eq!(detect_script_type(&p2sh, p2sh.len()), ScriptType::P2SH);

    let mut one_of_one = [0u8; 36];
    one_of_one[0] = 0x51;
    one_of_one[1] = 0x20;
    one_of_one[2..34].fill(0x11);
    one_of_one[34] = 0x51;
    one_of_one[35] = 0xae;
    assert_eq!(
        detect_script_type(&one_of_one, one_of_one.len()),
        ScriptType::Multisig,
    );
    let parsed = parse_multisig_script(&one_of_one, one_of_one.len()).expect("valid 1-of-1");
    assert_eq!((parsed.m, parsed.n), (1, 1));

    let mut multisig = [0u8; 69];
    multisig[0] = 0x51;
    multisig[1] = 0x20;
    multisig[34] = 0x20;
    multisig[67] = 0x52;
    multisig[68] = 0xae;
    assert_eq!(
        detect_script_type(&multisig, multisig.len()),
        ScriptType::Multisig
    );
    let parsed = parse_multisig_script(&multisig, multisig.len()).expect("valid multisig");
    assert_eq!((parsed.m, parsed.n), (1, 2));

    let mut bad_push = multisig;
    bad_push[34] = 0x21;
    assert_eq!(
        detect_script_type(&bad_push, bad_push.len()),
        ScriptType::Unknown
    );

    let mut bad_threshold = multisig;
    bad_threshold[0] = 0x53;
    assert_eq!(
        detect_script_type(&bad_threshold, bad_threshold.len()),
        ScriptType::Unknown
    );

    let mut bad_count = multisig;
    bad_count[67] = 0x56;
    assert_eq!(
        detect_script_type(&bad_count, bad_count.len()),
        ScriptType::Unknown
    );

    assert_eq!(
        detect_script_type(&multisig, multisig.len() - 1),
        ScriptType::Unknown
    );
    assert_eq!(detect_script_type(&[], 0), ScriptType::Unknown);
}

#[test]
fn multisig_configuration_builds_deterministic_child_script_and_rejects_invalid_thresholds() {
    use crate::{
        derivation::bip32::derive_account_key,
        transaction::model::{MultisigConfig, OP_CHECKMULTISIG, OP_DATA_32},
    };

    let mut invalid = MultisigConfig::new();
    assert_eq!(invalid.build_script(), 0);
    invalid.m = 2;
    invalid.n = 1;
    assert_eq!(invalid.build_script(), 0);

    let first = derive_account_key(&[0x11; 64])
        .expect("first account")
        .to_xpub()
        .expect("first xpub");
    let second = derive_account_key(&[0x22; 64])
        .expect("second account")
        .to_xpub()
        .expect("second xpub");

    fn config(
        first: &crate::derivation::bip32::ExtendedPubKey,
        second: &crate::derivation::bip32::ExtendedPubKey,
    ) -> MultisigConfig {
        let mut value = MultisigConfig::new();
        value.m = 2;
        value.n = 2;
        value.addr_index = 7;
        value.cosigner_pubkeys[0] = first.pubkey;
        value.cosigner_chain_codes[0] = first.chain_code;
        value.cosigner_pubkeys[1] = second.pubkey;
        value.cosigner_chain_codes[1] = second.chain_code;
        value
    }

    let mut forward = config(&first, &second);
    let mut reverse = config(&second, &first);
    let expected_len = 1 + 2 * 33 + 2;
    assert_eq!(forward.build_script(), expected_len);
    assert_eq!(reverse.build_script(), expected_len);
    assert_eq!(
        &forward.script[..forward.script_len],
        &reverse.script[..reverse.script_len],
    );
    assert_eq!(forward.script[1], OP_DATA_32);
    assert_eq!(forward.script[34], OP_DATA_32);
    assert_eq!(forward.script[forward.script_len - 1], OP_CHECKMULTISIG);
}
