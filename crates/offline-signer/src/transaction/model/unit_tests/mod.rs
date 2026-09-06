use super::*;

#[test]
fn transaction_model_constructors_totals_and_reset_are_covered() {
    let mut tx = Transaction::try_new().expect("transaction test allocation");
    assert!(tx.inputs.iter().all(|input| input.sig_op_count == 1));
    assert!(tx.is_native());

    tx.num_inputs = 2;
    tx.inputs[0].utxo_entry.amount = 80;
    tx.inputs[1].utxo_entry.amount = 70;
    tx.num_outputs = 2;
    tx.outputs[0].value = 40;
    tx.outputs[1].value = 50;
    assert_eq!(tx.inputs().len(), 2);
    assert_eq!(tx.outputs().len(), 2);
    assert_eq!(tx.total_input_value(), Ok(150));
    assert_eq!(tx.total_output_value(), Ok(90));
    assert_eq!(tx.fee(), Ok(60));

    tx.outputs[1].value = 200;
    assert_eq!(tx.fee(), Err(TransactionAmountError::OutputsExceedInputs));
    tx.subnetwork_id = [1; 20];
    assert!(!tx.is_native());

    tx.clear();
    assert_eq!(tx.num_inputs, 0);
    assert_eq!(tx.num_outputs, 0);
    assert!(tx.is_native());
    assert!(tx.inputs.iter().all(|input| input.sig_op_count == 1));
}

#[test]
fn monetary_totals_reject_overflow_and_outputs_exceeding_inputs_at_exact_boundaries() {
    let mut input_overflow = Transaction::try_new().expect("transaction test allocation");
    input_overflow.num_inputs = 2;
    input_overflow.num_outputs = 1;
    input_overflow.inputs[0].utxo_entry.amount = u64::MAX;
    input_overflow.inputs[1].utxo_entry.amount = 1;
    input_overflow.outputs[0].value = u64::MAX;
    assert_eq!(
        input_overflow.checked_amounts(),
        Err(TransactionAmountError::InputTotalOverflow)
    );

    let mut output_overflow = Transaction::try_new().expect("transaction test allocation");
    output_overflow.num_inputs = 1;
    output_overflow.num_outputs = 2;
    output_overflow.inputs[0].utxo_entry.amount = u64::MAX;
    output_overflow.outputs[0].value = u64::MAX;
    output_overflow.outputs[1].value = 1;
    assert_eq!(
        output_overflow.checked_amounts(),
        Err(TransactionAmountError::OutputTotalOverflow)
    );

    let mut outputs_exceed_inputs = Transaction::try_new().expect("transaction test allocation");
    outputs_exceed_inputs.num_inputs = 1;
    outputs_exceed_inputs.num_outputs = 1;
    outputs_exceed_inputs.inputs[0].utxo_entry.amount = 41;
    outputs_exceed_inputs.outputs[0].value = 42;
    assert_eq!(
        outputs_exceed_inputs.checked_amounts(),
        Err(TransactionAmountError::OutputsExceedInputs)
    );

    let mut exact_max = Transaction::try_new().expect("transaction test allocation");
    exact_max.num_inputs = 2;
    exact_max.num_outputs = 2;
    exact_max.inputs[0].utxo_entry.amount = u64::MAX - 1;
    exact_max.inputs[1].utxo_entry.amount = 1;
    exact_max.outputs[0].value = u64::MAX - 1;
    exact_max.outputs[1].value = 1;
    assert_eq!(
        exact_max.checked_amounts(),
        Ok(TransactionAmounts {
            input_total: u64::MAX,
            output_total: u64::MAX,
            fee: 0,
        })
    );
    assert_eq!(exact_max.total_input_value(), Ok(u64::MAX));
    assert_eq!(exact_max.total_output_value(), Ok(u64::MAX));
    assert_eq!(exact_max.fee(), Ok(0));
}

#[test]
fn redeem_storage_covers_empty_inline_pool_and_capacity_errors() {
    let mut tx = Transaction::try_new().expect("transaction test allocation");

    tx.store_redeem(0, &[]).expect("empty redeem");
    assert!(tx.redeem_bytes(0).is_empty());

    let inline = [0x51; MAX_SCRIPT_SIZE];
    tx.store_redeem(0, &inline).expect("inline redeem");
    assert_eq!(tx.redeem_bytes(0), inline.as_slice());
    assert!(!tx.inputs[0].redeem_in_pool);

    let pooled = [0x52; MAX_SCRIPT_SIZE + 1];
    tx.store_redeem(1, &pooled).expect("pooled redeem");
    assert_eq!(tx.redeem_bytes(1), pooled.as_slice());
    assert!(tx.inputs[1].redeem_in_pool);

    let oversized = [0x53; MAX_REDEEM_SIZE + 1];
    assert_eq!(
        tx.store_redeem(2, &oversized),
        Err(TransactionStorageError::RedeemScriptTooLarge)
    );

    tx.redeem_pool_used = REDEEM_POOL_SIZE;
    assert_eq!(
        tx.store_redeem(2, &pooled),
        Err(TransactionStorageError::RedeemPoolFull)
    );
}

#[test]
fn model_value_objects_and_sighash_variants_are_covered() {
    let script = ScriptPublicKey::new();
    assert_eq!(script.version, 0);
    assert!(script.script_bytes().is_empty());

    let input_sig = InputSig::empty();
    assert!(!input_sig.present);
    assert_eq!(input_sig.signature, [0; 64]);
    assert_eq!(input_sig.pubkey_compressed, [0; 33]);

    let incoming = IncomingPartialSig::empty();
    assert!(!incoming.present);
    assert_eq!(incoming.pubkey, [0; 33]);
    assert_eq!(incoming.signature, [0; 64]);

    let cases = [
        (0x01, SigHashType::All, false, false, false),
        (0x02, SigHashType::None, false, true, false),
        (0x04, SigHashType::Single, false, false, true),
        (0x81, SigHashType::AllAnyOneCanPay, true, false, false),
        (0x82, SigHashType::NoneAnyOneCanPay, true, true, false),
        (0x84, SigHashType::SingleAnyOneCanPay, true, false, true),
    ];
    for (byte, expected, anyone, none, single) in cases {
        let parsed = SigHashType::from_byte(byte).expect("known sighash");
        assert_eq!(parsed, expected);
        assert_eq!(parsed.to_byte(), byte);
        assert_eq!(parsed.is_anyone_can_pay(), anyone);
        assert_eq!(parsed.is_sighash_none(), none);
        assert_eq!(parsed.is_sighash_single(), single);
    }
    for invalid in [0, 0x03, 0x80, 0xff] {
        assert_eq!(SigHashType::from_byte(invalid), None);
    }
}

#[test]
fn multisig_labels_slots_and_store_capacity_are_covered() {
    let mut config = MultisigConfig::new();
    assert!(config.slot_empty(0));
    assert!(!config.slot_empty(MAX_MULTISIG_KEYS));
    // Slot occupancy is keyed by participant pubkey. Metadata cannot make an
    // otherwise empty slot look occupied; set_cosigner installs all fields atomically.
    config.cosigner_chain_codes[0][0] = 1;
    config.cosigner_depth[0] = 1;
    config.cosigner_parent_fp[0][0] = 1;
    config.cosigner_child_num[0][0] = 1;
    assert!(config.slot_empty(0));
    config.cosigner_pubkeys[0][0] = 2;
    assert!(!config.slot_empty(0));

    config.m = 2;
    config.n = 3;
    let mut label = [0u8; 6];
    let length = config.label(&mut label);
    assert_eq!(&label[..length], b"2-of-3");
    let mut short = [0u8; 3];
    assert_eq!(config.label(&mut short), 3);
    assert_eq!(&short, b"2-o");

    let mut store = MultisigStore::new();
    assert_eq!(store.find_free(), Some(0));
    store.configs[0].active = true;
    assert_eq!(store.find_free(), Some(1));
    store.configs[1].active = true;
    assert_eq!(store.find_free(), None);
}

#[test]
fn multisig_rejects_duplicate_cosigner_identity() {
    let encoded = b"kpub2J937qL9n85s7HrhYyYYdMkzq1kaMiAf9PAcJzRW3jV7NgntNfGGrNgut7ZxcVrJqH42BCT2WyjfnxJh3SBDjLhXHe3UC2RJUu5tcjsViuK";
    let parts = crate::derivation::xpub::parse_kpub_parts(encoded).expect("v1.0.6 kpub");
    let mut config = MultisigConfig::new();
    config.n = 3;
    assert!(config.set_cosigner(0, &parts));
    assert!(!config.set_cosigner(1, &parts));
    assert!(config.slot_empty(1));
    assert!(config.set_cosigner(0, &parts));
}

#[test]
fn script_detection_and_kas_formatting_cover_boundaries() {
    let mut p2pk = [0u8; 34];
    p2pk[0] = OP_DATA_32;
    p2pk[33] = OP_CHECKSIG;
    assert_eq!(detect_script_type(&p2pk, p2pk.len()), ScriptType::P2PK);

    let mut p2sh = [0u8; 35];
    p2sh[0] = OP_BLAKE2B;
    p2sh[1] = OP_DATA_32;
    p2sh[34] = OP_EQUAL;
    assert_eq!(detect_script_type(&p2sh, p2sh.len()), ScriptType::P2SH);

    let mut multisig = [0u8; 69];
    multisig[0] = OP_1;
    multisig[1] = OP_DATA_32;
    multisig[34] = OP_DATA_32;
    multisig[67] = OP_2;
    multisig[68] = OP_CHECKMULTISIG;
    assert_eq!(
        detect_script_type(&multisig, multisig.len()),
        ScriptType::Multisig
    );
    let parsed = parse_multisig_script(&multisig, multisig.len()).expect("multisig");
    assert_eq!((parsed.m, parsed.n), (1, 2));
    multisig[34] = 0;
    assert_eq!(
        detect_script_type(&multisig, multisig.len()),
        ScriptType::Unknown
    );
    assert!(parse_multisig_script(&multisig, multisig.len()).is_none());

    let mut buffer = [0u8; 32];
    let length = Transaction::format_kas(123_456_789, &mut buffer);
    assert_eq!(&buffer[..length], b"1.23456789");
    let length = Transaction::format_kas(100_000_000, &mut buffer);
    assert_eq!(&buffer[..length], b"1.00");
    let length = Transaction::format_kas(1, &mut buffer);
    assert_eq!(&buffer[..length], b"0.00000001");
    let mut tiny = [0u8; 2];
    assert_eq!(Transaction::format_kas(12_300_000_000, &mut tiny), 2);
    assert_eq!(&tiny, b"12");
}

#[test]
fn script_detection_rejects_each_structural_short_circuit() {
    let mut p2pk_wrong_prefix = [0u8; 34];
    p2pk_wrong_prefix[33] = OP_CHECKSIG;
    assert_eq!(
        detect_script_type(&p2pk_wrong_prefix, p2pk_wrong_prefix.len()),
        ScriptType::Unknown
    );

    let mut p2pk_wrong_suffix = [0u8; 34];
    p2pk_wrong_suffix[0] = OP_DATA_32;
    assert_eq!(
        detect_script_type(&p2pk_wrong_suffix, p2pk_wrong_suffix.len()),
        ScriptType::Unknown
    );

    let mut p2sh_wrong_push = [0u8; 35];
    p2sh_wrong_push[0] = OP_BLAKE2B;
    p2sh_wrong_push[34] = OP_EQUAL;
    assert_eq!(
        detect_script_type(&p2sh_wrong_push, p2sh_wrong_push.len()),
        ScriptType::Unknown
    );

    let mut p2sh_wrong_equal = [0u8; 35];
    p2sh_wrong_equal[0] = OP_BLAKE2B;
    p2sh_wrong_equal[1] = OP_DATA_32;
    assert_eq!(
        detect_script_type(&p2sh_wrong_equal, p2sh_wrong_equal.len()),
        ScriptType::Unknown
    );

    let mut multisig_bad_m = [0u8; 69];
    multisig_bad_m[0] = 0;
    multisig_bad_m[67] = OP_2;
    multisig_bad_m[68] = OP_CHECKMULTISIG;
    assert_eq!(
        detect_script_type(&multisig_bad_m, multisig_bad_m.len()),
        ScriptType::Unknown
    );

    let mut multisig_bad_n = multisig_bad_m;
    multisig_bad_n[0] = OP_1;
    multisig_bad_n[67] = 0;
    assert_eq!(
        detect_script_type(&multisig_bad_n, multisig_bad_n.len()),
        ScriptType::Unknown
    );

    let mut multisig_m_gt_n = multisig_bad_m;
    multisig_m_gt_n[0] = OP_3;
    multisig_m_gt_n[67] = OP_2;
    assert_eq!(
        detect_script_type(&multisig_m_gt_n, multisig_m_gt_n.len()),
        ScriptType::Unknown
    );

    let mut multisig_wrong_len = [0u8; 70];
    multisig_wrong_len[0] = OP_1;
    multisig_wrong_len[68] = OP_2;
    multisig_wrong_len[69] = OP_CHECKMULTISIG;
    assert_eq!(
        detect_script_type(&multisig_wrong_len, multisig_wrong_len.len()),
        ScriptType::Unknown
    );
}

#[test]
fn multisig_builder_rejects_each_invalid_threshold_shape_before_derivation() {
    for (m, n) in [
        (0u8, 1u8),
        (1, 0),
        (2, 1),
        (1, (MAX_MULTISIG_KEYS + 1) as u8),
    ] {
        let mut config = MultisigConfig::new();
        config.m = m;
        config.n = n;
        assert_eq!(
            config.build_script(),
            0,
            "unexpected valid shape {m}-of-{n}"
        );
    }
}

#[test]
fn v106_hd45_script_hash_vector_is_exact() {
    const KPUBS: [&[u8]; 5] = [
        b"kpub2J937qL9n85s7HrhYyYYdMkzq1kaMiAf9PAcJzRW3jV7NgntNfGGrNgut7ZxcVrJqH42BCT2WyjfnxJh3SBDjLhXHe3UC2RJUu5tcjsViuK",
        b"kpub2Jtuqt6WJWZv3fQUnKhuEaCxbAyzLsFn3UEEaM4g7CXa2LZjQZH4o6tpj83tFaewMEyX56qrAF4Q64uqunVyBayuuRNwjru5DWchDEcq5vz",
        b"kpub2JZg9pofE54nqvkhFRRx18pAMhYDPL2CpYqBx2AkzvsEknCh8V4rtez9ZYeab3HCW1Xsm9f4d6J5dfJVg9NADWN7rtqNft21batcii1SjXy",
        b"kpub2HuRXjAmhs3KwQ9WpHVaiHRjBP37TQUiUGFQBTwp7cdbArCo5s2MT6415nd3ZYaELvNbZ4qTJjCGTavExv514tWftaGQzCK8gQz6BQJNySp",
        b"kpub2KCvcuKVgfy1h7PvCw4xFcdLAPoerVZBG4qTo8vRGH2Qe6p5AgLyRek5CEnuCDkduXHqgwtvaVfYYBS7gQBR1J4XowdvqvPXsHZGA5WyRJF",
    ];
    const EXPECTED_HASH: [u8; 32] = [
        0x18, 0x8b, 0x12, 0x59, 0xe1, 0xb6, 0xd3, 0xdb, 0xcf, 0xca, 0x06, 0x31, 0x05, 0xa2, 0xa0,
        0xc1, 0x27, 0xf7, 0x1b, 0x1e, 0x88, 0x5a, 0xed, 0xd0, 0xfa, 0xcc, 0x90, 0xea, 0x78, 0xa3,
        0xfd, 0x55,
    ];

    let mut ordered = KPUBS;
    ordered.sort_unstable();
    let mut config = MultisigConfig::new();
    config.v45 = true;
    config.m = 2;
    config.n = 5;
    config.cosigner_index = 1;
    config.chain = 0;
    config.addr_index = 0;
    for (slot, encoded) in ordered.iter().enumerate() {
        let parts = crate::derivation::xpub::parse_kpub_parts(encoded).expect("v1.0.6 kpub");
        assert!(config.set_cosigner(slot, &parts));
    }
    assert!(config.build_script() > 0);
    assert_eq!(
        crate::transaction::sighash::blake2b_hash(&config.script[..config.script_len]),
        EXPECTED_HASH,
    );
}

#[test]
fn descriptor_backed_hd45_change_verification_rejects_only_forged_claims() {
    const KPUBS: [&[u8]; 2] = [
        b"kpub2J937qL9n85s7HrhYyYYdMkzq1kaMiAf9PAcJzRW3jV7NgntNfGGrNgut7ZxcVrJqH42BCT2WyjfnxJh3SBDjLhXHe3UC2RJUu5tcjsViuK",
        b"kpub2Jtuqt6WJWZv3fQUnKhuEaCxbAyzLsFn3UEEaM4g7CXa2LZjQZH4o6tpj83tFaewMEyX56qrAF4Q64uqunVyBayuuRNwjru5DWchDEcq5vz",
    ];
    let mut trusted = MultisigConfig::new();
    trusted.v45 = true;
    trusted.active = true;
    trusted.m = 2;
    trusted.n = 2;
    for (slot, encoded) in KPUBS.iter().enumerate() {
        let parts = crate::derivation::xpub::parse_kpub_parts(encoded).expect("v1.0.6 kpub");
        assert!(trusted.set_cosigner(slot, &parts));
    }
    trusted.sort_cosigners();

    let script_public_key = |config: &MultisigConfig, cosigner: u32, chain: u32, index: u32| {
        let mut derived = config.clone();
        derived.cosigner_index = cosigner as u8;
        derived.chain = chain as u8;
        derived.addr_index = index;
        assert!(derived.build_script() > 0);
        let hash = crate::transaction::sighash::blake2b_hash(&derived.script[..derived.script_len]);
        let mut spk = ScriptPublicKey::new();
        spk.script_len = 35;
        spk.script[0] = OP_BLAKE2B;
        spk.script[1] = OP_DATA_32;
        spk.script[2..34].copy_from_slice(&hash);
        spk.script[34] = OP_EQUAL;
        spk
    };

    let mut tx = Transaction::try_new().expect("transaction test allocation");
    tx.num_inputs = 1;
    tx.inputs[0].ms45_hint = Ms45Hint {
        present: true,
        cosigner: 0,
        chain: 0,
        index: 7,
    };
    tx.inputs[0].utxo_entry.script_public_key = script_public_key(&trusted, 0, 0, 7);
    tx.num_outputs = 1;
    tx.outputs[0].ms45_hint = Ms45Hint {
        present: true,
        cosigner: 0,
        chain: 1,
        index: 3,
    };
    tx.outputs[0].script_public_key = script_public_key(&trusted, 0, 1, 3);
    assert_eq!(
        find_forged_change(&tx, core::slice::from_ref(&trusted)),
        None
    );
    assert_eq!(
        trusted_multisig_output_chain(&tx, core::slice::from_ref(&trusted), 0),
        Some(1)
    );

    tx.outputs[0].script_public_key.script[2] ^= 1;
    assert_eq!(
        find_forged_change(&tx, core::slice::from_ref(&trusted)),
        Some(0)
    );
    assert_eq!(
        trusted_multisig_output_chain(&tx, core::slice::from_ref(&trusted), 0),
        None
    );

    tx.outputs[0].ms45_hint = Ms45Hint::none();
    assert_eq!(
        find_forged_change(&tx, core::slice::from_ref(&trusted)),
        None
    );
    assert_eq!(
        trusted_multisig_output_chain(&tx, core::slice::from_ref(&trusted), 0),
        None
    );

    // No eligible descriptor means there is no trusted basis for calling a
    // change claim forged. Exercise inactive, legacy, malformed-input, and
    // descriptor-miss paths independently.
    assert_eq!(find_forged_change(&tx, &[]), None);
    let mut inactive = trusted.clone();
    inactive.active = false;
    assert_eq!(
        find_forged_change(&tx, core::slice::from_ref(&inactive)),
        None
    );
    let mut legacy = trusted.clone();
    legacy.v45 = false;
    assert_eq!(
        find_forged_change(&tx, core::slice::from_ref(&legacy)),
        None
    );

    tx.outputs[0].ms45_hint = Ms45Hint {
        present: true,
        cosigner: 0,
        chain: 1,
        index: 3,
    };
    let valid_input = tx.inputs[0].utxo_entry.script_public_key.clone();
    tx.inputs[0].utxo_entry.script_public_key = ScriptPublicKey::new();
    assert_eq!(
        find_forged_change(&tx, core::slice::from_ref(&trusted)),
        None
    );
    tx.inputs[0].utxo_entry.script_public_key = valid_input.clone();
    tx.inputs[0].utxo_entry.script_public_key.script[2] ^= 1;
    assert_eq!(
        find_forged_change(&tx, core::slice::from_ref(&trusted)),
        None
    );
    tx.inputs[0].utxo_entry.script_public_key = valid_input.clone();

    // Once the descriptor is trusted, malformed/non-P2SH output claims are
    // unverifiable (not forged), and an output identical to an input is not
    // treated as change. Cover each P2SH structural guard separately.
    let valid_output = script_public_key(&trusted, 0, 1, 3);
    tx.outputs[0].ms45_hint = Ms45Hint {
        present: true,
        cosigner: 0,
        chain: 0,
        index: 4,
    };
    tx.outputs[0].script_public_key = script_public_key(&trusted, 0, 0, 4);
    assert_eq!(
        trusted_multisig_output_chain(&tx, core::slice::from_ref(&trusted), 0),
        Some(0)
    );
    tx.outputs[0].ms45_hint = Ms45Hint {
        present: true,
        cosigner: 0,
        chain: 1,
        index: 3,
    };
    tx.outputs[0].script_public_key = ScriptPublicKey::new();
    assert_eq!(
        find_forged_change(&tx, core::slice::from_ref(&trusted)),
        None
    );
    for slot in [0usize, 1, 34] {
        let mut malformed = valid_output.clone();
        malformed.script[slot] ^= 1;
        tx.outputs[0].script_public_key = malformed;
        assert_eq!(
            find_forged_change(&tx, core::slice::from_ref(&trusted)),
            None
        );
    }
    tx.outputs[0].script_public_key = valid_input;
    tx.outputs[0].ms45_hint = tx.inputs[0].ms45_hint;
    assert_eq!(
        find_forged_change(&tx, core::slice::from_ref(&trusted)),
        None
    );

    // Exercise empty traversal boundaries independently: without a trusted
    // input there can be no forged-change claim, and with a trusted input but
    // zero outputs there is nothing to inspect.
    tx.num_inputs = 0;
    assert_eq!(
        find_forged_change(&tx, core::slice::from_ref(&trusted)),
        None
    );
    tx.num_inputs = 1;
    tx.inputs[0].utxo_entry.script_public_key = script_public_key(&trusted, 0, 0, 7);
    tx.inputs[0].ms45_hint = Ms45Hint {
        present: true,
        cosigner: 0,
        chain: 0,
        index: 7,
    };
    tx.num_outputs = 0;
    assert_eq!(
        find_forged_change(&tx, core::slice::from_ref(&trusted)),
        None
    );
}

#[test]
fn hd45_wallet_identity_and_cosigner_resolution_cover_match_miss_and_legacy() {
    const FIRST: &[u8] = b"kpub2J937qL9n85s7HrhYyYYdMkzq1kaMiAf9PAcJzRW3jV7NgntNfGGrNgut7ZxcVrJqH42BCT2WyjfnxJh3SBDjLhXHe3UC2RJUu5tcjsViuK";
    const SECOND: &[u8] = b"kpub2Jtuqt6WJWZv3fQUnKhuEaCxbAyzLsFn3UEEaM4g7CXa2LZjQZH4o6tpj83tFaewMEyX56qrAF4Q64uqunVyBayuuRNwjru5DWchDEcq5vz";
    let first = crate::derivation::xpub::parse_kpub_parts(FIRST).expect("first kpub");
    let second = crate::derivation::xpub::parse_kpub_parts(SECOND).expect("second kpub");

    let mut config = MultisigConfig::new();
    config.v45 = true;
    config.m = 1;
    config.n = 2;
    assert!(config.set_cosigner(0, &first));
    assert!(config.set_cosigner(1, &second));
    let identical = config.clone();
    assert!(config.same_wallet_as(&identical));

    let mut different = identical.clone();
    different.cosigner_chain_codes[1][0] ^= 1;
    assert!(!config.same_wallet_as(&different));

    assert!(config.resolve_cosigner_index(&second));
    assert_eq!(config.cosigner_index, 1);
    let mut missing = second;
    missing.parent_fp[0] ^= 1;
    assert!(!config.resolve_cosigner_index(&missing));

    let mut legacy = MultisigConfig::new();
    legacy.n = 1;
    legacy.cosigner_index = 7;
    assert!(legacy.resolve_cosigner_index(&missing));
    assert_eq!(legacy.cosigner_index, 0);
}

#[test]
fn transaction_resource_cap_and_root_size_are_bounded() {
    let mut tx = Transaction::try_new().expect("bounded transaction allocation");
    assert!(tx.ensure_input_slots(MAX_INPUTS).is_ok());
    assert_eq!(
        tx.ensure_input_slots(MAX_INPUTS + 1),
        Err(TransactionStorageError::TooManyInputs)
    );
    assert!(core::mem::size_of::<Transaction>() <= 512);
}
