use serde_json::{json, Value};

use super::super::parse_summary;
use super::super::review::{
    find_pubkey_position_in_redeem, parse_input_summary, parse_multisig_redeem,
    parse_output_summary, parse_spk_hex,
};

fn p2pk(key: u8) -> Vec<u8> {
    let mut script = vec![0x20];
    script.extend_from_slice(&[key; 32]);
    script.push(0xac);
    script
}

fn p2sh(hash: u8) -> Vec<u8> {
    let mut script = vec![0xaa, 0x20];
    script.extend_from_slice(&[hash; 32]);
    script.push(0x87);
    script
}

fn multisig(keys: &[u8], required: u8) -> Vec<u8> {
    let mut script = vec![0x50 + required];
    for key in keys {
        script.push(0x20);
        script.extend_from_slice(&[*key; 32]);
    }
    script.push(0x50 + keys.len() as u8);
    script.push(0xae);
    script
}

fn spk(script: &[u8]) -> String {
    format!("0000{}", hex::encode(script))
}

fn wire(magic: &[u8; 4], body: Value) -> String {
    let mut encoded = magic.to_vec();
    encoded.extend_from_slice(hex::encode(serde_json::to_vec(&body).unwrap()).as_bytes());
    hex::encode(encoded)
}

fn partial_sig_map(pubkey: &str, field: &str, signature: &str) -> Value {
    let mut signature_object = serde_json::Map::new();
    signature_object.insert(field.to_string(), Value::String(signature.to_string()));
    let mut signatures = serde_json::Map::new();
    signatures.insert(pubkey.to_string(), Value::Object(signature_object));
    Value::Object(signatures)
}

fn partial_sig_value(pubkey: &str, value: Value) -> Value {
    let mut signatures = serde_json::Map::new();
    signatures.insert(pubkey.to_string(), value);
    Value::Object(signatures)
}

fn input(script: &[u8], redeem: Option<&[u8]>, partial_sigs: Value, minimum: Option<u8>) -> Value {
    let mut object = serde_json::Map::new();
    object.insert(
        "previousOutpoint".into(),
        json!({"transactionId": "11".repeat(32), "index": 2}),
    );
    object.insert(
        "utxoEntry".into(),
        json!({"amount": 1_000_u64, "scriptPublicKey": spk(script)}),
    );
    object.insert(
        "redeemScript".into(),
        redeem.map_or(Value::Null, |value| Value::String(hex::encode(value))),
    );
    object.insert("partialSigs".into(), partial_sigs);
    if let Some(value) = minimum {
        object.insert("minimumSignatures".into(), Value::from(value));
    }
    Value::Object(object)
}

fn maximum_value_input() -> Value {
    let mut value = input(&p2pk(1), None, json!({}), None);
    value["utxoEntry"]["amount"] = Value::String(u64::MAX.to_string());
    value
}

#[test]
fn script_classification_parses_standard_multisig_and_covenant_shapes() {
    assert_eq!(
        parse_spk_hex("00").unwrap_err(),
        "scriptPublicKey too short: 2"
    );
    assert!(parse_spk_hex("zz00")
        .unwrap_err()
        .contains("bad version hi"));
    assert!(parse_spk_hex("00zz")
        .unwrap_err()
        .contains("bad version lo"));
    assert!(parse_spk_hex("0000zz")
        .unwrap_err()
        .contains("bad script hex"));
    assert_eq!(parse_spk_hex(&spk(&p2pk(1))).unwrap(), (0, p2pk(1)));

    let redeem = multisig(&[1, 2], 2);
    assert_eq!(parse_multisig_redeem(&redeem), Some((2, 2)));
    let maximum_keys: Vec<u8> = (1..=16).collect();
    assert_eq!(
        parse_multisig_redeem(&multisig(&maximum_keys, 16)),
        Some((16, 16))
    );
    assert_eq!(
        find_pubkey_position_in_redeem(&redeem, &format!("02{}", "02".repeat(32))),
        Some(1)
    );
    assert_eq!(find_pubkey_position_in_redeem(&redeem, "00"), None);

    for invalid in [
        vec![],
        vec![0x52, 0xae],
        vec![0x50, 0x51, 0xae],
        vec![0x61, 0x51, 0xae],
        vec![0x52, 0x21, 0xae],
        vec![0x52, 0x20, 1, 0x51, 0xae],
    ] {
        assert_eq!(parse_multisig_redeem(&invalid), None);
    }

    let p2pk_summary = parse_input_summary(&input(&p2pk(3), None, json!({}), None)).unwrap();
    assert_eq!(p2pk_summary.script_kind, "p2pk");

    let p2sh_summary = parse_input_summary(&input(&p2sh(4), None, json!({}), None)).unwrap();
    assert_eq!(p2sh_summary.script_kind, "p2sh");

    let multisig_summary =
        parse_input_summary(&input(&p2sh(5), Some(&redeem), json!({}), None)).unwrap();
    assert_eq!(multisig_summary.script_kind, "p2sh-multisig");
    assert_eq!(
        (multisig_summary.multisig_m, multisig_summary.multisig_n),
        (Some(2), Some(2))
    );

    let covenant_summary =
        parse_input_summary(&input(&p2sh(6), Some(&[0x63, 1]), json!({}), None)).unwrap();
    assert_eq!(covenant_summary.script_kind, "p2sh-covenant");
}

#[test]
fn input_and_output_review_validate_fields_and_partial_signatures() {
    let redeem = multisig(&[1, 2], 1);
    let pubkey = format!("02{}", "01".repeat(32));
    let summary = parse_input_summary(&input(
        &p2sh(7),
        Some(&redeem),
        partial_sig_map(&pubkey, "schnorr", &"aa".repeat(64)),
        None,
    ))
    .unwrap();
    assert_eq!(summary.sigs_present, 1);
    assert_eq!(summary.partial_sigs[0].position, Some(0));

    for invalid in [
        json!([]),
        partial_sig_map("00", "schnorr", &"aa".repeat(64)),
        partial_sig_value(&pubkey, Value::Null),
        partial_sig_map(&pubkey, "ecdsa", &"aa".repeat(64)),
        partial_sig_map(&pubkey, "schnorr", "aa"),
    ] {
        assert!(parse_input_summary(&input(&p2pk(1), None, invalid, None)).is_err());
    }

    assert!(parse_input_summary(&json!(null)).is_err());
    assert!(parse_input_summary(&json!({})).is_err());
    assert!(parse_input_summary(&json!({"utxoEntry": {}})).is_err());

    let output = parse_output_summary(
        &json!({
            "amount": 500_u64,
            "scriptPublicKey": spk(&p2pk(9)),
            "proprietaries": {"kassignerDerivation": {"branch": 1, "index": "7"}},
        }),
        "kaspa",
    )
    .unwrap();
    assert_eq!(output.script_kind, "p2pk");
    assert!(output.address.unwrap().starts_with("kaspa:"));
    assert_eq!(output.derivation_branch, Some(1));
    assert_eq!(output.derivation_index, Some(7));

    let unknown = parse_output_summary(
        &json!({"amount": 1_u64, "scriptPublicKey": spk(&[1, 2, 3])}),
        "kaspa",
    )
    .unwrap();
    assert_eq!(unknown.script_kind, "unknown");
    assert!(unknown.address.is_none());
    assert!(parse_output_summary(&json!(null), "kaspa").is_err());
    assert!(parse_output_summary(&json!({}), "kaspa").is_err());
}

#[test]
fn multisig_readiness_accepts_exact_threshold_and_rejects_one_below() {
    let redeem = multisig(&[1, 2], 2);
    let first_key = format!("02{}", "01".repeat(32));
    let second_key = format!("02{}", "02".repeat(32));
    let mut signatures = serde_json::Map::new();
    signatures.insert(first_key.clone(), json!({"schnorr": "aa".repeat(64)}));
    signatures.insert(second_key.clone(), json!({"schnorr": "bb".repeat(64)}));
    let signatures = Value::Object(signatures);
    let exact = json!({
        "global": {"txVersion": 1},
        "inputs": [input(&p2sh(7), Some(&redeem), signatures, None)],
        "outputs": [{"amount": 500_u64, "scriptPublicKey": spk(&p2pk(3))}]
    });
    assert!(
        parse_summary(&wire(b"PSKT", exact), "kaspa")
            .unwrap()
            .finalize_ready
    );

    let one_short = json!({
        "global": {"txVersion": 1},
        "inputs": [input(
            &p2sh(7),
            Some(&redeem),
            partial_sig_map(&first_key, "schnorr", &"aa".repeat(64)),
            None,
        )],
        "outputs": [{"amount": 500_u64, "scriptPublicKey": spk(&p2pk(3))}]
    });
    assert!(
        !parse_summary(&wire(b"PSKT", one_short), "kaspa")
            .unwrap()
            .finalize_ready
    );
}

#[test]
fn summary_review_handles_pskb_pskt_readiness_and_checked_fee() {
    let sig_key = format!("02{}", "01".repeat(32));
    let signed = input(
        &p2pk(1),
        None,
        partial_sig_map(&sig_key, "schnorr", &"aa".repeat(64)),
        None,
    );
    let covenant = input(&p2sh(2), Some(&[0x63, 1]), json!({}), Some(0));
    let document = json!({
        "global": {"txVersion": 2},
        "inputs": [signed, covenant],
        "outputs": [{"amount": 1_500_u64, "scriptPublicKey": spk(&p2pk(3))}]
    });

    let single = parse_summary(&wire(b"PSKT", document.clone()), "kaspa").unwrap();
    assert_eq!(single.format, "pskt");
    assert_eq!((single.input_count, single.output_count), (2, 1));
    assert_eq!(single.total_in_sompi, 2_000);
    assert_eq!(single.total_out_sompi, 1_500);
    assert_eq!(single.fee_sompi, 500);
    assert!(single.finalize_ready);

    let bundle = parse_summary(&wire(b"PSKB", json!([document])), "kaspa").unwrap();
    assert_eq!(bundle.format, "pskb");

    let not_ready = json!({
        "global": {"txVersion": 1},
        "inputs": [input(&p2pk(1), None, json!({}), None)],
        "outputs": [{"amount": 500_u64, "scriptPublicKey": spk(&p2pk(2))}]
    });
    let summary = parse_summary(&wire(b"PSKT", not_ready), "kaspa").unwrap();
    assert!(!summary.finalize_ready);
    assert_eq!(summary.fee_sompi, 500);

    let outputs_exceed_inputs = json!({
        "global": {"txVersion": 1},
        "inputs": [input(&p2pk(1), None, json!({}), None)],
        "outputs": [{"amount": 2_000_u64, "scriptPublicKey": spk(&p2pk(2))}]
    });
    assert!(matches!(
        parse_summary(&wire(b"PSKT", outputs_exceed_inputs), "kaspa"),
        Err(error) if error.contains("outputs exceed inputs")
    ));

    let mut maximum_input = input(&p2pk(1), None, json!({}), None);
    maximum_input["utxoEntry"]["amount"] = Value::String(u64::MAX.to_string());
    let input_overflow = json!({
        "global": {"txVersion": 1},
        "inputs": [maximum_input, input(&p2pk(2), None, json!({}), None)],
        "outputs": [{"amount": 1_u64, "scriptPublicKey": spk(&p2pk(3))}]
    });
    assert!(matches!(
        parse_summary(&wire(b"PSKT", input_overflow), "kaspa"),
        Err(error) if error.contains("input total exceeds")
    ));

    let output_overflow = json!({
        "global": {"txVersion": 1},
        "inputs": [maximum_value_input()],
        "outputs": [
            {"amount": u64::MAX.to_string(), "scriptPublicKey": spk(&p2pk(3))},
            {"amount": 1_u64, "scriptPublicKey": spk(&p2pk(4))}
        ]
    });
    assert!(matches!(
        parse_summary(&wire(b"PSKT", output_overflow), "kaspa"),
        Err(error) if error.contains("output total exceeds")
    ));
}

#[test]
fn summary_review_rejects_invalid_envelopes_and_required_sections() {
    assert!(parse_summary("00", "kaspa").is_err());
    assert!(parse_summary(&wire(b"PSKB", json!([])), "kaspa").is_err());
    assert!(parse_summary(&wire(b"PSKB", json!([{}, {}])), "kaspa").is_err());

    for invalid in [
        json!(null),
        json!({}),
        json!({"global": {}}),
        json!({"global": {"txVersion": 1}}),
        json!({"global": {"txVersion": 1}, "inputs": []}),
    ] {
        assert!(parse_summary(&wire(b"PSKT", invalid), "kaspa").is_err());
    }
}

#[test]
fn classification_boundaries_are_byte_exact() {
    assert_eq!(parse_spk_hex("1234").unwrap(), (0x1234, Vec::new()));
    assert_eq!(parse_spk_hex("00ff51").unwrap(), (0x00ff, vec![0x51]));

    let valid_p2sh = p2sh(0x41);
    assert_eq!(
        parse_input_summary(&input(&valid_p2sh, None, json!({}), None))
            .unwrap()
            .script_kind,
        "p2sh"
    );
    assert_eq!(
        parse_output_summary(
            &json!({"amount": 1_u64, "scriptPublicKey": spk(&valid_p2sh)}),
            "kaspa",
        )
        .unwrap()
        .script_kind,
        "p2sh"
    );
    for index in [0usize, 1, 34] {
        let mut malformed = valid_p2sh.clone();
        malformed[index] ^= 1;
        assert_eq!(
            parse_input_summary(&input(&malformed, None, json!({}), None))
                .unwrap()
                .script_kind,
            "unknown",
            "p2sh input byte {index}"
        );
        assert_eq!(
            parse_output_summary(
                &json!({"amount": 1_u64, "scriptPublicKey": spk(&malformed)}),
                "kaspa",
            )
            .unwrap()
            .script_kind,
            "unknown",
            "p2sh output byte {index}"
        );
    }
    assert_eq!(
        parse_input_summary(&input(&valid_p2sh[..34], None, json!({}), None))
            .unwrap()
            .script_kind,
        "unknown"
    );
    assert_eq!(
        parse_output_summary(
            &json!({"amount": 1_u64, "scriptPublicKey": spk(&valid_p2sh[..34])}),
            "kaspa",
        )
        .unwrap()
        .script_kind,
        "unknown"
    );

    let valid_p2pk = p2pk(0x52);
    assert_eq!(
        parse_input_summary(&input(&valid_p2pk, None, json!({}), None))
            .unwrap()
            .script_kind,
        "p2pk"
    );
    assert_eq!(
        parse_output_summary(
            &json!({"amount": 1_u64, "scriptPublicKey": spk(&valid_p2pk)}),
            "kaspa",
        )
        .unwrap()
        .script_kind,
        "p2pk"
    );
    for index in [0usize, 33] {
        let mut malformed = valid_p2pk.clone();
        malformed[index] ^= 1;
        assert_eq!(
            parse_input_summary(&input(&malformed, None, json!({}), None))
                .unwrap()
                .script_kind,
            "unknown",
            "p2pk input byte {index}"
        );
        assert_eq!(
            parse_output_summary(
                &json!({"amount": 1_u64, "scriptPublicKey": spk(&malformed)}),
                "kaspa",
            )
            .unwrap()
            .script_kind,
            "unknown",
            "p2pk output byte {index}"
        );
    }
    assert_eq!(
        parse_input_summary(&input(&valid_p2pk[..33], None, json!({}), None))
            .unwrap()
            .script_kind,
        "unknown"
    );
    assert_eq!(
        parse_output_summary(
            &json!({"amount": 1_u64, "scriptPublicKey": spk(&valid_p2pk[..33])}),
            "kaspa",
        )
        .unwrap()
        .script_kind,
        "unknown"
    );

    let one_of_one = multisig(&[0x61], 1);
    assert_eq!(parse_multisig_redeem(&one_of_one), Some((1, 1)));
    let two_of_three = multisig(&[0x61, 0x62, 0x63], 2);
    assert_eq!(parse_multisig_redeem(&two_of_three), Some((2, 3)));

    let mut bad_m = one_of_one.clone();
    bad_m[0] = 0x50;
    assert_eq!(parse_multisig_redeem(&bad_m), None);
    let mut bad_n = one_of_one.clone();
    let n_index = bad_n.len() - 2;
    bad_n[n_index] = 0x52;
    assert_eq!(parse_multisig_redeem(&bad_n), None);
    let mut too_many_required = multisig(&[0x61], 1);
    too_many_required[0] = 0x52;
    assert_eq!(parse_multisig_redeem(&too_many_required), None);
    let mut bad_push = one_of_one.clone();
    bad_push[1] = 0x21;
    assert_eq!(parse_multisig_redeem(&bad_push), None);
    let mut bad_end = one_of_one.clone();
    *bad_end.last_mut().unwrap() = 0xad;
    assert_eq!(parse_multisig_redeem(&bad_end), None);

    let key = format!("02{}", "61".repeat(32));
    assert_eq!(find_pubkey_position_in_redeem(&two_of_three, &key), Some(0));
    let last = format!("03{}", "63".repeat(32));
    assert_eq!(
        find_pubkey_position_in_redeem(&two_of_three, &last),
        Some(2)
    );
    assert_eq!(
        find_pubkey_position_in_redeem(&two_of_three, &format!("02{}", "64".repeat(32))),
        None
    );
}
