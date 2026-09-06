use serde_json::{json, Value};

use crate::pskt::test_support::{encode, Format};
use crate::{finalize_json, ProtocolErrorKind};

#[test]
fn generic_finalizer_covers_p2pk_globals_defaults_and_explicit_covenants() {
    let mut document = signed_document(None, 0x11);
    document["global"] = json!({
        "txVersion": 2,
        "fallbackLockTime": "42",
        "subnetworkId": "ab".repeat(20),
        "gas": "7",
        "txPayload": "cafe"
    });
    document["inputs"][0]["sequence"] = json!("9");
    document["inputs"][0]["sigOpCount"] = json!(2);
    document["outputs"][0]["covenantBinding"] = json!({
        "authorizingInput": 0,
        "covenantId": "cd".repeat(32)
    });
    let finalized: Value =
        serde_json::from_str(&finalize_json(&pskb(document)).expect("finalize P2PK"))
            .expect("final JSON");
    assert_eq!(finalized["version"], 2);
    assert_eq!(finalized["lockTime"], "42");
    assert_eq!(finalized["gas"], "7");
    assert_eq!(finalized["payload"], "cafe");
    assert_eq!(finalized["inputs"][0]["sequence"], "9");
    assert_eq!(finalized["outputs"][0]["covenant"]["authorizingInput"], 0);

    let mut defaults = signed_document(None, 0x11);
    defaults["global"] = json!({"txVersion": 0});
    defaults["inputs"][0]
        .as_object_mut()
        .unwrap()
        .remove("sequence");
    defaults["inputs"][0]
        .as_object_mut()
        .unwrap()
        .remove("sigOpCount");
    let value: Value = serde_json::from_str(&finalize_json(&pskb(defaults)).expect("defaults"))
        .expect("default JSON");
    assert_eq!(value["lockTime"], "0");
    assert_eq!(value["gas"], "0");
    assert_eq!(value["inputs"][0]["sequence"], "0");
    assert_eq!(value["inputs"][0]["sigOpCount"], 1);
    assert!(value["outputs"][0]["covenant"].is_null());
}

#[test]
fn generic_finalizer_multisig_covers_all_reachable_push_encodings_and_thresholds() {
    for (keys, threshold, marker) in [
        (vec![0x11], 1, 36u16),
        (vec![0x11, 0x22, 0x33], 2, 0x4cu16),
        ((1u8..=8).collect::<Vec<_>>(), 2, 0x4du16),
    ] {
        let redeem = multisig(&keys, threshold);
        let mut document = signed_document(Some(&redeem), keys[0]);
        document["inputs"][0]["partialSigs"] = signatures(&keys[..usize::from(threshold)]);
        let finalized: Value =
            serde_json::from_str(&finalize_json(&pskb(document)).expect("multisig finalize"))
                .expect("multisig JSON");
        let script =
            hex::decode(finalized["inputs"][0]["signatureScript"].as_str().unwrap()).unwrap();
        if marker == 36 {
            assert!(script.ends_with(&redeem));
            assert_eq!(script[script.len() - redeem.len() - 1], redeem.len() as u8);
        } else {
            assert!(script.ends_with(&redeem));
            assert!(script[..script.len() - redeem.len()].contains(&(marker as u8)));
        }
    }

    let redeem = multisig(&[0x11, 0x22], 2);
    let mut insufficient = signed_document(Some(&redeem), 0x11);
    insufficient["inputs"][0]["partialSigs"] = signatures(&[0x11]);
    assert!(finalize_json(&pskb(insufficient))
        .unwrap_err()
        .message()
        .contains("only 1 sig(s), need 2"));

    let mut extra_unknown = signed_document(Some(&redeem), 0x11);
    extra_unknown["inputs"][0]["partialSigs"] = signatures(&[0x11, 0x22, 0x44]);
    assert!(finalize_json(&pskb(extra_unknown)).is_ok());
}

#[test]
fn generic_finalizer_reports_input_global_and_output_shape_errors_without_panics() {
    let cases = malformed_cases();
    for (document, expected) in cases {
        let error = finalize_json(&pskb(document)).unwrap_err();
        assert_eq!(error.kind(), ProtocolErrorKind::Finalization, "{expected}");
        assert!(
            error.message().contains(expected),
            "expected {expected:?}, got {:?}",
            error.message()
        );
    }
}

fn malformed_cases() -> Vec<(Value, &'static str)> {
    let mut cases = Vec::new();
    cases.push((json!(null), "PSKT not object"));
    cases.push((json!({"inputs": [], "outputs": []}), "missing global"));
    cases.push((json!({"global": {}, "outputs": []}), "missing inputs"));
    cases.push((json!({"global": {}, "inputs": []}), "missing outputs"));

    for (mutation, expected) in [
        (0u8, "missing txVersion"),
        (1, "txVersion exceeds u16"),
        (2, "fallbackLockTime"),
        (3, "subnetworkId must be 20 bytes"),
        (4, "subnetworkId hex"),
        (5, "subnetworkId must be a hex string"),
        (6, "gas must be a decimal string"),
        (7, "txPayload hex"),
        (8, "txPayload must be a hex string"),
    ] {
        let mut doc = signed_document(None, 0x11);
        match mutation {
            0 => {
                doc["global"].as_object_mut().unwrap().remove("txVersion");
            }
            1 => doc["global"]["txVersion"] = json!(65_536),
            2 => doc["global"]["fallbackLockTime"] = json!("01"),
            3 => doc["global"]["subnetworkId"] = json!("00"),
            4 => doc["global"]["subnetworkId"] = json!("zz"),
            5 => doc["global"]["subnetworkId"] = json!(true),
            6 => doc["global"]["gas"] = json!(true),
            7 => doc["global"]["txPayload"] = json!("z"),
            8 => doc["global"]["txPayload"] = json!(true),
            _ => unreachable!(),
        }
        cases.push((doc, expected));
    }

    for (mutation, expected) in [
        (0u8, "input[0]: not object"),
        (
            1,
            "generic KasSigner SDK finalization does not own covenant execution policy",
        ),
        (2, "missing previousOutpoint"),
        (3, "missing transactionId"),
        (4, "bad tx_id hex"),
        (5, "tx_id not 32 bytes"),
        (6, "missing index"),
        (7, "index exceeds u32"),
        (8, "sequence"),
        (9, "sigOpCount exceeds u8"),
        (10, "missing scriptPublicKey"),
        (11, "signed input has no partialSigs"),
        (12, "partial sig missing schnorr variant"),
        (13, "signature hex"),
        (14, "Schnorr signature must be 64 bytes"),
    ] {
        let mut doc = signed_document(None, 0x11);
        match mutation {
            0 => doc["inputs"][0] = Value::Null,
            1 => doc["inputs"][0]["proprietaries"] = json!({"persistentVault": true}),
            2 => {
                doc["inputs"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("previousOutpoint");
            }
            3 => {
                doc["inputs"][0]["previousOutpoint"]
                    .as_object_mut()
                    .unwrap()
                    .remove("transactionId");
            }
            4 => doc["inputs"][0]["previousOutpoint"]["transactionId"] = json!("zz"),
            5 => doc["inputs"][0]["previousOutpoint"]["transactionId"] = json!("00"),
            6 => {
                doc["inputs"][0]["previousOutpoint"]
                    .as_object_mut()
                    .unwrap()
                    .remove("index");
            }
            7 => doc["inputs"][0]["previousOutpoint"]["index"] = json!(u64::from(u32::MAX) + 1),
            8 => doc["inputs"][0]["sequence"] = json!("01"),
            9 => doc["inputs"][0]["sigOpCount"] = json!(256),
            10 => {
                doc["inputs"][0]["utxoEntry"]
                    .as_object_mut()
                    .unwrap()
                    .remove("scriptPublicKey");
            }
            11 => {
                doc["inputs"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("partialSigs");
            }
            12 => doc["inputs"][0]["partialSigs"] = json!({"02": {"ecdsa": "00"}}),
            13 => doc["inputs"][0]["partialSigs"] = json!({"02": {"schnorr": "zz"}}),
            14 => doc["inputs"][0]["partialSigs"] = json!({"02": {"schnorr": "00"}}),
            _ => unreachable!(),
        }
        cases.push((doc, expected));
    }

    let redeem = multisig(&[0x11], 1);
    for (mutation, expected) in [
        (0u8, "P2SH input without redeem script"),
        (1, "redeem hex"),
        (2, "host wallet must finalize specialized redeem scripts"),
        (3, "output[0]: not object"),
        (4, "missing amount"),
        (5, "amount must be a decimal string"),
        (6, "missing scriptPublicKey"),
        (7, "scriptPublicKey too short"),
        (8, "covenantBinding not object"),
        (9, "missing authorizingInput"),
        (10, "authorizingInput exceeds u16"),
        (11, "missing covenantId"),
        (12, "bad covenantId hex"),
        (13, "covenantId must be 32 bytes"),
    ] {
        let mut doc = signed_document(Some(&redeem), 0x11);
        match mutation {
            0 => {
                doc["inputs"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("redeemScript");
            }
            1 => doc["inputs"][0]["redeemScript"] = json!("zz"),
            2 => doc["inputs"][0]["redeemScript"] = json!("51ae"),
            3 => doc["outputs"][0] = Value::Null,
            4 => {
                doc["outputs"][0].as_object_mut().unwrap().remove("amount");
            }
            5 => doc["outputs"][0]["amount"] = json!(true),
            6 => {
                doc["outputs"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("scriptPublicKey");
            }
            7 => doc["outputs"][0]["scriptPublicKey"] = json!("00"),
            8 => doc["outputs"][0]["covenantBinding"] = json!([]),
            9 => doc["outputs"][0]["covenantBinding"] = json!({}),
            10 => {
                doc["outputs"][0]["covenantBinding"] =
                    json!({"authorizingInput": 65_536, "covenantId": "00".repeat(32)})
            }
            11 => doc["outputs"][0]["covenantBinding"] = json!({"authorizingInput": 0}),
            12 => {
                doc["outputs"][0]["covenantBinding"] =
                    json!({"authorizingInput": 0, "covenantId": "zz"})
            }
            13 => {
                doc["outputs"][0]["covenantBinding"] =
                    json!({"authorizingInput": 0, "covenantId": "00"})
            }
            _ => unreachable!(),
        }
        cases.push((doc, expected));
    }
    cases
}

fn signed_document(redeem: Option<&[u8]>, signer: u8) -> Value {
    let input_script = if redeem.is_some() {
        format!("0000aa20{}87", "44".repeat(32))
    } else {
        format!("000020{}ac", "11".repeat(32))
    };
    json!({
        "global": {
            "txVersion": 0,
            "fallbackLockTime": "0",
            "subnetworkId": "00".repeat(20),
            "gas": "0",
            "txPayload": ""
        },
        "inputs": [{
            "previousOutpoint": {"transactionId": "22".repeat(32), "index": 7},
            "utxoEntry": {"amount": "100000", "scriptPublicKey": input_script},
            "sequence": "0",
            "sigOpCount": 1,
            "redeemScript": redeem.map(hex::encode),
            "partialSigs": signatures(&[signer]),
            "proprietaries": {}
        }],
        "outputs": [{
            "amount": "90000",
            "scriptPublicKey": "000051",
            "covenantBinding": null
        }]
    })
}

fn signatures(keys: &[u8]) -> Value {
    let mut map = serde_json::Map::new();
    for key in keys {
        map.insert(
            format!("02{}", format!("{key:02x}").repeat(32)),
            json!({"schnorr": "77".repeat(64)}),
        );
    }
    Value::Object(map)
}

fn multisig(keys: &[u8], threshold: u8) -> Vec<u8> {
    let mut script = vec![0x50 + threshold];
    for key in keys {
        script.push(0x20);
        script.extend_from_slice(&[*key; 32]);
    }
    script.push(0x50 + u8::try_from(keys.len()).unwrap());
    script.push(0xae);
    script
}

fn pskb(document: Value) -> String {
    encode(Format::Pskb, &json!([document])).expect("encode finalizer PSKB")
}
