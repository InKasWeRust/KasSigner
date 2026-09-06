use serde_json::json;

use super::super::consensus::{build_consensus_input, build_consensus_output};

fn signature_map() -> serde_json::Value {
    let mut signatures = serde_json::Map::new();
    signatures.insert(
        format!("02{}", "11".repeat(32)),
        json!({ "schnorr": "22".repeat(64) }),
    );
    serde_json::Value::Object(signatures)
}

fn p2pk_input() -> serde_json::Value {
    json!({
        "utxoEntry": {
            "scriptPublicKey": format!("000020{}ac", "33".repeat(32))
        },
        "previousOutpoint": {
            "transactionId": "44".repeat(32),
            "index": 7
        },
        "sequence": 9,
        "sigOpCount": 2,
        "redeemScript": null,
        "partialSigs": signature_map()
    })
}

#[test]
fn consensus_input_builds_p2pk_and_reports_required_fields() {
    let input =
        build_consensus_input(&p2pk_input(), false, false, &None, &None).expect("consensus input");
    assert_eq!(input.prev_tx_id, [0x44; 32]);
    assert_eq!(input.prev_index, 7);
    assert_eq!(input.sequence, 9);
    assert_eq!(input.sig_op_count, 2);
    assert_eq!(input.sig_script.len(), 66);
    assert_eq!(input.sig_script[0], 65);
    assert_eq!(input.sig_script[65], 1);

    for invalid in [
        json!(null),
        json!({}),
        json!({"utxoEntry": {}}),
        json!({"utxoEntry": {"scriptPublicKey": "000051"}}),
        json!({
            "utxoEntry": {"scriptPublicKey": "000051"},
            "previousOutpoint": {}
        }),
        json!({
            "utxoEntry": {"scriptPublicKey": "000051"},
            "previousOutpoint": {"transactionId": "00", "index": 0}
        }),
    ] {
        assert!(build_consensus_input(&invalid, false, false, &None, &None).is_err());
    }
}

#[test]
fn consensus_output_covers_plain_bound_and_malformed_outputs() {
    let plain = build_consensus_output(&json!({
        "amount": 42,
        "scriptPublicKey": "000051",
        "covenantBinding": null
    }))
    .expect("plain output");
    assert_eq!(plain.value, 42);
    assert_eq!(plain.spk_version, 0);
    assert_eq!(plain.spk_script, vec![0x51]);
    assert!(plain.covenant.is_none());

    let bound = build_consensus_output(&json!({
        "amount": 7,
        "scriptPublicKey": "000051",
        "covenantBinding": {
            "authorizingInput": 3,
            "covenantId": "aa".repeat(32)
        }
    }))
    .expect("bound output");
    assert_eq!(bound.covenant, Some((3, [0xaa; 32])));

    for invalid in [
        json!(null),
        json!({}),
        json!({"amount": 1}),
        json!({"amount": 1, "scriptPublicKey": "000051", "covenantBinding": []}),
        json!({"amount": 1, "scriptPublicKey": "000051", "covenantBinding": {}}),
        json!({"amount": 1, "scriptPublicKey": "000051", "covenantBinding": {"authorizingInput": 0}}),
        json!({"amount": 1, "scriptPublicKey": "000051", "covenantBinding": {"authorizingInput": 0, "covenantId": "00"}}),
    ] {
        assert!(build_consensus_output(&invalid).is_err());
    }
}
