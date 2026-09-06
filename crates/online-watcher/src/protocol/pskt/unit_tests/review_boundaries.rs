use serde_json::{json, Value};

use super::super::{parse_summary, review::find_pubkey_position_in_redeem};

fn p2pk(key: u8) -> Vec<u8> {
    let mut script = vec![0x20];
    script.extend_from_slice(&[key; 32]);
    script.push(0xac);
    script
}

fn spk(script: &[u8]) -> String {
    format!("0000{}", hex::encode(script))
}

fn wire(body: Value) -> String {
    let mut encoded = b"PSKT".to_vec();
    encoded.extend_from_slice(hex::encode(serde_json::to_vec(&body).unwrap()).as_bytes());
    hex::encode(encoded)
}

#[test]
fn review_summary_preserves_exact_version_outpoint_and_display_amounts() {
    let transaction_id = "12".repeat(32);
    let body = json!({
        "global": {"txVersion": 0x1234_u64},
        "inputs": [{
            "previousOutpoint": {"transactionId": transaction_id, "index": 0x1020_3040_u64},
            "utxoEntry": {"amount": 123_456_789_u64, "scriptPublicKey": spk(&p2pk(0x31))},
            "partialSigs": {}
        }],
        "outputs": [{"amount": 23_456_789_u64, "scriptPublicKey": spk(&p2pk(0x32))}]
    });

    let summary = parse_summary(&wire(body), "kaspa").expect("review summary");
    assert_eq!(summary.tx_version, 0x1234);
    assert_eq!(summary.inputs[0].prev_tx_id, "12".repeat(32));
    assert_eq!(summary.inputs[0].prev_index, 0x1020_3040);
    assert_eq!(summary.inputs[0].amount_sompi, 123_456_789);
    assert_eq!(summary.inputs[0].amount_kas, 1.234_567_89);
    assert_eq!(summary.outputs[0].amount_sompi, 23_456_789);
    assert_eq!(summary.outputs[0].amount_kas, 0.234_567_89);
}

#[test]
fn pubkey_position_requires_room_for_multisig_tail() {
    let key = [0x41u8; 32];
    let mut tail_less = vec![0x51, 0x20];
    tail_less.extend_from_slice(&key);
    let key_text = format!("02{}", hex::encode(key));
    assert_eq!(find_pubkey_position_in_redeem(&tail_less, &key_text), None);
}
