use serde_json::json;

use super::explicit_utxos::parse_explicit_utxos_string;

fn utxo(script: serde_json::Value) -> serde_json::Value {
    json!({
        "tx_id": "11".repeat(32),
        "index": 2,
        "amount": 3,
        "script_public_key": script,
        "block_daa_score": 4
    })
}

#[test]
fn explicit_utxo_parser_accepts_hex_and_bytes_and_rejects_invalid_shapes() {
    let script_hex = format!("20{}ac", "22".repeat(32));
    let parsed = parse_explicit_utxos_string(
        &json!([utxo(json!(script_hex)), utxo(json!([0, 1, 255]))]).to_string(),
    )
    .unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].index, 2);
    assert_eq!(parsed[1].script_public_key, vec![0, 1, 255]);

    assert!(parse_explicit_utxos_string("not-json").is_err());
    assert!(parse_explicit_utxos_string(&json!([utxo(json!([]))]).to_string()).is_err());
    assert!(parse_explicit_utxos_string(&json!([utxo(json!([256]))]).to_string()).is_err());
    assert!(parse_explicit_utxos_string(&json!([utxo(json!("zz"))]).to_string()).is_err());

    let mut short_id = utxo(json!([1]));
    short_id["tx_id"] = json!("00");
    assert!(parse_explicit_utxos_string(&json!([short_id]).to_string()).is_err());

    let mut bad_id = utxo(json!([1]));
    bad_id["tx_id"] = json!("zz");
    assert!(parse_explicit_utxos_string(&json!([bad_id]).to_string()).is_err());

    let mut large_index = utxo(json!([1]));
    large_index["index"] = json!(u64::from(u32::MAX) + 1);
    assert!(parse_explicit_utxos_string(&json!([large_index]).to_string()).is_err());
}
