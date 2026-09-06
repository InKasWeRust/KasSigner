use super::{parse_thread_utxo, parse_withdrawal_thread_utxos};

#[test]
fn private_thread_parsers_have_owner_local_native_coverage() {
    let one = serde_json::json!({
        "tx_id": "55".repeat(32),
        "index": 7,
        "amount": "123456",
        "block_daa_score": "99"
    })
    .to_string();
    let parsed_one = parse_thread_utxo(&one).expect("single thread UTXO");
    assert_eq!(parsed_one.index, 7);
    assert_eq!(parsed_one.amount, 123456);

    let many = format!("[{one}]");
    let parsed_many = parse_withdrawal_thread_utxos(&many).expect("withdrawal thread UTXOs");
    assert_eq!(parsed_many.len(), 1);
    assert_eq!(parsed_many[0].tx_id, "55".repeat(32));
}

#[test]
fn thread_utxo_validates_presence_amount_length_and_hex_independently() {
    let valid = |tx_id: String, amount: &str| {
        serde_json::json!({
            "tx_id": tx_id, "index": 0, "amount": amount, "block_daa_score": "0"
        })
        .to_string()
    };
    assert!(parse_thread_utxo(&valid("11".repeat(32), "1")).is_ok());
    assert!(parse_thread_utxo(&valid(String::new(), "1")).is_err());
    assert!(parse_thread_utxo(&valid("11".repeat(32), "0")).is_err());
    assert!(parse_thread_utxo(&valid("11".repeat(31), "1")).is_err());
    let mut bad_hex = "11".repeat(32);
    bad_hex.replace_range(62..64, "zz");
    assert!(parse_thread_utxo(&valid(bad_hex, "1")).is_err());
}
