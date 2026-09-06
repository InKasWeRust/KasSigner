use super::*;

#[test]
fn private_swap_claim_builder_returns_real_pskb_wire() {
    let source = crate::account::address::encode_p2pk_address(&[0x31; 32], "kaspa");
    let destination = crate::account::address::encode_p2pk_address(&[0x32; 32], "kaspa");
    let selected = serde_json::json!([{
        "tx_id": "11".repeat(32), "index": 0, "amount": "20000000"
    }])
    .to_string();
    let wire = build_claim(&source, &destination, "51", &selected, 1_000).expect("claim");
    let decoded = hex::decode(wire).expect("wire hex");
    assert_eq!(&decoded[..4], b"PSKB");
}
