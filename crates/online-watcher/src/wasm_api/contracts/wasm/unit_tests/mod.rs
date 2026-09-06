use super::*;
use crate::wasm_api::test_support::ready;

#[test]
fn covenant_pskb_api_boundaries_validate_numbers_and_json_before_network_io() {
    let request = CovenantPskbApiRequest {
        wallet_json: "{}".into(),
        covenant_address: "bad".into(),
        covenant_type: String::new(),
        send_amount: "100".into(),
        fee: "7".into(),
        change_address: "bad".into(),
        payload_hex: String::new(),
        utxo_indices_csv: String::new(),
        ws_url: "ws://unused".into(),
        tag_genesis: false,
    };
    assert_eq!(request.send_amount().unwrap(), 100);
    assert_eq!(request.fee().unwrap(), 7);

    assert!(ready(create_covenant_pskb("not-json")).is_err());
    assert!(ready(create_covenant_pskb_with_payload("not-json")).is_err());
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn covenant_pskb_valid_requests_reach_native_transport() {
    let wallet = crate::account::bip32::WalletData {
        kpub: "test".into(),
        receive_addresses: vec![crate::account::address::encode_p2pk_address(
            &[0x31; 32],
            "kaspa",
        )],
        change_addresses: vec![crate::account::address::encode_p2pk_address(
            &[0x32; 32],
            "kaspa",
        )],
        next_receive_index: 0,
        next_change_index: 0,
    };
    let covenant_address = crate::account::address::encode_p2pk_address(&[0x33; 32], "kaspa");
    let change_address = wallet.change_addresses[0].clone();
    let request = serde_json::json!({
        "wallet_json": serde_json::to_string(&wallet).unwrap(),
        "covenant_address": covenant_address,
        "send_amount": "10000000",
        "fee": "300000",
        "change_address": change_address,
        "utxo_indices_csv": "",
        "ws_url": "ws://unused"
    });
    assert!(ready(create_covenant_pskb(&request.to_string())).is_err());

    let mut payload_request = request;
    payload_request["payload_hex"] = serde_json::Value::String("aa".into());
    payload_request["tag_genesis"] = serde_json::Value::Bool(true);
    assert!(ready(create_covenant_pskb_with_payload(
        &payload_request.to_string()
    ))
    .is_err());
}
