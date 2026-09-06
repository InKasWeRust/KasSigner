use serde::Deserialize;

use super::common::{
    decode_named_32, decode_pubkey32, network_to_prefix, parse_request_string,
    parse_u64_field_string, serialize_json_string,
};

#[derive(Deserialize, serde::Serialize, PartialEq, Debug)]
struct Request {
    value: u64,
}

#[test]
fn pure_wasm_boundary_utilities_cover_networks_parsing_and_hex_validation() {
    assert_eq!(network_to_prefix("testnet-10"), "kaspatest");
    assert_eq!(network_to_prefix("testnet-11"), "kaspatest");
    assert_eq!(network_to_prefix("testnet-12"), "kaspatest");
    assert_eq!(network_to_prefix("simnet"), "kaspasim");
    assert_eq!(network_to_prefix("devnet"), "kaspadev");
    assert_eq!(network_to_prefix("mainnet"), "kaspa");

    assert_eq!(decode_pubkey32(&"11".repeat(32)).unwrap(), [0x11; 32]);
    assert!(decode_pubkey32("zz").is_err());
    assert!(decode_pubkey32("00").is_err());
    assert_eq!(
        decode_named_32(&"22".repeat(32), "field").unwrap(),
        [0x22; 32]
    );
    assert!(decode_named_32("00", "field").is_err());

    let request: Request = parse_request_string(r#"{"value":7}"#, "request").unwrap();
    assert_eq!(request, Request { value: 7 });
    assert!(parse_request_string::<Request>("{}", "request").is_err());
    assert_eq!(parse_u64_field_string("42", "value").unwrap(), 42);
    assert!(parse_u64_field_string("bad", "value").is_err());
    assert_eq!(serialize_json_string(&request).unwrap(), r#"{"value":7}"#);
}

#[test]
fn wasm_utility_boundaries_are_host_testable() {
    use super::common::{
        hex_to_pubkey32, parse_request, parse_u64_field, parse_utxo_indices, parse_wallet,
        serialize_json,
    };

    let wallet_json = serde_json::json!({
        "kpub": "test",
        "receive_addresses": [crate::account::address::encode_p2pk_address(&[0x31; 32], "kaspa")],
        "change_addresses": [crate::account::address::encode_p2pk_address(&[0x32; 32], "kaspa")],
        "next_receive_index": 0,
        "next_change_index": 0
    })
    .to_string();
    assert_eq!(parse_wallet(&wallet_json, "wallet").unwrap().kpub, "test");
    assert!(parse_wallet("not-json", "wallet").is_err());

    let request: Request = parse_request(r#"{"value":9}"#, "request").unwrap();
    assert_eq!(request.value, 9);
    assert!(parse_request::<Request>("{}", "request").is_err());

    assert_eq!(parse_u64_field("77", "value").unwrap(), 77);
    assert!(parse_u64_field("bad", "value").is_err());
    assert_eq!(parse_utxo_indices("0, 2,,4").unwrap(), vec![0, 2, 4]);
    assert!(parse_utxo_indices("0,bad").is_err());

    assert_eq!(serialize_json(&request).unwrap(), r#"{"value":9}"#);
    assert_eq!(hex_to_pubkey32(&"44".repeat(32)).unwrap(), [0x44; 32]);
}

#[test]
fn hash_boundaries_cover_blake2b_and_sha256() {
    assert_eq!(super::crypto::blake2b_hash("").unwrap().len(), 64);
    assert_eq!(
        super::crypto::sha256_hash("").unwrap(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
}
