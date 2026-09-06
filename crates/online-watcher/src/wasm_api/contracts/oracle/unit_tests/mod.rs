use serde_json::{json, Value};

use super::genesis::build_oracle_genesis_json;

fn request(hashfn: &str) -> String {
    json!({
        "genesis_price": "1000",
        "genesis_t": "2000",
        "image_id_hex": "11".repeat(32),
        "control_id_hex": "22".repeat(32),
        "set_root_hex": "33".repeat(32),
        "hashfn_hex": hashfn,
        "heartbeat_cov_id_hex": "44".repeat(32),
        "network": "testnet-12"
    })
    .to_string()
}

#[test]
fn oracle_genesis_builder_covers_valid_and_malformed_requests() {
    let document: Value =
        serde_json::from_str(&build_oracle_genesis_json(&request("01")).unwrap()).unwrap();
    assert_eq!(document["genesis_price"], 1000);
    assert_eq!(document["genesis_t"], 2000);
    assert!(document["address"]
        .as_str()
        .unwrap()
        .starts_with("kaspatest:"));

    assert!(build_oracle_genesis_json("{}").is_err());
    assert!(build_oracle_genesis_json(&request("")).is_err());
    assert!(build_oracle_genesis_json(&request("0102")).is_err());

    let mut bad: Value = serde_json::from_str(&request("01")).unwrap();
    bad["genesis_price"] = json!("not-a-number");
    assert!(build_oracle_genesis_json(&bad.to_string()).is_err());
    bad["genesis_price"] = json!("1");
    bad["image_id_hex"] = json!("00");
    assert!(build_oracle_genesis_json(&bad.to_string()).is_err());
}

#[test]
fn oracle_wasm_genesis_boundaries_are_directly_covered() {
    let genesis = super::covenant_oracle_mb(&request("01")).expect("oracle genesis boundary");
    let genesis: Value = serde_json::from_str(&genesis).unwrap();
    assert!(genesis["address"]
        .as_str()
        .unwrap()
        .starts_with("kaspatest:"));

    let heartbeat = super::covenant_oracle_mb_heartbeat("testnet-12").expect("heartbeat boundary");
    let heartbeat: Value = serde_json::from_str(&heartbeat).unwrap();
    assert!(heartbeat["address"]
        .as_str()
        .unwrap()
        .starts_with("kaspatest:"));
}
