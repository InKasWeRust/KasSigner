use super::*;
use crate::account::utxo::UtxoEntry;

const ADDR_A: &str = "kaspa:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e";
const ADDR_B: &str = "kaspa:qp0l70zd5x85ttwd6jv7g3s3a8llzj96d8dncn4zmhv4tlzx5k2jyqh70xmfj";

fn utxo(byte: u8, amount: u64) -> UtxoEntry {
    UtxoEntry {
        tx_id: hex::encode([byte; 32]),
        index: 0,
        amount,
        script_public_key: vec![0x51],
        block_daa_score: 1,
        covenant_id: None,
    }
}

#[test]
fn merkle_public_builders_cover_success_paths_without_js_errors() {
    let addresses = serde_json::to_string(&[ADDR_A, ADDR_B]).expect("addresses json");
    let root_json = merkle_root_from_addresses(&addresses).expect("root");
    let root: serde_json::Value = serde_json::from_str(&root_json).expect("root json");
    assert_eq!(root["leaf_count"], 2);
    assert_eq!(root["depth"], 1);

    let proof_json = merkle_proof_for_address(&addresses, ADDR_A).expect("proof");
    let proof: serde_json::Value = serde_json::from_str(&proof_json).expect("proof json");
    assert_eq!(proof["leaf_index"], 0);
    assert_eq!(proof["proof"].as_array().map(Vec::len), Some(1));

    let root_hex = root["root"].as_str().expect("root hex");
    let covenant_json =
        covenant_merkle_whitelist(&"11".repeat(32), root_hex, 1, 123, "mainnet").expect("covenant");
    let covenant: serde_json::Value = serde_json::from_str(&covenant_json).expect("covenant json");
    assert!(covenant["address"]
        .as_str()
        .expect("address")
        .starts_with("kaspa:"));
}

#[test]
fn merkle_spend_helpers_cover_limits_fees_amounts_and_encoding() {
    let mut many = vec![
        utxo(1, 1_000_000),
        utxo(2, 2_000_000),
        utxo(3, 3_000_000),
        utxo(4, 4_000_000),
        utxo(5, 5_000_000),
    ];
    limit_merkle_utxos(&mut many);
    assert_eq!(many.len(), 4);
    assert_eq!(merkle_total(&many), Ok(14_000_000));
    assert_eq!(
        require_merkle_utxos(&[]),
        Err("No UTXOs at covenant address".to_string())
    );
    assert!(require_merkle_utxos(&many).is_ok());
    assert!(parse_merkle_proof("[]").is_ok());
    assert!(parse_merkle_proof("{").is_err());
    assert_eq!(
        require_merkle_send(0),
        Err("Send amount must be > 0".to_string())
    );
    assert!(require_merkle_send(1).is_ok());
    assert!(merkle_required(u64::MAX, 1).is_err());
    assert_eq!(require_merkle_balance(2, 1, 3, 5), Ok(2));
    assert!(require_merkle_balance(4, 2, 6, 5).is_err());
    assert!(merkle_spend_fee(1, 1, 1).expect("fee") > 1);

    let script =
        crate::account::address::address_to_script_pubkey(ADDR_A).expect("covenant script");
    let scripts = decode_merkle_scripts(ADDR_A, ADDR_B, "51").expect("scripts");
    assert_eq!(scripts.covenant, script);
    assert_eq!(scripts.redeem, vec![0x51]);
    assert!(decode_merkle_scripts("bad", ADDR_B, "51").is_err());
    assert!(decode_merkle_scripts(ADDR_A, "bad", "51").is_err());
    assert!(decode_merkle_scripts(ADDR_A, ADDR_B, "zz").is_err());

    let request = MerkleSpendRequest {
        covenant_address: ADDR_A,
        destination_address: ADDR_B,
        redeem_script_hex: "51",
        proof_json: "[]",
        send_amount: 500_000,
        requested_fee: 1,
        utxos: vec![utxo(7, 2_000_000)],
    };
    let inputs = merkle_inputs(&request, &scripts);
    assert_eq!(inputs.len(), 1);
    let outputs_with_change = merkle_outputs(500_000, 100, &scripts.destination, &scripts.covenant);
    let outputs_without_change =
        merkle_outputs(500_000, 0, &scripts.destination, &scripts.covenant);
    assert_eq!(outputs_with_change.len(), 2);
    assert_eq!(outputs_without_change.len(), 1);

    let prepared = encode_merkle_spend(&request, scripts, 100).expect("encode spend");
    assert!(!prepared.wire.is_empty());
}

#[test]
fn merkle_prepare_fail_closed_amount_and_balance_paths_are_host_testable() {
    let empty = MerkleSpendRequest {
        covenant_address: ADDR_A,
        destination_address: ADDR_B,
        redeem_script_hex: "51",
        proof_json: "[]",
        send_amount: 1,
        requested_fee: 1,
        utxos: vec![],
    };
    assert!(prepare_merkle_whitelist_spend(empty).is_err());

    let zero_send = MerkleSpendRequest {
        covenant_address: ADDR_A,
        destination_address: ADDR_B,
        redeem_script_hex: "51",
        proof_json: "[]",
        send_amount: 0,
        requested_fee: 1,
        utxos: vec![utxo(8, 10_000_000)],
    };
    assert!(prepare_merkle_whitelist_spend(zero_send).is_err());

    let overspend = MerkleSpendRequest {
        covenant_address: ADDR_A,
        destination_address: ADDR_B,
        redeem_script_hex: "51",
        proof_json: "[]",
        send_amount: 10_000_000,
        requested_fee: 1,
        utxos: vec![utxo(9, 1)],
    };
    assert!(prepare_merkle_whitelist_spend(overspend).is_err());
}
