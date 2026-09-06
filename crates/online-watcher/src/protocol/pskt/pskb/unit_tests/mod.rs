use sha2::{Digest, Sha256};

use crate::{
    account::utxo::UtxoEntry,
    transaction_builder::model::{PlannedOutput, UnsignedTransactionPlan},
};

#[test]
fn standard_pskb_exact_integer_wire_digest_is_stable() {
    let plan = UnsignedTransactionPlan::standard(
        vec![UtxoEntry {
            tx_id: "11".repeat(32),
            index: 2,
            amount: 50_000_000,
            script_public_key: vec![0x20; 34],
            block_daa_score: 1,
            covenant_id: None,
        }],
        vec![PlannedOutput::new(49_000_000, vec![0x21; 34])],
    );
    let wire_hex = super::encode_plan(&plan).expect("encode");
    let wire = hex::decode(wire_hex).expect("outer hex");
    assert_eq!(&wire[..4], b"PSKB");
    assert_eq!(
        hex::encode(Sha256::digest(&wire)),
        "efff1d67f8f15990d1b2730b86b9daf42225cfbad23c289427feacaa4cb79355"
    );

    let body = hex::decode(std::str::from_utf8(&wire[4..]).expect("body hex")).expect("body");
    let value: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(value[0]["global"]["subnetworkId"], "00".repeat(20));
    assert_eq!(value[0]["inputs"][0]["utxoEntry"]["amount"], "50000000");
    assert_eq!(value[0]["inputs"][0]["utxoEntry"]["blockDaaScore"], "1");
    assert_eq!(value[0]["inputs"][0]["sequence"], "0");
    assert_eq!(value[0]["outputs"][0]["amount"], "49000000");
}

#[test]
fn standard_pskb_relays_to_compact_kspt_with_explicit_native_subnetwork() {
    let plan = UnsignedTransactionPlan::standard(
        vec![UtxoEntry {
            tx_id: "44".repeat(32),
            index: 0,
            amount: 50_000_000,
            script_public_key: vec![0x20; 34],
            block_daa_score: 1,
            covenant_id: None,
        }],
        vec![PlannedOutput::new(49_000_000, vec![0x21; 34])],
    );
    let wire = super::encode_plan(&plan).expect("encode standard PSKB");
    let kspt = crate::protocol::pskt::relay_pskb_as_kspt_hex_for_network(&wire, "testnet-10")
        .expect("standard PSKB must relay to compact KSPT");
    assert!(kspt.starts_with("4b535054"));
}

#[test]
fn multisig_redeem_script_is_carried_in_the_pskb_input() {
    let plan = UnsignedTransactionPlan::multisig(
        vec![UtxoEntry {
            tx_id: "22".repeat(32),
            index: 0,
            amount: 50_000_000,
            script_public_key: vec![0xaa; 34],
            block_daa_score: 1,
            covenant_id: None,
        }],
        vec![PlannedOutput::new(49_000_000, vec![0xbb; 34])],
        &[0x51, 0xae],
        1,
    );
    let wire = hex::decode(super::encode_plan(&plan).expect("encode")).expect("outer hex");
    let body = hex::decode(std::str::from_utf8(&wire[4..]).expect("body hex")).expect("body");
    let value: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(value[0]["inputs"][0]["redeemScript"], "51ae");
}

#[test]
fn payload_encoder_preserves_an_explicit_empty_payload_field() {
    let inputs = vec![UtxoEntry {
        tx_id: "33".repeat(32),
        index: 0,
        amount: 50_000_000,
        script_public_key: vec![0x20; 34],
        block_daa_score: 1,
        covenant_id: None,
    }];
    let outputs = vec![super::PskbOutput::plain(49_000_000, vec![0x21; 34])];
    let wire =
        hex::decode(super::encode_covenant_with_payload(&inputs, &outputs, &[]).expect("encode"))
            .expect("outer hex");
    let body = hex::decode(std::str::from_utf8(&wire[4..]).expect("body hex")).expect("body");
    let value: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(value[0]["global"]["txPayload"], "");
}

#[test]
fn covenant_encoder_boundary_is_directly_covered() {
    use super::{encode_covenant, PskbOutput};

    let utxo = crate::account::utxo::UtxoEntry {
        tx_id: "11".repeat(32),
        index: 0,
        amount: 100,
        script_public_key: vec![0x51],
        block_daa_score: 0,
        covenant_id: None,
    };
    let output = PskbOutput::plain(90, vec![0x51]);
    let wire = encode_covenant(&[utxo], &[output]).expect("covenant PSKB");
    assert!(wire.starts_with("50534b42"));
}
