// KasSee Web — organized PSKT subsystem
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use serde_json::Value;

use super::wire::{decode_root, inject_tx_payload};
use super::*;

mod consensus;
mod consensus_finalizer;
mod exact_json;
mod kspt_bridge;
mod kspt_compact;
mod review;
mod review_boundaries;

#[test]
fn detects_supported_wire_magics() {
    assert_eq!(detect_format_hex("50534b42"), PsktFormat::Pskb);
    assert_eq!(detect_format_hex("50534b54"), PsktFormat::PsktSingle);
    assert_eq!(detect_format_hex("4b535054"), PsktFormat::Unknown);
}

#[test]
fn payload_mutation_preserves_pskb_envelope() {
    let wire = pskb_wire(serde_json::json!([{
        "global": {},
        "inputs": [],
        "outputs": []
    }]));

    let result = inject_tx_payload(&wire, &[1, 2, 3]).unwrap();
    assert_eq!(detect_format_hex(&result), PsktFormat::Pskb);

    let (_, root) = decode_root(&result).unwrap();
    assert_eq!(
        root[0]["global"]["txPayload"],
        Value::String("010203".into())
    );
}

#[test]
fn payload_mutation_changes_only_first_pskb_entry() {
    let wire = pskb_wire(serde_json::json!([
        {"global": {}, "inputs": [], "outputs": []},
        {"global": {"sentinel": true}, "inputs": [], "outputs": []}
    ]));

    let result = inject_tx_payload(&wire, &[0xaa]).unwrap();
    let (_, root) = decode_root(&result).unwrap();

    assert_eq!(root[0]["global"]["txPayload"], Value::String("aa".into()));
    assert_eq!(root[1]["global"]["sentinel"], Value::Bool(true));
    assert!(root[1]["global"].get("txPayload").is_none());
}

#[test]
fn transaction_lane_mutation_sets_all_lane_fields() {
    let wire = pskb_wire(serde_json::json!([{
        "global": {},
        "inputs": [],
        "outputs": []
    }]));
    let subnetwork_id = "11".repeat(20);

    let result = set_tx_lane(&wire, &subnetwork_id, 42, 7, &[0xde, 0xad]).unwrap();
    let (_, root) = decode_root(&result).unwrap();
    let global = &root[0]["global"];

    assert_eq!(global["subnetworkId"], Value::String(subnetwork_id));
    assert_eq!(global["gas"], Value::from(42));
    assert_eq!(global["txVersion"], Value::from(7));
    assert_eq!(global["txPayload"], Value::String("dead".into()));
}

#[test]
fn transaction_lane_and_payload_mutation_reject_invalid_envelopes_and_subnetworks() {
    assert!(inject_tx_payload("4b535054", &[1])
        .unwrap_err()
        .contains("not a PSKB"));
    assert!(set_tx_lane("4b535054", &"11".repeat(20), 0, 0, &[])
        .unwrap_err()
        .contains("not a PSKB"));

    let wire = pskb_wire(serde_json::json!([{
        "global": {},
        "inputs": [],
        "outputs": []
    }]));
    assert!(set_tx_lane(&wire, "zz", 0, 0, &[])
        .unwrap_err()
        .contains("subnetwork hex"));
    assert!(set_tx_lane(&wire, &"11".repeat(19), 0, 0, &[])
        .unwrap_err()
        .contains("must be 20 bytes"));

    let missing_global = pskb_wire(serde_json::json!([{
        "inputs": [],
        "outputs": []
    }]));
    assert!(inject_tx_payload(&missing_global, &[1])
        .unwrap_err()
        .contains("missing global"));
    assert!(set_tx_lane(&missing_global, &"11".repeat(20), 0, 0, &[])
        .unwrap_err()
        .contains("missing global"));
}

fn pskb_wire(document: Value) -> String {
    let json = serde_json::to_vec(&document).unwrap();
    let mut wire = b"PSKB".to_vec();
    wire.extend_from_slice(hex::encode(json).as_bytes());
    hex::encode(wire)
}

mod wire;
