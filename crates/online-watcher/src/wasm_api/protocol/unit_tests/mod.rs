use serde_json::json;

use super::pskb_planning::{prepare_selected_sweep_string, prepare_sweep_from_utxos_string};

fn address(byte: u8) -> String {
    crate::account::address::encode_p2pk_address(&[byte; 32], "kaspa")
}

#[test]
fn selected_sweep_preparation_covers_valid_rows_and_all_validation_stages() {
    let source = address(1);
    let destination = address(2);
    let valid = json!([
        {"tx_id": "11".repeat(32), "index": 1, "amount": 40},
        {"tx_id": "22".repeat(32), "index": 2, "amount": 60}
    ])
    .to_string();
    let prepared =
        prepare_selected_sweep_string(&valid, &source, &destination, 10, "missing", "low").unwrap();
    assert_eq!(prepared.total, 100);
    assert_eq!(prepared.send_amount, 90);
    assert_eq!(prepared.utxos.len(), 2);

    for bad in ["not-json", "[]"] {
        assert!(
            prepare_selected_sweep_string(bad, &source, &destination, 0, "missing", "low",)
                .is_err()
        );
    }

    let missing = json!([{"index": 0, "amount": 1}]).to_string();
    assert!(
        prepare_selected_sweep_string(&missing, &source, &destination, 0, "missing", "low",)
            .is_err()
    );

    let bad_txid = json!([{"tx_id": "zz", "index": 0, "amount": 1}]).to_string();
    assert!(
        prepare_selected_sweep_string(&bad_txid, &source, &destination, 0, "missing", "low",)
            .is_err()
    );

    let large_index = json!([{
        "tx_id": "11".repeat(32),
        "index": u64::from(u32::MAX) + 1,
        "amount": 1
    }])
    .to_string();
    assert!(prepare_selected_sweep_string(
        &large_index,
        &source,
        &destination,
        0,
        "missing",
        "low",
    )
    .is_err());

    assert!(
        prepare_selected_sweep_string(&valid, &source, &destination, 100, "missing", "low",)
            .is_err()
    );

    let overflow = json!([
        {"tx_id": "11".repeat(32), "index": 0, "amount": u64::MAX},
        {"tx_id": "22".repeat(32), "index": 1, "amount": 1}
    ])
    .to_string();
    assert!(
        prepare_selected_sweep_string(&overflow, &source, &destination, 0, "missing", "low",)
            .is_err()
    );
}

fn utxo(byte: u8, amount: u64) -> crate::account::utxo::UtxoEntry {
    crate::account::utxo::UtxoEntry {
        tx_id: format!("{byte:02x}").repeat(32),
        index: u32::from(byte),
        amount,
        script_public_key: Vec::new(),
        block_daa_score: 0,
        covenant_id: None,
    }
}

#[test]
fn fetched_sweep_preparation_is_native_testable_without_jsvalue_errors() {
    let source = address(8);
    let destination = address(9);
    let prepared = prepare_sweep_from_utxos_string(
        vec![utxo(1, 40), utxo(2, 60)],
        &source,
        &destination,
        10,
        "missing",
        "low",
    )
    .unwrap();
    assert_eq!(prepared.total, 100);
    assert_eq!(prepared.send_amount, 90);
    assert_eq!(prepared.utxos.len(), 2);

    assert!(prepare_sweep_from_utxos_string(
        Vec::new(),
        &source,
        &destination,
        0,
        "missing",
        "low",
    )
    .err()
    .unwrap()
    .contains("missing"));
    assert!(prepare_sweep_from_utxos_string(
        vec![utxo(1, 10)],
        &source,
        &destination,
        10,
        "missing",
        "low",
    )
    .err()
    .unwrap()
    .contains("low"));
    assert!(prepare_sweep_from_utxos_string(
        vec![utxo(1, u64::MAX), utxo(2, 1)],
        &source,
        &destination,
        0,
        "missing",
        "low",
    )
    .is_err());
    assert!(prepare_sweep_from_utxos_string(
        vec![utxo(1, 100)],
        "bad-address",
        &destination,
        1,
        "missing",
        "low",
    )
    .is_err());
    assert!(prepare_sweep_from_utxos_string(
        vec![utxo(1, 100)],
        &source,
        "bad-address",
        1,
        "missing",
        "low",
    )
    .is_err());
}

#[test]
fn wasm_qr_boundaries_cover_generation_decoding_progress_and_version() {
    use super::qr::{
        decode_qr_frame, decoder_progress, generate_qr_frames, generate_qr_svg_text,
        reset_qr_decoder, version,
    };

    reset_qr_decoder();
    assert_eq!(decoder_progress(), "0/0");
    assert_eq!(version(), "KasSee Web");

    let frames = generate_qr_frames(&hex::encode([0x41; 32])).expect("QR frames");
    let frames: serde_json::Value = serde_json::from_str(&frames).unwrap();
    assert_eq!(frames.as_array().unwrap().len(), 1);
    assert!(generate_qr_svg_text("hello").unwrap().starts_with("<svg"));

    // KasSigner emits small payloads as raw single-frame QR binary rather than
    // wrapping them in KQ session framing. The watcher must accept that exact
    // path (anti-klepto v2 commitments are typically ~129 bytes for one input).
    let raw_single = b"KAKP\x02\x02single-frame-anti-klepto";
    assert_eq!(
        decode_qr_frame(&hex::encode(raw_single)).unwrap(),
        hex::encode(raw_single),
    );
    assert_eq!(decoder_progress(), "0/0");

    let payload = b"two-frame-boundary";
    let session = shared_signer::qr_frame::session_id(payload);
    let mut first = [0u8; 64];
    let mut second = [0u8; 64];
    let first_len =
        shared_signer::qr_frame::encode_frame(&session, 0, 2, &payload[..8], &mut first).unwrap();
    let second_len =
        shared_signer::qr_frame::encode_frame(&session, 1, 2, &payload[8..], &mut second).unwrap();
    assert_eq!(
        decode_qr_frame(&hex::encode(&first[..first_len])).unwrap(),
        ""
    );
    assert!(decoder_progress().contains("\"count\":1"));
    assert_eq!(
        decode_qr_frame(&hex::encode(&second[..second_len])).unwrap(),
        hex::encode(payload),
    );
    assert_eq!(decoder_progress(), "0/0");
}

#[test]
fn pskt_and_payload_wasm_boundaries_reject_malformed_inputs_natively() {
    use super::pskt::{
        pskt_detect, pskt_finalize_and_broadcast, pskt_merge_signed_kspt, pskt_relay_to_kspt,
        pskt_summary,
    };
    use crate::wasm_api::{
        contracts::{build_covenant_payload, parse_covenant_payload},
        test_support::ready,
    };

    assert_eq!(pskt_detect("00"), "unknown");
    assert!(pskt_summary("00", "mainnet").is_err());
    assert!(pskt_relay_to_kspt("00", "mainnet").is_err());
    assert!(pskt_merge_signed_kspt("00", "00").is_err());
    assert!(ready(pskt_finalize_and_broadcast("00", "ws://unused")).is_err());

    let payload = build_covenant_payload(7, "aabb").expect("payload");
    assert_eq!(payload, "0107aabb");
    let decoded = parse_covenant_payload(&payload).expect("decoded payload");
    assert!(decoded.contains("\"covenant_type\":7"));
    assert!(build_covenant_payload(1, "zz").is_err());
    assert!(parse_covenant_payload("00").is_err());
}

#[test]
fn pskb_planning_public_boundaries_are_directly_covered() {
    use super::pskb_planning::{
        encode_prepared_sweep, prepare_selected_sweep, prepare_sweep_from_utxos,
    };
    use crate::transaction_builder::pskb::{PskbGlobalPlan, SweepInputPolicy};

    let source = address(0x31);
    let destination = address(0x32);
    let prepared = prepare_sweep_from_utxos(
        vec![utxo(1, 100)],
        &source,
        &destination,
        10,
        "missing",
        "low",
    )
    .expect("fetched sweep boundary");
    let wire = encode_prepared_sweep(
        &prepared,
        PskbGlobalPlan::standard(),
        &SweepInputPolicy::p2pk(serde_json::json!([])),
    )
    .expect("encoded sweep");
    assert!(wire.starts_with("50534b42"));

    let selected = serde_json::json!([{
        "tx_id": "22".repeat(32),
        "index": 0,
        "amount": 100u64
    }])
    .to_string();
    let selected_prepared =
        prepare_selected_sweep(&selected, &source, &destination, 10, "missing", "low")
            .expect("selected sweep boundary");
    assert_eq!(selected_prepared.send_amount, 90);
}

mod anti_klepto_transcript;
