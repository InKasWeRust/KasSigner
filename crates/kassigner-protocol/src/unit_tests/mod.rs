mod coverage_ratchet;
mod finalization;
mod kspt_wire;
mod multisig_descriptor;
mod qr_payload;

use serde_json::json;

use super::*;

#[test]
fn strict_networks_never_fall_back_to_mainnet() {
    assert_eq!(Network::parse("mainnet"), Ok(Network::Mainnet));
    assert_eq!(Network::parse("testnet-10"), Ok(Network::Testnet10));
    assert_eq!(Network::parse("testnet-11"), Ok(Network::Testnet11));
    assert_eq!(Network::parse("testnet-12"), Ok(Network::Testnet12));
    assert!(Network::parse("testnet-whatever").is_err());
    assert!(Network::parse("kaspa").is_err());
}

#[test]
fn qr_frames_are_raw_and_decoder_instances_are_isolated() {
    let payload = vec![0x5au8; 240];
    let frames = encode_qr_frames(&payload).expect("frame payload");
    assert!(frames.len() > 1);
    assert!(frames
        .iter()
        .all(|frame| !frame.payload.starts_with(b"<svg")));
    let mut first = QrDecoder::new();
    let second = QrDecoder::new();
    assert!(first
        .accept(&frames[0].payload)
        .expect("first frame")
        .is_none());
    assert_eq!(second.progress().received, 0);
    let mut complete = None;
    for frame in &frames[1..] {
        complete = first.accept(&frame.payload).expect("remaining frame");
    }
    assert_eq!(complete, Some(payload));
    assert_eq!(second.progress().received, 0);
}

#[test]
fn privacy_pairing_binds_nonce_account_and_typed_derivations() {
    use shared_signer::pairing::{
        account_fingerprint, encode_response_header, ACCOUNT_FINGERPRINT_LEN,
    };
    let nonce = [0x42; 16];
    let request = create_privacy_pairing_request(nonce, 100, 2, 900, 1).expect("request");
    let wire_request = request.wire_request().expect("wire request");
    let fingerprint = account_fingerprint(&[0x02; 33], &[0x33; 32]);
    let mut response = vec![0u8; wire_request.response_len()];
    let mut cursor =
        encode_response_header(wire_request, fingerprint, &mut response).expect("header");
    for key in [[0x11; 32], [0x22; 32], [0x33; 32]] {
        response[cursor..cursor + 32].copy_from_slice(&key);
        cursor += 32;
    }
    let batch = accept_privacy_pairing_response(
        &request,
        &response,
        Network::Mainnet,
        Some(&hex::encode(fingerprint)),
    )
    .expect("bound response");
    assert_eq!(batch.receive_addresses[0].branch, AddressBranch::Receive);
    assert_eq!(batch.receive_addresses[0].index, 100);
    assert_eq!(batch.receive_addresses[1].index, 101);
    assert_eq!(batch.change_addresses[0].branch, AddressBranch::Change);
    assert_eq!(batch.change_addresses[0].index, 900);

    let wrong_request =
        create_privacy_pairing_request([0x43; 16], 100, 2, 900, 1).expect("wrong request");
    assert!(
        accept_privacy_pairing_response(&wrong_request, &response, Network::Mainnet, None).is_err()
    );
    assert!(accept_privacy_pairing_response(
        &request,
        &response,
        Network::Mainnet,
        Some(&hex::encode([0u8; ACCOUNT_FINGERPRINT_LEN])),
    )
    .is_err());
}

#[test]
fn maximum_privacy_batch_is_supported() {
    let request =
        create_privacy_pairing_request([0x7c; 16], 1000, 50, 2000, 50).expect("50+50 request");
    assert_eq!(request.receive_count, 50);
    assert_eq!(request.change_count, 50);
    assert!(!request.qr_frames.is_empty());
}

#[test]
fn derivation_helpers_own_kassigner_proprietary_encoding() {
    let original = test_pskb([0x11; 32], 500);
    let attached =
        attach_input_derivation(&original, 0, AddressBranch::Receive, 500).expect("attach hint");
    let (format, root) = crate::pskt::test_support::decode(&attached).expect("decode");
    let doc = crate::pskt::test_support::document(&root, format).expect("document");
    assert_eq!(
        doc["inputs"][0]["proprietaries"]["kassignerDerivation"]["branch"],
        0
    );
    assert_eq!(
        doc["inputs"][0]["proprietaries"]["kassignerDerivation"]["index"],
        "500"
    );

    let attached_output = attach_output_derivation(&attached, 0, AddressBranch::Change, 700)
        .expect("attach output hint");
    let (format, root) =
        crate::pskt::test_support::decode(&attached_output).expect("decode output hint");
    let doc = crate::pskt::test_support::document(&root, format).expect("output document");
    assert_eq!(
        doc["outputs"][0]["proprietaries"]["kassignerDerivation"]["branch"],
        1
    );
    assert_eq!(
        doc["outputs"][0]["proprietaries"]["kassignerDerivation"]["index"],
        "700"
    );

    assert!(attach_input_derivation(&original, 0, AddressBranch::Receive, 0x8000_0000).is_err());
    assert!(attach_output_derivation(&original, 0, AddressBranch::Change, 0x8000_0000).is_err());
}

fn test_pskb(input_key: [u8; 32], _index: u32) -> String {
    let input_script = format!("000020{}ac", hex::encode(input_key));
    let output_script = input_script.clone();
    let document = json!({
        "global": {
            "txVersion": 0,
            "fallbackLockTime": "0",
            "subnetworkId": "0000000000000000000000000000000000000000",
            "gas": "0",
            "txPayload": ""
        },
        "inputs": [{
            "previousOutpoint": { "transactionId": hex::encode([0x77u8; 32]), "index": 0 },
            "utxoEntry": { "amount": "100000", "scriptPublicKey": input_script },
            "sequence": "0",
            "sigOpCount": 1,
            "partialSigs": {},
            "proprietaries": {}
        }],
        "outputs": [{ "amount": "90000", "scriptPublicKey": output_script, "proprietaries": {} }]
    });
    crate::pskt::test_support::encode(crate::pskt::test_support::Format::Pskb, &json!([document]))
        .expect("encode PSKB")
}
