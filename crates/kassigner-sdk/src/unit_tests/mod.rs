use super::*;

#[test]
fn public_limits_match_reference_signer_protocol_capabilities() {
    let limits = limits();
    assert_eq!(limits, kassigner_protocol::SIGNER_CAPABILITIES);
    assert_eq!(
        limits.kspt_generation,
        kassigner_protocol::wire::kspt::GENERATION_CURRENT
    );
    assert_eq!(limits.max_inputs, 32);
    assert_eq!(limits.max_outputs, 8);
    assert!(limits.qr_session_binding);
    assert_eq!(KasSigner::new().limits(), limits);
}

#[test]
fn friendly_api_exposes_protocol_workflow_not_transaction_policy() {
    let source = include_str!("../lib.rs");
    for required in [
        "pair_normal",
        "pair_privacy",
        "prepare",
        "complete",
        "finalize",
    ] {
        assert!(
            source.contains(&format!("fn {required}")),
            "missing friendly operation: {required}"
        );
    }
    for forbidden in [
        "pub fn create_transaction",
        "pub fn prepare_send",
        "pub fn broadcast",
        "pub fn send_tx",
        "available_utxos",
        "selected_utxos",
        "fee_policy",
        "pub change_address:",
        "change_address: &str",
    ] {
        assert!(
            !source.to_ascii_lowercase().contains(forbidden),
            "SDK owns host policy: {forbidden}"
        );
    }
}

#[test]
fn friendly_layer_reexports_protocol_request_instead_of_copying_it() {
    let source = include_str!("../lib.rs");
    assert!(source.contains("pub use kassigner_protocol"));
    assert!(!source.contains("pub struct SigningRequest"));
}

#[test]
fn kas_signer_decoders_are_instance_owned() {
    let payload = vec![0x66u8; 220];
    let frames = kassigner_protocol::encode_qr_frames(&payload).expect("frames");
    let mut first = KasSigner::new();
    let second = KasSigner::new();
    assert!(first
        .accept_qr_frame(&frames[0].payload)
        .expect("first")
        .is_none());
    assert_eq!(second.qr_decoder_progress().received, 0);
}

#[test]
fn privacy_response_requires_pending_request_and_is_one_shot() {
    let mut signer = KasSigner::new();
    assert_eq!(
        signer
            .pair_privacy("00", Network::Mainnet)
            .unwrap_err()
            .kind(),
        SdkErrorKind::PairingReplay,
    );
}

#[test]
fn privacy_pairing_replay_is_rejected_after_success() {
    let request =
        protocol::create_privacy_pairing_request([0x21; 16], 10, 1, 20, 1).expect("request");
    let response = pairing_response(&request, [0x31; 16]);
    let mut signer = KasSigner::new();
    signer.pending_pairing = Some(request);
    let first = signer
        .pair_privacy(&hex::encode(&response), Network::Mainnet)
        .expect("first response");
    assert_eq!(first.account_fingerprint, hex::encode([0x31; 16]));
    assert_eq!(
        signer
            .pair_privacy(&hex::encode(response), Network::Mainnet)
            .unwrap_err()
            .kind(),
        SdkErrorKind::PairingReplay,
    );
}

#[test]
fn privacy_pairing_rejects_a_different_account_on_later_batch() {
    let first_request =
        protocol::create_privacy_pairing_request([0x41; 16], 0, 1, 0, 1).expect("first request");
    let mut signer = KasSigner::new();
    signer.pending_pairing = Some(first_request.clone());
    signer
        .pair_privacy(
            &hex::encode(pairing_response(&first_request, [0x51; 16])),
            Network::Mainnet,
        )
        .expect("first account batch");

    let second_request =
        protocol::create_privacy_pairing_request([0x42; 16], 50, 1, 50, 1).expect("second request");
    signer.pending_pairing = Some(second_request.clone());
    let error = signer
        .pair_privacy(
            &hex::encode(pairing_response(&second_request, [0x52; 16])),
            Network::Mainnet,
        )
        .unwrap_err();
    assert_eq!(error.kind(), SdkErrorKind::PairingMismatch);
    let expected_fingerprint = hex::encode([0x51; 16]);
    assert_eq!(
        signer.account_fingerprint(),
        Some(expected_fingerprint.as_str())
    );
}

fn pairing_response(request: &PairingRequest, fingerprint: [u8; 16]) -> Vec<u8> {
    let wire_request = request.wire_request().expect("wire request");
    let mut response = vec![0u8; wire_request.response_len()];
    let mut cursor =
        shared_signer::pairing::encode_response_header(wire_request, fingerprint, &mut response)
            .expect("response header");
    for offset in 0..wire_request.key_count() {
        let byte = u8::try_from(offset + 1).expect("small batch");
        response[cursor..cursor + shared_signer::pairing::PUBLIC_KEY_LEN].fill(byte);
        cursor += shared_signer::pairing::PUBLIC_KEY_LEN;
    }
    response
}

#[test]
fn complete_rejects_non_kspt_response_with_typed_error() {
    let request: SigningRequest = serde_json::from_value(serde_json::json!({
        "network": "mainnet",
        "originalPsktHex": "00",
        "ksptHex": "00",
        "qrFrames": []
    }))
    .expect("test request");
    assert_eq!(
        complete(&request, "00").unwrap_err().kind(),
        SdkErrorKind::Decoding
    );
}

#[test]
fn public_error_categories_do_not_require_text_matching() {
    let network = Network::parse("testnet-99").unwrap_err();
    assert_eq!(network.kind(), ProtocolErrorKind::WrongNetwork);
    assert_eq!(network.kind().as_str(), "wrongNetwork");
    assert_eq!(
        SdkErrorKind::TransactionMismatch.as_str(),
        "transactionMismatch"
    );
}

#[test]
fn sdk_error_names_and_protocol_mapping_cover_every_stable_category() {
    let sdk_names = [
        (SdkErrorKind::MalformedRequest, "malformedRequest"),
        (SdkErrorKind::WrongNetwork, "wrongNetwork"),
        (SdkErrorKind::TransactionMismatch, "transactionMismatch"),
        (SdkErrorKind::PairingMismatch, "pairingMismatch"),
        (SdkErrorKind::PairingReplay, "pairingReplay"),
        (SdkErrorKind::Qr, "qr"),
        (SdkErrorKind::Finalization, "finalization"),
        (SdkErrorKind::Derivation, "derivation"),
        (SdkErrorKind::RandomnessUnavailable, "randomnessUnavailable"),
        (SdkErrorKind::Encoding, "encoding"),
        (SdkErrorKind::Decoding, "decoding"),
        (SdkErrorKind::Unsupported, "unsupported"),
        (SdkErrorKind::Internal, "internal"),
    ];
    for (kind, expected) in sdk_names {
        assert_eq!(kind.as_str(), expected);
    }

    let mappings = [
        (
            ProtocolErrorKind::MalformedRequest,
            SdkErrorKind::MalformedRequest,
        ),
        (ProtocolErrorKind::WrongNetwork, SdkErrorKind::WrongNetwork),
        (
            ProtocolErrorKind::TransactionMismatch,
            SdkErrorKind::TransactionMismatch,
        ),
        (
            ProtocolErrorKind::PairingMismatch,
            SdkErrorKind::PairingMismatch,
        ),
        (ProtocolErrorKind::Qr, SdkErrorKind::Qr),
        (ProtocolErrorKind::Finalization, SdkErrorKind::Finalization),
        (ProtocolErrorKind::Derivation, SdkErrorKind::Derivation),
        (ProtocolErrorKind::Encoding, SdkErrorKind::Encoding),
        (ProtocolErrorKind::Decoding, SdkErrorKind::Decoding),
        (ProtocolErrorKind::Unsupported, SdkErrorKind::Unsupported),
        (ProtocolErrorKind::Internal, SdkErrorKind::Internal),
    ];
    for (protocol_kind, sdk_kind) in mappings {
        let error = SdkError::from(ProtocolError::new(protocol_kind, "coverage"));
        assert_eq!(error.kind(), sdk_kind);
        assert_eq!(error.message(), "coverage");
    }
}

#[test]
fn sdk_privacy_pairing_request_uses_runtime_randomness_and_tracks_pending_session() {
    let mut signer = KasSigner::new();
    let request = signer
        .create_privacy_pairing_request(7, 2, 19, 3)
        .expect("runtime privacy pairing request");
    let wire = request.wire_request().expect("wire request");
    assert_eq!(wire.receive_start, 7);
    assert_eq!(wire.receive_count, 2);
    assert_eq!(wire.change_start, 19);
    assert_eq!(wire.change_count, 3);
    assert_eq!(signer.pending_pairing.as_ref(), Some(&request));
}
