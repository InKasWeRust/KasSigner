use kassigner_protocol::wire::qr_payload::{
    unwrap_v1_raw, wrap_v1_raw, MAX_RAW_LEN, PAYLOAD_V1_RAW,
};

#[test]
fn raw_payload_round_trips_through_v1_framing() {
    let payload = include_bytes!("../fixtures/sample_payload.bin");
    let mut encoded = [0u8; 8];
    let written = wrap_v1_raw(payload, &mut encoded).expect("buffer is large enough");

    assert_eq!(written, payload.len() + 1);
    assert_eq!(encoded[0], PAYLOAD_V1_RAW);
    assert_eq!(unwrap_v1_raw(&encoded[..written]), Some(payload.as_slice()));
}

#[test]
fn raw_payload_rejects_unframed_empty_and_unknown_versions() {
    assert_eq!(unwrap_v1_raw(&[]), None);
    assert_eq!(unwrap_v1_raw(&[PAYLOAD_V1_RAW]), None);
    assert_eq!(unwrap_v1_raw(b"invalid-envelope"), None);
    assert_eq!(unwrap_v1_raw(&[0x02, 0xaa]), None);
}

#[test]
fn raw_payload_rejects_invalid_capacity() {
    let mut output = [0u8; 2];
    assert_eq!(wrap_v1_raw(&[], &mut output), None);

    let payload = [0u8; 100];
    let mut short = [0u8; 50];
    assert_eq!(wrap_v1_raw(&payload, &mut short), None);

    let oversized = vec![0u8; MAX_RAW_LEN + 1];
    let mut output = vec![0u8; oversized.len() + 1];
    assert_eq!(wrap_v1_raw(&oversized, &mut output), None);
}

fn sdk_vectors() -> serde_json::Value {
    serde_json::from_str(include_str!("../../../docs/integration/vectors/kassigner_sdk_v2.json"))
        .expect("KasSigner SDK conformance vector JSON")
}

#[test]
fn kassigner_privacy_pairing_vector_is_wire_exact() {
    use shared_signer::pairing::{
        account_fingerprint, encode_request, encode_response_header, AddressBatchRequest,
    };
    let vector = sdk_vectors();
    let pairing = &vector["privacyPairing"];
    let nonce: [u8; 16] = hex::decode(pairing["nonceHex"].as_str().unwrap())
        .unwrap().try_into().unwrap();
    let request = AddressBatchRequest::new(
        nonce,
        pairing["receiveStart"].as_u64().unwrap() as u32,
        pairing["receiveCount"].as_u64().unwrap() as u8,
        pairing["changeStart"].as_u64().unwrap() as u32,
        pairing["changeCount"].as_u64().unwrap() as u8,
    );
    let mut request_wire = vec![0u8; shared_signer::pairing::REQUEST_LEN];
    encode_request(request, &mut request_wire).expect("request encode");
    assert_eq!(hex::encode(&request_wire), pairing["requestHex"].as_str().unwrap());

    let pubkey: [u8; 33] = hex::decode(pairing["compressedAccountPubkeyHex"].as_str().unwrap())
        .unwrap().try_into().unwrap();
    let chain: [u8; 32] = hex::decode(pairing["chainCodeHex"].as_str().unwrap())
        .unwrap().try_into().unwrap();
    let fingerprint = account_fingerprint(&pubkey, &chain);
    assert_eq!(hex::encode(fingerprint), pairing["accountFingerprintHex"].as_str().unwrap());

    let mut response = vec![0u8; request.response_len()];
    let mut cursor = encode_response_header(request, fingerprint, &mut response).expect("response header");
    for key in pairing["receivePublicKeysHex"].as_array().unwrap()
        .iter().chain(pairing["changePublicKeysHex"].as_array().unwrap())
    {
        let bytes = hex::decode(key.as_str().unwrap()).unwrap();
        response[cursor..cursor + bytes.len()].copy_from_slice(&bytes);
        cursor += bytes.len();
    }
    assert_eq!(hex::encode(&response), pairing["responseHex"].as_str().unwrap());

    let protocol_request = kassigner_protocol::create_privacy_pairing_request(
        nonce, request.receive_start, request.receive_count, request.change_start, request.change_count,
    ).expect("protocol request");
    assert_eq!(protocol_request.payload, request_wire);
    let batch = kassigner_protocol::accept_privacy_pairing_response(
        &protocol_request, &response, kassigner_protocol::Network::Mainnet,
        Some(pairing["accountFingerprintHex"].as_str().unwrap()),
    ).expect("protocol response");
    assert_eq!(batch.receive_addresses[0].branch, kassigner_protocol::AddressBranch::Receive);
    assert_eq!(batch.receive_addresses[0].index, 500);
    assert_eq!(batch.receive_addresses[1].index, 501);
    assert_eq!(batch.change_addresses[0].branch, kassigner_protocol::AddressBranch::Change);
    assert_eq!(batch.change_addresses[0].index, 700);
    assert_eq!(batch.change_addresses[1].index, 701);
}

#[test]
fn kassigner_qr_session_vector_is_exact_and_instance_decodable() {
    let vector = sdk_vectors();
    let qr = &vector["qrSession"];
    let payload = hex::decode(qr["payloadHex"].as_str().unwrap()).unwrap();
    let frames = kassigner_protocol::encode_qr_frames(&payload).expect("QR frames");
    let expected = qr["framesHex"].as_array().unwrap();
    assert_eq!(frames.len(), expected.len());
    for (frame, expected) in frames.iter().zip(expected) {
        assert_eq!(hex::encode(&frame.payload), expected.as_str().unwrap());
    }
    let mut first = kassigner_protocol::QrDecoder::new();
    let second = kassigner_protocol::QrDecoder::new();
    let mut complete = None;
    for frame in &frames {
        complete = first.accept(&frame.payload).expect("QR decode");
    }
    assert_eq!(complete, Some(payload));
    assert_eq!(second.progress().received, 0);
}

#[test]
fn kassigner_kspt_v4_vector_locks_metadata_order() {
    let vector = sdk_vectors();
    let kspt = &vector["ksptV4"];
    let request = kassigner_protocol::SigningRequest::from_pskt(
        kspt["pskbHex"].as_str().unwrap(),
        kassigner_protocol::Network::Mainnet,
    ).expect("signing request");
    assert_eq!(request.kspt_hex, kspt["expectedKsptHex"].as_str().unwrap());
}

#[test]
fn kassigner_network_vector_is_strict() {
    let vector = sdk_vectors();
    for value in vector["networks"]["accepted"].as_array().unwrap() {
        assert!(kassigner_protocol::Network::parse(value.as_str().unwrap()).is_ok());
    }
    for value in vector["networks"]["rejected"].as_array().unwrap() {
        assert!(kassigner_protocol::Network::parse(value.as_str().unwrap()).is_err());
    }
}
