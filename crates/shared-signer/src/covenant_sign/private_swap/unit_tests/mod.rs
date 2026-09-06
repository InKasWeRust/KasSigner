use super::session_id;
use super::*;

fn request(kind: RequestKind) -> PrivateSwapRequest<'static> {
    let payload = b"KSPT-v4-private-swap";
    match kind {
        RequestKind::KeyInfo => PrivateSwapRequest {
            kind,
            session_id: [0; 16],
            host_commitment: [0; 32],
            key_id: [0; 32],
            binding_token: [0; 32],
            adaptor_point: [0; 32],
            presignature: [0; 64],
            presignature_negated: false,
            payload: &[],
        },
        RequestKind::Bind => PrivateSwapRequest {
            kind,
            session_id: [0; 16],
            host_commitment: [0; 32],
            key_id: [2; 32],
            binding_token: [0; 32],
            adaptor_point: [3; 32],
            presignature: [0; 64],
            presignature_negated: false,
            payload,
        },
        RequestKind::PreSign => {
            let host = [4; 32];
            let key = [2; 32];
            let point = [3; 32];
            PrivateSwapRequest {
                kind,
                session_id: session_id(&host, payload, &key, &point),
                host_commitment: host,
                key_id: key,
                binding_token: [5; 32],
                adaptor_point: point,
                presignature: [0; 64],
                presignature_negated: false,
                payload,
            }
        }
        RequestKind::Complete => PrivateSwapRequest {
            kind,
            session_id: [0; 16],
            host_commitment: [0; 32],
            key_id: [2; 32],
            binding_token: [5; 32],
            adaptor_point: [3; 32],
            presignature: [6; 64],
            presignature_negated: true,
            payload,
        },
    }
}

fn response(kind: ResponseKind) -> PrivateSwapResponse {
    let mut value = PrivateSwapResponse {
        kind,
        session_id: [0; 16],
        key_id: [2; 32],
        claim_pubkey: [3; 32],
        binding_token: [0; 32],
        adaptor_point: [4; 32],
        commitment: [0; 32],
        nonce_point: [0; 33],
        signature: [0; 64],
        negated: false,
    };
    match kind {
        ResponseKind::KeyInfo => {}
        ResponseKind::Binding => {
            value.binding_token = [5; 32];
            value.commitment = [6; 32];
        }
        ResponseKind::Nonce => {
            value.session_id = [7; 16];
            value.binding_token = [5; 32];
            value.commitment = [6; 32];
            value.nonce_point = [8; 33];
        }
        ResponseKind::PreSignature => {
            value.session_id = [7; 16];
            value.binding_token = [5; 32];
            value.commitment = [6; 32];
            value.nonce_point = [8; 33];
            value.signature = [9; 64];
            value.negated = true;
        }
        ResponseKind::Completed => {
            value.binding_token = [5; 32];
            value.commitment = [6; 32];
            value.signature = [9; 64];
        }
    }
    value
}

#[test]
fn presign_session_is_bound_to_exact_transaction_key_and_adaptor_point() {
    let host = [1u8; 32];
    let key = [2u8; 32];
    let point = [3u8; 32];
    let tx = b"KSPT-v4";
    let original = session_id(&host, tx, &key, &point);
    assert_ne!(original, session_id(&host, b"KSPT-v4!", &key, &point));
    assert_ne!(original, session_id(&host, tx, &[4u8; 32], &point));
    assert_ne!(original, session_id(&host, tx, &key, &[5u8; 32]));
    assert_ne!(transaction_digest(tx), transaction_digest(b"KSPT-v4!"));
    assert!(is_message(&[b'P', b'S', b'W', b'G', VERSION]));
    assert!(is_message(&[b'P', b'S', b'W', b'R', VERSION]));
    assert!(!is_message(&[b'P', b'S', b'W', b'S', VERSION]));
}

#[test]
fn every_private_swap_request_kind_roundtrips_and_invalid_wire_fails_closed() {
    for kind in [
        RequestKind::KeyInfo,
        RequestKind::Bind,
        RequestKind::PreSign,
        RequestKind::Complete,
    ] {
        let source = request(kind);
        let mut wire = [0u8; REQUEST_HEADER_LEN + 64];
        let len = encode_request(&source, &mut wire).expect("request encode");
        let parsed = parse_request(&wire[..len]).expect("request parse");
        assert_eq!(parsed.kind, kind);
        assert_eq!(parsed.key_id, source.key_id);
        assert_eq!(parsed.binding_token, source.binding_token);
        assert_eq!(parsed.adaptor_point, source.adaptor_point);
        assert_eq!(parsed.payload, source.payload);
        assert_eq!(parsed.presignature_negated, source.presignature_negated);
    }

    let source = request(RequestKind::Bind);
    assert_eq!(
        encode_request(&source, &mut [0u8; 8]),
        Err(ProtocolError::OutputTooSmall)
    );
    let mut wire = [0u8; REQUEST_HEADER_LEN + 64];
    let len = encode_request(&source, &mut wire).expect("bind encode");

    let mut bad = wire[..len].to_vec();
    bad[0] ^= 1;
    assert!(matches!(
        parse_request(&bad),
        Err(ProtocolError::InvalidMagic)
    ));
    bad = wire[..len].to_vec();
    bad[4] ^= 1;
    assert!(matches!(
        parse_request(&bad),
        Err(ProtocolError::UnsupportedVersion)
    ));
    bad = wire[..len].to_vec();
    bad[5] = 0xff;
    assert!(matches!(
        parse_request(&bad),
        Err(ProtocolError::InvalidKind)
    ));
    bad = wire[..len].to_vec();
    bad[219] = 1;
    assert!(matches!(
        parse_request(&bad),
        Err(ProtocolError::InvalidFields)
    ));
    bad = wire[..len].to_vec();
    bad[214] = 2;
    assert!(matches!(
        parse_request(&bad),
        Err(ProtocolError::InvalidFields)
    ));
    bad = wire[..len].to_vec();
    bad.push(0);
    assert!(matches!(
        parse_request(&bad),
        Err(ProtocolError::InvalidLength)
    ));

    let mut invalid_presign = request(RequestKind::PreSign);
    invalid_presign.session_id[0] ^= 1;
    assert_eq!(
        encode_request(&invalid_presign, &mut wire),
        Err(ProtocolError::InvalidFields)
    );
    let mut invalid_complete = request(RequestKind::Complete);
    invalid_complete.presignature = [0; 64];
    assert_eq!(
        encode_request(&invalid_complete, &mut wire),
        Err(ProtocolError::InvalidFields)
    );
}

#[test]
fn reveal_roundtrip_covers_exact_shape_and_nonzero_fields() {
    let reveal = PrivateSwapReveal {
        session_id: [1; 16],
        key_id: [2; 32],
        sighash: [3; 32],
        host_secret: [4; 32],
    };
    let mut wire = [0u8; REVEAL_LEN];
    assert_eq!(encode_reveal(&reveal, &mut wire), Ok(REVEAL_LEN));
    assert_eq!(parse_reveal(&wire), Ok(reveal));
    assert_eq!(
        encode_reveal(&reveal, &mut [0u8; 8]),
        Err(ProtocolError::OutputTooSmall)
    );

    let mut bad = wire;
    bad[0] ^= 1;
    assert_eq!(parse_reveal(&bad), Err(ProtocolError::InvalidMagic));
    bad = wire;
    bad[4] ^= 1;
    assert_eq!(parse_reveal(&bad), Err(ProtocolError::UnsupportedVersion));
    bad = wire;
    bad[5..21].fill(0);
    assert_eq!(parse_reveal(&bad), Err(ProtocolError::InvalidFields));

    let mut zero = reveal;
    zero.host_secret = [0; 32];
    assert_eq!(
        encode_reveal(&zero, &mut wire),
        Err(ProtocolError::InvalidFields)
    );
}

#[test]
fn every_private_swap_response_kind_roundtrips_and_shape_validation_is_exercised() {
    for kind in [
        ResponseKind::KeyInfo,
        ResponseKind::Binding,
        ResponseKind::Nonce,
        ResponseKind::PreSignature,
        ResponseKind::Completed,
    ] {
        let source = response(kind);
        let mut wire = [0u8; RESPONSE_LEN];
        assert_eq!(encode_response(&source, &mut wire), Ok(RESPONSE_LEN));
        assert_eq!(parse_response(&wire), Ok(source));
    }

    let valid = response(ResponseKind::Binding);
    assert_eq!(
        encode_response(&valid, &mut [0u8; 8]),
        Err(ProtocolError::OutputTooSmall)
    );
    let mut wire = [0u8; RESPONSE_LEN];
    encode_response(&valid, &mut wire).expect("binding response");

    let mut bad = wire;
    bad[0] ^= 1;
    assert_eq!(parse_response(&bad), Err(ProtocolError::InvalidMagic));
    bad = wire;
    bad[4] ^= 1;
    assert_eq!(parse_response(&bad), Err(ProtocolError::UnsupportedVersion));
    bad = wire;
    bad[5] = 0xff;
    assert_eq!(parse_response(&bad), Err(ProtocolError::InvalidKind));
    bad = wire;
    bad[279] = 2;
    assert_eq!(parse_response(&bad), Err(ProtocolError::InvalidFields));

    for kind in [
        ResponseKind::KeyInfo,
        ResponseKind::Binding,
        ResponseKind::Nonce,
        ResponseKind::PreSignature,
        ResponseKind::Completed,
    ] {
        let mut invalid = response(kind);
        invalid.key_id = [0; 32];
        assert_eq!(
            encode_response(&invalid, &mut wire),
            Err(ProtocolError::InvalidFields)
        );
    }
}

fn assert_private_request_invalid(request: &PrivateSwapRequest<'_>) {
    let mut wire = [0u8; REQUEST_HEADER_LEN + 64];
    assert_eq!(
        encode_request(request, &mut wire),
        Err(ProtocolError::InvalidFields)
    );
}

#[test]
fn private_swap_request_fields_fail_closed_one_at_a_time() {
    let mut value = request(RequestKind::KeyInfo);
    value.session_id = [1; 16];
    assert_private_request_invalid(&value);
    value = request(RequestKind::KeyInfo);
    value.host_commitment = [1; 32];
    assert_private_request_invalid(&value);
    value = request(RequestKind::KeyInfo);
    value.key_id = [1; 32];
    assert_private_request_invalid(&value);
    value = request(RequestKind::KeyInfo);
    value.binding_token = [1; 32];
    assert_private_request_invalid(&value);
    value = request(RequestKind::KeyInfo);
    value.adaptor_point = [1; 32];
    assert_private_request_invalid(&value);
    value = request(RequestKind::KeyInfo);
    value.presignature = [1; 64];
    assert_private_request_invalid(&value);
    value = request(RequestKind::KeyInfo);
    value.presignature_negated = true;
    assert_private_request_invalid(&value);
    value = request(RequestKind::KeyInfo);
    value.payload = b"x";
    assert_private_request_invalid(&value);

    value = request(RequestKind::Bind);
    value.session_id = [1; 16];
    assert_private_request_invalid(&value);
    value = request(RequestKind::Bind);
    value.host_commitment = [1; 32];
    assert_private_request_invalid(&value);
    value = request(RequestKind::Bind);
    value.key_id = [0; 32];
    assert_private_request_invalid(&value);
    value = request(RequestKind::Bind);
    value.binding_token = [1; 32];
    assert_private_request_invalid(&value);
    value = request(RequestKind::Bind);
    value.adaptor_point = [0; 32];
    assert_private_request_invalid(&value);
    value = request(RequestKind::Bind);
    value.presignature = [1; 64];
    assert_private_request_invalid(&value);
    value = request(RequestKind::Bind);
    value.presignature_negated = true;
    assert_private_request_invalid(&value);
    value = request(RequestKind::Bind);
    value.payload = &[];
    assert_private_request_invalid(&value);

    value = request(RequestKind::PreSign);
    value.host_commitment = [0; 32];
    assert_private_request_invalid(&value);
    value = request(RequestKind::PreSign);
    value.key_id = [0; 32];
    assert_private_request_invalid(&value);
    value = request(RequestKind::PreSign);
    value.binding_token = [0; 32];
    assert_private_request_invalid(&value);
    value = request(RequestKind::PreSign);
    value.adaptor_point = [0; 32];
    assert_private_request_invalid(&value);
    value = request(RequestKind::PreSign);
    value.presignature = [1; 64];
    assert_private_request_invalid(&value);
    value = request(RequestKind::PreSign);
    value.presignature_negated = true;
    assert_private_request_invalid(&value);
    value = request(RequestKind::PreSign);
    value.payload = &[];
    assert_private_request_invalid(&value);
    value = request(RequestKind::PreSign);
    value.session_id[0] ^= 1;
    assert_private_request_invalid(&value);

    value = request(RequestKind::Complete);
    value.session_id = [1; 16];
    assert_private_request_invalid(&value);
    value = request(RequestKind::Complete);
    value.host_commitment = [1; 32];
    assert_private_request_invalid(&value);
    value = request(RequestKind::Complete);
    value.key_id = [0; 32];
    assert_private_request_invalid(&value);
    value = request(RequestKind::Complete);
    value.binding_token = [0; 32];
    assert_private_request_invalid(&value);
    value = request(RequestKind::Complete);
    value.adaptor_point = [0; 32];
    assert_private_request_invalid(&value);
    value = request(RequestKind::Complete);
    value.presignature = [0; 64];
    assert_private_request_invalid(&value);
    value = request(RequestKind::Complete);
    value.payload = &[];
    assert_private_request_invalid(&value);
}

fn assert_private_response_invalid(response: &PrivateSwapResponse) {
    let mut wire = [0u8; RESPONSE_LEN];
    assert_eq!(
        encode_response(response, &mut wire),
        Err(ProtocolError::InvalidFields)
    );
}

#[test]
fn private_swap_response_fields_fail_closed_one_at_a_time() {
    for field in 0..3 {
        let mut value = response(ResponseKind::KeyInfo);
        match field {
            0 => value.key_id = [0; 32],
            1 => value.claim_pubkey = [0; 32],
            _ => value.adaptor_point = [0; 32],
        }
        assert_private_response_invalid(&value);
    }

    let mut value = response(ResponseKind::KeyInfo);
    value.session_id = [1; 16];
    assert_private_response_invalid(&value);
    value = response(ResponseKind::KeyInfo);
    value.binding_token = [1; 32];
    assert_private_response_invalid(&value);
    value = response(ResponseKind::KeyInfo);
    value.commitment = [1; 32];
    assert_private_response_invalid(&value);
    value = response(ResponseKind::KeyInfo);
    value.nonce_point[0] = 2;
    assert_private_response_invalid(&value);
    value = response(ResponseKind::KeyInfo);
    value.signature[0] = 1;
    assert_private_response_invalid(&value);
    value = response(ResponseKind::KeyInfo);
    value.negated = true;
    assert_private_response_invalid(&value);

    value = response(ResponseKind::Binding);
    value.session_id = [1; 16];
    assert_private_response_invalid(&value);
    value = response(ResponseKind::Binding);
    value.binding_token = [0; 32];
    assert_private_response_invalid(&value);
    value = response(ResponseKind::Binding);
    value.commitment = [0; 32];
    assert_private_response_invalid(&value);
    value = response(ResponseKind::Binding);
    value.nonce_point[0] = 2;
    assert_private_response_invalid(&value);
    value = response(ResponseKind::Binding);
    value.signature[0] = 1;
    assert_private_response_invalid(&value);
    value = response(ResponseKind::Binding);
    value.negated = true;
    assert_private_response_invalid(&value);

    value = response(ResponseKind::Nonce);
    value.session_id = [0; 16];
    assert_private_response_invalid(&value);
    value = response(ResponseKind::Nonce);
    value.binding_token = [0; 32];
    assert_private_response_invalid(&value);
    value = response(ResponseKind::Nonce);
    value.commitment = [0; 32];
    assert_private_response_invalid(&value);
    value = response(ResponseKind::Nonce);
    value.nonce_point = [0; 33];
    assert_private_response_invalid(&value);
    value = response(ResponseKind::Nonce);
    value.signature[0] = 1;
    assert_private_response_invalid(&value);
    value = response(ResponseKind::Nonce);
    value.negated = true;
    assert_private_response_invalid(&value);

    value = response(ResponseKind::PreSignature);
    value.session_id = [0; 16];
    assert_private_response_invalid(&value);
    value = response(ResponseKind::PreSignature);
    value.binding_token = [0; 32];
    assert_private_response_invalid(&value);
    value = response(ResponseKind::PreSignature);
    value.commitment = [0; 32];
    assert_private_response_invalid(&value);
    value = response(ResponseKind::PreSignature);
    value.nonce_point = [0; 33];
    assert_private_response_invalid(&value);
    value = response(ResponseKind::PreSignature);
    value.signature = [0; 64];
    assert_private_response_invalid(&value);

    value = response(ResponseKind::Completed);
    value.session_id = [1; 16];
    assert_private_response_invalid(&value);
    value = response(ResponseKind::Completed);
    value.binding_token = [0; 32];
    assert_private_response_invalid(&value);
    value = response(ResponseKind::Completed);
    value.commitment = [0; 32];
    assert_private_response_invalid(&value);
    value = response(ResponseKind::Completed);
    value.nonce_point[0] = 2;
    assert_private_response_invalid(&value);
    value = response(ResponseKind::Completed);
    value.signature = [0; 64];
    assert_private_response_invalid(&value);
    value = response(ResponseKind::Completed);
    value.negated = true;
    assert_private_response_invalid(&value);
}

#[test]
fn private_swap_reveal_and_wire_boolean_boundaries_cover_each_rejection() {
    let base = PrivateSwapReveal {
        session_id: [1; 16],
        key_id: [2; 32],
        sighash: [3; 32],
        host_secret: [4; 32],
    };
    let mut wire = [0u8; REVEAL_LEN];
    for field in 0..4 {
        let mut value = base;
        match field {
            0 => value.session_id = [0; 16],
            1 => value.key_id = [0; 32],
            2 => value.sighash = [0; 32],
            _ => value.host_secret = [0; 32],
        }
        assert_eq!(
            encode_reveal(&value, &mut wire),
            Err(ProtocolError::InvalidFields)
        );
    }

    let source = request(RequestKind::Bind);
    let mut request_wire = [0u8; REQUEST_HEADER_LEN + 64];
    let len = encode_request(&source, &mut request_wire).expect("bind");
    request_wire[214] = 2;
    assert!(matches!(
        parse_request(&request_wire[..len]),
        Err(ProtocolError::InvalidFields)
    ));
    let mut response_wire = [0u8; RESPONSE_LEN];
    let completed = response(ResponseKind::Completed);
    encode_response(&completed, &mut response_wire).expect("completed");
    response_wire[279] = 2;
    assert_eq!(
        parse_response(&response_wire),
        Err(ProtocolError::InvalidFields)
    );
}

#[test]
fn private_swap_wire_short_circuits_cover_each_parse_boundary() {
    assert!(!is_message(b"PSWG"));

    let reveal = PrivateSwapReveal {
        session_id: [1; SESSION_ID_LEN],
        key_id: [2; 32],
        sighash: [3; 32],
        host_secret: [4; 32],
    };
    let mut reveal_wire = [0u8; REVEAL_LEN];
    encode_reveal(&reveal, &mut reveal_wire).expect("reveal encode");
    assert_eq!(
        parse_reveal(&reveal_wire[..REVEAL_LEN - 1]),
        Err(ProtocolError::InvalidMagic),
    );
    let mut bad_reveal_magic = reveal_wire;
    bad_reveal_magic[0] ^= 1;
    assert_eq!(
        parse_reveal(&bad_reveal_magic),
        Err(ProtocolError::InvalidMagic)
    );
    let mut bad_reveal_version = reveal_wire;
    bad_reveal_version[4] = VERSION.wrapping_add(1);
    assert_eq!(
        parse_reveal(&bad_reveal_version),
        Err(ProtocolError::UnsupportedVersion),
    );
    for range in [5..21, 21..53, 53..85, 85..117] {
        let mut zero_field = reveal_wire;
        zero_field[range].fill(0);
        assert_eq!(parse_reveal(&zero_field), Err(ProtocolError::InvalidFields));
    }

    let completed = response(ResponseKind::Completed);
    let mut response_wire = [0u8; RESPONSE_LEN];
    encode_response(&completed, &mut response_wire).expect("response encode");
    assert_eq!(
        parse_response(&response_wire[..RESPONSE_LEN - 1]),
        Err(ProtocolError::InvalidMagic),
    );
    let mut bad_response_magic = response_wire;
    bad_response_magic[0] ^= 1;
    assert_eq!(
        parse_response(&bad_response_magic),
        Err(ProtocolError::InvalidMagic),
    );
    let mut bad_response_version = response_wire;
    bad_response_version[4] = VERSION.wrapping_add(1);
    assert_eq!(
        parse_response(&bad_response_version),
        Err(ProtocolError::UnsupportedVersion),
    );

    let source = request(RequestKind::Bind);
    let mut request_wire = [0u8; REQUEST_HEADER_LEN + 64];
    let request_len = encode_request(&source, &mut request_wire).expect("bind encode");
    let mut bad_request_magic = request_wire;
    bad_request_magic[0] ^= 1;
    assert_eq!(
        parse_request(&bad_request_magic[..request_len]).map(|_| ()),
        Err(ProtocolError::InvalidMagic),
    );
    for reserved_index in [219usize, 220usize] {
        let mut bad_reserved = request_wire;
        bad_reserved[reserved_index] = 1;
        assert_eq!(
            parse_request(&bad_reserved[..request_len]).map(|_| ()),
            Err(ProtocolError::InvalidFields),
        );
    }

    let mut oversized_declared = request_wire;
    let oversized = (MAX_PAYLOAD_LEN as u32 + 1).to_be_bytes();
    oversized_declared[215..219].copy_from_slice(&oversized);
    assert_eq!(
        parse_request(&oversized_declared[..request_len]).map(|_| ()),
        Err(ProtocolError::InvalidLength),
    );
    let mut mismatched_declared = request_wire;
    mismatched_declared[215..219].copy_from_slice(&0u32.to_be_bytes());
    assert_eq!(
        parse_request(&mismatched_declared[..request_len]).map(|_| ()),
        Err(ProtocolError::InvalidLength),
    );

    let oversized_payload = [1u8; MAX_PAYLOAD_LEN + 1];
    let oversized_request = PrivateSwapRequest {
        kind: RequestKind::Bind,
        session_id: [0; SESSION_ID_LEN],
        host_commitment: [0; 32],
        key_id: [2; 32],
        binding_token: [0; 32],
        adaptor_point: [3; 32],
        presignature: [0; 64],
        presignature_negated: false,
        payload: &oversized_payload,
    };
    let mut output = [0u8; REQUEST_HEADER_LEN];
    assert_eq!(
        encode_request(&oversized_request, &mut output),
        Err(ProtocolError::InvalidLength),
    );
}
