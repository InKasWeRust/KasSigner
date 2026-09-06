use sha2::{Digest, Sha256};
use std::vec;
use std::vec::Vec;

use super::*;

fn signing_request<'a>(script: &'a [u8], context: &'a [u8]) -> CovenantSignRequest<'a> {
    CovenantSignRequest {
        kind: RequestKind::Known,
        scheme: KnownScheme::Sha256Preimage,
        binding: BindingHint::FixedCheckSigFromStack,
        session_id: [3u8; SESSION_ID_LEN],
        host_commitment: [4u8; 32],
        key_id: [7u8; 32],
        binding_token: [8u8; 32],
        commitment: [9u8; 32],
        script,
        context,
    }
}

#[test]
fn exact_envelope_roundtrip_and_trailing_bytes_rejected() {
    let request = signing_request(b"script", b"context");
    let mut wire = [0u8; 384];
    let len = encode_request(&request, &mut wire).expect("encode");
    let parsed = parse_request(&wire[..len]).expect("parse");
    assert_eq!(parsed.key_id, request.key_id);
    assert_eq!(parsed.binding_token, request.binding_token);
    assert_eq!(parsed.session_id, request.session_id);
    assert_eq!(parsed.context, b"context");
    assert!(parse_request(&wire[..len + 1]).is_err());
}

#[test]
fn request_kind_decoder_rejects_unknown_wire_values() {
    let request = signing_request(b"script", b"context");
    let mut wire = [0u8; 384];
    let len = encode_request(&request, &mut wire).expect("encode");
    wire[5] = u8::MAX;
    assert!(matches!(
        parse_request(&wire[..len]),
        Err(ProtocolError::InvalidKind)
    ));
}

#[test]
fn key_info_requires_device_allocation_not_host_selected_id() {
    let request = CovenantSignRequest {
        kind: RequestKind::KeyInfo,
        scheme: KnownScheme::None,
        binding: BindingHint::None,
        session_id: [0; SESSION_ID_LEN],
        host_commitment: [0; 32],
        key_id: [0; 32],
        binding_token: [0; 32],
        commitment: [0; 32],
        script: &[],
        context: &[],
    };
    let mut wire = [0u8; 192];
    let len = encode_request(&request, &mut wire).expect("key request");
    assert_eq!(
        parse_request(&wire[..len]).expect("parse").kind,
        RequestKind::KeyInfo
    );
    let mut hostile = request;
    hostile.key_id = [8; 32];
    assert!(encode_request(&hostile, &mut wire).is_err());
}

#[test]
fn binding_request_has_no_host_nonce_and_no_prior_binding_token() {
    let request = CovenantSignRequest {
        kind: RequestKind::Bind,
        scheme: KnownScheme::None,
        binding: BindingHint::None,
        session_id: [0; SESSION_ID_LEN],
        host_commitment: [0; 32],
        key_id: [3; 32],
        binding_token: [0; 32],
        commitment: [0; 32],
        script: b"third-party script",
        context: &[],
    };
    let mut wire = [0u8; 256];
    let len = encode_request(&request, &mut wire).expect("bind");
    assert_eq!(
        parse_request(&wire[..len]).expect("parse").kind,
        RequestKind::Bind
    );
}

#[test]
fn opaque_requires_portable_binding_record() {
    let request = CovenantSignRequest {
        kind: RequestKind::Opaque,
        scheme: KnownScheme::None,
        binding: BindingHint::None,
        session_id: [1; SESSION_ID_LEN],
        host_commitment: [2; 32],
        key_id: [3; 32],
        binding_token: [4; 32],
        commitment: [0; 32],
        script: b"third-party script",
        context: &[],
    };
    let mut wire = [0u8; 320];
    let len = encode_request(&request, &mut wire).expect("opaque");
    let parsed = parse_request(&wire[..len]).expect("parse");
    assert_eq!(parsed.commitment, [0; 32]);
    assert_eq!(parsed.binding_token, [4; 32]);
    let mut unbound = request;
    unbound.binding_token = [0; 32];
    assert!(encode_request(&unbound, &mut wire).is_err());
}

#[test]
fn opaque_rejects_unreviewed_context_bytes() {
    let request = CovenantSignRequest {
        kind: RequestKind::Opaque,
        scheme: KnownScheme::None,
        binding: BindingHint::None,
        session_id: [1; SESSION_ID_LEN],
        host_commitment: [2; 32],
        key_id: [3; 32],
        binding_token: [4; 32],
        commitment: [5; 32],
        script: b"third-party script",
        context: b"ignored by opaque UI",
    };
    let mut wire = [0u8; 320];
    assert!(encode_request(&request, &mut wire).is_err());
}

#[test]
fn reveal_and_nonce_response_are_exactly_bound() {
    let reveal = CovenantSignReveal {
        session_id: [5; SESSION_ID_LEN],
        key_id: [6; 32],
        commitment: [7; 32],
        host_secret: [8; 32],
    };
    let mut wire = [0u8; REVEAL_LEN];
    encode_reveal(&reveal, &mut wire).expect("reveal");
    assert_eq!(parse_reveal(&wire).expect("parse"), reveal);

    let mut nonce = [0u8; 33];
    nonce[0] = 0x02;
    nonce[1] = 9;
    let response = CovenantSignResponse {
        kind: ResponseKind::NonceCommitment,
        session_id: [5; SESSION_ID_LEN],
        key_id: [6; 32],
        pubkey_x: [10; 32],
        binding_token: [11; 32],
        commitment: [7; 32],
        nonce_point: nonce,
        signature: [0; 64],
    };
    let mut encoded = [0u8; RESPONSE_LEN];
    encode_response(&response, &mut encoded).expect("nonce response");
    assert_eq!(parse_response(&encoded).expect("parse response"), response);
}

#[test]
fn binding_response_carries_script_fingerprint_and_record() {
    let response = CovenantSignResponse {
        kind: ResponseKind::Binding,
        session_id: [0; SESSION_ID_LEN],
        key_id: [6; 32],
        pubkey_x: [10; 32],
        binding_token: [11; 32],
        commitment: [12; 32],
        nonce_point: [0; 33],
        signature: [0; 64],
    };
    let mut encoded = [0u8; RESPONSE_LEN];
    encode_response(&response, &mut encoded).expect("binding response");
    assert_eq!(parse_response(&encoded).expect("parse response"), response);
}

#[test]
fn known_context_limit_is_review_buffer_limit_not_a_preview() {
    let context = [b'a'; MAX_CONTEXT_LEN];
    assert!(recompute_known_commitment(KnownScheme::Sha256Preimage, &context).is_some());
    let oversized = [b'a'; MAX_CONTEXT_LEN + 1];
    assert!(recompute_known_commitment(KnownScheme::Sha256Preimage, &oversized).is_none());
}

#[test]
fn known_context_rejects_non_displayable_or_bidi_text() {
    assert!(recompute_known_commitment(KnownScheme::Sha256Preimage, b"visible context").is_some());
    assert!(recompute_known_commitment(KnownScheme::Sha256Preimage, b"hidden\nline").is_none());
    assert!(recompute_known_commitment(
        KnownScheme::Sha256Preimage,
        "bidi \u{202e} text".as_bytes()
    )
    .is_none());
}

#[test]
fn fixed_binding_requires_exact_commitment_and_key_sequence() {
    let commitment = [1u8; 32];
    let key = [2u8; 32];
    let mut script = [0u8; 67];
    script[0] = 0x20;
    script[1..33].copy_from_slice(&commitment);
    script[33] = 0x20;
    script[34..66].copy_from_slice(&key);
    script[66] = 0xd7;
    assert!(script_binds_fixed_commitment(&script, &commitment, &key));
    let mut other = commitment;
    other[0] ^= 1;
    assert!(!script_binds_fixed_commitment(&script, &other, &key));
}

#[test]
fn known_sha256_scheme_requires_the_entire_registered_script() {
    let commitment = [3u8; 32];
    let key = [4u8; 32];
    let mut exact = [0u8; 67];
    exact[0] = 0x20;
    exact[1..33].copy_from_slice(&commitment);
    exact[33] = 0x20;
    exact[34..66].copy_from_slice(&key);
    exact[66] = 0xd7;
    assert!(known_script_binds(
        KnownScheme::Sha256Preimage,
        &exact,
        &commitment,
        &key
    ));
    let mut wrapped = [0u8; 69];
    wrapped[0] = 0x51;
    wrapped[1..68].copy_from_slice(&exact);
    wrapped[68] = 0x51;
    assert!(!known_script_binds(
        KnownScheme::Sha256Preimage,
        &wrapped,
        &commitment,
        &key
    ));
}

#[test]
fn oracle_v1_known_scheme_requires_canonical_whole_script() {
    let owner = [0x11u8; 32];
    let beneficiary = [0x22u8; 32];
    let commitment = [0x33u8; 32];
    let oracle = [0x44u8; 32];
    let salt = [0x55u8; 16];
    let mut script = Vec::new();
    script.push(0x10);
    script.extend_from_slice(&salt);
    script.push(0x75);
    script.push(0x63);
    script.push(0x20);
    script.extend_from_slice(&owner);
    script.push(0xad);
    script.extend_from_slice(&[0x02, 0xe8, 0x03]);
    script.extend_from_slice(&[0xb0, 0x51, 0x67, 0x20]);
    script.extend_from_slice(&beneficiary);
    script.push(0xad);
    script.push(0x20);
    script.extend_from_slice(&commitment);
    script.push(0x20);
    script.extend_from_slice(&oracle);
    script.extend_from_slice(&[0xd7, 0x69, 0x51, 0x68]);
    assert!(known_script_binds(
        KnownScheme::OracleV1,
        &script,
        &commitment,
        &oracle
    ));
    script.insert(0, 0x51);
    assert!(!known_script_binds(
        KnownScheme::OracleV1,
        &script,
        &commitment,
        &oracle
    ));
}

#[test]
fn every_covenant_response_shape_roundtrips_including_key_info_and_signature() {
    let variants = [
        CovenantSignResponse {
            kind: ResponseKind::KeyInfo,
            session_id: [0; SESSION_ID_LEN],
            key_id: [1; 32],
            pubkey_x: [2; 32],
            binding_token: [0; 32],
            commitment: [0; 32],
            nonce_point: [0; 33],
            signature: [0; 64],
        },
        CovenantSignResponse {
            kind: ResponseKind::Binding,
            session_id: [0; SESSION_ID_LEN],
            key_id: [1; 32],
            pubkey_x: [2; 32],
            binding_token: [3; 32],
            commitment: [4; 32],
            nonce_point: [0; 33],
            signature: [0; 64],
        },
        CovenantSignResponse {
            kind: ResponseKind::NonceCommitment,
            session_id: [5; SESSION_ID_LEN],
            key_id: [1; 32],
            pubkey_x: [2; 32],
            binding_token: [3; 32],
            commitment: [4; 32],
            nonce_point: {
                let mut point = [0; 33];
                point[0] = 0x02;
                point[1] = 6;
                point
            },
            signature: [0; 64],
        },
        CovenantSignResponse {
            kind: ResponseKind::Signature,
            session_id: [5; SESSION_ID_LEN],
            key_id: [1; 32],
            pubkey_x: [2; 32],
            binding_token: [3; 32],
            commitment: [4; 32],
            nonce_point: {
                let mut point = [0; 33];
                point[0] = 0x02;
                point[1] = 6;
                point
            },
            signature: [7; 64],
        },
    ];
    for response in variants {
        let mut wire = [0u8; RESPONSE_LEN];
        encode_response(&response, &mut wire).expect("response encode");
        assert_eq!(parse_response(&wire).expect("response parse"), response);
    }

    let mut wire = [0u8; RESPONSE_LEN];
    encode_response(&variants[0], &mut wire).expect("key info");
    wire[5] = 0xff;
    assert!(matches!(
        parse_response(&wire),
        Err(ProtocolError::InvalidKind)
    ));
}

#[test]
fn bind_validation_covers_known_and_key_present_shapes() {
    let mut wire = [0u8; 512];
    let generic = CovenantSignRequest {
        kind: RequestKind::Bind,
        scheme: KnownScheme::None,
        binding: BindingHint::KeyPresent,
        session_id: [0; SESSION_ID_LEN],
        host_commitment: [0; 32],
        key_id: [1; 32],
        binding_token: [0; 32],
        commitment: [0; 32],
        script: b"generic",
        context: &[],
    };
    let len = encode_request(&generic, &mut wire).expect("generic bind");
    assert_eq!(
        parse_request(&wire[..len])
            .expect("generic bind parse")
            .binding,
        BindingHint::KeyPresent
    );

    let commitment = Sha256::digest(b"known statement");
    let mut commitment_bytes = [0u8; 32];
    commitment_bytes.copy_from_slice(&commitment);
    let mut script = [0u8; 67];
    script[0] = 0x20;
    script[1..33].copy_from_slice(&commitment_bytes);
    script[33] = 0x20;
    script[34..66].fill(0x22);
    script[66] = 0xd7;
    let known = CovenantSignRequest {
        kind: RequestKind::Bind,
        scheme: KnownScheme::Sha256Preimage,
        binding: BindingHint::FixedCheckSigFromStack,
        session_id: [0; SESSION_ID_LEN],
        host_commitment: [0; 32],
        key_id: [1; 32],
        binding_token: [0; 32],
        commitment: commitment_bytes,
        script: &script,
        context: b"known statement",
    };
    let len = encode_request(&known, &mut wire).expect("known bind");
    assert_eq!(
        parse_request(&wire[..len])
            .expect("known bind parse")
            .scheme,
        KnownScheme::Sha256Preimage
    );
}

#[test]
fn canonical_u64_script_numbers_cover_small_large_sign_and_padding_rules() {
    assert!(canonical_u64_push(&[0x00]));
    assert!(canonical_u64_push(&[0x51]));
    assert!(canonical_u64_push(&[0x60]));
    assert!(canonical_u64_push(&[0x01, 0x11]));
    assert!(canonical_u64_push(&[0x02, 0x80, 0x00]));
    assert!(!canonical_u64_push(&[]));
    assert!(!canonical_u64_push(&[0x00, 0x00]));
    assert!(!canonical_u64_push(&[0x01, 0x10]));
    assert!(!canonical_u64_push(&[0x01, 0x80]));
    assert!(!canonical_u64_push(&[0x02, 0x01, 0x00]));
    assert!(!canonical_u64_push(&[0x09, 1, 2, 3, 4, 5, 6, 7, 8, 1]));
}

fn invariant_request(kind: RequestKind) -> CovenantSignRequest<'static> {
    match kind {
        RequestKind::KeyInfo => CovenantSignRequest {
            kind,
            scheme: KnownScheme::None,
            binding: BindingHint::None,
            session_id: [0; SESSION_ID_LEN],
            host_commitment: [0; 32],
            key_id: [0; 32],
            binding_token: [0; 32],
            commitment: [0; 32],
            script: &[],
            context: &[],
        },
        RequestKind::Bind => CovenantSignRequest {
            kind,
            scheme: KnownScheme::None,
            binding: BindingHint::KeyPresent,
            session_id: [0; SESSION_ID_LEN],
            host_commitment: [0; 32],
            key_id: [1; 32],
            binding_token: [0; 32],
            commitment: [0; 32],
            script: b"bound script",
            context: &[],
        },
        RequestKind::Known => CovenantSignRequest {
            kind,
            scheme: KnownScheme::Sha256Preimage,
            binding: BindingHint::FixedCheckSigFromStack,
            session_id: [1; SESSION_ID_LEN],
            host_commitment: [2; 32],
            key_id: [3; 32],
            binding_token: [4; 32],
            commitment: [5; 32],
            script: b"known script",
            context: b"review context",
        },
        RequestKind::Opaque => CovenantSignRequest {
            kind,
            scheme: KnownScheme::None,
            binding: BindingHint::KeyPresent,
            session_id: [1; SESSION_ID_LEN],
            host_commitment: [2; 32],
            key_id: [3; 32],
            binding_token: [4; 32],
            commitment: [0; 32],
            script: b"opaque script",
            context: &[],
        },
    }
}

fn assert_request_invalid(request: &CovenantSignRequest<'_>) {
    let mut wire = [0u8; 512];
    assert_eq!(
        encode_request(request, &mut wire),
        Err(ProtocolError::InvalidFields)
    );
}

#[test]
fn request_field_invariants_reject_each_independent_invalid_shape() {
    let mut request = invariant_request(RequestKind::KeyInfo);
    request.scheme = KnownScheme::Sha256Preimage;
    assert_request_invalid(&request);
    request = invariant_request(RequestKind::KeyInfo);
    request.binding = BindingHint::KeyPresent;
    assert_request_invalid(&request);
    request = invariant_request(RequestKind::KeyInfo);
    request.session_id = [1; SESSION_ID_LEN];
    assert_request_invalid(&request);
    request = invariant_request(RequestKind::KeyInfo);
    request.host_commitment = [1; 32];
    assert_request_invalid(&request);
    request = invariant_request(RequestKind::KeyInfo);
    request.key_id = [1; 32];
    assert_request_invalid(&request);
    request = invariant_request(RequestKind::KeyInfo);
    request.binding_token = [1; 32];
    assert_request_invalid(&request);
    request = invariant_request(RequestKind::KeyInfo);
    request.commitment = [1; 32];
    assert_request_invalid(&request);
    request = invariant_request(RequestKind::KeyInfo);
    request.script = b"x";
    assert_request_invalid(&request);
    request = invariant_request(RequestKind::KeyInfo);
    request.context = b"x";
    assert_request_invalid(&request);

    request = invariant_request(RequestKind::Bind);
    request.session_id = [1; SESSION_ID_LEN];
    assert_request_invalid(&request);
    request = invariant_request(RequestKind::Bind);
    request.host_commitment = [1; 32];
    assert_request_invalid(&request);
    request = invariant_request(RequestKind::Bind);
    request.key_id = [0; 32];
    assert_request_invalid(&request);
    request = invariant_request(RequestKind::Bind);
    request.binding_token = [1; 32];
    assert_request_invalid(&request);
    request = invariant_request(RequestKind::Bind);
    request.script = &[];
    assert_request_invalid(&request);
    request = invariant_request(RequestKind::Bind);
    request.binding = BindingHint::FixedCheckSigFromStack;
    assert_request_invalid(&request);
    request = invariant_request(RequestKind::Bind);
    request.commitment = [1; 32];
    assert_request_invalid(&request);
    request = invariant_request(RequestKind::Bind);
    request.context = b"unexpected";
    assert_request_invalid(&request);
    request = invariant_request(RequestKind::Bind);
    request.scheme = KnownScheme::Sha256Preimage;
    request.binding = BindingHint::None;
    request.context = b"known";
    assert_request_invalid(&request);
    request = invariant_request(RequestKind::Bind);
    request.scheme = KnownScheme::Sha256Preimage;
    request.binding = BindingHint::FixedCheckSigFromStack;
    request.context = &[];
    assert_request_invalid(&request);

    request = invariant_request(RequestKind::Known);
    request.scheme = KnownScheme::None;
    assert_request_invalid(&request);
    request = invariant_request(RequestKind::Known);
    request.binding = BindingHint::None;
    assert_request_invalid(&request);
    request = invariant_request(RequestKind::Known);
    request.session_id = [0; SESSION_ID_LEN];
    assert_request_invalid(&request);
    request = invariant_request(RequestKind::Known);
    request.host_commitment = [0; 32];
    assert_request_invalid(&request);
    request = invariant_request(RequestKind::Known);
    request.key_id = [0; 32];
    assert_request_invalid(&request);
    request = invariant_request(RequestKind::Known);
    request.binding_token = [0; 32];
    assert_request_invalid(&request);
    request = invariant_request(RequestKind::Known);
    request.script = &[];
    assert_request_invalid(&request);
    request = invariant_request(RequestKind::Known);
    request.context = &[];
    assert_request_invalid(&request);

    request = invariant_request(RequestKind::Opaque);
    request.scheme = KnownScheme::Sha256Preimage;
    assert_request_invalid(&request);
    request = invariant_request(RequestKind::Opaque);
    request.binding = BindingHint::FixedCheckSigFromStack;
    assert_request_invalid(&request);
    request = invariant_request(RequestKind::Opaque);
    request.session_id = [0; SESSION_ID_LEN];
    assert_request_invalid(&request);
    request = invariant_request(RequestKind::Opaque);
    request.host_commitment = [0; 32];
    assert_request_invalid(&request);
    request = invariant_request(RequestKind::Opaque);
    request.key_id = [0; 32];
    assert_request_invalid(&request);
    request = invariant_request(RequestKind::Opaque);
    request.binding_token = [0; 32];
    assert_request_invalid(&request);
    request = invariant_request(RequestKind::Opaque);
    request.script = &[];
    assert_request_invalid(&request);
    request = invariant_request(RequestKind::Opaque);
    request.context = b"not reviewed";
    assert_request_invalid(&request);
}

fn invariant_response(kind: ResponseKind) -> CovenantSignResponse {
    CovenantSignResponse {
        kind,
        session_id: if matches!(
            kind,
            ResponseKind::NonceCommitment | ResponseKind::Signature
        ) {
            [1; SESSION_ID_LEN]
        } else {
            [0; SESSION_ID_LEN]
        },
        key_id: [2; 32],
        pubkey_x: [3; 32],
        binding_token: if matches!(kind, ResponseKind::KeyInfo) {
            [0; 32]
        } else {
            [4; 32]
        },
        commitment: if matches!(
            kind,
            ResponseKind::Binding | ResponseKind::NonceCommitment | ResponseKind::Signature
        ) {
            [5; 32]
        } else {
            [0; 32]
        },
        nonce_point: if matches!(
            kind,
            ResponseKind::NonceCommitment | ResponseKind::Signature
        ) {
            let mut point = [0; 33];
            point[0] = 0x02;
            point[1] = 6;
            point
        } else {
            [0; 33]
        },
        signature: if kind == ResponseKind::Signature {
            [7; 64]
        } else {
            [0; 64]
        },
    }
}

fn assert_response_invalid(response: &CovenantSignResponse) {
    let mut wire = [0u8; RESPONSE_LEN];
    assert_eq!(
        encode_response(response, &mut wire),
        Err(ProtocolError::InvalidFields)
    );
}

#[test]
fn response_field_invariants_reject_each_independent_invalid_shape() {
    let mut response = invariant_response(ResponseKind::KeyInfo);
    response.key_id = [0; 32];
    assert_response_invalid(&response);
    response = invariant_response(ResponseKind::KeyInfo);
    response.pubkey_x = [0; 32];
    assert_response_invalid(&response);
    response = invariant_response(ResponseKind::KeyInfo);
    response.session_id = [1; SESSION_ID_LEN];
    assert_response_invalid(&response);
    response = invariant_response(ResponseKind::KeyInfo);
    response.binding_token = [1; 32];
    assert_response_invalid(&response);
    response = invariant_response(ResponseKind::KeyInfo);
    response.commitment = [1; 32];
    assert_response_invalid(&response);
    response = invariant_response(ResponseKind::KeyInfo);
    response.nonce_point[0] = 2;
    assert_response_invalid(&response);
    response = invariant_response(ResponseKind::KeyInfo);
    response.signature[0] = 1;
    assert_response_invalid(&response);

    response = invariant_response(ResponseKind::Binding);
    response.session_id = [1; SESSION_ID_LEN];
    assert_response_invalid(&response);
    response = invariant_response(ResponseKind::Binding);
    response.binding_token = [0; 32];
    assert_response_invalid(&response);
    response = invariant_response(ResponseKind::Binding);
    response.commitment = [0; 32];
    assert_response_invalid(&response);
    response = invariant_response(ResponseKind::Binding);
    response.nonce_point[0] = 2;
    assert_response_invalid(&response);
    response = invariant_response(ResponseKind::Binding);
    response.signature[0] = 1;
    assert_response_invalid(&response);

    response = invariant_response(ResponseKind::NonceCommitment);
    response.session_id = [0; SESSION_ID_LEN];
    assert_response_invalid(&response);
    response = invariant_response(ResponseKind::NonceCommitment);
    response.binding_token = [0; 32];
    assert_response_invalid(&response);
    response = invariant_response(ResponseKind::NonceCommitment);
    response.nonce_point[0] = 0x03;
    assert_response_invalid(&response);
    response = invariant_response(ResponseKind::NonceCommitment);
    response.signature[0] = 1;
    assert_response_invalid(&response);

    response = invariant_response(ResponseKind::Signature);
    response.session_id = [0; SESSION_ID_LEN];
    assert_response_invalid(&response);
    response = invariant_response(ResponseKind::Signature);
    response.binding_token = [0; 32];
    assert_response_invalid(&response);
    response = invariant_response(ResponseKind::Signature);
    response.nonce_point[0] = 0x03;
    assert_response_invalid(&response);
    response = invariant_response(ResponseKind::Signature);
    response.signature = [0; 64];
    assert_response_invalid(&response);
}

#[test]
fn review_context_and_wire_prefix_boundaries_fail_closed() {
    assert_eq!(valid_review_context(b"", 16, None), None);
    assert_eq!(valid_review_context(b"0123456789abcdefx", 16, None), None);
    assert_eq!(valid_review_context(&[0xff], 16, None), None);
    assert_eq!(valid_review_context(b"line\n", 16, None), None);
    assert_eq!(
        valid_review_context(b"wrong prefix", 32, Some(b"right ")),
        None
    );
    assert_eq!(
        valid_review_context(b"right statement", 32, Some(b"right ")),
        Some(&b"right statement"[..])
    );

    assert!(matches!(
        parse_request(&[]),
        Err(ProtocolError::InvalidMagic)
    ));
    let request = invariant_request(RequestKind::KeyInfo);
    let mut wire = [0u8; 256];
    let len = encode_request(&request, &mut wire).expect("key info");
    wire[4] = VERSION.wrapping_add(1);
    assert!(matches!(
        parse_request(&wire[..len]),
        Err(ProtocolError::UnsupportedVersion)
    ));
}

#[test]
fn script_xonly_key_search_requires_full_contiguous_key() {
    let key = [0x5au8; 32];
    let mut script = vec![0x01, 0x02, 0x03];
    script.extend_from_slice(&key);
    script.push(0x04);
    assert!(script_contains_xonly_key(&script, &key));
    assert!(!script_contains_xonly_key(&script[..34], &key));
    let other = [0x5bu8; 32];
    assert!(!script_contains_xonly_key(&script, &other));
}

#[test]
fn request_length_enum_and_review_helpers_cover_all_boundaries() {
    assert_eq!(validate_lengths(MAX_SCRIPT_LEN, MAX_CONTEXT_LEN), Ok(()));
    assert_eq!(
        validate_lengths(MAX_SCRIPT_LEN + 1, 0),
        Err(ProtocolError::InvalidLength)
    );
    assert_eq!(
        validate_lengths(0, MAX_CONTEXT_LEN + 1),
        Err(ProtocolError::InvalidLength)
    );
    assert_eq!(request_total_len(0, 0), Ok(REQUEST_HEADER_LEN));
    assert_eq!(
        request_total_len(usize::MAX, 1),
        Err(ProtocolError::InvalidLength)
    );

    for (wire, expected) in [
        (0, RequestKind::KeyInfo),
        (1, RequestKind::Known),
        (2, RequestKind::Opaque),
        (3, RequestKind::Bind),
    ] {
        assert_eq!(parse_kind(wire), Ok(expected));
    }
    assert_eq!(parse_kind(4), Err(ProtocolError::InvalidKind));
    assert_eq!(parse_scheme(0), Ok(KnownScheme::None));
    assert_eq!(parse_scheme(1), Ok(KnownScheme::Sha256Preimage));
    assert_eq!(parse_scheme(2), Ok(KnownScheme::OracleV1));
    assert_eq!(parse_scheme(3), Err(ProtocolError::InvalidScheme));
    assert_eq!(parse_binding(0), Ok(BindingHint::None));
    assert_eq!(parse_binding(1), Ok(BindingHint::KeyPresent));
    assert_eq!(parse_binding(2), Ok(BindingHint::FixedCheckSigFromStack));
    assert_eq!(parse_binding(3), Err(ProtocolError::InvalidBinding));

    assert_eq!(
        valid_review_context(b"visible", 7, None),
        Some(&b"visible"[..])
    );
    assert_eq!(valid_review_context(b"visible", 6, None), None);
    assert_eq!(
        valid_review_context(b"prefix body", 16, Some(b"prefix ")),
        Some(&b"prefix body"[..])
    );
    assert_eq!(
        valid_review_context(b"prefiy body", 16, Some(b"prefix ")),
        None
    );
    assert_eq!(valid_review_context(&[0x1f], 16, None), None);
    assert_eq!(valid_review_context(&[0x7f], 16, None), None);
}

#[test]
fn response_shape_helpers_cover_true_and_false_sides_directly() {
    for kind in [
        ResponseKind::KeyInfo,
        ResponseKind::Binding,
        ResponseKind::NonceCommitment,
        ResponseKind::Signature,
    ] {
        let valid = invariant_response(kind);
        assert!(response_shape_valid(&valid));
        assert_eq!(validate_response(&valid), Ok(()));
    }

    let mut key_info = invariant_response(ResponseKind::KeyInfo);
    key_info.signature[0] = 1;
    assert!(!key_info_response_valid(&key_info));
    let mut binding = invariant_response(ResponseKind::Binding);
    binding.nonce_point[0] = 2;
    assert!(!binding_response_valid(&binding));
    let mut nonce = invariant_response(ResponseKind::NonceCommitment);
    nonce.signature[0] = 1;
    assert!(!nonce_response_valid(&nonce));
    let mut signature = invariant_response(ResponseKind::Signature);
    signature.signature = [0; 64];
    assert!(!signature_response_valid(&signature));

    let mut zero_key = invariant_response(ResponseKind::KeyInfo);
    zero_key.key_id = [0; 32];
    assert_eq!(
        validate_response(&zero_key),
        Err(ProtocolError::InvalidFields)
    );
    let mut zero_pubkey = invariant_response(ResponseKind::KeyInfo);
    zero_pubkey.pubkey_x = [0; 32];
    assert_eq!(
        validate_response(&zero_pubkey),
        Err(ProtocolError::InvalidFields)
    );
}

#[test]
fn message_and_known_binding_helpers_cover_registered_and_unregistered_shapes() {
    let mut request_prefix = REQUEST_MAGIC.to_vec();
    request_prefix.push(VERSION);
    assert!(is_message(&request_prefix));
    let mut reveal_prefix = REVEAL_MAGIC.to_vec();
    reveal_prefix.push(VERSION);
    assert!(is_message(&reveal_prefix));
    let mut response_prefix = RESPONSE_MAGIC.to_vec();
    response_prefix.push(VERSION);
    assert!(!is_message(&response_prefix));
    let invalid_magic = [b'C', b'V', b'S', b'X', VERSION];
    assert!(!is_message(&invalid_magic));
    assert!(!is_message(b"CVS"));
    let mut wrong_version = REQUEST_MAGIC.to_vec();
    wrong_version.push(VERSION.wrapping_add(1));
    assert!(!is_message(&wrong_version));

    assert_eq!(expected_known_binding(KnownScheme::None), BindingHint::None);
    assert_eq!(
        expected_known_binding(KnownScheme::Sha256Preimage),
        BindingHint::FixedCheckSigFromStack,
    );
    assert_eq!(
        expected_known_binding(KnownScheme::OracleV1),
        BindingHint::FixedCheckSigFromStack,
    );

    let key = [0x44u8; 32];
    assert!(script_contains_xonly_key(&key, &key));
    assert!(!script_contains_xonly_key(&key[..31], &key));
    assert_eq!(array16(&[1u8; 16]), [1u8; 16]);
    assert_eq!(array32(&[2u8; 32]), [2u8; 32]);
}

fn oracle_v1_branch_script(commitment: &[u8; 32], oracle: &[u8; 32]) -> Vec<u8> {
    let owner = [0x11u8; 32];
    let beneficiary = [0x22u8; 32];
    let salt = [0x55u8; 16];
    let mut script = Vec::new();
    script.push(0x10);
    script.extend_from_slice(&salt);
    script.push(0x75);
    script.push(0x63);
    script.push(0x20);
    script.extend_from_slice(&owner);
    script.push(0xad);
    script.extend_from_slice(&[0x02, 0xe8, 0x03]);
    script.extend_from_slice(&[0xb0, 0x51, 0x67, 0x20]);
    script.extend_from_slice(&beneficiary);
    script.push(0xad);
    script.push(0x20);
    script.extend_from_slice(commitment);
    script.push(0x20);
    script.extend_from_slice(oracle);
    script.extend_from_slice(&[0xd7, 0x69, 0x51, 0x68]);
    script
}

#[test]
fn envelope_wire_failures_cover_short_circuit_sides_without_relaxing_types() {
    let request = invariant_request(RequestKind::KeyInfo);
    let mut request_wire = [0u8; 256];
    let request_len = encode_request(&request, &mut request_wire).expect("key-info encode");
    let mut request_too_small = [0u8; REQUEST_HEADER_LEN - 1];
    assert_eq!(
        encode_request(&request, &mut request_too_small),
        Err(ProtocolError::OutputTooSmall),
    );
    let mut bad_request_magic = request_wire;
    bad_request_magic[0] ^= 1;
    assert_eq!(
        parse_request(&bad_request_magic[..request_len]).map(|_| ()),
        Err(ProtocolError::InvalidMagic),
    );

    let reveal = CovenantSignReveal {
        session_id: [1; SESSION_ID_LEN],
        key_id: [2; 32],
        commitment: [3; 32],
        host_secret: [4; 32],
    };
    let mut reveal_wire = [0u8; REVEAL_LEN];
    encode_reveal(&reveal, &mut reveal_wire).expect("reveal encode");
    let mut reveal_too_small = [0u8; REVEAL_LEN - 1];
    assert_eq!(
        encode_reveal(&reveal, &mut reveal_too_small),
        Err(ProtocolError::OutputTooSmall),
    );
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
    let mut zero_reveal_session = reveal_wire;
    zero_reveal_session[5..21].fill(0);
    assert_eq!(
        parse_reveal(&zero_reveal_session),
        Err(ProtocolError::InvalidFields),
    );
    let mut zero_reveal_key = reveal_wire;
    zero_reveal_key[21..53].fill(0);
    assert_eq!(
        parse_reveal(&zero_reveal_key),
        Err(ProtocolError::InvalidFields)
    );

    let response = invariant_response(ResponseKind::KeyInfo);
    let mut response_wire = [0u8; RESPONSE_LEN];
    encode_response(&response, &mut response_wire).expect("response encode");
    let mut response_too_small = [0u8; RESPONSE_LEN - 1];
    assert_eq!(
        encode_response(&response, &mut response_too_small),
        Err(ProtocolError::OutputTooSmall),
    );
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
}

#[test]
fn oracle_v1_binding_rejects_every_layout_and_commitment_boundary() {
    let commitment = [0x33u8; 32];
    let oracle = [0x44u8; 32];
    assert!(!known_script_binds(
        KnownScheme::OracleV1,
        &[0u8; 106],
        &commitment,
        &oracle,
    ));
    assert!(!known_script_binds(
        KnownScheme::OracleV1,
        &[0u8; 107],
        &commitment,
        &oracle,
    ));

    let valid = oracle_v1_branch_script(&commitment, &oracle);
    assert!(known_script_binds(
        KnownScheme::OracleV1,
        &valid,
        &commitment,
        &oracle
    ));

    let mut bad_layout = valid.clone();
    bad_layout[17] ^= 1;
    assert!(!known_script_binds(
        KnownScheme::OracleV1,
        &bad_layout,
        &commitment,
        &oracle,
    ));

    let mut noncanonical_integer = valid.clone();
    noncanonical_integer[53] = 0x01;
    assert!(!known_script_binds(
        KnownScheme::OracleV1,
        &noncanonical_integer,
        &commitment,
        &oracle,
    ));

    let mut other_commitment = commitment;
    other_commitment[0] ^= 1;
    assert!(!known_script_binds(
        KnownScheme::OracleV1,
        &valid,
        &other_commitment,
        &oracle,
    ));
    let mut other_oracle = oracle;
    other_oracle[0] ^= 1;
    assert!(!known_script_binds(
        KnownScheme::OracleV1,
        &valid,
        &commitment,
        &other_oracle,
    ));
}
