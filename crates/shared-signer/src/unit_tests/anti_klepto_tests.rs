use super::*;

#[test]
fn message_detection_and_domain_hashes_are_exact() {
    let secret = [0x42u8; HASH_LEN];
    let tx = b"KSPT\x04example";
    let expected_commitment = [
        0xa4, 0xbd, 0x6f, 0xbd, 0x5f, 0xe9, 0x98, 0xc5, 0xf7, 0x01, 0x3a, 0x8d, 0xd2, 0x6d, 0x15,
        0xe4, 0xe6, 0x04, 0x7c, 0x29, 0x8a, 0xfc, 0xb0, 0xae, 0x2e, 0x34, 0xe5, 0xb3, 0x91, 0xf3,
        0x4d, 0xd4,
    ];
    let expected_digest = [
        0x90, 0xd4, 0xbf, 0xb2, 0x40, 0x7a, 0x20, 0x01, 0x30, 0x92, 0x45, 0x94, 0x56, 0xd4, 0x3f,
        0xe1, 0xf8, 0x17, 0x0c, 0x3d, 0xc4, 0x30, 0x93, 0xdf, 0xab, 0x23, 0x52, 0x38, 0x5b, 0x44,
        0x07, 0xff,
    ];
    let expected_session = [
        0x91, 0x0b, 0x88, 0xa4, 0x5f, 0x6c, 0x1a, 0xd3, 0xff, 0x68, 0xa6, 0xc4, 0xf2, 0x38, 0x00,
        0xf6,
    ];

    assert_eq!(host_commitment(&secret), expected_commitment);
    assert_eq!(transaction_digest(tx), expected_digest);
    assert_eq!(
        session_id(&expected_commitment, &expected_digest),
        expected_session
    );
    assert!(verify_host_secret(&expected_commitment, &secret));
    assert!(!verify_host_secret(&expected_commitment, &[0x43; HASH_LEN]));

    let mut public_key = [0u8; 33];
    public_key[0] = 0x02;
    for (index, byte) in public_key[1..].iter_mut().enumerate() {
        *byte = (index + 1) as u8;
    }
    let mut nonce_point = [0u8; 33];
    nonce_point[0] = 0x02;
    for (index, byte) in nonce_point[1..].iter_mut().enumerate() {
        *byte = (index + 33) as u8;
    }
    assert_eq!(
        host_scalar_material(
            &expected_session,
            &secret,
            0x0102_0304,
            3,
            &public_key,
            &nonce_point
        ),
        [
            0x06, 0x62, 0x19, 0x5a, 0x3e, 0xa9, 0x94, 0x3d, 0xc1, 0x8a, 0x9c, 0x59, 0x72, 0x4d,
            0xa0, 0xde, 0x72, 0xc0, 0xe2, 0xe8, 0x1c, 0xb7, 0x32, 0x04, 0xca, 0x21, 0x74, 0x66,
            0xcf, 0x81, 0xca, 0x62,
        ],
    );

    let mut header = [0u8; HEADER_LEN];
    write_header(&mut header, MessageKind::Request, &expected_session).unwrap();
    assert!(is_message(&header));
    header[4] = 1;
    assert!(!is_message(&header));
    assert!(!is_message(&header[..HEADER_LEN - 1]));
    let mut wrong_magic = header;
    wrong_magic[0] ^= 1;
    assert!(!is_message(&wrong_magic));
    let mut wrong_version = header;
    wrong_version[4] = VERSION.wrapping_add(1);
    assert!(!is_message(&wrong_version));
}

#[test]
fn request_wire_enforces_exact_current_layout() {
    let secret = [7u8; HASH_LEN];

    let layout = request_layout();
    assert_eq!(layout.fixed, 90);

    let mut exact = [0u8; 90];
    assert_eq!(encode_request(&secret, b"", &mut exact), Ok(90));
    let parsed = parse_request(&exact).unwrap();
    assert_eq!(parsed.transaction, b"");
    assert_eq!(parsed.host_commitment, host_commitment(&secret));
    assert_eq!(parsed.transaction_digest, transaction_digest(b""));
    assert_eq!(
        parse_request(&exact[..89]).unwrap_err(),
        WireError::Truncated
    );

    let mut short = [0u8; 89];
    assert_eq!(
        encode_request(&secret, b"", &mut short),
        Err(WireError::OutputTooSmall)
    );
    let mut long = [0xa5u8; 91];
    assert_eq!(encode_request(&secret, b"", &mut long), Ok(90));
    assert_eq!(long[90], 0xa5);
}

#[test]
fn commitment_wire_enforces_capacity_and_count() {
    let session = [3u8; SESSION_ID_LEN];
    let digest = [4u8; HASH_LEN];
    let record = NonceCommitment {
        input_index: 0x0102_0304,
        signature_slot: 3,
        public_key: [5u8; 33],
        nonce_point: [6u8; 33],
    };

    let mut exact = [0u8; 129];
    assert_eq!(
        encode_commitment(&session, &digest, &[record], &mut exact),
        Ok(129)
    );
    let parsed = parse_commitment(&exact).unwrap();
    assert_eq!(parsed.len(), 1);
    assert!(!parsed.is_empty());
    assert_eq!(parsed.record(0), Some(record));
    assert_eq!(parsed.record(1), None);
    let mut short = [0u8; 128];
    assert_eq!(
        encode_commitment(&session, &digest, &[record], &mut short),
        Err(WireError::OutputTooSmall)
    );

    let mut zero_count = [0u8; HEADER_LEN + HASH_LEN + 4];
    write_header(&mut zero_count, MessageKind::Commitment, &session).unwrap();
    zero_count[HEADER_LEN..HEADER_LEN + HASH_LEN].copy_from_slice(&digest);
    assert_eq!(
        parse_commitment(&zero_count).unwrap_err(),
        WireError::TooManyProofs
    );
    assert_eq!(
        parse_commitment(&zero_count[..zero_count.len() - 1]).unwrap_err(),
        WireError::Truncated
    );
}

#[test]
fn reveal_and_signed_wire_enforce_exact_current_capacity() {
    let session = [0x12u8; SESSION_ID_LEN];
    let secret = [0x34u8; HASH_LEN];
    let digest = [0x56u8; HASH_LEN];

    let mut reveal = [0u8; REVEAL_LEN];
    assert_eq!(
        encode_reveal(&session, &secret, &mut reveal),
        Ok(REVEAL_LEN)
    );
    assert_eq!(parse_reveal(&reveal), Ok((session, secret)));
    let mut short_reveal = [0u8; REVEAL_LEN - 1];
    assert_eq!(
        encode_reveal(&session, &secret, &mut short_reveal),
        Err(WireError::OutputTooSmall)
    );
    let mut long_reveal = [0u8; REVEAL_LEN + 1];
    long_reveal[..REVEAL_LEN].copy_from_slice(&reveal);
    assert_eq!(parse_reveal(&long_reveal), Err(WireError::InvalidLength));

    let current_layout = signed_layout();
    assert_eq!(current_layout.fixed, 58);
    assert_eq!(current_layout.proof_len, 5);
    assert_eq!(current_layout.length_bytes, 4);

    let proof = SignatureProof {
        input_index: 0x0102_0304,
        signature_slot: 3,
    };
    let tx = b"xyz";
    let mut signed = [0u8; 70];
    assert_eq!(
        encode_signed(&session, &digest, &[proof], tx, &mut signed),
        Ok(70)
    );
    let parsed = parse_signed(&signed).unwrap();
    assert_eq!(parsed.proof_count(), 1);
    assert_eq!(parsed.proof(0), Some(proof));
    assert_eq!(parsed.proof(1), None);
    assert_eq!(parsed.transaction, tx);
    let mut short_signed = [0u8; 69];
    assert_eq!(
        encode_signed(&session, &digest, &[proof], tx, &mut short_signed),
        Err(WireError::OutputTooSmall)
    );

    let mut zero_count = [0u8; HEADER_LEN + HASH_LEN + 4];
    write_header(&mut zero_count, MessageKind::Signed, &session).unwrap();
    zero_count[HEADER_LEN..HEADER_LEN + HASH_LEN].copy_from_slice(&digest);
    assert_eq!(
        parse_signed(&zero_count).unwrap_err(),
        WireError::TooManyProofs
    );
    assert_eq!(
        parse_signed(&zero_count[..zero_count.len() - 1]).unwrap_err(),
        WireError::Truncated
    );
    assert_eq!(read_signed_proof_count(&zero_count, current_layout), Ok(0));
}

#[test]
fn header_and_integer_helpers_enforce_every_length_boundary() {
    let session = [0x77u8; SESSION_ID_LEN];
    let mut header = [0u8; HEADER_LEN];
    assert_eq!(
        write_header(&mut header, MessageKind::Reveal, &session),
        Ok(())
    );
    assert_eq!(
        parse_header(&header, MessageKind::Reveal)
            .unwrap()
            .session_id,
        session
    );

    let mut short = [0u8; HEADER_LEN - 1];
    assert_eq!(
        write_header(&mut short, MessageKind::Reveal, &session),
        Err(WireError::OutputTooSmall)
    );
    assert_eq!(
        parse_header(&short, MessageKind::Reveal),
        Err(WireError::Truncated)
    );

    let mut bad_magic = header;
    bad_magic[0] ^= 1;
    assert_eq!(
        parse_header(&bad_magic, MessageKind::Reveal),
        Err(WireError::InvalidMagic)
    );
    let mut bad_version = header;
    bad_version[4] = VERSION + 1;
    assert_eq!(
        parse_header(&bad_version, MessageKind::Reveal),
        Err(WireError::UnsupportedVersion)
    );
    assert_eq!(
        parse_header(&header, MessageKind::Request),
        Err(WireError::WrongKind)
    );

    assert_eq!(read_u32(&[0x78, 0x56, 0x34, 0x12]), Ok(0x1234_5678));
    assert_eq!(read_u32(&[0x78, 0x56, 0x34]), Err(WireError::Truncated));
    assert_eq!(read_u32(&[0x78, 0x56, 0x34, 0x12, 0xff]), Ok(0x1234_5678));
}

#[test]
fn request_commit_reveal_round_trip_is_session_bound() {
    let secret = [0x42u8; 32];
    let tx = b"KSPT\x04example";
    let mut buffer = [0u8; 512];
    let len = encode_request(&secret, tx, &mut buffer).unwrap();
    let request = parse_request(&buffer[..len]).unwrap();
    assert_eq!(request.transaction, tx);
    assert!(verify_host_secret(&request.host_commitment, &secret));
    let session_id = request.session_id;

    let reveal_len = encode_reveal(&session_id, &secret, &mut buffer).unwrap();
    let (session, revealed) = parse_reveal(&buffer[..reveal_len]).unwrap();
    assert_eq!(session, session_id);
    assert_eq!(revealed, secret);
}

#[test]
fn tampered_request_transaction_is_rejected() {
    let secret = [7u8; 32];
    let mut buffer = [0u8; 512];
    let len = encode_request(&secret, b"KSPT\x04payload", &mut buffer).unwrap();
    buffer[len - 1] ^= 1;
    assert_eq!(
        parse_request(&buffer[..len]).unwrap_err(),
        WireError::TransactionMismatch
    );
}

#[test]
fn commitment_and_signed_records_round_trip() {
    let session = [3u8; 16];
    let digest = [4u8; 32];
    let record = NonceCommitment {
        input_index: 2,
        signature_slot: 1,
        public_key: [5u8; 33],
        nonce_point: [6u8; 33],
    };
    let proof = SignatureProof {
        input_index: 2,
        signature_slot: 1,
    };
    let tx = b"signed transaction";
    let mut buffer = [0u8; 512];
    let len = encode_commitment(&session, &digest, &[record], &mut buffer).unwrap();
    let parsed = parse_commitment(&buffer[..len]).unwrap();
    assert_eq!(parsed.record(0), Some(record));

    let len = encode_signed(&session, &digest, &[proof], tx, &mut buffer).unwrap();
    let signed = parse_signed(&buffer[..len]).unwrap();
    assert_eq!(signed.proof(0), Some(proof));
    assert_eq!(signed.transaction, tx);
}
