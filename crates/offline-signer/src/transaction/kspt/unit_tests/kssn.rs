use crate::transaction::model::SigHashType;

use super::super::{PsktError, SignedResponse};

#[test]
fn kssn_rejects_trailing_data() {
    let mut response = SignedResponse::new();
    response
        .add_signature(0, SigHashType::All, &[0x88; 64])
        .expect("add signature");
    let mut wire = [0u8; 256];
    let len = response.serialize(&mut wire).expect("serialize KSSN");
    wire[len] = 0xee;
    assert!(matches!(
        SignedResponse::parse(&wire[..len + 1]),
        Err(PsktError::TrailingData)
    ));
}

#[test]
fn kssn_builder_rejects_duplicate_input_indexes() {
    let mut response = SignedResponse::new();
    response
        .add_signature(0, SigHashType::All, &[0x11; 64])
        .expect("first signature");
    assert_eq!(
        response.add_signature(0, SigHashType::All, &[0x22; 64]),
        Err(PsktError::InvalidSignatureState)
    );

    let mut wire = [0u8; 256];
    assert!(response.serialize(&mut wire).is_ok());
    assert_eq!(response.signatures.len(), 1);
}

#[test]
fn kssn_parser_rejects_duplicate_input_indexes() {
    let mut response = SignedResponse::new();
    response
        .add_signature(0, SigHashType::All, &[0x11; 64])
        .expect("first signature");
    response
        .add_signature(1, SigHashType::All, &[0x22; 64])
        .expect("second signature");

    let mut wire = [0u8; 256];
    let len = response.serialize(&mut wire).expect("serialize KSSN");
    const V2_HEADER_LEN: usize = 4 + 1 + 4;
    const V2_RECORD_LEN: usize = 4 + 1 + 64;
    let second_input_index = V2_HEADER_LEN + V2_RECORD_LEN;
    wire[second_input_index..second_input_index + 4].fill(0);

    assert!(matches!(
        SignedResponse::parse(&wire[..len]),
        Err(PsktError::InvalidSignatureState)
    ));
}

#[test]
fn kssn_parser_rejects_retired_v1() {
    let mut wire = [0u8; 4 + 1 + 1 + 1 + 1 + 64];
    wire[..4].copy_from_slice(b"KSSN");
    wire[4] = 1;
    wire[5] = 1;
    wire[6] = 7;
    wire[7] = SigHashType::All.to_byte();
    wire[8..].fill(0x5a);

    assert_eq!(
        SignedResponse::parse(&wire).unwrap_err(),
        PsktError::UnsupportedVersion
    );
}

#[test]
fn kssn_parser_covers_magic_sighash_and_empty_envelope_boundaries() {
    let mut empty = [0u8; 9];
    empty[..4].copy_from_slice(b"KSSN");
    empty[4] = 2;
    assert!(SignedResponse::parse(&empty)
        .expect("empty KSSN")
        .signatures
        .is_empty());

    let mut bad_magic = empty;
    bad_magic[0] ^= 0x01;
    assert_eq!(
        SignedResponse::parse(&bad_magic).unwrap_err(),
        PsktError::InvalidMagic
    );

    let mut one = SignedResponse::new();
    one.add_signature(7, SigHashType::All, &[0x42; 64])
        .expect("signature");
    let mut wire = [0u8; 128];
    let len = one.serialize(&mut wire).expect("serialize KSSN");
    // KSSN header = magic(4) + version(1) + count(4), then input index(4).
    wire[13] = 0xff;
    assert_eq!(
        SignedResponse::parse(&wire[..len]).unwrap_err(),
        PsktError::InvalidSigHashType
    );
}
