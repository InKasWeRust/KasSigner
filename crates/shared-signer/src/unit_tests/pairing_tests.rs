use std::vec;

use crate::pairing::{
    account_fingerprint, encode_request, encode_response_header, parse_request, parse_response,
    AddressBatchRequest, PairingError, ACCOUNT_FINGERPRINT_LEN, MAX_BATCH_PER_CHAIN, NONCE_LEN,
    REQUEST_LEN, RESPONSE_HEADER_LEN, SOFT_INDEX_LIMIT,
};

fn request(
    receive_start: u32,
    receive_count: u8,
    change_start: u32,
    change_count: u8,
) -> AddressBatchRequest {
    AddressBatchRequest::new(
        [0xA5; NONCE_LEN],
        receive_start,
        receive_count,
        change_start,
        change_count,
    )
}

#[test]
fn privacy_pairing_request_round_trips_nonce_and_explicit_ranges() {
    let request = request(20, 20, 40, 10);
    let mut wire = [0u8; REQUEST_LEN];
    assert_eq!(encode_request(request, &mut wire), Ok(REQUEST_LEN));
    assert_eq!(parse_request(&wire), Ok(request));
}

#[test]
fn privacy_pairing_rejects_stateful_or_hardened_ranges() {
    let empty = request(0, 0, 0, 0);
    let too_large = request(0, MAX_BATCH_PER_CHAIN + 1, 0, 0);
    let past_soft_range = request(SOFT_INDEX_LIMIT - 10, 20, 0, 0);
    assert_eq!(empty.validate(), Err(PairingError::EmptyBatch));
    assert_eq!(too_large.validate(), Err(PairingError::BatchTooLarge));
    assert_eq!(
        past_soft_range.validate(),
        Err(PairingError::RangeOutsideSoftDerivation)
    );
}

#[test]
fn privacy_pairing_response_binds_nonce_fingerprint_and_key_order() {
    let request = request(5, 2, 7, 1);
    let fingerprint = [0x5A; ACCOUNT_FINGERPRINT_LEN];
    let mut wire = vec![0u8; RESPONSE_HEADER_LEN + 3 * 32];
    let mut cursor = encode_response_header(request, fingerprint, &mut wire).expect("header");
    wire[cursor..cursor + 32].fill(0x11);
    cursor += 32;
    wire[cursor..cursor + 32].fill(0x22);
    cursor += 32;
    wire[cursor..cursor + 32].fill(0x33);

    let response = parse_response(&wire).expect("response");
    assert_eq!(response.request(), request);
    assert_eq!(response.account_fingerprint(), fingerprint);
    assert_eq!(response.receive_key(0), Some(&[0x11; 32]));
    assert_eq!(response.receive_key(1), Some(&[0x22; 32]));
    assert_eq!(response.change_key(0), Some(&[0x33; 32]));
    assert!(response.change_key(1).is_none());
}

#[test]
fn privacy_pairing_response_requires_exact_length() {
    let request = request(0, 1, 0, 0);
    let mut wire = vec![0u8; RESPONSE_HEADER_LEN + 32];
    encode_response_header(request, [0u8; ACCOUNT_FINGERPRINT_LEN], &mut wire).expect("header");
    assert!(parse_response(&wire[..wire.len() - 1]).is_err());
}

#[test]
fn account_fingerprint_is_domain_bound_and_stable() {
    let pubkey = [0x02; 33];
    let chain = [0x03; 32];
    let first = account_fingerprint(&pubkey, &chain);
    assert_eq!(first, account_fingerprint(&pubkey, &chain));
    assert_ne!(first, account_fingerprint(&[0x04; 33], &chain));
}
