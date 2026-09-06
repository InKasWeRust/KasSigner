use crate::network::codec::responses::fee;

#[test]
fn short_fee_response_uses_conservative_fallback() {
    let estimate = fee::decode(&[]).expect("fallback should be available");
    assert_eq!(estimate.priority_sompi_per_gram, 1.0);
    assert_eq!(estimate.normal_sompi_per_gram, 1.0);
    assert_eq!(estimate.low_sompi_per_gram, 1.0);
    assert_eq!(estimate.suggested_fee, 10_000);
}

#[test]
fn fee_response_vector_is_stable() {
    let bytes = hex::decode(concat!(
        "014000000001003a000000010000000000000000400000000000000840",
        "0100000000000000000010400000000000001440010000000000000000001840",
        "0000000000001c40"
    ))
    .expect("fixture hex should decode");
    let estimate = fee::decode(&bytes).expect("fee response should decode");

    assert_eq!(estimate.priority_sompi_per_gram, 2.0);
    assert_eq!(estimate.priority_seconds, 3.0);
    assert_eq!(estimate.normal_sompi_per_gram, 4.0);
    assert_eq!(estimate.normal_seconds, 5.0);
    assert_eq!(estimate.low_sompi_per_gram, 6.0);
    assert_eq!(estimate.low_seconds, 7.0);
    assert_eq!(estimate.suggested_fee, 10_000);
}

fn bytes_field(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
    out
}

fn fee_payload(normal: &[(f64, f64)], low: &[(f64, f64)]) -> Vec<u8> {
    let mut estimate = Vec::new();
    estimate.extend_from_slice(&1u16.to_le_bytes());
    estimate.extend_from_slice(&2.0f64.to_le_bytes());
    estimate.extend_from_slice(&3.0f64.to_le_bytes());
    estimate.extend_from_slice(&(normal.len() as u32).to_le_bytes());
    for (rate, seconds) in normal {
        estimate.extend_from_slice(&rate.to_le_bytes());
        estimate.extend_from_slice(&seconds.to_le_bytes());
    }
    estimate.extend_from_slice(&(low.len() as u32).to_le_bytes());
    for (rate, seconds) in low {
        estimate.extend_from_slice(&rate.to_le_bytes());
        estimate.extend_from_slice(&seconds.to_le_bytes());
    }
    let mut outer = 1u16.to_le_bytes().to_vec();
    outer.extend_from_slice(&bytes_field(&estimate));
    let mut response = vec![1];
    response.extend_from_slice(&bytes_field(&outer));
    response
}

#[test]
fn fee_response_covers_multiple_bucket_selection_and_count_limit() {
    let response = fee_payload(&[(4.0, 5.0), (40.0, 50.0)], &[(6.0, 7.0), (60.0, 70.0)]);
    let estimate = fee::decode(&response).expect("multi-bucket fee response");
    assert_eq!(
        (estimate.normal_sompi_per_gram, estimate.normal_seconds),
        (4.0, 5.0)
    );
    assert_eq!(
        (estimate.low_sompi_per_gram, estimate.low_seconds),
        (6.0, 7.0)
    );

    let mut bad_estimate = Vec::new();
    bad_estimate.extend_from_slice(&1u16.to_le_bytes());
    bad_estimate.extend_from_slice(&2.0f64.to_le_bytes());
    bad_estimate.extend_from_slice(&3.0f64.to_le_bytes());
    bad_estimate.extend_from_slice(&10_001u32.to_le_bytes());
    let mut outer = 1u16.to_le_bytes().to_vec();
    outer.extend_from_slice(&bytes_field(&bad_estimate));
    let mut response = vec![1];
    response.extend_from_slice(&bytes_field(&outer));
    assert!(fee::decode(&response).is_err());
}

#[test]
fn fee_response_accepts_length_prefix_whose_first_byte_is_sentinel() {
    // Sentinel 255 makes the decoder rewind and interpret the first four bytes
    // as the outer length. Supply exactly 255 bytes of outer data.
    let estimate = {
        let mut value = Vec::new();
        value.extend_from_slice(&1u16.to_le_bytes());
        value.extend_from_slice(&2.0f64.to_le_bytes());
        value.extend_from_slice(&3.0f64.to_le_bytes());
        value.extend_from_slice(&0u32.to_le_bytes());
        value.extend_from_slice(&0u32.to_le_bytes());
        value
    };
    let mut outer = 1u16.to_le_bytes().to_vec();
    outer.extend_from_slice(&bytes_field(&estimate));
    outer.resize(255, 0);
    let mut response = 255u32.to_le_bytes().to_vec();
    response.extend_from_slice(&outer);
    let estimate = fee::decode(&response).expect("sentinel-prefixed fee response");
    assert_eq!(estimate.normal_sompi_per_gram, 1.0);
    assert_eq!(estimate.low_sompi_per_gram, 1.0);
}
