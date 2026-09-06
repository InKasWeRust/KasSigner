use crate::network::codec::responses::utxo;

#[test]
fn short_utxo_response_is_an_empty_set() {
    assert!(utxo::decode(&[])
        .expect("empty response should decode")
        .is_empty());
}

#[test]
fn malformed_utxo_wrapper_is_rejected() {
    assert!(utxo::decode(&[1, 1, 0, 0, 0, 0]).is_err());
}

#[test]
fn utxo_response_vector_is_stable() {
    let bytes = hex::decode(concat!(
        "0177000000010071000000010000006900000001002500000001",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "030000003a000000020400000000000000000001000000510500000000000000",
        "00013333333333333333333333333333333333333333333333333333333333333333"
    ))
    .expect("fixture hex should decode");
    let entries = utxo::decode(&bytes).expect("UTXO response should decode");

    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry.tx_id, "22".repeat(32));
    assert_eq!(entry.index, 3);
    assert_eq!(entry.amount, 4);
    assert_eq!(entry.script_public_key, [0x51]);
    assert_eq!(entry.block_daa_score, 5);
    let expected_covenant_id = "33".repeat(32);
    assert_eq!(
        entry.covenant_id.as_deref(),
        Some(expected_covenant_id.as_str())
    );
}

fn bytes_field(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
    out
}

fn wrap_entries(entries_blob: &[u8]) -> Vec<u8> {
    let mut outer = 1u16.to_le_bytes().to_vec();
    outer.extend_from_slice(&bytes_field(entries_blob));
    let mut response = vec![1];
    response.extend_from_slice(&bytes_field(&outer));
    response
}

fn encoded_entry(
    optional_tag: u8,
    outpoint_len: usize,
    version: u8,
    covenant_tag: Option<u8>,
) -> Vec<u8> {
    let mut entry = vec![0, optional_tag];
    if optional_tag == 1 {
        entry.extend_from_slice(&[0, 0]);
        entry.extend_from_slice(&bytes_field(&[]));
    }
    let mut outpoint = vec![0; outpoint_len];
    if outpoint_len >= 37 {
        outpoint[1..33].fill(0x22);
        outpoint[33..37].copy_from_slice(&3u32.to_le_bytes());
    }
    entry.extend_from_slice(&bytes_field(&outpoint));

    let mut utxo = vec![version];
    utxo.extend_from_slice(&4u64.to_le_bytes());
    utxo.extend_from_slice(&0u16.to_le_bytes());
    utxo.extend_from_slice(&bytes_field(&[0x51]));
    utxo.extend_from_slice(&5u64.to_le_bytes());
    utxo.push(0);
    if let Some(tag) = covenant_tag {
        utxo.push(tag);
        if tag == 1 {
            utxo.extend_from_slice(&[0x33; 32]);
        }
    }
    entry.extend_from_slice(&bytes_field(&utxo));
    entry
}

fn one_entry_response(entry: &[u8]) -> Vec<u8> {
    let mut entries = 1u32.to_le_bytes().to_vec();
    entries.extend_from_slice(&bytes_field(entry));
    wrap_entries(&entries)
}

fn repeated_entry_response(entry: &[u8], count: u32) -> Vec<u8> {
    let mut entries = count.to_le_bytes().to_vec();
    for _ in 0..count {
        entries.extend_from_slice(&bytes_field(entry));
    }
    wrap_entries(&entries)
}

#[test]
fn utxo_response_preserves_every_entry_in_multi_entry_reply() {
    let response = repeated_entry_response(&encoded_entry(0, 37, 1, None), 5);
    let entries = utxo::decode(&response).expect("multi-entry UTXO response should decode");
    assert_eq!(entries.len(), 5);
}

#[test]
fn utxo_response_covers_empty_count_limit_optional_and_outpoint_boundaries() {
    assert!(utxo::decode(&wrap_entries(&[])).unwrap().is_empty());

    let too_many = (1_000_001u32).to_le_bytes();
    assert!(utxo::decode(&wrap_entries(&too_many)).is_err());

    let no_optional = one_entry_response(&encoded_entry(0, 37, 1, None));
    let entries = utxo::decode(&no_optional).expect("entry without optional envelope");
    assert_eq!(entries.len(), 1);
    assert!(entries[0].covenant_id.is_none());

    let short_outpoint = one_entry_response(&encoded_entry(0, 36, 1, None));
    assert!(utxo::decode(&short_outpoint).is_err());
}

#[test]
fn utxo_response_skips_present_optional_metadata_and_rejects_truncation() {
    let with_metadata = one_entry_response(&encoded_entry(1, 37, 2, Some(1)));
    let entries = utxo::decode(&with_metadata).expect("entry with optional metadata");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].tx_id, "22".repeat(32));
    let expected_covenant_id = "33".repeat(32);
    assert_eq!(
        entries[0].covenant_id.as_deref(),
        Some(expected_covenant_id.as_str())
    );

    let truncated_metadata = one_entry_response(&[0, 1, 0, 0, 4, 0, 0, 0, 0xaa]);
    assert!(utxo::decode(&truncated_metadata).is_err());
}

#[test]
fn utxo_response_covers_both_covenant_version_short_circuit_paths() {
    let version_one = one_entry_response(&encoded_entry(0, 37, 1, None));
    assert!(utxo::decode(&version_one).unwrap()[0].covenant_id.is_none());

    let version_two_without_covenant = one_entry_response(&encoded_entry(0, 37, 2, Some(0)));
    assert!(utxo::decode(&version_two_without_covenant).unwrap()[0]
        .covenant_id
        .is_none());
}

#[test]
fn utxo_response_accepts_length_prefix_whose_first_byte_is_sentinel() {
    let mut outer = 1u16.to_le_bytes().to_vec();
    outer.extend_from_slice(&bytes_field(&[]));
    outer.resize(255, 0);
    let mut response = 255u32.to_le_bytes().to_vec();
    response.extend_from_slice(&outer);
    assert!(utxo::decode(&response).unwrap().is_empty());
}
