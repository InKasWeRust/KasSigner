use super::super::{codec::responses::dag::virtual_daa_score, error::NetworkError};

fn push_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn response(
    include_pruning_point: bool,
    first_hashes: u32,
    second_hashes: u32,
    score: u64,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(1);
    push_u32(&mut bytes, 2);
    push_u16(&mut bytes, 3);
    bytes.push(4);
    bytes.push(u8::from(include_pruning_point));
    if include_pruning_point {
        push_u32(&mut bytes, 5);
    }
    push_u64(&mut bytes, 6);
    push_u64(&mut bytes, 7);
    push_u32(&mut bytes, first_hashes);
    bytes.extend(std::iter::repeat_n(0x11, first_hashes as usize * 32));
    bytes.extend_from_slice(&8.5f64.to_le_bytes());
    push_u64(&mut bytes, 9);
    push_u32(&mut bytes, second_hashes);
    bytes.extend(std::iter::repeat_n(0x22, second_hashes as usize * 32));
    bytes.extend_from_slice(&[0x33; 32]);
    push_u64(&mut bytes, score);
    bytes
}

#[test]
fn virtual_daa_score_decodes_optional_and_hash_sections() {
    assert_eq!(virtual_daa_score(&response(false, 0, 0, 41)).unwrap(), 41);
    assert_eq!(
        virtual_daa_score(&response(true, 2, 1, u64::MAX)).unwrap(),
        u64::MAX
    );
}

#[test]
fn virtual_daa_score_rejects_every_truncated_suffix() {
    let valid = response(true, 1, 1, 99);
    for length in 0..valid.len() {
        assert!(matches!(
            virtual_daa_score(&valid[..length]),
            Err(NetworkError::TruncatedPayload)
        ));
    }
}

#[test]
fn virtual_daa_score_rejects_hash_counts_larger_than_payload() {
    let mut bytes = response(false, 0, 0, 12);
    let first_count_offset = 1 + 4 + 2 + 1 + 1 + 8 + 8;
    bytes[first_count_offset..first_count_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        virtual_daa_score(&bytes),
        Err(NetworkError::TruncatedPayload)
    ));
}
