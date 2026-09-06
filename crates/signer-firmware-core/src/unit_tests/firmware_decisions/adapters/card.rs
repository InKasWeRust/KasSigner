use crate::storage::card::{
    classify_card_kind, classify_card_state, command_frame, csd_sector_count,
    decode_card_type_code, map_card_kind, CardKind, CardState,
};

#[test]
fn card_kind_and_state_classification_cover_protocol_states() {
    assert_eq!(classify_card_kind(false, 0), CardKind::V1);
    assert_eq!(classify_card_kind(true, 0), CardKind::V2Standard);
    assert_eq!(classify_card_kind(true, 1 << 30), CardKind::V2HighCapacity);
    assert_eq!(map_card_kind(CardKind::V2Standard, 1, 2, 3), 2);
    assert_eq!(decode_card_type_code(1, 10, 20, 30), Some(10));
    assert_eq!(decode_card_type_code(4, 10, 20, 30), None);
    assert_eq!(classify_card_state(3 << 9), CardState::Standby);
    assert_eq!(classify_card_state(4 << 9), CardState::Transfer);
    assert_eq!(classify_card_state(5 << 9), CardState::Other);
}

#[test]
fn command_frame_is_big_endian_and_sets_the_command_prefix() {
    assert_eq!(
        command_frame(8, 0x1122_3344),
        [0x48, 0x11, 0x22, 0x33, 0x44]
    );
}

#[test]
fn csd_sector_count_handles_v1_and_v2() {
    let mut v2 = [0u8; 16];
    v2[0] = 1 << 6;
    let c_size = 0x3fff_u32;
    v2[7] = ((c_size >> 16) as u8) & 0x3f;
    v2[8] = (c_size >> 8) as u8;
    v2[9] = c_size as u8;
    assert_eq!(csd_sector_count(&v2), Ok(16_777_216));

    let mut v1 = [0u8; 16];
    v1[5] = 9; // READ_BL_LEN = 512 bytes
    let c_size = 1023_u32;
    v1[6] = ((c_size >> 10) as u8) & 0x03;
    v1[7] = (c_size >> 2) as u8;
    v1[8] = ((c_size & 0x03) << 6) as u8;
    let mult = 7_u8;
    v1[9] = (mult >> 1) & 0x03;
    v1[10] = (mult & 1) << 7;
    assert_eq!(csd_sector_count(&v1), Ok(524_288));
}
