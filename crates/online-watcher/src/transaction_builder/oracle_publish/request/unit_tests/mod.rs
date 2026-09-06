use super::*;

#[test]
fn heartbeat_covenant_id_decoder_preserves_all_32_bytes() {
    let value = "ab".repeat(32);
    assert_eq!(decode_heartbeat_covenant_id(&value), Ok([0xab; 32]));
    assert!(decode_heartbeat_covenant_id("00").is_err());
}
