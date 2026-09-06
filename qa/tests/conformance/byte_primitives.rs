use shared_signer::bytes::{
    decode_hex_nibble, decode_lower_hex_nibble, zeroize_bytes, zeroize_u16,
};

#[test]
fn shared_hex_nibble_decoding_is_consistent() {
    assert_eq!(decode_hex_nibble(b'0'), Some(0));
    assert_eq!(decode_hex_nibble(b'9'), Some(9));
    assert_eq!(decode_hex_nibble(b'a'), Some(10));
    assert_eq!(decode_hex_nibble(b'F'), Some(15));
    assert_eq!(decode_hex_nibble(b'g'), None);
    assert_eq!(decode_lower_hex_nibble(b'f'), Some(15));
    assert_eq!(decode_lower_hex_nibble(b'F'), None);
}

#[test]
fn shared_zeroization_clears_bytes_and_indices() {
    let mut bytes = [1u8, 2, 3, 4];
    let mut indices = [1u16, 2, 3, 4];
    zeroize_bytes(&mut bytes);
    zeroize_u16(&mut indices);
    assert_eq!(bytes, [0; 4]);
    assert_eq!(indices, [0; 4]);
}
