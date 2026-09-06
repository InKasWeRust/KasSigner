use crate::runtime::data::AppData;

pub(super) fn derive_hex(ad: &AppData, address_index: u16, liveness: &mut dyn FnMut()) -> Result<[u8; 64], &'static str> {
    let mut private_key = crate::runtime::signing::derive_active_private_key_with_checkpoint(ad, address_index, liveness)?;
    let encoded = encode_hex(&private_key);
    shared_signer::bytes::zeroize_bytes(&mut private_key);
    Ok(encoded)
}

fn encode_hex(input: &[u8; 32]) -> [u8; 64] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = [0u8; 64];
    for (index, byte) in input.iter().copied().enumerate() {
        output[index * 2] = HEX[(byte >> 4) as usize];
        output[index * 2 + 1] = HEX[(byte & 0x0f) as usize];
    }
    output
}
