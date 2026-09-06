use crate::network::codec::primitives::WireWriter;

pub fn encode_empty_query() -> Vec<u8> {
    let mut writer = WireWriter::new();
    writer.write_u16(1);
    writer.into_vec()
}

pub fn encode_get_block(hash: &[u8; 32]) -> Vec<u8> {
    let mut writer = WireWriter::with_capacity(35);
    writer.write_u16(1);
    writer.write_raw(hash);
    writer.write_u8(1);
    writer.into_vec()
}
