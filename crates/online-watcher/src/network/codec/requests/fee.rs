use crate::network::codec::primitives::WireWriter;

pub fn encode() -> Vec<u8> {
    let mut writer = WireWriter::new();
    writer.write_u16(1);
    writer.into_vec()
}
