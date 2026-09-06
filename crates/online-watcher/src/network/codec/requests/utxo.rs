use crate::network::{codec::primitives::WireWriter, error::NetworkError};

use super::address::write_address;

pub fn encode(addresses: &[String]) -> Result<Vec<u8>, NetworkError> {
    let mut writer = WireWriter::new();
    writer.write_u16(1);
    writer.write_count(addresses.len())?;
    for address in addresses {
        write_address(&mut writer, address)?;
    }
    Ok(writer.into_vec())
}
