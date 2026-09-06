use crate::network::{codec::primitives::WireWriter, error::NetworkError};

pub fn write_address(writer: &mut WireWriter, address: &str) -> Result<(), NetworkError> {
    let (version, payload) =
        crate::account::address::decode_address(address).map_err(NetworkError::InvalidEncoding)?;
    let prefix = if address.starts_with("kaspatest:") {
        1
    } else if address.starts_with("kaspasim:") {
        2
    } else if address.starts_with("kaspadev:") {
        3
    } else {
        0
    };
    writer.write_u8(prefix);
    writer.write_u8(version);
    writer.write_bytes(&payload)
}
