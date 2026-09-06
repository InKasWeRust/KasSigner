use crate::network::{codec::primitives::WireWriter, error::NetworkError};

use super::operation::Operation;

pub struct WrpcRequest<'a> {
    pub id: u64,
    pub operation: Operation,
    pub payload: &'a [u8],
}

pub fn encode(request: &WrpcRequest<'_>) -> Result<Vec<u8>, NetworkError> {
    let mut writer = WireWriter::with_capacity(32 + request.payload.len());
    writer.write_u8(1);
    writer.write_u64(request.id);
    writer.write_u8(request.operation.code());
    writer.write_bytes(request.payload)?;
    Ok(writer.into_vec())
}
