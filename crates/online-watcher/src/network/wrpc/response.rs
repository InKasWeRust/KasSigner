use crate::network::{codec::primitives::WireReader, error::NetworkError};

use super::operation::Operation;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseKind {
    Success,
    Error(u8),
}

pub struct WrpcResponse<'a> {
    pub id: Option<u64>,
    pub operation: Option<Operation>,
    pub raw_operation: Option<u8>,
    pub kind: ResponseKind,
    pub payload: &'a [u8],
}

fn read_optional_id(reader: &mut WireReader<'_>) -> Result<Option<u64>, NetworkError> {
    match reader.read_u8()? {
        0 => Ok(None),
        1 => Ok(Some(reader.read_u64()?)),
        tag => Err(NetworkError::InvalidEncoding(format!(
            "invalid response id tag {tag}"
        ))),
    }
}

fn read_optional_operation(reader: &mut WireReader<'_>) -> Result<Option<u8>, NetworkError> {
    match reader.read_u8()? {
        0 => Ok(None),
        1 => Ok(Some(reader.read_u8()?)),
        tag => Err(NetworkError::InvalidEncoding(format!(
            "invalid operation tag {tag}"
        ))),
    }
}

fn response_kind(code: u8) -> ResponseKind {
    if code == 0 {
        ResponseKind::Success
    } else {
        ResponseKind::Error(code)
    }
}

pub fn decode(data: &[u8]) -> Result<WrpcResponse<'_>, NetworkError> {
    let mut reader = WireReader::new(data);
    let id = read_optional_id(&mut reader)?;
    let kind = response_kind(reader.read_u8()?);
    let raw_operation = read_optional_operation(&mut reader)?;
    Ok(WrpcResponse {
        id,
        operation: raw_operation.and_then(Operation::from_code),
        raw_operation,
        kind,
        payload: reader.remaining(),
    })
}
