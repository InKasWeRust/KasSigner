use crate::network::{
    codec::{primitives::WireWriter, requests::address::write_address},
    error::NetworkError,
    wrpc::{
        operation::Operation,
        request::{self, WrpcRequest},
    },
};

#[derive(Clone, Copy)]
enum SubscriptionScope {
    BlockAdded = 0,
    UtxosChanged = 4,
}

fn encode_subscription_request(
    request_id: u64,
    scope: SubscriptionScope,
    inner: Vec<u8>,
) -> Result<Vec<u8>, NetworkError> {
    let mut payload = WireWriter::new();
    payload.write_u16(1);
    payload.write_u32(scope as u32);
    payload.write_bytes(&inner)?;
    let payload = payload.into_vec();
    request::encode(&WrpcRequest {
        id: request_id,
        operation: Operation::Subscribe,
        payload: &payload,
    })
}

pub fn block_added(request_id: u64) -> Result<Vec<u8>, NetworkError> {
    let mut inner = WireWriter::new();
    inner.write_u16(1);
    encode_subscription_request(request_id, SubscriptionScope::BlockAdded, inner.into_vec())
}

pub fn utxos_changed(address: &str, request_id: u64) -> Result<Vec<u8>, NetworkError> {
    let mut inner = WireWriter::new();
    inner.write_u16(1);
    inner.write_u32(1);
    write_address(&mut inner, address)?;
    encode_subscription_request(
        request_id,
        SubscriptionScope::UtxosChanged,
        inner.into_vec(),
    )
}
