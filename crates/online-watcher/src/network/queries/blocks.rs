use crate::{
    infrastructure::BrowserWebSocketTransport,
    network::{codec::requests, wrpc::operation::Operation},
};

pub async fn get_raw(websocket_url: &str, hash: &[u8; 32]) -> Result<Vec<u8>, String> {
    let transport = BrowserWebSocketTransport::new(websocket_url).map_err(String::from)?;
    transport
        .call(
            Operation::GetBlock,
            &requests::block::encode_get_block(hash),
        )
        .await
        .map_err(String::from)
}
