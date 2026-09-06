use crate::{
    infrastructure::BrowserWebSocketTransport,
    network::{
        codec::{requests, responses},
        wrpc::operation::Operation,
    },
};

pub async fn virtual_daa_score(websocket_url: &str) -> Result<u64, String> {
    let transport = BrowserWebSocketTransport::new(websocket_url).map_err(String::from)?;
    let response = transport
        .call(
            Operation::GetBlockDagInfo,
            &requests::block::encode_empty_query(),
        )
        .await
        .map_err(String::from)?;
    responses::dag::virtual_daa_score(&response).map_err(String::from)
}
