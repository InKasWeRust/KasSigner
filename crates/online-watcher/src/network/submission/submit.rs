use crate::{
    infrastructure::BrowserWebSocketTransport,
    network::{codec::responses::submission, submission::encoder, wrpc::operation::Operation},
    protocol::transaction::consensus::ConsensusTransaction,
};

pub async fn submit(
    websocket_url: &str,
    transaction: &ConsensusTransaction,
) -> Result<String, String> {
    let payload = encoder::encode_submit_request(transaction, false).map_err(String::from)?;
    let transport = BrowserWebSocketTransport::new(websocket_url).map_err(String::from)?;
    let response = transport
        .call(Operation::SubmitTransaction, &payload)
        .await
        .map_err(String::from)?;
    submission::decode(&response).map_err(String::from)
}
