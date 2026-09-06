use crate::{
    infrastructure::BrowserWebSocketTransport,
    network::{
        codec::{requests, responses},
        model::fee_estimate::FeeEstimate,
        wrpc::operation::Operation,
    },
};

pub async fn get(websocket_url: &str) -> Result<FeeEstimate, String> {
    let transport = BrowserWebSocketTransport::new(websocket_url).map_err(String::from)?;
    let response = transport
        .call(Operation::GetFeeEstimate, &requests::fee::encode())
        .await
        .map_err(String::from)?;
    responses::fee::decode(&response).map_err(String::from)
}
