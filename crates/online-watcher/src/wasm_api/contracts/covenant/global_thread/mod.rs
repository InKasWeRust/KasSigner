//! Global-thread WASM façade shared by allowance and spending-limit families.

#[cfg(any(test, target_arch = "wasm32"))]
use crate::wasm_api::utilities::common::parse_u64_field_string;
#[cfg(any(test, target_arch = "wasm32"))]
use serde::Deserialize;

mod boundary;
mod planning;

pub(crate) use crate::transaction_builder::pskb::GlobalThreadFamily;
#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) use boundary::create_topup;
pub(crate) use boundary::create_withdrawal;
#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) use planning::TopupRequest;
pub(crate) use planning::WithdrawalRequest;

#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Deserialize)]
pub(crate) struct TopupApiRequest {
    wallet_json: String,
    covenant_address: String,
    redeem_script_hex: String,
    covenant_id_hex: String,
    thread_utxo_json: String,
    fee: String,
    #[cfg(target_arch = "wasm32")]
    #[serde(default)]
    utxo_indices_csv: String,
    #[cfg(target_arch = "wasm32")]
    ws_url: String,
}

#[cfg(any(test, target_arch = "wasm32"))]
impl TopupApiRequest {
    pub(crate) fn request(&self, family: GlobalThreadFamily) -> Result<TopupRequest<'_>, String> {
        Ok(TopupRequest {
            family,
            wallet_json: &self.wallet_json,
            covenant_address: &self.covenant_address,
            redeem_script_hex: &self.redeem_script_hex,
            covenant_id_hex: &self.covenant_id_hex,
            thread_utxo_json: &self.thread_utxo_json,
            fee: parse_u64_field_string(&self.fee, "fee")?,
            #[cfg(target_arch = "wasm32")]
            utxo_indices_csv: &self.utxo_indices_csv,
            #[cfg(target_arch = "wasm32")]
            websocket_url: &self.ws_url,
        })
    }
}

#[cfg(test)]
mod unit_tests;
