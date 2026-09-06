//! Browser-neutral global-thread allowance/spending-limit planning.
//!
//! This application layer owns wallet parsing, network UTXO acquisition, selection,
//! and delegation to the lower-level PSKB planner. Browser adapters only translate
//! API DTOs, errors, and logs.

#[cfg(target_arch = "wasm32")]
use crate::network;

use crate::transaction_builder::pskb::{
    build_global_thread_withdrawal as build_withdrawal_core, PreparedWithdrawal,
    WithdrawalBuildRequest,
};

#[cfg(any(test, target_arch = "wasm32"))]
use crate::serialization::input::parse_json;

#[cfg(target_arch = "wasm32")]
use crate::transaction_builder::pskb::{
    build_global_thread_topup as build_topup_core, select_wallet_utxos,
};
#[cfg(target_arch = "wasm32")]
use crate::transaction_builder::pskb::{prepare_global_thread_topup_material, PreparedTopup};
#[cfg(all(test, not(target_arch = "wasm32")))]
use crate::transaction_builder::pskb::{prepare_global_thread_topup_material, PreparedTopup};

pub(crate) use crate::transaction_builder::pskb::GlobalThreadFamily;
pub(crate) type WithdrawalRequest<'a> = WithdrawalBuildRequest<'a>;

pub(crate) fn build_withdrawal(
    request: WithdrawalRequest<'_>,
) -> Result<PreparedWithdrawal, String> {
    build_withdrawal_core(request)
}

#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) struct TopupRequest<'a> {
    pub family: GlobalThreadFamily,
    pub wallet_json: &'a str,
    pub covenant_address: &'a str,
    pub redeem_script_hex: &'a str,
    pub covenant_id_hex: &'a str,
    pub thread_utxo_json: &'a str,
    pub fee: u64,
    #[cfg(target_arch = "wasm32")]
    pub utxo_indices_csv: &'a str,
    #[cfg(target_arch = "wasm32")]
    pub websocket_url: &'a str,
}

#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) async fn build_topup(request: TopupRequest<'_>) -> Result<PreparedTopup, String> {
    let wallet: crate::account::bip32::WalletData =
        parse_json(request.wallet_json, "Bad wallet JSON")?;
    let material = prepare_global_thread_topup_material(
        request.family,
        request.covenant_address,
        request.redeem_script_hex,
        request.covenant_id_hex,
        request.thread_utxo_json,
    )?;
    #[cfg(target_arch = "wasm32")]
    {
        let selected =
            fetch_selected_wallet_utxos(request.websocket_url, &wallet, request.utxo_indices_csv)
                .await?;
        return build_topup_core(material, selected, request.fee);
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _wallet = wallet;
        let _material = material;
        let _fee = request.fee;
        Err("Wallet UTXO lookup requires a wasm32 browser target".to_string())
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
async fn fetch_selected_wallet_utxos(
    websocket_url: &str,
    wallet: &crate::account::bip32::WalletData,
    indices_csv: &str,
) -> Result<Vec<crate::account::utxo::UtxoEntry>, String> {
    #[cfg(target_arch = "wasm32")]
    {
        let mut utxos = network::queries::utxos::fetch_all(websocket_url, wallet).await?;
        crate::transaction_builder::selection::sort_for_display(&mut utxos);
        return select_wallet_utxos(&utxos, indices_csv);
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _websocket_url = websocket_url;
        let _wallet = wallet;
        let _indices_csv = indices_csv;
        Err("Wallet UTXO lookup requires a wasm32 browser target".to_string())
    }
}

#[cfg(test)]
mod unit_tests;
