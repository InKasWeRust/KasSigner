//! Thin WASM adapter for KIP-20 vault genesis planning.

use wasm_bindgen::prelude::JsValue;

pub(super) use crate::transaction_builder::covenant::vault::genesis::VaultGenesisKind;

#[cfg(test)]
pub(super) use crate::transaction_builder::covenant::vault::genesis::{
    finalize_vault_genesis, prepare_vault_genesis, prepare_vault_genesis_request,
};

pub(super) async fn build_vault_genesis_pskb(
    kind: VaultGenesisKind,
    wallet_json: &str,
    owner_pubkey_hex: &str,
    send_amount: u64,
    fee: u64,
    network: &str,
    ws_url: &str,
) -> Result<String, JsValue> {
    crate::transaction_builder::covenant::vault::genesis::build_vault_genesis_pskb(
        kind,
        wallet_json,
        owner_pubkey_hex,
        send_amount,
        fee,
        network,
        ws_url,
    )
    .await
    .map_err(|error| wasm_error!(&error))
}
