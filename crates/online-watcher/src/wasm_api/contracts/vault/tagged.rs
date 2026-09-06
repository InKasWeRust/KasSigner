use wasm_bindgen::prelude::*;

use super::{
    genesis::{build_vault_genesis_pskb, VaultGenesisKind},
    spend::{build_vault_spend_pskb, VaultSpendKind},
};

#[wasm_bindgen]
pub async fn tagged_vault_genesis_pskb(
    wallet_json: &str,
    owner_pubkey_hex: &str,
    send_amount: u64,
    fee: u64,
    network: &str,
    ws_url: &str,
) -> Result<String, JsValue> {
    build_vault_genesis_pskb(
        VaultGenesisKind::Tagged,
        wallet_json,
        owner_pubkey_hex,
        send_amount,
        fee,
        network,
        ws_url,
    )
    .await
}

#[wasm_bindgen]
pub async fn tagged_vault_spend_pskb(
    covenant_address: &str,
    owner_pubkey_hex: &str,
    covenant_id_hex: &str,
    fee: u64,
    network: &str,
    ws_url: &str,
) -> Result<String, JsValue> {
    build_vault_spend_pskb(
        VaultSpendKind::Tagged,
        covenant_address,
        owner_pubkey_hex,
        covenant_id_hex,
        fee,
        network,
        ws_url,
    )
    .await
}
