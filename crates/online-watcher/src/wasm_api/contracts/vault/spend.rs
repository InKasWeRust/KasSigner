//! Thin WASM adapter for KIP-20 vault continuation planning.

use wasm_bindgen::prelude::JsValue;

pub(super) use crate::transaction_builder::covenant::vault::spend::VaultSpendKind;

#[cfg(test)]
pub(super) use crate::transaction_builder::covenant::vault::spend::{
    decode_covenant_id, encode_vault_spend_pskb, encode_vault_spend_response, finalize_vault_spend,
    prepare_from_utxos, prepare_vault_spend_material, split_vault_amounts,
    validate_covenant_address,
};

pub(super) async fn build_vault_spend_pskb(
    kind: VaultSpendKind,
    covenant_address: &str,
    owner_pubkey_hex: &str,
    covenant_id_hex: &str,
    fee: u64,
    network_name: &str,
    websocket_url: &str,
) -> Result<String, JsValue> {
    crate::transaction_builder::covenant::vault::spend::build_vault_spend_pskb(
        kind,
        covenant_address,
        owner_pubkey_hex,
        covenant_id_hex,
        fee,
        network_name,
        websocket_url,
    )
    .await
    .map_err(|error| wasm_error!(&error))
}
