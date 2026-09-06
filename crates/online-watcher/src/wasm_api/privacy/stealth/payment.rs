use crate::wasm_api::utilities::common::js_error;
use crate::wasm_api::utilities::common::{network_to_prefix, parse_wallet_string};
use crate::{
    account::{address, bip32},
    contracts::seq_commit,
    facade::WatchWallet,
    privacy::stealth,
};
use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

pub(super) struct DerivedStealthPayment {
    pub(super) payment: stealth::StealthPayment,
    pub(super) one_time_address: String,
}

struct PreparedStealthPayment {
    payment: stealth::StealthPayment,
    one_time_address: String,
    base_wire: String,
}

pub(super) fn derive_stealth_payment(
    meta_hex: &str,
    entropy_hex: &str,
    network: &str,
) -> Result<DerivedStealthPayment, String> {
    let meta = stealth::decode_stealth_meta(meta_hex)?;
    let entropy: [u8; 32] = hex::decode(entropy_hex)
        .map_err(|error| format!("Bad entropy hex: {error}"))?
        .try_into()
        .map_err(|_: Vec<u8>| "Entropy must be 32 bytes".to_string())?;
    let payment = stealth::generate_stealth_payment(&meta, &entropy)?;
    let one_time_address =
        address::encode_p2pk_address(&payment.one_time_pubkey, network_to_prefix(network));
    Ok(DerivedStealthPayment {
        payment,
        one_time_address,
    })
}

async fn prepare_stealth_payment(
    wallet_json: &str,
    meta_hex: &str,
    amount_sompi: u64,
    fee_sompi: u64,
    entropy_hex: &str,
    ws_url: &str,
    network: &str,
) -> Result<PreparedStealthPayment, JsValue> {
    let derived = derive_stealth_payment(meta_hex, entropy_hex, network).map_err(js_error)?;
    let wallet: bip32::WalletData =
        parse_wallet_string(wallet_json, "Bad wallet").map_err(js_error)?;
    let base_wire = WatchWallet::new()
        .build_transaction(
            &wallet,
            &derived.one_time_address,
            amount_sompi,
            fee_sompi,
            ws_url,
        )
        .await
        .map_err(js_error)?;
    Ok(PreparedStealthPayment {
        payment: derived.payment,
        one_time_address: derived.one_time_address,
        base_wire,
    })
}

#[wasm_bindgen]
pub async fn stealth_create_payment_lane(
    wallet_json: &str,
    meta_hex: &str,
    amount_sompi: u64,
    fee_sompi: u64,
    entropy_hex: &str,
    ws_url: &str,
    network: &str,
) -> Result<String, JsValue> {
    let prepared = prepare_stealth_payment(
        wallet_json,
        meta_hex,
        amount_sompi,
        fee_sompi,
        entropy_hex,
        ws_url,
        network,
    )
    .await?;
    let wire = seq_commit::stamp_stealth_proof(
        &prepared.base_wire,
        &prepared.payment.ephemeral_pubkey,
        prepared.payment.view_tag,
    )
    .map_err(js_error)?;
    Ok(serde_json::json!({
        "pskb_wire": wire,
        "address": prepared.one_time_address,
        "ephemeral_r": hex::encode(prepared.payment.ephemeral_pubkey),
        "view_tag": prepared.payment.view_tag,
    })
    .to_string())
}
