//! Stealth-wallet spend planning.

use crate::{
    account::address,
    serialization::input::decode_named_32,
    transaction_builder::pskb::{application, PskbGlobalPlan, SweepInputPolicy},
};

pub(crate) struct StealthSpendMaterial {
    pub(crate) source_address: String,
    pub(crate) tweak_hex: String,
}

pub(crate) fn prepare_material(
    one_time_pubkey_hex: &str,
    tweak_hex: &str,
    network: &str,
) -> Result<StealthSpendMaterial, String> {
    let public_key = decode_named_32(one_time_pubkey_hex, "pubkey")?;
    decode_named_32(tweak_hex, "tweak")?;
    Ok(StealthSpendMaterial {
        source_address: address::encode_p2pk_address(&public_key, address::network_prefix(network)),
        tweak_hex: tweak_hex.to_string(),
    })
}

pub(crate) async fn build(
    one_time_pubkey_hex: &str,
    tweak_hex: &str,
    destination_address: &str,
    fee: u64,
    websocket_url: &str,
    network: &str,
) -> Result<String, String> {
    let material = prepare_material(one_time_pubkey_hex, tweak_hex, network)?;
    let prepared = application::prepare_sweep(
        websocket_url,
        &material.source_address,
        destination_address,
        fee,
        "No UTXOs at stealth address",
        "Balance too low to cover fee",
    )
    .await?;
    let policy = SweepInputPolicy::p2pk(serde_json::json!({
        "stealthTweak": material.tweak_hex,
    }));
    application::encode(&prepared, PskbGlobalPlan::standard(), &policy)
}
