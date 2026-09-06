use super::{wasm_bindgen, JsValue};

/// Build a true dead man's switch (CSV-based) covenant P2SH address.
/// owner_pubkey_hex / heir_pubkey_hex: 32-byte x-only pubkeys (hex)
/// inactivity_daa: relative DAA units of inactivity before heir can claim
/// Returns JSON: { "address", "redeem_script_hex", "inactivity_daa" }
#[wasm_bindgen]
pub fn covenant_dms(
    owner_pubkey_hex: &str,
    heir_pubkey_hex: &str,
    inactivity_daa: u64,
    network: &str,
) -> Result<String, JsValue> {
    build_dms_json(owner_pubkey_hex, heir_pubkey_hex, inactivity_daa, network)
        .map_err(|error| wasm_error!(&error))
}

pub(crate) fn build_dms_json(
    owner_pubkey_hex: &str,
    heir_pubkey_hex: &str,
    inactivity_daa: u64,
    network: &str,
) -> Result<String, String> {
    crate::contracts::covenant::construction::dms::build_json(
        owner_pubkey_hex,
        heir_pubkey_hex,
        inactivity_daa,
        network,
    )
}
