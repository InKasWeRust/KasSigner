use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

/// Build an escrow covenant P2SH address.
#[wasm_bindgen]
pub fn covenant_escrow(
    alice_pubkey_hex: &str,
    bob_pubkey_hex: &str,
    arbiter_pubkey_hex: &str,
    alice_address: &str,
    bob_address: &str,
    network: &str,
) -> Result<String, JsValue> {
    crate::contracts::covenant::construction::escrow::build_random_json(
        alice_pubkey_hex,
        bob_pubkey_hex,
        arbiter_pubkey_hex,
        alice_address,
        bob_address,
        network,
    )
    .map_err(|error| wasm_error!(&error))
}

#[cfg(test)]
pub(crate) fn build_escrow_json(
    alice_pubkey_hex: &str,
    bob_pubkey_hex: &str,
    arbiter_pubkey_hex: &str,
    alice_address: &str,
    bob_address: &str,
    network: &str,
    salt: [u8; 8],
) -> Result<String, String> {
    crate::contracts::covenant::construction::escrow::build_json(
        alice_pubkey_hex,
        bob_pubkey_hex,
        arbiter_pubkey_hex,
        alice_address,
        bob_address,
        network,
        salt,
    )
}
