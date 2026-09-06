use crate::{account::address, serialization::input::decode_pubkey32};

pub(crate) fn build_json(
    owner_pubkey_hex: &str,
    claimer_pubkey_hex: &str,
    destination_address: &str,
    refund_locktime_daa: u64,
    salt_hex: &str,
    network: &str,
) -> Result<String, String> {
    let owner = decode_pubkey32(owner_pubkey_hex)?;
    let claimer = decode_pubkey32(claimer_pubkey_hex)?;
    let salt_bytes = hex::decode(salt_hex).map_err(|error| format!("Bad salt: {error}"))?;
    let salt: [u8; 16] = salt_bytes
        .try_into()
        .map_err(|_| "Private Swap salt must be 16 bytes".to_string())?;
    let destination = address::address_to_script_pubkey(destination_address)?;
    let script = crate::contracts::covenant::script::build_private_swap_script(
        &owner,
        &claimer,
        &destination,
        refund_locktime_daa,
        &salt,
    )?;
    let covenant_address = crate::protocol::script::p2sh::script_to_address(
        &script,
        address::network_prefix(network),
    )?;
    serde_json::to_string(&serde_json::json!({
        "type": "private-swap",
        "address": covenant_address,
        "redeem_script_hex": hex::encode(script),
        "locktime_daa": refund_locktime_daa.to_string(),
        "destination": destination_address,
        "claimer_pubkey": claimer_pubkey_hex,
        "owner_pubkey": owner_pubkey_hex,
        "salt": salt_hex,
    }))
    .map_err(|error| error.to_string())
}
