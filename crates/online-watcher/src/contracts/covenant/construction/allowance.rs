use crate::{account::address::network_prefix, serialization::input::decode_pubkey32};

pub(crate) fn build_local_json(
    owner_pubkey_hex: &str,
    beneficiary_pubkey_hex: &str,
    max_withdraw_sompi: u64,
    min_sequence: u64,
    start_daa: u64,
    network: &str,
) -> Result<String, String> {
    let owner = decode_pubkey32(owner_pubkey_hex)?;
    let beneficiary = decode_pubkey32(beneficiary_pubkey_hex)?;
    let script = crate::contracts::covenant::script::build_allowance_script(
        &owner,
        &beneficiary,
        max_withdraw_sompi,
        min_sequence,
        start_daa,
    );
    let address =
        crate::protocol::script::p2sh::script_to_address(&script, network_prefix(network))?;
    serde_json::to_string(&serde_json::json!({
        "address": address,
        "redeem_script_hex": hex::encode(&script),
        "max_withdraw_sompi": max_withdraw_sompi.to_string(),
        "min_sequence": min_sequence.to_string(),
        "start_daa": start_daa.to_string(),
        "type": "allowance",
    }))
    .map_err(|error| error.to_string())
}

pub(crate) fn build_global_json(
    owner_pubkey_hex: &str,
    beneficiary_pubkey_hex: &str,
    max_withdraw_sompi: u64,
    cooldown_daa: u64,
    start_daa: u64,
    network: &str,
) -> Result<String, String> {
    let owner = decode_pubkey32(owner_pubkey_hex)?;
    let beneficiary = decode_pubkey32(beneficiary_pubkey_hex)?;
    let mut salt = [0u8; 8];
    getrandom::getrandom(&mut salt).map_err(|error| format!("RNG failed: {error}"))?;
    let script = crate::contracts::covenant::script::build_global_allowance_script(
        &owner,
        &beneficiary,
        max_withdraw_sompi,
        cooldown_daa,
        start_daa,
        &salt,
    );
    let address =
        crate::protocol::script::p2sh::script_to_address(&script, network_prefix(network))?;
    serde_json::to_string(&serde_json::json!({
        "address": address,
        "redeem_script_hex": hex::encode(&script),
        "max_withdraw_sompi": max_withdraw_sompi.to_string(),
        "cooldown_daa": cooldown_daa.to_string(),
        "start_daa": start_daa.to_string(),
        "salt": hex::encode(salt),
        "type": "global_allowance",
    }))
    .map_err(|error| error.to_string())
}
