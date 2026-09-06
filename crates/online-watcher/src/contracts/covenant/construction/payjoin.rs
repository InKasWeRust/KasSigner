use crate::{account::address::network_prefix, serialization::input::decode_pubkey32};

pub(crate) fn build_json(
    owner_pubkey_hex: &str,
    beneficiary_pubkey_hex: &str,
    locktime_daa: u64,
    min_inputs: u64,
    min_outputs: u64,
    network: &str,
) -> Result<String, String> {
    let owner = decode_pubkey32(owner_pubkey_hex)?;
    let beneficiary = decode_pubkey32(beneficiary_pubkey_hex)?;
    let script = crate::contracts::covenant::script::build_payjoin_covenant_script(
        &owner,
        &beneficiary,
        locktime_daa,
        min_inputs,
        min_outputs,
    );
    let address =
        crate::protocol::script::p2sh::script_to_address(&script, network_prefix(network))?;
    serde_json::to_string(&serde_json::json!({
        "address": address,
        "redeem_script_hex": hex::encode(&script),
        "locktime_daa": locktime_daa.to_string(),
        "min_inputs": min_inputs,
        "min_outputs": min_outputs,
    }))
    .map_err(|error| error.to_string())
}
