use crate::{account::address::network_prefix, serialization::input::decode_pubkey32};

pub(crate) fn build_json(
    owner_pubkey_hex: &str,
    heir_pubkey_hex: &str,
    inactivity_daa: u64,
    network: &str,
) -> Result<String, String> {
    let owner = decode_pubkey32(owner_pubkey_hex)?;
    let heir = decode_pubkey32(heir_pubkey_hex)?;
    let script =
        crate::contracts::covenant::script::build_dms_csv_script(&owner, &heir, inactivity_daa);
    let address =
        crate::protocol::script::p2sh::script_to_address(&script, network_prefix(network))?;
    serde_json::to_string(&serde_json::json!({
        "address": address,
        "redeem_script_hex": hex::encode(&script),
        "inactivity_daa": inactivity_daa.to_string(),
    }))
    .map_err(|error| error.to_string())
}
