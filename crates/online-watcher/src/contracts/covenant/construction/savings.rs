use crate::{account::address::network_prefix, serialization::input::decode_named_32};

pub(crate) fn build_json(
    wallet1_pubkey_hex: &str,
    wallet2_pubkey_hex: &str,
    locktime_daa: u64,
    network: &str,
) -> Result<String, String> {
    let first = decode_named_32(wallet1_pubkey_hex, "wallet1 pubkey")?;
    let second = decode_named_32(wallet2_pubkey_hex, "wallet2 pubkey")?;
    let script = crate::contracts::covenant::script::build_timelocked_savings_script(
        &first,
        &second,
        locktime_daa,
    );
    let address =
        crate::protocol::script::p2sh::script_to_address(&script, network_prefix(network))?;
    serde_json::to_string(&serde_json::json!({
        "address": address,
        "redeem_script_hex": hex::encode(&script),
        "locktime_daa": locktime_daa.to_string(),
    }))
    .map_err(|error| error.to_string())
}
