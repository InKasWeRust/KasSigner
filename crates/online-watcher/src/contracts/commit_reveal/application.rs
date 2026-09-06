//! Browser-neutral commit-reveal covenant construction.

pub(crate) fn build_json(
    owner_pubkey_hex: &str,
    committed_hash_hex: &str,
    locktime_daa: u64,
    network: &str,
) -> Result<String, String> {
    let owner_public_key = crate::serialization::input::decode_pubkey32(owner_pubkey_hex)?;
    let committed_hash =
        crate::serialization::input::decode_named_32(committed_hash_hex, "committed hash")?;
    let script = crate::contracts::commit_reveal::script::build_commit_reveal_script(
        &owner_public_key,
        &committed_hash,
        locktime_daa,
    );
    let address = crate::protocol::script::p2sh::script_to_address(
        &script,
        crate::account::address::network_prefix(network),
    )?;
    serde_json::to_string(&serde_json::json!({
        "address": address,
        "redeem_script_hex": hex::encode(&script),
        "committed_hash": committed_hash_hex,
        "locktime_daa": locktime_daa.to_string(),
    }))
    .map_err(|error| error.to_string())
}
