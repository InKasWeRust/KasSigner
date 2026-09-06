//! Browser-neutral crowdfunding proof and covenant construction services.

use crate::{
    account::{address, address::network_prefix},
    contracts::{
        crowdfund::script::{
            crowdfund_campaign_id as campaign_id_for_script, crowdfund_redeem_script,
            CrowdfundScript,
        },
        zk::proof,
    },
    protocol::script::p2sh,
    serialization::input::decode_pubkey32,
};

pub(crate) const MAX_CROWDFUND_PK_BYTES: usize = 65_535;
pub(crate) const MAX_CROWDFUND_VK_BYTES: usize = 16_384;

pub(crate) fn setup_json() -> Result<String, String> {
    let (proving_key, verifying_key) = proof::crowdfund_trusted_setup()?;
    encode_setup_json(proving_key, verifying_key)
}

pub(crate) fn encode_setup_json(
    proving_key: Vec<u8>,
    verifying_key: Vec<u8>,
) -> Result<String, String> {
    if proving_key.len() > MAX_CROWDFUND_PK_BYTES {
        return Err("Crowdfunding proving key exceeds the supported size limit".to_string());
    }
    if verifying_key.is_empty() || verifying_key.len() > MAX_CROWDFUND_VK_BYTES {
        return Err("Crowdfunding verifying key exceeds the supported size limit".to_string());
    }
    let verifying_key_hash = p2sh::blake2b_hash(&verifying_key);
    serde_json::to_string(&serde_json::json!({
        "pk_hex": hex::encode(proving_key),
        "vk_hex": hex::encode(&verifying_key),
        "vk_hash_hex": hex::encode(verifying_key_hash),
        "vk_len": verifying_key.len(),
    }))
    .map_err(|error| error.to_string())
}

pub(crate) fn build_proof_json(
    proving_key_hex: &str,
    verifying_key_hex: &str,
    amounts_json: &str,
) -> Result<String, String> {
    let proving_key = decode_hex_bounded(
        proving_key_hex,
        "crowdfunding proving key",
        MAX_CROWDFUND_PK_BYTES,
    )?;
    let verifying_key = decode_hex_bounded(
        verifying_key_hex,
        "crowdfunding verifying key",
        MAX_CROWDFUND_VK_BYTES,
    )?;
    let amount_strings: Vec<String> = serde_json::from_str(amounts_json)
        .map_err(|error| format!("Invalid crowdfunding amount JSON: {error}"))?;
    let amounts = amount_strings
        .into_iter()
        .map(|value| {
            value.parse::<u64>().map_err(|_| {
                "Crowdfunding amounts must be exact unsigned decimal strings".to_string()
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (proof_bytes, public_input, total) =
        proof::crowdfund_generate_proof(&proving_key, &amounts)?;
    if !proof::verify_proof(&verifying_key, &proof_bytes, &public_input)? {
        return Err("Generated crowdfunding proof failed local verification".to_string());
    }
    serde_json::to_string(&serde_json::json!({
        "proof_hex": hex::encode(proof_bytes),
        "public_input_hex": hex::encode(public_input),
        "total_sompi": total.to_string(),
        "contribution_count": amounts.len(),
        "verified": true,
    }))
    .map_err(|error| error.to_string())
}

pub(crate) fn compute_campaign_id_hex(
    organizer_address: &str,
    goal_sompi: u64,
    locktime_daa: u64,
    verifying_key_hex: &str,
) -> Result<String, String> {
    let verifying_key = decode_hex_bounded(
        verifying_key_hex,
        "crowdfunding verifying key",
        MAX_CROWDFUND_VK_BYTES,
    )?;
    if verifying_key.is_empty() {
        return Err("Crowdfunding verifying key is empty".to_string());
    }
    let organizer_script = address::address_to_script_pubkey(organizer_address)?;
    let organizer_output_spk = versioned_spk(&organizer_script);
    let verifying_key_hash = p2sh::blake2b_hash(&verifying_key);
    Ok(hex::encode(campaign_id_for_script(
        goal_sompi,
        locktime_daa,
        &verifying_key_hash,
        &organizer_output_spk,
    )))
}

pub(crate) fn build_address_json(
    contributor_pubkey_hex: &str,
    organizer_address: &str,
    goal_sompi: u64,
    locktime_daa: u64,
    verifying_key_hex: &str,
    network: &str,
) -> Result<String, String> {
    let contributor_pubkey = decode_pubkey32(contributor_pubkey_hex)?;
    let verifying_key = decode_hex_bounded(
        verifying_key_hex,
        "crowdfunding verifying key",
        MAX_CROWDFUND_VK_BYTES,
    )?;
    if verifying_key.is_empty() {
        return Err("Crowdfunding verifying key is empty".to_string());
    }
    let mut salt = [0u8; 8];
    getrandom::getrandom(&mut salt).map_err(|error| format!("Crowdfunding RNG failed: {error}"))?;
    if salt.iter().all(|byte| *byte == 0) {
        return Err("Crowdfunding RNG returned an invalid all-zero salt".to_string());
    }
    let organizer_script = address::address_to_script_pubkey(organizer_address)?;
    let organizer_output_spk = versioned_spk(&organizer_script);
    let verifying_key_hash = p2sh::blake2b_hash(&verifying_key);
    let redeem_script = crowdfund_redeem_script(CrowdfundScript {
        contributor_pubkey: &contributor_pubkey,
        goal_sompi,
        locktime_daa,
        verifying_key_hash: &verifying_key_hash,
        organizer_output_spk: &organizer_output_spk,
        salt: &salt,
    })?;
    let covenant_address = p2sh::script_to_address(&redeem_script, network_prefix(network))?;
    serde_json::to_string(&serde_json::json!({
        "address": covenant_address,
        "redeem_script_hex": hex::encode(redeem_script),
        "contributor_pubkey_hex": contributor_pubkey_hex,
        "organizer_address": organizer_address,
        "goal_sompi": goal_sompi.to_string(),
        "locktime_daa": locktime_daa.to_string(),
        "vk_hex": verifying_key_hex,
        "vk_hash_hex": hex::encode(verifying_key_hash),
        "campaign_id": hex::encode(campaign_id_for_script(
            goal_sompi,
            locktime_daa,
            &verifying_key_hash,
            &organizer_output_spk,
        )),
        "crowdfund_salt_hex": hex::encode(salt),
        "crowdfund_role": "contributor",
    }))
    .map_err(|error| error.to_string())
}

pub(crate) fn versioned_spk(script: &[u8]) -> Vec<u8> {
    let mut versioned = Vec::with_capacity(script.len() + 2);
    versioned.extend_from_slice(&[0, 0]);
    versioned.extend_from_slice(script);
    versioned
}

pub(crate) fn decode_hex(value: &str, field: &str) -> Result<Vec<u8>, String> {
    hex::decode(value).map_err(|error| format!("Invalid {field} hex: {error}"))
}

pub(crate) fn decode_hex_bounded(
    value: &str,
    field: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    if value.len() > max_bytes.saturating_mul(2) {
        return Err(format!("{field} exceeds the supported size limit"));
    }
    decode_hex(value, field)
}
