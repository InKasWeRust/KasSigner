//! Browser-neutral Merkle whitelist construction and proof services.

use crate::account::address;

pub(crate) fn root_from_addresses(addresses_json: &str) -> Result<String, String> {
    let addresses: Vec<String> =
        serde_json::from_str(addresses_json).map_err(|error| format!("Bad JSON: {error}"))?;
    let leaves = leaves_from_addresses(&addresses)?;
    let depth = (leaves.len() as f64).log2().ceil() as u8;
    let root = crate::contracts::merkle::script::compute_merkle_root(&leaves);
    serde_json::to_string(&serde_json::json!({
        "root": hex::encode(root),
        "depth": depth,
        "leaf_count": addresses.len(),
    }))
    .map_err(|error| error.to_string())
}

pub(crate) fn proof_for_address(
    addresses_json: &str,
    target_address: &str,
) -> Result<String, String> {
    let addresses: Vec<String> =
        serde_json::from_str(addresses_json).map_err(|error| format!("Bad JSON: {error}"))?;
    let leaves = leaves_from_addresses(&addresses)?;
    let target_spk = full_script_public_key(target_address)?;
    let leaf_index = leaves
        .iter()
        .position(|leaf| *leaf == target_spk)
        .ok_or_else(|| "Address not found in whitelist".to_string())?;
    let proof = crate::contracts::merkle::script::generate_merkle_proof(&leaves, leaf_index);
    let proof_json: Vec<_> = proof
        .iter()
        .map(|(sibling, direction)| {
            serde_json::json!({
                "sibling": hex::encode(sibling),
                "direction": *direction,
            })
        })
        .collect();
    serde_json::to_string(&serde_json::json!({
        "proof": proof_json,
        "leaf_spk_hex": hex::encode(&target_spk),
        "leaf_index": leaf_index,
    }))
    .map_err(|error| error.to_string())
}

pub(crate) fn build_whitelist_json(
    owner_pubkey_hex: &str,
    merkle_root_hex: &str,
    depth: u8,
    locktime_daa: u64,
    network: &str,
) -> Result<String, String> {
    let owner = crate::serialization::input::decode_pubkey32(owner_pubkey_hex)?;
    let root_bytes =
        hex::decode(merkle_root_hex).map_err(|error| format!("Bad root hex: {error}"))?;
    let root: [u8; 32] = root_bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("Merkle root must be 32 bytes, got {}", bytes.len()))?;
    let script = crate::contracts::merkle::script::build_merkle_whitelist_script(
        &owner,
        &root,
        depth,
        locktime_daa,
    );
    let covenant_address = crate::protocol::script::p2sh::script_to_address(
        &script,
        address::network_prefix(network),
    )?;
    serde_json::to_string(&serde_json::json!({
        "address": covenant_address,
        "redeem_script_hex": hex::encode(&script),
        "merkle_root": merkle_root_hex,
        "depth": depth,
        "locktime_daa": locktime_daa.to_string(),
    }))
    .map_err(|error| error.to_string())
}

fn leaves_from_addresses(addresses: &[String]) -> Result<Vec<Vec<u8>>, String> {
    addresses
        .iter()
        .map(|value| full_script_public_key(value))
        .collect()
}

fn full_script_public_key(value: &str) -> Result<Vec<u8>, String> {
    let script = address::address_to_script_pubkey(value)?;
    let mut full = Vec::with_capacity(2 + script.len());
    full.extend_from_slice(&[0, 0]);
    full.extend_from_slice(&script);
    Ok(full)
}
