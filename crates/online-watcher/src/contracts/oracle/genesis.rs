//! Browser-neutral Oracle Model-B genesis construction.

use serde::Deserialize;

use crate::{
    account::address::network_prefix,
    serialization::input::{decode_named_32, parse_named_json, parse_u64},
};

#[derive(Clone, Deserialize)]
struct OracleGenesisRequest {
    genesis_price: String,
    genesis_t: String,
    image_id_hex: String,
    control_id_hex: String,
    set_root_hex: String,
    hashfn_hex: String,
    heartbeat_cov_id_hex: String,
    network: String,
}

struct OracleGenesisMaterial {
    request: OracleGenesisRequest,
    genesis_price: u64,
    genesis_t: u64,
    image_id: [u8; 32],
    control_id: [u8; 32],
    set_root: [u8; 32],
    heartbeat_cov_id: [u8; 32],
    hashfn: u8,
}

pub(crate) fn build_json(request_json: &str) -> Result<String, String> {
    let request: OracleGenesisRequest = parse_named_json(request_json, "oracle genesis request")?;
    serialize(decode(request)?)
}

pub(crate) fn build_heartbeat_json(network: &str) -> Result<String, String> {
    let redeem = crate::contracts::oracle::script::build_oracle_mb_heartbeat_script();
    let address =
        crate::protocol::script::p2sh::script_to_address(&redeem, network_prefix(network))?;
    serde_json::to_string(&serde_json::json!({
        "address": address,
        "redeem_script_hex": hex::encode(&redeem),
        "redeem_len": redeem.len(),
        "sig_op_count": crate::contracts::oracle::script::ORACLE_MB_HEARTBEAT_SIG_OP_COUNT,
    }))
    .map_err(|error| error.to_string())
}

fn decode(request: OracleGenesisRequest) -> Result<OracleGenesisMaterial, String> {
    Ok(OracleGenesisMaterial {
        genesis_price: parse_u64(&request.genesis_price, "genesis_price")?,
        genesis_t: parse_u64(&request.genesis_t, "genesis_t")?,
        image_id: decode_named_32(&request.image_id_hex, "image_id")?,
        control_id: decode_named_32(&request.control_id_hex, "control_id")?,
        set_root: decode_named_32(&request.set_root_hex, "set_root")?,
        heartbeat_cov_id: decode_named_32(&request.heartbeat_cov_id_hex, "heartbeat_cov_id")?,
        hashfn: decode_hashfn(&request.hashfn_hex)?,
        request,
    })
}

fn decode_hashfn(value: &str) -> Result<u8, String> {
    let bytes = hex::decode(value).map_err(|error| format!("Bad hashfn hex: {error}"))?;
    bytes
        .first()
        .copied()
        .filter(|_| bytes.len() == 1)
        .ok_or_else(|| "hashfn must be 1 byte".to_string())
}

fn serialize(material: OracleGenesisMaterial) -> Result<String, String> {
    let redeem = crate::contracts::oracle::script::build_oracle_mb_genesis_redeem(
        material.genesis_price,
        material.genesis_t,
        &material.image_id,
        &material.control_id,
        &material.set_root,
        material.hashfn,
        &material.heartbeat_cov_id,
    );
    let address = crate::protocol::script::p2sh::script_to_address(
        &redeem,
        network_prefix(&material.request.network),
    )?;
    serde_json::to_string(&serde_json::json!({
        "address": address,
        "redeem_script_hex": hex::encode(&redeem),
        "genesis_price": material.genesis_price,
        "genesis_t": material.genesis_t,
        "image_id": material.request.image_id_hex,
        "control_id": material.request.control_id_hex,
        "set_root": material.request.set_root_hex,
        "redeem_len": redeem.len(),
        "sig_op_count": crate::contracts::oracle::script::ORACLE_MB_SIG_OP_COUNT,
    }))
    .map_err(|error| error.to_string())
}
