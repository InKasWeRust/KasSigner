//! Shipping-escrow construction and tranche economics.

use serde::Deserialize;

use crate::{
    account::address::network_prefix,
    serialization::input::{decode_pubkey32, parse_named_json, parse_u64},
};

#[derive(Clone, Deserialize)]
struct ShippingEscrowRequest {
    seller_pubkey_hex: String,
    deliverer_pubkey_hex: String,
    buyer_pubkey_hex: String,
    arbiter_pubkey_hex: String,
    product_sompi: String,
    fee_sompi: String,
    cltv1_deadline: String,
    cltv2_deadline: String,
    network: String,
}

struct ShippingEscrowMaterial {
    request: ShippingEscrowRequest,
    salt: [u8; 8],
    product: u64,
    fee: u64,
    first_deadline: u64,
    second_deadline: u64,
    seller: [u8; 32],
    deliverer: [u8; 32],
    buyer: [u8; 32],
    arbiter: [u8; 32],
    total: u64,
}

pub(crate) fn build_random_json(request_json: &str) -> Result<String, String> {
    let mut salt = [0u8; 8];
    getrandom::getrandom(&mut salt).map_err(|error| format!("RNG failed: {error}"))?;
    build_json(request_json, salt)
}

pub(crate) fn build_json(request_json: &str, salt: [u8; 8]) -> Result<String, String> {
    let request = parse_named_json(request_json, "shipping escrow request")?;
    let material = decode(request, salt)?;
    serialize(material)
}

fn decode(request: ShippingEscrowRequest, salt: [u8; 8]) -> Result<ShippingEscrowMaterial, String> {
    let product = parse_u64(&request.product_sompi, "product_sompi")?;
    let fee = parse_u64(&request.fee_sompi, "fee_sompi")?;
    let first_deadline = parse_u64(&request.cltv1_deadline, "cltv1_deadline")?;
    let second_deadline = parse_u64(&request.cltv2_deadline, "cltv2_deadline")?;
    let seller = decode_pubkey32(&request.seller_pubkey_hex)?;
    let deliverer = decode_pubkey32(&request.deliverer_pubkey_hex)?;
    let buyer = decode_pubkey32(&request.buyer_pubkey_hex)?;
    let arbiter = decode_pubkey32(&request.arbiter_pubkey_hex)?;
    let total = product
        .checked_add(fee)
        .ok_or("Shipping escrow total overflows u64".to_string())?;
    Ok(ShippingEscrowMaterial {
        request,
        salt,
        product,
        fee,
        first_deadline,
        second_deadline,
        seller,
        deliverer,
        buyer,
        arbiter,
        total,
    })
}

fn serialize(material: ShippingEscrowMaterial) -> Result<String, String> {
    let first_tranche = material.product / 2;
    let second_tranche = material
        .product
        .checked_sub(first_tranche)
        .ok_or("Shipping escrow second tranche underflow".to_string())?;
    let remaining = material
        .total
        .checked_sub(first_tranche)
        .ok_or("Shipping escrow remaining balance underflow".to_string())?;
    let script = crate::contracts::shipping_escrow::script::build_ship_escrow_script(
        crate::contracts::shipping_escrow::script::ShippingEscrowScriptRequest {
            seller_pubkey: &material.seller,
            deliverer_pubkey: &material.deliverer,
            buyer_pubkey: &material.buyer,
            arbiter_pubkey: &material.arbiter,
            product_sompi: material.product,
            fee_sompi: material.fee,
            cltv1_deadline: material.first_deadline,
            cltv2_deadline: material.second_deadline,
            salt: &material.salt,
        },
    )?;
    let address = crate::protocol::script::p2sh::script_to_address(
        &script,
        network_prefix(&material.request.network),
    )?;
    serde_json::to_string(&serde_json::json!({
        "address": address,
        "redeem_script_hex": hex::encode(&script),
        "salt": hex::encode(material.salt),
        "product_sompi": material.product.to_string(),
        "fee_sompi": material.fee.to_string(),
        "t1_sompi": first_tranche.to_string(),
        "t2_sompi": second_tranche.to_string(),
        "total_sompi": material.total.to_string(),
        "rem_sompi": remaining.to_string(),
        "cltv1_deadline": material.first_deadline.to_string(),
        "cltv2_deadline": material.second_deadline.to_string(),
        "type": "ship-escrow",
    }))
    .map_err(|error| error.to_string())
}
