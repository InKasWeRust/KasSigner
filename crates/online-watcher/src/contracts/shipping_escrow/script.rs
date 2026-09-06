//! Shipment-escrow covenant script assembly.

use crate::protocol::script::opcode as ops;

use super::state_zero;

pub struct ShippingEscrowScriptRequest<'a> {
    pub seller_pubkey: &'a [u8; 32],
    pub deliverer_pubkey: &'a [u8; 32],
    pub buyer_pubkey: &'a [u8; 32],
    pub arbiter_pubkey: &'a [u8; 32],
    pub product_sompi: u64,
    pub fee_sompi: u64,
    pub cltv1_deadline: u64,
    pub cltv2_deadline: u64,
    pub salt: &'a [u8; 8],
}

pub fn build_ship_escrow_script(
    request: ShippingEscrowScriptRequest<'_>,
) -> Result<Vec<u8>, String> {
    let ShippingEscrowScriptRequest {
        seller_pubkey,
        deliverer_pubkey,
        buyer_pubkey,
        arbiter_pubkey,
        product_sompi,
        fee_sompi,
        cltv1_deadline,
        cltv2_deadline,
        salt,
    } = request;
    let first_tranche = product_sompi / 2;
    let total = product_sompi
        .checked_add(fee_sompi)
        .ok_or("Shipping escrow total exceeds supported monetary range".to_string())?;
    let remainder = total
        .checked_sub(first_tranche)
        .ok_or("Shipping escrow remainder underflow".to_string())?;
    let seller_spk = p2pk_script_public_key(seller_pubkey);
    let deliverer_spk = p2pk_script_public_key(deliverer_pubkey);
    let buyer_spk = p2pk_script_public_key(buyer_pubkey);

    let mut script = Vec::with_capacity(512);
    script.push(0x08);
    script.extend_from_slice(salt);
    script.push(ops::OP_DROP);
    script.push(ops::OP_TX_INPUT_INDEX);
    script.push(ops::OP_TX_INPUT_AMOUNT);
    state_zero::append_dispatch(
        &mut script,
        state_zero::StateZeroConfig {
            total,
            remainder,
            fee_sompi,
            pickup_deadline: cltv1_deadline,
            delivery_deadline: cltv2_deadline,
            seller_spk: &seller_spk,
            deliverer_spk: &deliverer_spk,
            buyer_spk: &buyer_spk,
            deliverer_pubkey,
            buyer_pubkey,
            arbiter_pubkey,
        },
    );
    Ok(script)
}

fn p2pk_script_public_key(pubkey: &[u8; 32]) -> Vec<u8> {
    let mut script_public_key = Vec::with_capacity(36);
    script_public_key.extend_from_slice(&[0x00, 0x00]);
    script_public_key.push(0x20);
    script_public_key.extend_from_slice(pubkey);
    script_public_key.push(ops::OP_CHECKSIG);
    script_public_key
}
