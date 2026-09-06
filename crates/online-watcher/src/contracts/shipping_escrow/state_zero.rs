//! Funded-state pickup and refund branches.

use crate::protocol::script::{opcode as ops, push_data, push_int, push_pubkey};

use super::state_one;

pub(super) struct StateZeroConfig<'a> {
    pub total: u64,
    pub remainder: u64,
    pub fee_sompi: u64,
    pub pickup_deadline: u64,
    pub delivery_deadline: u64,
    pub seller_spk: &'a [u8],
    pub deliverer_spk: &'a [u8],
    pub buyer_spk: &'a [u8],
    pub deliverer_pubkey: &'a [u8; 32],
    pub buyer_pubkey: &'a [u8; 32],
    pub arbiter_pubkey: &'a [u8; 32],
}

pub(super) fn append_dispatch(script: &mut Vec<u8>, config: StateZeroConfig<'_>) {
    script.push(ops::OP_DUP);
    push_int(script, config.total);
    script.push(ops::OP_EQUAL);
    script.push(ops::OP_IF);
    script.push(ops::OP_DROP);
    append_pickup_or_refund(script, &config);
    script.push(ops::OP_ELSE);
    state_one::append_dispatch(
        script,
        state_one::StateOneConfig {
            remainder: config.remainder,
            fee_sompi: config.fee_sompi,
            delivery_deadline: config.delivery_deadline,
            seller_spk: config.seller_spk,
            deliverer_spk: config.deliverer_spk,
            buyer_spk: config.buyer_spk,
            buyer_pubkey: config.buyer_pubkey,
            arbiter_pubkey: config.arbiter_pubkey,
        },
    );
    script.push(ops::OP_ENDIF);
}

fn append_pickup_or_refund(script: &mut Vec<u8>, config: &StateZeroConfig<'_>) {
    script.push(ops::OP_IF);
    push_pubkey(script, config.deliverer_pubkey);
    script.push(ops::OP_CHECKSIGVERIFY);
    push_int(script, 0);
    script.push(ops::OP_TX_OUTPUT_SPK);
    script.push(ops::OP_TX_INPUT_INDEX);
    script.push(ops::OP_TX_INPUT_SPK);
    script.push(ops::OP_EQUALVERIFY);
    push_int(script, 0);
    script.push(ops::OP_TX_OUTPUT_AMOUNT);
    push_int(script, config.remainder);
    script.push(ops::OP_EQUALVERIFY);
    push_int(script, 1);
    script.push(ops::OP_TX_OUTPUT_SPK);
    push_data(script, config.seller_spk);
    script.push(ops::OP_EQUALVERIFY);
    script.push(ops::OP_TX_OUTPUT_COUNT);
    push_int(script, 2);
    script.push(ops::OP_EQUALVERIFY);
    script.push(0x51);

    script.push(ops::OP_ELSE);
    script.push(ops::OP_IF);
    push_pubkey(script, config.arbiter_pubkey);
    script.push(ops::OP_CHECKSIGVERIFY);
    script.push(ops::OP_ELSE);
    push_int(script, config.pickup_deadline);
    script.push(ops::OP_CHECKLOCKTIMEVERIFY);
    script.push(ops::OP_ENDIF);
    push_int(script, 0);
    script.push(ops::OP_TX_OUTPUT_SPK);
    push_data(script, config.buyer_spk);
    script.push(ops::OP_EQUALVERIFY);
    script.push(ops::OP_TX_OUTPUT_COUNT);
    push_int(script, 1);
    script.push(ops::OP_EQUALVERIFY);
    script.push(0x51);
    script.push(ops::OP_ENDIF);
}
