//! In-transit delivery, award, timeout, and refund branches.

use crate::protocol::script::{opcode as ops, push_data, push_int, push_pubkey};

pub(super) struct StateOneConfig<'a> {
    pub remainder: u64,
    pub fee_sompi: u64,
    pub delivery_deadline: u64,
    pub seller_spk: &'a [u8],
    pub deliverer_spk: &'a [u8],
    pub buyer_spk: &'a [u8],
    pub buyer_pubkey: &'a [u8; 32],
    pub arbiter_pubkey: &'a [u8; 32],
}

pub(super) fn append_dispatch(script: &mut Vec<u8>, config: StateOneConfig<'_>) {
    script.push(ops::OP_DUP);
    push_int(script, config.remainder);
    script.push(ops::OP_EQUAL);
    script.push(ops::OP_IF);
    script.push(ops::OP_DROP);
    append_delivery_or_refund(script, &config);
    script.push(ops::OP_ELSE);
    script.push(ops::OP_DROP);
    script.push(ops::OP_0);
    script.push(ops::OP_ENDIF);
}

fn append_delivery_or_refund(script: &mut Vec<u8>, config: &StateOneConfig<'_>) {
    script.push(ops::OP_IF);
    script.push(ops::OP_IF);
    push_pubkey(script, config.buyer_pubkey);
    script.push(ops::OP_CHECKSIGVERIFY);
    script.push(ops::OP_ELSE);
    script.push(ops::OP_IF);
    push_pubkey(script, config.arbiter_pubkey);
    script.push(ops::OP_CHECKSIGVERIFY);
    script.push(ops::OP_ELSE);
    push_int(script, config.delivery_deadline);
    script.push(ops::OP_CHECKLOCKTIMEVERIFY);
    script.push(ops::OP_ENDIF);
    script.push(ops::OP_ENDIF);
    push_int(script, 0);
    script.push(ops::OP_TX_OUTPUT_SPK);
    push_data(script, config.seller_spk);
    script.push(ops::OP_EQUALVERIFY);
    push_int(script, 1);
    script.push(ops::OP_TX_OUTPUT_SPK);
    push_data(script, config.deliverer_spk);
    script.push(ops::OP_EQUALVERIFY);
    push_int(script, 1);
    script.push(ops::OP_TX_OUTPUT_AMOUNT);
    push_int(script, config.fee_sompi);
    script.push(ops::OP_EQUALVERIFY);
    script.push(ops::OP_TX_OUTPUT_COUNT);
    push_int(script, 2);
    script.push(ops::OP_EQUALVERIFY);
    script.push(0x51);

    script.push(ops::OP_ELSE);
    push_pubkey(script, config.arbiter_pubkey);
    script.push(ops::OP_CHECKSIGVERIFY);
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
