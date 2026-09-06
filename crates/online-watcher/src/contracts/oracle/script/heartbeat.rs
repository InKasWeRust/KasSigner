//! Fixed-address heartbeat covenant.
use super::{push_data, push_int};
/// Oracle (Model B) keyless strict-singleton heartbeat: the discovery signpost.
///
/// Fixed-address self-perpetuating singleton. The oracle ROLL branch requires
/// exactly one heartbeat input (by its covenant_id H), so every price roll spends
/// and recreates this heartbeat in the SAME tx. Its body forces a self-send, so
/// its address never changes, and value rolls forward (out >= in, no skim). Net
/// effect: the heartbeat UTXO's txid is always the latest roll. A wallet finds the
/// rotating oracle with no indexer: query this fixed address, take its UTXO's
/// txid, fetch that roll, the oracle is the sibling output (cov_id G).
///
/// It carries no price and no T. Freshness is not its job (the consume reads T
/// from the oracle redeem and checks it off-chain). It references the oracle
/// nowhere, so H is independent of G and the binding stays one-directional (oracle
/// requires heartbeat, never the reverse), avoiding the circular cov_id a mutual
/// bind would need.
///
/// STRICT SINGLETON (no fork, no merge): exactly one lineage input and one
/// lineage output, enforced by COV_INPUT_COUNT == 1 && COV_OUTPUT_COUNT == 1 on
/// this input's covenant_id.
///
/// Redeem (single keyless roll path, no IF/ELSE):
///   OP_TX_INPUT_INDEX OP_INPUT_COVENANT_ID
///   OP_DUP OP_COV_INPUT_COUNT  1 OP_NUMEQUALVERIFY      -- exactly one lineage input
///   OP_DUP OP_COV_OUTPUT_COUNT 1 OP_NUMEQUALVERIFY      -- exactly one lineage output
///   0 OP_COV_OUTPUT_IDX                                 -- locate the continuation
///   OP_DUP OP_TX_OUTPUT_SPK OP_TX_INPUT_INDEX OP_TX_INPUT_SPK OP_EQUALVERIFY  -- self-send
///   OP_TX_OUTPUT_AMOUNT OP_TX_INPUT_INDEX OP_TX_INPUT_AMOUNT
///       OP_GREATERTHANOREQUAL OP_VERIFY                 -- value rolls forward (out >= in)
///   OP_1
///
/// Sig_script to roll it (bottom -> top): just the revealed <redeem>. No selector,
/// no signature. A lone roll (no oracle) is allowed but pointless: it cannot bleed
/// value (out >= in) and a reader trusts price only from a tx that also carries the
/// oracle, so it can never feed a fake price.
///
/// tx_version = 1 (covenant-binding outputs). sigOpCount = 0 (keyless).
pub fn build_oracle_mb_heartbeat_script() -> Vec<u8> {
    use super::covenant_ops::*;
    let mut s = Vec::with_capacity(32);

    // bind this input's covenant_id, then pin the lineage to a strict singleton
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_INPUT_COVENANT_ID);
    s.push(OP_DUP);
    s.push(OP_COV_INPUT_COUNT);
    push_int(&mut s, 1);
    s.push(OP_NUMEQUALVERIFY);
    s.push(OP_DUP);
    s.push(OP_COV_OUTPUT_COUNT);
    push_int(&mut s, 1);
    s.push(OP_NUMEQUALVERIFY);

    // locate the single continuation output for this covenant_id
    push_int(&mut s, 0);
    s.push(OP_COV_OUTPUT_IDX);

    // continuation SPK == own input SPK (self-send: same address rolls forward)
    s.push(OP_DUP);
    s.push(OP_TX_OUTPUT_SPK);
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_SPK);
    s.push(OP_EQUALVERIFY);

    // value rolls forward: out_amount >= in_amount (no skim; the roller pays the
    // tx fee from its own other inputs, so a lone griefing roll drains nothing)
    s.push(OP_TX_OUTPUT_AMOUNT);
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_AMOUNT);
    s.push(OP_GREATERTHANOREQUAL);
    s.push(OP_VERIFY);

    s.push(OP_1);
    s
}

/// Sig_script to roll the heartbeat (bottom -> top): the revealed redeem only.
/// Keyless: no selector and no signature, since the redeem has a single path.
pub fn build_oracle_mb_heartbeat_sig_script(redeem: &[u8]) -> Vec<u8> {
    let mut s = Vec::with_capacity(redeem.len() + 4);
    push_data(&mut s, redeem);
    s
}
