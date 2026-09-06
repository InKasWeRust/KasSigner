//! Oracle publication, rollover, passthrough, and genesis scripts.
use super::{
    push_data, push_int, OP_WITHIN, ORACLE_MB_BODY_LEN, ORACLE_MB_MAX_FEE_SOMPI,
    ORACLE_MB_REDEEM_LEN, RISC0_TAG,
};
/// The 20-byte oracle-state prefix: pushes price and T (Pyth publish_time, each
/// OP_DATA_8 + LE8 + OP_DROP) so both are baked into the redeem bytes (and thus the
/// SPK) while leaving the stack clean before the body runs. T replaces the old daa
/// score in the same slot: carried as data, it survives passthrough reads, and the
/// guest welds it to the price, which the on-chain daa structurally cannot do.
fn oracle_mb_prefix(price: u64, t: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(20);
    p.push(0x08); // OP_DATA_8
    p.extend_from_slice(&price.to_le_bytes());
    p.push(0x75); // OP_DROP
    p.push(0x08); // OP_DATA_8
    p.extend_from_slice(&t.to_le_bytes());
    p.push(0x75); // OP_DROP
    p
}

/// cov_id of this input, then COV_INPUT_COUNT==1 && COV_OUTPUT_COUNT==1 (strict
/// singleton: no fork, no merge). Net zero on the stack (the cov_id is consumed).
fn push_oracle_mb_singleton_strict(s: &mut Vec<u8>) {
    use super::covenant_ops::*;
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_INPUT_COVENANT_ID);
    s.push(OP_DUP);
    s.push(OP_COV_INPUT_COUNT);
    push_int(s, 1);
    s.push(OP_NUMEQUALVERIFY);
    s.push(OP_COV_OUTPUT_COUNT);
    push_int(s, 1);
    s.push(OP_NUMEQUALVERIFY);
}

fn push_oracle_roll_branch(
    s: &mut Vec<u8>,
    image_id: &[u8; 32],
    control_id: &[u8; 32],
    set_root: &[u8; 32],
    hashfn: u8,
    heartbeat_cov_id: &[u8; 32],
) {
    use super::covenant_ops::*;
    // ===== ROLL: verify a fresh proof, commit the price, keep the singleton =====
    // entry stack (bottom->top): claim, ctrl_idx, ctrl_dig, seal, J
    // 0) co-roll: require exactly one heartbeat input (by its covenant_id H). The
    //    heartbeat's own body then forces its recreation in this same tx, so every
    //    roll co-rolls the fixed-address heartbeat, making it a discovery signpost
    //    (its UTXO's txid == the latest roll). Stack-neutral: push H, COV_INPUT_COUNT
    //    pops it, 1 NUMEQUALVERIFY pops the count, the entry stack is untouched.
    //    ROLL only -- PASSTHROUGH stays heartbeat-free, so a 2-input consume (CDP
    //    read) never drags the heartbeat.
    push_data(s, heartbeat_cov_id);
    s.push(OP_COV_INPUT_COUNT);
    push_int(s, 1);
    s.push(OP_NUMEQUALVERIFY);
    // 1) set_root pin: J[16:48] == set_root
    push_int(s, 0);
    s.push(OP_PICK);
    push_int(s, 16);
    push_int(s, 48);
    s.push(OP_SUBSTR);
    push_data(s, set_root);
    s.push(OP_EQUALVERIFY);
    // 2) range-check price = J[0:8] in [1, 2^60]
    push_int(s, 0);
    s.push(OP_PICK);
    push_int(s, 0);
    push_int(s, 8);
    s.push(OP_SUBSTR);
    push_int(s, 1);
    push_int(s, (1u64 << 60) + 1);
    s.push(OP_WITHIN);
    s.push(OP_VERIFY);
    // 2b) monotonicity: new_T (J[8:16]) >= old_T (this input's revealed redeem[11:19]).
    //     T is the Pyth publish_time (seconds), welded to its price by the signature the
    //     guest verifies, so rolling an older price (stale replay) needs an older Pyth
    //     signature == forging Pyth. Carried in the same 8-byte slot the old daa used, so
    //     it survives passthrough reads; the chain's own daa cannot (a read resets it).
    //     >= (not strict >) admits a harmless same-update re-roll. old_T is read exactly
    //     as the consumer reads the field; a genesis T of 0 lets the first roll pass.
    push_int(s, 0);
    s.push(OP_PICK);
    push_int(s, 8);
    push_int(s, 16);
    s.push(OP_SUBSTR); // new_T = J[8:16]
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_SCRIPT_SIG_LEN);
    s.push(OP_DUP);
    push_int(s, ORACLE_MB_REDEEM_LEN - 11);
    s.push(OP_SUB); // start = sig_len - (LEN-11)
    s.push(OP_SWAP);
    push_int(s, ORACLE_MB_REDEEM_LEN - 19);
    s.push(OP_SUB); // end   = sig_len - (LEN-19)
    s.push(OP_TX_INPUT_SCRIPT_SIG_SUBSTR); // old_T = redeem[11:19]
    s.push(OP_GREATERTHANOREQUAL);
    s.push(OP_VERIFY);
    // 3) next_prefix = 08 || J[0:8] || 7508 || J[8:16] || 75
    push_data(s, &[0x08]);
    push_int(s, 1);
    s.push(OP_PICK);
    push_int(s, 0);
    push_int(s, 8);
    s.push(OP_SUBSTR);
    s.push(OP_CAT);
    push_data(s, &[0x75, 0x08]);
    s.push(OP_CAT);
    push_int(s, 1);
    s.push(OP_PICK);
    push_int(s, 8);
    push_int(s, 16);
    s.push(OP_SUBSTR);
    s.push(OP_CAT);
    push_data(s, &[0x75]);
    s.push(OP_CAT); // [.., J, next_prefix]
                    // 4) self_body = sigsig[sig_len - BODY_LEN : sig_len]; next_redeem = next_prefix || self_body
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_SCRIPT_SIG_LEN);
    s.push(OP_DUP);
    push_int(s, ORACLE_MB_BODY_LEN);
    s.push(OP_SUB);
    s.push(OP_SWAP);
    s.push(OP_TX_INPUT_SCRIPT_SIG_SUBSTR);
    s.push(OP_CAT); // [.., J, next_redeem]
                    // 5a) strict singleton (preserves next_redeem)
    push_oracle_mb_singleton_strict(s);
    // 5b) next_spk = 0000||AA20||blake2b(next_redeem)||87 == output[0].spk
    s.push(OP_BLAKE2B);
    push_data(s, &[0x87]);
    s.push(OP_CAT);
    push_data(s, &[0xAA, 0x20]);
    s.push(OP_SWAP);
    s.push(OP_CAT);
    push_data(s, &[0x00, 0x00]);
    s.push(OP_SWAP);
    s.push(OP_CAT);
    push_int(s, 0);
    s.push(OP_TX_OUTPUT_SPK);
    s.push(OP_EQUALVERIFY);
    // 5c) value conservation: output[0].amount >= input.amount - max_fee
    push_int(s, 0);
    s.push(OP_TX_OUTPUT_AMOUNT);
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_AMOUNT);
    push_int(s, ORACLE_MB_MAX_FEE_SOMPI);
    s.push(OP_SUB);
    s.push(OP_GREATERTHANOREQUAL);
    s.push(OP_VERIFY);
    // 6) precompile: journal_hash = sha256(J); then image_id, control_id, hashfn, tag
    //    pop order claim|ctrl_idx|ctrl_dig|seal|journal|image_id|ctrl_id|hashfn
    s.push(OP_SHA256);
    push_data(s, image_id);
    push_data(s, control_id);
    push_data(s, &[hashfn]);
    push_data(s, &[RISC0_TAG]);
    s.push(OP_ZK_PRECOMPILE);
    s.push(OP_VERIFY);
    // 7) clean true
    s.push(OP_1);
}

fn push_oracle_passthrough_branch(s: &mut Vec<u8>) {
    use super::covenant_ops::*;
    // ===== PASSTHROUGH: strict-singleton recreate unchanged (keyless read survival) =====
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_INPUT_COVENANT_ID);
    s.push(OP_DUP);
    s.push(OP_COV_INPUT_COUNT);
    push_int(s, 1);
    s.push(OP_NUMEQUALVERIFY);
    s.push(OP_DUP);
    s.push(OP_COV_OUTPUT_COUNT);
    push_int(s, 1);
    s.push(OP_NUMEQUALVERIFY);
    push_int(s, 0);
    s.push(OP_COV_OUTPUT_IDX);
    s.push(OP_DUP);
    s.push(OP_TX_OUTPUT_SPK);
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_SPK);
    s.push(OP_EQUALVERIFY);
    s.push(OP_TX_OUTPUT_AMOUNT);
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_AMOUNT);
    push_int(s, ORACLE_MB_MAX_FEE_SOMPI);
    s.push(OP_SUB);
    s.push(OP_GREATERTHANOREQUAL);
    s.push(OP_VERIFY);
    s.push(OP_1);
}

/// The constant publish body (IF = ROLL, ELSE = PASSTHROUGH). 288 bytes.
fn build_oracle_mb_publish_body(
    image_id: &[u8; 32],
    control_id: &[u8; 32],
    set_root: &[u8; 32],
    hashfn: u8,
    heartbeat_cov_id: &[u8; 32],
) -> Vec<u8> {
    use super::covenant_ops::*;
    let mut script = Vec::with_capacity(ORACLE_MB_BODY_LEN as usize);
    script.push(OP_IF);
    push_oracle_roll_branch(
        &mut script,
        image_id,
        control_id,
        set_root,
        hashfn,
        heartbeat_cov_id,
    );
    script.push(OP_ELSE);
    push_oracle_passthrough_branch(&mut script);
    script.push(OP_ENDIF);
    script
}

/// The full oracle UTXO redeem: prefix(price, t) || body. 308 bytes.
pub fn build_oracle_mb_redeem(
    price: u64,
    t: u64,
    image_id: &[u8; 32],
    control_id: &[u8; 32],
    set_root: &[u8; 32],
    hashfn: u8,
    heartbeat_cov_id: &[u8; 32],
) -> Vec<u8> {
    let mut r = oracle_mb_prefix(price, t);
    r.extend_from_slice(&build_oracle_mb_publish_body(
        image_id,
        control_id,
        set_root,
        hashfn,
        heartbeat_cov_id,
    ));
    r
}

/// ROLL sig_script (bottom -> top): the four spender precompile fields, then the
/// raw 48-byte journal, then OP_1 (selects IF), then the revealed redeem.
pub fn build_oracle_mb_publish_sig_script(
    redeem: &[u8],
    claim: &[u8],
    control_index: &[u8],
    control_digests: &[u8],
    seal: &[u8],
    raw_journal: &[u8; 48],
) -> Vec<u8> {
    let mut s = Vec::with_capacity(redeem.len() + seal.len() + 256);
    push_data(&mut s, claim);
    push_data(&mut s, control_index);
    push_data(&mut s, control_digests);
    push_data(&mut s, seal);
    push_data(&mut s, raw_journal);
    push_data(&mut s, &[0x01]); // selector -> IF (ROLL): push-only truthy (bare OP_1=0x51 fails push-only)
    push_data(&mut s, redeem);
    s
}

/// PASSTHROUGH sig_script (bottom -> top): OP_0 (selects ELSE), then the redeem.
pub fn build_oracle_mb_passthrough_sig_script(redeem: &[u8]) -> Vec<u8> {
    use super::covenant_ops::*;
    let mut s = Vec::with_capacity(redeem.len() + 4);
    s.push(OP_0); // selector -> ELSE (PASSTHROUGH)
    push_data(&mut s, redeem);
    s
}

/// Genesis oracle UTXO redeem: the oracle at an initial price and T. Identical to
/// build_oracle_mb_redeem; the lineage's covenant_id is fixed by the genesis outpoint
/// when this UTXO is created (build the genesis tx with tx_version = 1). Pass
/// genesis_t = 0 to bootstrap: the monotonicity gate is new_T >= old_T, so the first
/// real roll's Pyth publish_time clears a genesis T of 0. After genesis, pin the
/// resulting covenant_id as the consumer's oracle_cov_id.
pub fn build_oracle_mb_genesis_redeem(
    genesis_price: u64,
    genesis_t: u64,
    image_id: &[u8; 32],
    control_id: &[u8; 32],
    set_root: &[u8; 32],
    hashfn: u8,
    heartbeat_cov_id: &[u8; 32],
) -> Vec<u8> {
    build_oracle_mb_redeem(
        genesis_price,
        genesis_t,
        image_id,
        control_id,
        set_root,
        hashfn,
        heartbeat_cov_id,
    )
}
