// KasSee Web — Oracle (Model B) covenant builders (moved out of kspt.rs).
// Re-exported by kspt via `pub use oracle_mb::*`, so `kspt::build_oracle_mb_*`
// and `kspt::ORACLE_MB_*` resolve unchanged. License: GPL-3.0.

//! Oracle (Model B) covenant builders: genesis, heartbeat, publish and consume
//! redeem scripts and their sig-scripts. Re-exported by the parent `kspt` module.

use super::{covenant_ops, push_data, push_int, ZK_RISC0_SIG_OP_COUNT, ZK_TAG_RISC0};

// Oracle (Model B) -- complete covenant builders (heartbeat + publish/passthrough
// + consume read + genesis). Paste this whole file into kassee/src/kspt.rs, beside
// the other build_*_covenant functions. It uses `use covenant_ops::*` for the
// existing opcodes, and defines the four opcodes covenant_ops did not yet declare
// as local consts below (they exist in the rusty-kaspa 2.0.0 engine at these bytes),
// so NO edit to your covenant_ops module is needed. Move them into covenant_ops if
// you prefer them centralized.
//
// Every redeem here was byte-checked against its Python sim (oracle_mb_*_sim.py)
// during development. The engine/crypto sign-off is the TN10 run, as with the
// bridge and vault.
//
// hashfn is poseidon2 = 0x01 (ORACLE_MB_HASHFN_POSEIDON2); the engine rejects 0x00
// and 0x02 for a succinct receipt. image_id/control_id/set_root come from the
// oracle-zkvm guest; pin them into build_oracle_mb_publish_body.
// ============================================================================

// --- opcodes present in the engine but not (yet) declared in covenant_ops --------
const OP_TX_INPUT_SCRIPT_SIG_SUBSTR: u8 = 0xbc; // pop [idx,start,end] -> input[idx].sig_script[start..end]
                                                // Retired with the daa staleness gate (the 3-input read). Kept for the dormant
                                                // heartbeat / future rate-accumulator beacon, which reads a creation DAA.
                                                // Kept: retained for future use; not currently wired.
#[allow(dead_code)]
const OP_TX_INPUT_DAA_SCORE: u8 = 0xc0; // pop idx -> input[idx] UTXO's creation block_daa_score
const OP_TX_INPUT_SCRIPT_SIG_LEN: u8 = 0xc9; // pop idx -> len(input[idx].sig_script)
const OP_COV_INPUT_IDX: u8 = 0xd1; // pop (covenant_id, k) -> k-th input index with that id
const OP_WITHIN: u8 = 0xa5;

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
    use covenant_ops::*;
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

/// Keyless: the heartbeat roll carries no signature, only its revealed redeem.
pub const ORACLE_MB_HEARTBEAT_SIG_OP_COUNT: u8 = 0;

/// Oracle (Model B) fee cap (sompi). Pinned, not a parameter: it appears twice in
/// the oracle body (ROLL value check and PASSTHROUGH), so its push width
/// participates in BODY_LEN. The heartbeat no longer uses it (out >= in, no skim).
pub const ORACLE_MB_MAX_FEE_SOMPI: u64 = 1_000_000;

/// The only hashfn the toc5 OP_ZK_PRECOMPILE accepts for a RISC0 succinct receipt
/// is poseidon2 = 0x01 (blake2b=0x00 and sha-256=0x02 are rejected by the engine).
/// Confirmed against bridge.hashfn.hex (the TN10-proven value). The publish body
/// MUST be built with this; passing 0x02 makes the proof rejected on-chain.
// Kept: retained for future use; not currently wired.
#[allow(dead_code)]
pub const ORACLE_MB_HASHFN_POSEIDON2: u8 = 0x01;

/// Byte length of the constant publish body. The body reads its own length-suffix
/// from the sig_script (self_body = sigsig[sig_len - BODY_LEN : sig_len]), so this
/// must equal the assembled body length. push_int(288) is 3 bytes (OP_DATA_2 + 2
/// LE bytes; the 3-byte band runs 128..32767, so crossing 256 keeps the width), a
/// stable fixed point. Grew from 252 by the 36-byte heartbeat-input gate in the
/// ROLL branch (push H, OP_COV_INPUT_COUNT, 1, OP_NUMEQUALVERIFY). Asserted below.
pub const ORACLE_MB_BODY_LEN: u64 = 288;

/// RISC0 succinct verification path -> sigOpCount 255 (same as the bridge).
pub const ORACLE_MB_SIG_OP_COUNT: u8 = ZK_RISC0_SIG_OP_COUNT;

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
    use covenant_ops::*;
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

/// The constant publish body (IF = ROLL, ELSE = PASSTHROUGH). 288 bytes.
pub fn build_oracle_mb_publish_body(
    image_id: &[u8; 32],
    control_id: &[u8; 32],
    set_root: &[u8; 32],
    hashfn: u8,
    heartbeat_cov_id: &[u8; 32],
) -> Vec<u8> {
    use covenant_ops::*;
    let mut s = Vec::with_capacity(ORACLE_MB_BODY_LEN as usize);

    s.push(OP_IF);
    // ===== ROLL: verify a fresh proof, commit the price, keep the singleton =====
    // entry stack (bottom->top): claim, ctrl_idx, ctrl_dig, seal, J
    // 0) co-roll: require exactly one heartbeat input (by its covenant_id H). The
    //    heartbeat's own body then forces its recreation in this same tx, so every
    //    roll co-rolls the fixed-address heartbeat, making it a discovery signpost
    //    (its UTXO's txid == the latest roll). Stack-neutral: push H, COV_INPUT_COUNT
    //    pops it, 1 NUMEQUALVERIFY pops the count, the entry stack is untouched.
    //    ROLL only -- PASSTHROUGH stays heartbeat-free, so a 2-input consume (CDP
    //    read) never drags the heartbeat.
    push_data(&mut s, heartbeat_cov_id);
    s.push(OP_COV_INPUT_COUNT);
    push_int(&mut s, 1);
    s.push(OP_NUMEQUALVERIFY);
    // 1) set_root pin: J[16:48] == set_root
    push_int(&mut s, 0);
    s.push(OP_PICK);
    push_int(&mut s, 16);
    push_int(&mut s, 48);
    s.push(OP_SUBSTR);
    push_data(&mut s, set_root);
    s.push(OP_EQUALVERIFY);
    // 2) range-check price = J[0:8] in [1, 2^60]
    push_int(&mut s, 0);
    s.push(OP_PICK);
    push_int(&mut s, 0);
    push_int(&mut s, 8);
    s.push(OP_SUBSTR);
    push_int(&mut s, 1);
    push_int(&mut s, (1u64 << 60) + 1);
    s.push(OP_WITHIN);
    s.push(OP_VERIFY);
    // 2b) monotonicity: new_T (J[8:16]) >= old_T (this input's revealed redeem[11:19]).
    //     T is the Pyth publish_time (seconds), welded to its price by the signature the
    //     guest verifies, so rolling an older price (stale replay) needs an older Pyth
    //     signature == forging Pyth. Carried in the same 8-byte slot the old daa used, so
    //     it survives passthrough reads; the chain's own daa cannot (a read resets it).
    //     >= (not strict >) admits a harmless same-update re-roll. old_T is read exactly
    //     as the consumer reads the field; a genesis T of 0 lets the first roll pass.
    push_int(&mut s, 0);
    s.push(OP_PICK);
    push_int(&mut s, 8);
    push_int(&mut s, 16);
    s.push(OP_SUBSTR); // new_T = J[8:16]
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_SCRIPT_SIG_LEN);
    s.push(OP_DUP);
    push_int(&mut s, ORACLE_MB_REDEEM_LEN - 11);
    s.push(OP_SUB); // start = sig_len - (LEN-11)
    s.push(OP_SWAP);
    push_int(&mut s, ORACLE_MB_REDEEM_LEN - 19);
    s.push(OP_SUB); // end   = sig_len - (LEN-19)
    s.push(OP_TX_INPUT_SCRIPT_SIG_SUBSTR); // old_T = redeem[11:19]
    s.push(OP_GREATERTHANOREQUAL);
    s.push(OP_VERIFY);
    // 3) next_prefix = 08 || J[0:8] || 7508 || J[8:16] || 75
    push_data(&mut s, &[0x08]);
    push_int(&mut s, 1);
    s.push(OP_PICK);
    push_int(&mut s, 0);
    push_int(&mut s, 8);
    s.push(OP_SUBSTR);
    s.push(OP_CAT);
    push_data(&mut s, &[0x75, 0x08]);
    s.push(OP_CAT);
    push_int(&mut s, 1);
    s.push(OP_PICK);
    push_int(&mut s, 8);
    push_int(&mut s, 16);
    s.push(OP_SUBSTR);
    s.push(OP_CAT);
    push_data(&mut s, &[0x75]);
    s.push(OP_CAT); // [.., J, next_prefix]
                    // 4) self_body = sigsig[sig_len - BODY_LEN : sig_len]; next_redeem = next_prefix || self_body
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_SCRIPT_SIG_LEN);
    s.push(OP_DUP);
    push_int(&mut s, ORACLE_MB_BODY_LEN);
    s.push(OP_SUB);
    s.push(OP_SWAP);
    s.push(OP_TX_INPUT_SCRIPT_SIG_SUBSTR);
    s.push(OP_CAT); // [.., J, next_redeem]
                    // 5a) strict singleton (preserves next_redeem)
    push_oracle_mb_singleton_strict(&mut s);
    // 5b) next_spk = 0000||AA20||blake2b(next_redeem)||87 == output[0].spk
    s.push(OP_BLAKE2B);
    push_data(&mut s, &[0x87]);
    s.push(OP_CAT);
    push_data(&mut s, &[0xAA, 0x20]);
    s.push(OP_SWAP);
    s.push(OP_CAT);
    push_data(&mut s, &[0x00, 0x00]);
    s.push(OP_SWAP);
    s.push(OP_CAT);
    push_int(&mut s, 0);
    s.push(OP_TX_OUTPUT_SPK);
    s.push(OP_EQUALVERIFY);
    // 5c) value conservation: output[0].amount >= input.amount - max_fee
    push_int(&mut s, 0);
    s.push(OP_TX_OUTPUT_AMOUNT);
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_AMOUNT);
    push_int(&mut s, ORACLE_MB_MAX_FEE_SOMPI);
    s.push(OP_SUB);
    s.push(OP_GREATERTHANOREQUAL);
    s.push(OP_VERIFY);
    // 6) precompile: journal_hash = sha256(J); then image_id, control_id, hashfn, tag
    //    pop order claim|ctrl_idx|ctrl_dig|seal|journal|image_id|ctrl_id|hashfn
    s.push(OP_SHA256);
    push_data(&mut s, image_id);
    push_data(&mut s, control_id);
    push_data(&mut s, &[hashfn]);
    push_data(&mut s, &[ZK_TAG_RISC0]);
    s.push(OP_ZK_PRECOMPILE);
    s.push(OP_VERIFY);
    // 7) clean true
    s.push(OP_1);

    s.push(OP_ELSE);
    // ===== PASSTHROUGH: strict-singleton recreate unchanged (keyless read survival) =====
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
    push_int(&mut s, 0);
    s.push(OP_COV_OUTPUT_IDX);
    s.push(OP_DUP);
    s.push(OP_TX_OUTPUT_SPK);
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_SPK);
    s.push(OP_EQUALVERIFY);
    s.push(OP_TX_OUTPUT_AMOUNT);
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_AMOUNT);
    push_int(&mut s, ORACLE_MB_MAX_FEE_SOMPI);
    s.push(OP_SUB);
    s.push(OP_GREATERTHANOREQUAL);
    s.push(OP_VERIFY);
    s.push(OP_1);

    s.push(OP_ENDIF);
    s
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
    use covenant_ops::*;
    let mut s = Vec::with_capacity(redeem.len() + 4);
    s.push(OP_0); // selector -> ELSE (PASSTHROUGH)
    push_data(&mut s, redeem);
    s
}

/// The oracle UTXO redeem length: prefix(20) + body(288). The committed price sits
/// at redeem[1..9], so the read slices the last (LEN-1 .. LEN-9) bytes of the oracle
/// input's sig_script (the redeem is always the last push of a spend).
pub const ORACLE_MB_REDEEM_LEN: u64 = 308;

/// Default freshness window in DAA (~60 s at 10 BPS). Tunable per consumer.
// Kept: retained for future use; not currently wired.
#[allow(dead_code)]
pub const ORACLE_MB_DEFAULT_MAX_AGE: u64 = 600;

/// Append the consume READ to a consumer covenant's redeem (e.g. the CDP). It:
///   1. locates the oracle input by covenant_id (OpCovInputIdx oracle_cov_id 0),
///   2. reads the committed price (V) from the oracle's revealed redeem[1..9],
///   3. reads the committed T (Pyth publish_time) from redeem[11..19] the same way,
/// leaving both on the stack as [price, T] with T on top, each 8-byte LE: the
/// consumer gets V at a specific T.
///
/// No proof rides in the consumer's tx and no re-hash is needed: locating by
/// covenant_id yields the genuine oracle lineage, whose redeem the engine has already
/// P2SH-validated against its SPK. Oracle continuity is enforced by its own covenant
/// when spent, so the read does not re-check it.
///
/// 2-input: the consume tx carries the consumer and the oracle (passthrough), no
/// heartbeat. The old daa staleness gate is gone. Freshness is T: welded to the price
/// by the proof and made monotone on-chain by the roll (new_T >= old_T). Whether a
/// price is recent enough RIGHT NOW is the consumer's call, off-chain against the wall
/// clock or on-chain against a CLTV bound, using the T this leaves on the stack. 65 bytes.
#[allow(clippy::doc_lazy_continuation)]
pub fn push_oracle_mb_read(s: &mut Vec<u8>, oracle_cov_id: &[u8; 32]) {
    use covenant_ops::*;
    // 1) locate the oracle input by covenant_id; keep oracle_idx (DUP it: price + T both read it)
    push_data(s, oracle_cov_id);
    push_int(s, 0);
    s.push(OP_COV_INPUT_IDX);
    s.push(OP_DUP);
    // 2) price (V) = oracle_sig_script[sig_len-(LEN-1) : sig_len-(LEN-9)] = redeem[1..9]
    s.push(OP_DUP);
    s.push(OP_TX_INPUT_SCRIPT_SIG_LEN); // sig_len
    s.push(OP_DUP);
    push_int(s, ORACLE_MB_REDEEM_LEN - 9);
    s.push(OP_SUB); // end   = sig_len - (LEN-9)
    s.push(OP_SWAP);
    push_int(s, ORACLE_MB_REDEEM_LEN - 1);
    s.push(OP_SUB); // start = sig_len - (LEN-1)
    s.push(OP_SWAP); // [oracle_idx, start, end]
    s.push(OP_TX_INPUT_SCRIPT_SIG_SUBSTR); // [oracle_idx, price]
    s.push(OP_SWAP); // [price, oracle_idx]
                     // 3) T = oracle_sig_script[sig_len-(LEN-11) : sig_len-(LEN-19)] = redeem[11..19]
    s.push(OP_DUP);
    s.push(OP_TX_INPUT_SCRIPT_SIG_LEN); // sig_len
    s.push(OP_DUP);
    push_int(s, ORACLE_MB_REDEEM_LEN - 19);
    s.push(OP_SUB); // end   = sig_len - (LEN-19)
    s.push(OP_SWAP);
    push_int(s, ORACLE_MB_REDEEM_LEN - 11);
    s.push(OP_SUB); // start = sig_len - (LEN-11)
    s.push(OP_SWAP); // [price, start, end]
    s.push(OP_TX_INPUT_SCRIPT_SIG_SUBSTR); // [price, T]  (8-byte LE each, T on top)
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

// ============================================================================
// Oracle (Model B) -- TEST CONSUMER. APPEND into kassee/src/kspt.rs, after the
// oracle_mb block (it calls push_oracle_mb_read + the covenant_ops there).
//
// This is a minimal standalone CONSUMER for validating the read end-to-end on
// TN10 before the CDP exists. It is a read-gated release: spend is allowed iff
// push_oracle_mb_read succeeds, i.e. the genuine oracle lineage is present as an
// input (located by covenant_id). 2-input: consumer + oracle, no heartbeat.
// The committed price and T are read and dropped; the real CDP keeps both on the
// stack and runs its CDP logic instead of the two OP_DROPs + OP_1.
//
// The redeem runs on an empty initial stack (its sig_script pushes only the
// revealed redeem), so push_oracle_mb_read needs nothing pre-pushed. It leaves
// [price, T]; OP_DROP OP_DROP OP_1 turns that into a clean TRUE.
// ============================================================================

/// Build the test-consumer redeem for a specific oracle lineage:
///   push_oracle_mb_read(oracle_cov_id)   // -> [price, T] on stack
///   OP_DROP OP_DROP                      // drop T then price
///   OP_1                                 // read gated -> TRUE
pub fn build_oracle_mb_test_consumer_script(oracle_cov_id: &[u8; 32]) -> Vec<u8> {
    use covenant_ops::*;
    let mut s = Vec::new();
    push_oracle_mb_read(&mut s, oracle_cov_id);
    s.push(OP_DROP); // drop T
    s.push(OP_DROP); // drop price
    s.push(OP_1); // clean TRUE: the read is the spend gate
    s
}

/// Keyless consumer sig_script: JUST the revealed redeem (no selector, no sig).
/// The read executes on the empty stack left after the P2SH redeem pop.
pub fn build_oracle_mb_consumer_sig_script(redeem: &[u8]) -> Vec<u8> {
    let mut s = Vec::with_capacity(redeem.len() + 4);
    push_data(&mut s, redeem);
    s
}
