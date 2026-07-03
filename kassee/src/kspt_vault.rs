// KasSee Web — KIP-20 Tagged/Split Vault builders (moved out of kspt.rs).
// Re-exported by kspt via `pub use vault::*`. License: GPL-3.0.

//! KIP-20 tagged- and split-vault script builders and covenant-id computation.
//! Re-exported by the parent `kspt` module.

use super::{covenant_ops, push_pubkey};

/// Build a Tagged Vault redeem script.
///
/// The script enforces two things:
///   1. Owner signature (standard CHECKSIG)
///   2. Output[0] must carry the same covenant_id as this input
///
/// This is the simplest possible covenant that exercises the KIP-20
/// covenant ID opcodes. It proves state continuity: any spend must
/// create a continuation UTXO tagged with the same covenant_id.
///
/// Script:
///   <owner_pk> OP_CHECKSIGVERIFY
///   OP_TX_INPUT_IDX           // push current input index
///   OP_INPUT_COVENANT_ID      // push this input's covenant_id (32 bytes)
///   0                         // output index 0
///   OP_OUTPUT_COVENANT_ID     // push output[0]'s covenant_id (32 bytes)
///   OP_EQUALVERIFY
///   OP_1
///
/// sig_op_count: 1 (CHECKSIGVERIFY)
pub fn build_tagged_vault_script(owner_pubkey: &[u8; 32]) -> Vec<u8> {
    use covenant_ops::*;
    let mut s = Vec::with_capacity(64);

    // Owner must sign
    push_pubkey(&mut s, owner_pubkey);
    s.push(OP_CHECKSIGVERIFY);

    // Read this input's covenant_id
    s.push(OP_TX_INPUT_INDEX); // push current input idx
    s.push(OP_INPUT_COVENANT_ID); // 0xcf: pop idx, push covenant_id

    // Read output[0]'s covenant_id
    s.push(OP_0); // push 0
    s.push(OP_OUTPUT_COVENANT_ID); // 0xd5: pop idx, push covenant_id

    // They must match
    s.push(OP_EQUALVERIFY);

    // Leave TRUE on stack
    s.push(OP_1);

    s
}

pub const TAGGED_VAULT_SIG_OP_COUNT: u8 = 1;

/// Compute a KIP-20 covenant_id from a genesis outpoint and authorized outputs.
///
/// Replicates the consensus computation in hashing/covenant_id.rs:
///   blake2b(key=b"CovenantID", hash_length=32):
///     update(transaction_id)            // 32 bytes
///     update(index as u32 LE)           // 4 bytes
///     update(num_outputs as u64 LE)     // 8 bytes
///     for each output:
///       update(output_index as u32 LE)  // 4 bytes
///       update(value as u64 LE)         // 8 bytes
///       update(spk_version as u16 LE)   // 2 bytes
///       update(script_len as u64 LE)    // 8 bytes (write_var_bytes)
///       update(script)                  // raw bytes
pub fn compute_covenant_id(
    prev_txid: &[u8; 32],
    prev_index: u32,
    auth_outputs: &[(u32, u64, u16, &[u8])], // (out_idx, value, spk_version, spk_script)
) -> [u8; 32] {
    let state = blake2b_simd::Params::new()
        .hash_length(32)
        .key(b"CovenantID")
        .to_state();
    let mut h = state;

    // outpoint
    h.update(prev_txid);
    h.update(&prev_index.to_le_bytes());

    // num outputs
    h.update(&(auth_outputs.len() as u64).to_le_bytes());

    for &(idx, value, spk_ver, spk_script) in auth_outputs {
        h.update(&idx.to_le_bytes());
        h.update(&value.to_le_bytes());
        h.update(&spk_ver.to_le_bytes());
        // write_var_bytes: len as u64 LE, then bytes
        h.update(&(spk_script.len() as u64).to_le_bytes());
        h.update(spk_script);
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

// ================================================================
// Split Vault: one input splits into two tagged outputs (KIP-20)
// ================================================================

/// Build a Split Vault redeem script.
///
/// Enforces:
///   1. Owner signature
///   2. Exactly 2 outputs carry the same covenant_id as this input
///   3. This input authorizes exactly 2 outputs
///
/// This exercises: OP_AUTH_OUTPUT_COUNT (0xcb), OP_COV_OUTPUT_COUNT (0xd2),
/// OP_INPUT_COVENANT_ID (0xcf), OP_TX_INPUT_IDX (0xb9), plus CHECKSIGVERIFY.
///
/// Script:
///   <owner_pk> CHECKSIGVERIFY
///   TX_INPUT_IDX INPUT_COVENANT_ID   // get our covenant_id
///   DUP                              // need it twice
///   COV_OUTPUT_COUNT                 // how many outputs share this id?
///   2 EQUALVERIFY                    // must be exactly 2
///   TX_INPUT_IDX AUTH_OUTPUT_COUNT   // how many outputs does this input auth?
///   2 EQUALVERIFY                    // must be exactly 2
///   DROP                             // clean the dup'd covenant_id
///   1
///
/// sig_op_count: 1 (CHECKSIGVERIFY)
pub fn build_split_vault_script(owner_pubkey: &[u8; 32]) -> Vec<u8> {
    use covenant_ops::*;
    let mut s = Vec::with_capacity(48);

    // Owner must sign
    push_pubkey(&mut s, owner_pubkey);
    s.push(OP_CHECKSIGVERIFY);

    // Read this input's covenant_id
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_INPUT_COVENANT_ID); // stack: [cov_id]

    // DUP for two checks
    s.push(OP_DUP); // stack: [cov_id, cov_id]

    // Check: exactly 2 outputs carry this covenant_id
    s.push(OP_COV_OUTPUT_COUNT); // stack: [cov_id, count]
    s.push(0x52); // OP_2
    s.push(OP_EQUALVERIFY); // stack: [cov_id]

    // Check: this input authorizes exactly 2 outputs
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_AUTH_OUTPUT_COUNT); // stack: [cov_id, auth_count]
    s.push(0x52); // OP_2
    s.push(OP_EQUALVERIFY); // stack: [cov_id]

    // Clean up
    s.push(OP_DROP); // stack: []
    s.push(OP_1); // stack: [TRUE]

    s
}

pub const SPLIT_VAULT_SIG_OP_COUNT: u8 = 1;
