// KasSee Web — Crowdfunding (ZK-gated) covenant builder (moved out of kspt.rs).
// Re-exported by kspt via `pub use crowdfund::*`. Shared ZK helpers/consts stay in kspt.
// License: GPL-3.0.

//! ZK-gated crowdfunding covenant redeem-script builder.
//! Re-exported by the parent `kspt` module.

use super::{
    blake2b_hash, covenant_ops, push_data, push_int, push_pubkey, ZK_GROTH16_SIG_OP_COUNT,
};

/// Build a crowdfunding P2SH redeem script.
///
/// IF path (contributor refund): <locktime> CLTV <contributor_pk> CHECKSIG
/// ELSE path (ZK sweep): push VK, verify VK hash, push tag, ZK_PRECOMPILE
///
/// The ZK proof proves that the total contributions sum to >= goal.
/// The sig_script for sweep: <proof> <public_input(sum)> OP_FALSE <redeem>
/// The sig_script for refund: <sig> OP_TRUE <redeem>
pub fn crowdfund_redeem_script(
    contributor_pubkey: &[u8; 32],
    organizer_pubkey: &[u8; 32],
    locktime_daa: u64,
    vk_bytes: &[u8],
) -> Vec<u8> {
    use covenant_ops::*;
    let mut s = Vec::with_capacity(240 + vk_bytes.len());
    let vk_hash = blake2b_hash(vk_bytes);

    // IF: contributor refund (after timeout)
    s.push(OP_IF);
    push_int(&mut s, locktime_daa);
    s.push(OP_CHECKLOCKTIMEVERIFY);
    push_pubkey(&mut s, contributor_pubkey);
    s.push(OP_CHECKSIG);

    // ELSE: Dual-gate ZK sweep
    // sig_script stack (bottom to top): commitment_sig | msg_hash | public_input | 1 | proof | vk
    // Step 1: ZK_PRECOMPILE consumes top 4 items (vk, proof, n_inputs, public_input)
    // Step 2: CHECKSIGFROMSTACK consumes remaining 2 + pushed pubkey (sig, msg_hash, pubkey)
    s.push(OP_ELSE);

    // Verify VK integrity: DUP, BLAKE2B, compare hash
    s.push(OP_DUP);
    s.push(OP_BLAKE2B);
    push_data(&mut s, &vk_hash);
    s.push(OP_EQUALVERIFY);

    // Push tag byte: 0x20 = Groth16
    s.push(0x01); // OP_DATA_1
    s.push(crate::zkproof::ZK_TAG_GROTH16);

    // Verify ZK proof (consumes vk, tag, proof, n_inputs, public_input)
    s.push(OP_ZK_PRECOMPILE);
    s.push(OP_VERIFY);

    // Stack now: commitment_sig | msg_hash
    // Verify organizer signed the sweep commitment
    push_pubkey(&mut s, organizer_pubkey);
    s.push(OP_CHECKSIGFROMSTACK);
    s.push(OP_VERIFY);
    s.push(OP_1); // OP_TRUE for clean stack

    s.push(OP_ENDIF);
    s
}

/// SigOpCount for crowdfunding ZK sweep. Same as ZK_GROTH16_SIG_OP_COUNT
/// since the circuit uses the same Groth16 verifier.
pub const ZK_CROWDFUND_SIG_OP_COUNT: u8 = ZK_GROTH16_SIG_OP_COUNT;
