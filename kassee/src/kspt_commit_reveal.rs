// KasSee Web — Commit-Reveal + CDP owner/borrower sig-script builders (moved out of kspt.rs).
// Re-exported by kspt via `pub use commit_reveal::*`. License: GPL-3.0.

//! Commit-reveal covenant script and the CDP owner/borrower sig-script builders.
//! Re-exported by the parent `kspt` module.

use super::{covenant_ops, push_data, push_int, push_pubkey};

/// Build a commit-reveal covenant redeem script.
///
/// Two branches:
///   IF: owner refund after locktime (commitment expired, get funds back)
///   ELSE: reveal — provide preimage that hashes to committed value + owner sig
///
/// Commit phase: owner creates this covenant with BLAKE2B(preimage) embedded.
///   The preimage contains the secret data (bid, action, nonce+data).
///   Nobody can see the data until reveal.
///
/// Reveal phase: owner provides the preimage in sig_script.
///   Script hashes it, verifies against committed hash.
///   Owner must also sign (prevents front-running the reveal).
///
/// Script:
///   OP_IF
///     <owner_pk> CHECKSIGVERIFY <locktime> CLTV TRUE
///   OP_ELSE
///     OP_BLAKE2B <committed_hash_32B> OP_EQUALVERIFY
///     <owner_pk> OP_CHECKSIG
///   OP_ENDIF
///
/// Sig_script for reveal: <sig> <preimage> OP_FALSE <redeem>
///
pub fn build_commit_reveal_script(
    owner_pubkey: &[u8; 32],
    committed_hash: &[u8; 32],
    locktime_daa: u64,
) -> Vec<u8> {
    use covenant_ops::*;
    let mut s = Vec::with_capacity(128);

    // Owner refund path (IF) — timeout, commitment expired
    s.push(OP_IF);
    push_pubkey(&mut s, owner_pubkey);
    s.push(OP_CHECKSIGVERIFY);
    push_int(&mut s, locktime_daa);
    s.push(OP_CHECKLOCKTIMEVERIFY);
    s.push(OP_1);

    // Reveal path (ELSE) — provide preimage parts + signature
    s.push(OP_ELSE);

    // Owner must sign first (prevents front-running the reveal)
    push_pubkey(&mut s, owner_pubkey);
    s.push(OP_CHECKSIGVERIFY);

    // Two preimage parts on stack: part_A (second), part_B (top)
    // CAT: pop part_B (x2), pop part_A (x1), push part_A||part_B
    // Then hash and verify against commitment
    s.push(OP_CAT);
    s.push(OP_BLAKE2B);
    push_data(&mut s, committed_hash);
    s.push(OP_EQUALVERIFY);
    s.push(OP_1);

    s.push(OP_ENDIF);
    s
}

/// Sig_script for owner spending (OP_IF branch).
// Kept: CDP owner sig-script builder, not yet wired to UI.
#[allow(dead_code)]
pub fn build_covenant_owner_sig_script(
    signature: &[u8],
    sighash_type: u8,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(signature.len() + redeem_script.len() + 10);
    let sig_len = signature.len() + 1;
    ss.push(sig_len as u8);
    ss.extend_from_slice(signature);
    ss.push(sighash_type);
    ss.push(0x51); // OP_TRUE → IF branch
    if redeem_script.len() <= 75 {
        ss.push(redeem_script.len() as u8);
    } else {
        ss.push(0x4c);
        ss.push(redeem_script.len() as u8);
    }
    ss.extend_from_slice(redeem_script);
    ss
}

/// Sig_script for borrower spending (OP_ELSE branch — no signature).
// Kept: CDP borrower sig-script builder, not yet wired to UI.
#[allow(dead_code)]
pub fn build_covenant_borrower_sig_script(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(redeem_script.len() + 5);
    ss.push(covenant_ops::OP_0); // OP_FALSE → ELSE branch
    if redeem_script.len() <= 75 {
        ss.push(redeem_script.len() as u8);
    } else {
        ss.push(0x4c);
        ss.push(redeem_script.len() as u8);
    }
    ss.extend_from_slice(redeem_script);
    ss
}
