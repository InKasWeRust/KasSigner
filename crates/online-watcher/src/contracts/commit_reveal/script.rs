// KasSee Web — Commit-Reveal + CDP owner/borrower sig-script builders.
// License: GPL-3.0.

//! Commit-reveal covenant script and the CDP owner/borrower sig-script builders.

use crate::protocol::script::{opcode as covenant_ops, push_data, push_int, push_pubkey};

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
