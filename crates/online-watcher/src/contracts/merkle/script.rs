// KasSee Web — Merkle Whitelist Vault builders.
// License: GPL-3.0.

//! Merkle-whitelist vault script builder plus the merkle root and proof helpers.

use crate::protocol::script::{
    opcode as covenant_ops, p2sh::blake2b_hash, push_data, push_int, push_pubkey,
};

/// Build a Merkle-whitelist vault redeem script.
///
/// The owner may recover after `locktime_daa`. Before that, an owner-signed
/// spend must prove the destination script belongs to the committed Merkle
/// tree and must bind output zero to that destination.
pub fn build_merkle_whitelist_script(
    owner_pubkey: &[u8; 32],
    merkle_root: &[u8; 32],
    depth: u8,
    locktime_daa: u64,
) -> Vec<u8> {
    use covenant_ops::*;
    let mut script = Vec::with_capacity(256);
    append_owner_refund_branch(&mut script, owner_pubkey, locktime_daa);
    append_whitelist_branch(&mut script, owner_pubkey, merkle_root, depth);
    script.push(OP_ENDIF);
    script
}

fn append_owner_refund_branch(script: &mut Vec<u8>, owner_pubkey: &[u8; 32], locktime_daa: u64) {
    use covenant_ops::*;
    script.push(OP_IF);
    push_pubkey(script, owner_pubkey);
    script.push(OP_CHECKSIGVERIFY);
    push_int(script, locktime_daa);
    script.push(OP_CHECKLOCKTIMEVERIFY);
    script.push(OP_1);
    script.push(OP_ELSE);
}

fn append_whitelist_branch(
    script: &mut Vec<u8>,
    owner_pubkey: &[u8; 32],
    merkle_root: &[u8; 32],
    depth: u8,
) {
    use covenant_ops::*;
    push_pubkey(script, owner_pubkey);
    script.push(OP_CHECKSIGVERIFY);
    script.push(OP_BLAKE2B);

    // Before each level the stack ends with sibling, direction, current hash.
    // Direction 1 swaps the pair before concatenation; direction 0 preserves it.
    for _ in 0..depth {
        script.push(OP_SWAP);
        script.push(OP_IF);
        script.push(OP_SWAP);
        script.push(OP_ENDIF);
        script.push(OP_CAT);
        script.push(OP_BLAKE2B);
    }

    push_data(script, merkle_root);
    script.push(OP_EQUALVERIFY);
    push_int(script, 0);
    script.push(OP_TX_OUTPUT_SPK);
    script.push(OP_EQUALVERIFY);
    script.push(OP_1);
}

/// Compute a merkle root from a list of leaf data (SPK bytes).
/// Each leaf is BLAKE2B(data). Tree is built bottom-up.
/// If the number of leaves is not a power of 2, pad with zero hashes.
pub fn compute_merkle_root(leaves: &[Vec<u8>]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }

    // Hash all leaves
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|leaf| blake2b_hash(leaf)).collect();

    // Pad to next power of 2
    let target = level.len().next_power_of_two();
    while level.len() < target {
        level.push([0u8; 32]);
    }

    // Build tree bottom-up
    while level.len() > 1 {
        let mut next_level = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let mut combined = Vec::with_capacity(64);
            combined.extend_from_slice(&pair[0]);
            combined.extend_from_slice(&pair[1]);
            next_level.push(blake2b_hash(&combined));
        }
        level = next_level;
    }

    level[0]
}

/// Generate a merkle proof for a leaf at the given index.
/// Returns: Vec of (sibling_hash, direction) where direction=0 means
/// the leaf is the left child, direction=1 means right child.
pub fn generate_merkle_proof(leaves: &[Vec<u8>], leaf_index: usize) -> Vec<([u8; 32], u8)> {
    if leaves.is_empty() || leaf_index >= leaves.len() {
        return vec![];
    }

    // Hash all leaves
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|leaf| blake2b_hash(leaf)).collect();

    // Pad to next power of 2
    let target = level.len().next_power_of_two();
    while level.len() < target {
        level.push([0u8; 32]);
    }

    let mut proof = Vec::new();
    let mut idx = leaf_index;

    while level.len() > 1 {
        let sibling_idx = if idx.is_multiple_of(2) {
            idx + 1
        } else {
            idx - 1
        };
        // Direction is INVERTED for the script's CAT order:
        // idx even (left child) → dir=1 (SWAP so leaf becomes x1 in CAT)
        // idx odd (right child) → dir=0 (no swap, sibling is x1 in CAT)
        let direction = if idx.is_multiple_of(2) { 1u8 } else { 0u8 };
        proof.push((level[sibling_idx], direction));

        // Build next level
        let mut next_level = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let mut combined = Vec::with_capacity(64);
            combined.extend_from_slice(&pair[0]);
            combined.extend_from_slice(&pair[1]);
            next_level.push(blake2b_hash(&combined));
        }
        level = next_level;
        idx /= 2;
    }

    proof
}
