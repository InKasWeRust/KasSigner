// KasSee Web — Merkle Whitelist Vault builders (moved out of kspt.rs).
// Re-exported by kspt via `pub use merkle::*`. License: GPL-3.0.

//! Merkle-whitelist vault script builder plus the merkle root and proof helpers.
//! Re-exported by the parent `kspt` module.

use super::{blake2b_hash, covenant_ops, push_data, push_int, push_pubkey};

/// Build a merkle whitelist vault covenant redeem script.
///
/// Funds can ONLY be sent to addresses in the merkle tree.
/// The script stores only the 32-byte merkle root.
/// At spend time, the sig_script provides:
///   - the destination SPK (leaf)
///   - sibling hashes for each tree level
///   - direction bits (0=leaf is left, 1=leaf is right)
///   - owner signature
///
/// Two branches:
///   IF: owner refund after locktime (emergency recovery)
///   ELSE: owner signs + merkle proof verifies destination is whitelisted
///         + output[0].spk == proven leaf (destination enforcement)
///
/// Script (ELSE branch):
///   <owner_pk> CHECKSIGVERIFY
///   — merkle proof verification (unrolled loop, `depth` levels) —
///   For each level (direction bit + sibling already on stack):
///     OP_IF OP_SWAP OP_ENDIF   (swap if leaf is right child)
///     OP_CAT OP_BLAKE2B        (hash the pair)
///   — end loop —
///   <merkle_root_32B> EQUALVERIFY   (verify computed root)
///   — destination enforcement —
///   push(0) TX_OUTPUT_SPK EQUAL     (output[0].spk == leaf from sig_script)
///
/// Sig_script layout (bottom → top):
///   <dest_spk> <sibling_0> <dir_0> <sibling_1> <dir_1> ... <sibling_N> <dir_N> <sig>
///   OP_FALSE <redeem>
///
/// After CHECKSIGVERIFY consumes sig, stack is:
///   <dest_spk> <sibling_0> <dir_0> <sibling_1> <dir_1> ... <sibling_N> <dir_N>
///
/// Wait — the merkle loop needs to consume direction bits and siblings
/// from top of stack downward, but the leaf (dest_spk) is at the bottom.
/// We need the leaf on top first.
///
/// Revised sig_script layout (bottom → top):
///   <dir_N> <sibling_N> ... <dir_1> <sibling_1> <dir_0> <sibling_0> <dest_spk> <sig>
///   OP_FALSE <redeem>
///
/// After CHECKSIGVERIFY: stack top = dest_spk
/// Then script DUPs dest_spk (for later output verification).
/// Loop level 0: pop sibling_0, pop dir_0, swap-if-right, CAT, BLAKE2B
/// Loop level 1: pop sibling_1, pop dir_1, swap-if-right, CAT, BLAKE2B
/// ... up to level N.
/// Result: computed root on top. EQUALVERIFY against stored root.
/// Then: verify output[0].spk == dest_spk (saved via DUP at start).
///
/// Actually simpler: after CHECKSIGVERIFY, dest_spk is on top.
/// We need to save it AND use it for hashing. Use OP_DUP:
///   DUP → [dest_spk, dest_spk]
///   BLAKE2B → [dest_spk, BLAKE2B(dest_spk)]  ← this is the leaf hash
///
/// Wait — the merkle tree leaves are BLAKE2B(address_spk).
/// So the leaf = BLAKE2B(dest_spk). The sig_script pushes raw dest_spk,
/// the script hashes it to get the leaf, then walks up the tree.
///
pub fn build_merkle_whitelist_script(
    owner_pubkey: &[u8; 32],
    merkle_root: &[u8; 32],
    depth: u8,
    locktime_daa: u64,
) -> Vec<u8> {
    use covenant_ops::*;
    let mut s = Vec::with_capacity(256);

    // Owner refund path (IF) — emergency recovery
    s.push(OP_IF);
    push_pubkey(&mut s, owner_pubkey);
    s.push(OP_CHECKSIGVERIFY);
    push_int(&mut s, locktime_daa);
    s.push(OP_CHECKLOCKTIMEVERIFY);
    s.push(OP_1);

    // Merkle whitelist path (ELSE)
    s.push(OP_ELSE);

    // Owner must sign
    push_pubkey(&mut s, owner_pubkey);
    s.push(OP_CHECKSIGVERIFY);

    // Stack after CHECKSIGVERIFY (top → bottom):
    //   dest_spk | dir_0 | sibling_0 | ... | dir_N | sibling_N | dest_spk_copy
    // dest_spk_copy is at the bottom (pushed first in sig_script)

    // Hash dest_spk to get the leaf — consumes dest_spk, leaves leaf_hash
    s.push(OP_BLAKE2B);

    // Now stack: dest_spk | leaf_hash
    // leaf_hash is on top. Walk up the tree.

    // For each level: consume sibling + direction from deeper in the stack.
    // But siblings are BELOW dest_spk in the stack. We need them on top.
    //
    // Revised approach: push siblings and dirs on TOP, above dest_spk.
    //
    // Sig_script (bottom → top):
    //   <dest_spk> <sig> <dir_0> <sibling_0> <dir_1> <sibling_1> ...
    //
    // No — sig must be on top for CHECKSIGVERIFY. Let me rethink.
    //
    // Sig_script (bottom → top):
    //   <dir_N-1> <sibling_N-1> ... <dir_0> <sibling_0> <dest_spk> <sig>
    //   OP_FALSE <redeem>
    //
    // After CHECKSIGVERIFY eats sig:
    //   Stack: dir_N-1 | sibling_N-1 | ... | dir_0 | sibling_0 | dest_spk
    //   (dest_spk on top)
    //
    // DUP dest_spk, BLAKE2B → leaf_hash on top
    // Stack: dir_N-1 | ... | dir_0 | sibling_0 | dest_spk | leaf_hash
    //
    // Now need sibling_0 and dir_0. They're below dest_spk.
    // After DUP+BLAKE2B we have 2 extra items on top.
    //
    // This stack ordering is getting complex. Let me use a cleaner layout.
    //
    // Cleanest: all proof data ABOVE sig on the stack. But CHECKSIGVERIFY
    // pops the top 2 items (sig + pubkey). Pubkey is pushed by the script.
    // So sig must be right below the script-pushed pubkey.
    //
    // Layout that works:
    //   Sig_script pushes (bottom → top):
    //     <dest_spk> <sig> OP_FALSE <redeem>
    //
    //   The merkle proof (siblings + directions) are embedded in the
    //   sig_script BELOW dest_spk:
    //     <sibling_0> <dir_0> <sibling_1> <dir_1> ... <dest_spk> <sig> OP_FALSE <redeem>
    //
    //   After P2SH pops redeem + FALSE selects ELSE:
    //     Stack: sibling_0 | dir_0 | sibling_1 | dir_1 | ... | dest_spk | sig
    //   CHECKSIGVERIFY eats sig:
    //     Stack: sibling_0 | dir_0 | sibling_1 | dir_1 | ... | dest_spk
    //
    //   DUP, BLAKE2B:
    //     Stack: sibling_0 | dir_0 | ... | dest_spk | leaf_hash
    //
    //   Now for level 0: need sibling_0 and dir_0 from bottom.
    //   Can't reach them — they're buried.
    //
    // Final clean approach: push proof items in REVERSE order so they're
    // consumed top-down:
    //
    //   Sig_script (bottom → top):
    //     <dest_spk> <sibling_N-1> <dir_N-1> ... <sibling_0> <dir_0> <sig>
    //     OP_FALSE <redeem>
    //
    //   After CHECKSIGVERIFY:
    //     Stack: dest_spk | sibling_N-1 | dir_N-1 | ... | sibling_0 | dir_0
    //     (dir_0 on top)
    //
    //   But we need dest_spk first (it's at the bottom).
    //
    // OK — the real solution is to put dest_spk on TOP, after the proof:
    //
    //   Sig_script (bottom → top):
    //     <sibling_N-1> <dir_N-1> ... <sibling_0> <dir_0> <dest_spk> <sig>
    //     OP_FALSE <redeem>
    //
    //   After CHECKSIGVERIFY:
    //     Stack: sibling_N-1 | dir_N-1 | ... | sibling_0 | dir_0 | dest_spk
    //
    //   DUP, BLAKE2B:
    //     Stack: sibling_N-1 | dir_N-1 | ... | sibling_0 | dir_0 | dest_spk | leaf_hash
    //
    //   Level 0: need dir_0 and sibling_0. They're below dest_spk.
    //   Use SWAP to get dir_0: SWAP → ... | sibling_0 | dest_spk | leaf_hash | dir_0
    //   Hmm, SWAP only swaps top 2. dir_0 is 2 items below top.
    //
    // This requires OP_ROT or OP_PICK. Let me check if we have those.
    // OP_ROT = 0x7b (rotate top 3: [a,b,c] → [b,c,a])
    // OP_PICK = 0x79 (copy item at depth N to top)
    //
    // Actually — simplest approach: don't save dest_spk. After merkle
    // verification, push output[0].spk and verify it matches the
    // dest_spk by computing BLAKE2B(output[0].spk) and comparing
    // against the leaf hash that we just computed.
    //
    // But we don't have the leaf hash anymore — it was consumed by
    // the merkle tree computation.
    //
    // Simplest correct design: no DUP. Just verify the merkle proof,
    // then separately verify output[0].spk is the same dest_spk.
    // Push dest_spk twice in the sig_script:
    //
    //   Sig_script (bottom → top):
    //     <dest_spk_copy> <dir_0> <sibling_0> <dir_1> <sibling_1> ... <dest_spk> <sig>
    //     OP_FALSE <redeem>
    //
    //   After CHECKSIGVERIFY:
    //     dest_spk_copy | dir_0 | sibling_0 | ... | dest_spk
    //
    //   Script: BLAKE2B (hashes dest_spk → leaf_hash)
    //   For each level: script does OP_ROT to bring dir to top,
    //     IF SWAP ENDIF, then OP_ROT to bring sibling, CAT, BLAKE2B
    //
    // This is getting complicated. Let me use a much simpler layout
    // where proof items are interleaved and consumed from the top:
    //
    //   Sig_script (bottom → top):
    //     <dest_spk_for_output_check>
    //     <dest_spk> <dir_0> <sibling_0> <dir_1> <sibling_1> ... <dir_N-1> <sibling_N-1>
    //     <sig>
    //     OP_FALSE <redeem>
    //
    //   After CHECKSIGVERIFY, stack (top → bottom):
    //     sibling_N-1 | dir_N-1 | ... | sibling_0 | dir_0 | dest_spk | dest_spk_copy
    //
    //   Script processes top-down:
    //     Level N-1: pop sibling_N-1, then pop dir_N-1
    //   But there's nothing to hash with yet — we need to start from the leaf.
    //
    // I need the leaf at the TOP, and siblings consumed from top.
    // Let me just reverse everything:
    //
    //   Sig_script (bottom → top):
    //     <dest_spk_for_output_check>
    //     <sibling_N-1> <dir_N-1> ... <sibling_0> <dir_0>
    //     <dest_spk>
    //     <sig>
    //     OP_FALSE <redeem>
    //
    //   After CHECKSIGVERIFY:
    //     Top: dest_spk
    //     Below: dir_0 | sibling_0 | dir_1 | sibling_1 | ... | dest_spk_copy
    //
    //   BLAKE2B → leaf_hash on top
    //   Level 0: need dir_0 (now 2nd from top) and sibling_0 (3rd from top)
    //     SWAP → dir_0 on top, leaf_hash below
    //     IF SWAP ENDIF → conditionally swap leaf_hash and upcoming sibling
    //
    // Hmm, still need to get sibling_0. After SWAP, stack is:
    //     dir_0 | leaf_hash | sibling_0 | dir_1 | ...
    //   IF (consumes dir_0):
    //     SWAP → sibling_0 | leaf_hash
    //   ENDIF
    //   CAT → sibling_0 || leaf_hash (or leaf_hash || sibling_0)
    //   BLAKE2B → level_1_hash
    //
    // Wait — after the IF consumes dir_0, I need the sibling.
    // Stack after IF consumed dir_0: leaf_hash | sibling_0 | dir_1 | ...
    // Inside IF: SWAP → sibling_0 | leaf_hash
    // After ENDIF: either (leaf_hash | sibling_0) or (sibling_0 | leaf_hash)
    // CAT: concatenates top two → correct order
    // BLAKE2B: hash
    //
    // But SWAP only works inside the IF. If dir=0, no swap happens,
    // so stack is: leaf_hash | sibling_0
    // CAT → leaf_hash || sibling_0 — LEFT child first. Correct!
    // If dir=1, SWAP → sibling_0 | leaf_hash
    // CAT → sibling_0 || leaf_hash — RIGHT child swapped. Correct!
    //
    // After BLAKE2B: level_1_hash on top. Next: dir_1 | sibling_1 | ...
    // SWAP brings dir_1 to top. IF consumes it. Same pattern.
    //
    // THIS WORKS! The pattern per level is: SWAP IF SWAP ENDIF CAT BLAKE2B
    // That's 6 bytes per level.

    // Merkle proof verification — unrolled loop
    // Stack before each level: ... | sibling | dir | current_hash
    // SWAP brings dir to top. IF checks dir.
    // CAT: pops x2(top), pops x1(second), pushes x1||x2
    //
    // When dir=1: SWAP inside IF → current_hash goes below sibling
    //   CAT gives current_hash || sibling (leaf is left)
    // When dir=0: no swap
    //   CAT gives sibling || current_hash (leaf is right)
    //
    // Direction encoding is INVERTED in the proof generator:
    //   leaf is left child → dir=1 (swap so leaf ends up as x1 in CAT)
    //   leaf is right child → dir=0 (no swap, sibling is x1 in CAT)
    for _ in 0..depth {
        s.push(OP_SWAP); // bring dir bit to top
        s.push(OP_IF); // if dir=1
        s.push(OP_SWAP); //   swap positions
        s.push(OP_ENDIF);
        s.push(OP_CAT); // x1(second) || x2(top)
        s.push(OP_BLAKE2B); // hash the pair
    }

    // Verify computed root matches embedded root
    push_data(&mut s, merkle_root);
    s.push(OP_EQUALVERIFY);

    // Verify output[0].spk matches the dest_spk we just proved
    // dest_spk_copy is still on the stack (pushed first in sig_script)
    push_int(&mut s, 0);
    s.push(OP_TX_OUTPUT_SPK);
    s.push(OP_EQUALVERIFY);

    s.push(OP_1);

    s.push(OP_ENDIF);
    s
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
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        // Direction is INVERTED for the script's CAT order:
        // idx even (left child) → dir=1 (SWAP so leaf becomes x1 in CAT)
        // idx odd (right child) → dir=0 (no swap, sibling is x1 in CAT)
        let direction = if idx % 2 == 0 { 1u8 } else { 0u8 };
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
