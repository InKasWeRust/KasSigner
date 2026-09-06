use crate::{
    contracts::merkle::script::{compute_merkle_root, generate_merkle_proof},
    protocol::script::p2sh::blake2b_hash,
};

fn rebuild_root(leaf: &[u8], proof: &[([u8; 32], u8)]) -> [u8; 32] {
    let mut current = blake2b_hash(leaf);
    for (sibling, direction) in proof {
        let mut pair = Vec::with_capacity(64);
        if *direction == 1 {
            pair.extend_from_slice(&current);
            pair.extend_from_slice(sibling);
        } else {
            pair.extend_from_slice(sibling);
            pair.extend_from_slice(&current);
        }
        current = blake2b_hash(&pair);
    }
    current
}

#[test]
fn merkle_proofs_cover_left_right_padding_and_invalid_indices() {
    assert!(generate_merkle_proof(&[], 0).is_empty());

    let leaves = vec![vec![0x51], vec![0x52], vec![0x53]];
    assert!(generate_merkle_proof(&leaves, leaves.len()).is_empty());
    let expected = compute_merkle_root(&leaves);

    for (index, leaf) in leaves.iter().enumerate() {
        let proof = generate_merkle_proof(&leaves, index);
        assert_eq!(proof.len(), 2);
        assert_eq!(rebuild_root(leaf, &proof), expected);
    }

    assert_eq!(generate_merkle_proof(&leaves, 0)[0].1, 1);
    assert_eq!(generate_merkle_proof(&leaves, 1)[0].1, 0);
}
