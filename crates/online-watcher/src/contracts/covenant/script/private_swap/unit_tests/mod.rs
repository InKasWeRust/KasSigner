use super::build_private_swap_script;
use crate::protocol::script::opcode::{OP_BLAKE2B, OP_CHECKSIGFROMSTACK, OP_SHA256};

#[test]
fn private_swap_script_is_canonical_and_has_no_hashlock_or_checksigfromstack() {
    let destination: Vec<u8> = [0, 0, 0x20].into_iter().chain([3u8; 32]).collect();
    let script =
        build_private_swap_script(&[1; 32], &[2; 32], &destination, 5000, &[4; 16]).unwrap();
    assert!(!script.contains(&OP_SHA256));
    assert!(!script.contains(&OP_BLAKE2B));
    assert!(!script.contains(&OP_CHECKSIGFROMSTACK));
}

#[test]
fn private_swap_rejects_invalid_configuration_boundaries() {
    let owner = [1u8; 32];
    let claimer = [2u8; 32];
    let valid_destination = [3u8; 35];
    let salt = [4u8; 16];

    assert!(build_private_swap_script(&owner, &claimer, &valid_destination, 0, &salt).is_err());
    assert!(build_private_swap_script(&owner, &claimer, &valid_destination, 1, &[0; 16]).is_err());
    assert!(build_private_swap_script(&owner, &claimer, &[0; 2], 1, &salt).is_err());
    assert!(build_private_swap_script(&owner, &claimer, &[0; 74], 1, &salt).is_err());
    assert!(build_private_swap_script(&owner, &owner, &valid_destination, 1, &salt).is_err());
}
