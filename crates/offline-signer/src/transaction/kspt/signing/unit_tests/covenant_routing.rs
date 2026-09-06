use alloc::{vec, vec::Vec};

use super::super::covenant::scan_candidate_keys;
use crate::transaction::kspt::PsktError;

fn append_candidate(script: &mut Vec<u8>, value: u8, checksig: u8) {
    script.push(0x20);
    script.extend_from_slice(&[value; 32]);
    script.push(checksig);
}

#[test]
fn covenant_scanner_keeps_exact_first_eight_candidates_in_wire_order() {
    let mut script = Vec::new();
    for value in 0x10u8..=0x18 {
        append_candidate(&mut script, value, 0xac);
    }

    let candidates = scan_candidate_keys(&script).expect("nine-candidate scan");
    assert_eq!(candidates.len, 8);
    for (index, value) in (0x10u8..=0x17).enumerate() {
        assert_eq!(candidates.keys[index], [value; 32], "candidate {index}");
    }
    assert!(!candidates.keys[..candidates.len].contains(&[0x18; 32]));
}

#[test]
fn covenant_scanner_validates_the_tail_after_candidate_capacity_is_full() {
    let mut script = Vec::new();
    for value in 0u8..8 {
        append_candidate(&mut script, value, 0xac);
    }
    // A full candidate table must not make the parser stop validating the
    // remainder of the redeem script. This truncated PUSHDATA2 is malformed.
    script.extend_from_slice(&[0x4d, 0x01]);
    assert!(matches!(
        scan_candidate_keys(&script),
        Err(PsktError::InvalidModel)
    ));
}

#[test]
fn covenant_scanner_observes_exact_checksig_offsets() {
    let key = [0x51u8; 32];

    let mut immediate = vec![0x20];
    immediate.extend_from_slice(&key);
    immediate.push(0xac);
    assert_eq!(scan_candidate_keys(&immediate).unwrap().keys[0], key);

    let mut one_opcode_gap = vec![0x20];
    one_opcode_gap.extend_from_slice(&key);
    one_opcode_gap.extend_from_slice(&[0x00, 0xad]);
    assert_eq!(scan_candidate_keys(&one_opcode_gap).unwrap().keys[0], key);

    let mut two_opcode_gap = vec![0x20];
    two_opcode_gap.extend_from_slice(&key);
    two_opcode_gap.extend_from_slice(&[0x00, 0x00, 0xac]);
    assert_eq!(scan_candidate_keys(&two_opcode_gap).unwrap().len, 0);

    let mut one_trailing_non_checksig = vec![0x20];
    one_trailing_non_checksig.extend_from_slice(&key);
    one_trailing_non_checksig.push(0x00);
    assert_eq!(
        scan_candidate_keys(&one_trailing_non_checksig).unwrap().len,
        0
    );

    let mut no_checksig = vec![0x20];
    no_checksig.extend_from_slice(&key);
    assert_eq!(scan_candidate_keys(&no_checksig).unwrap().len, 0);
}

#[test]
fn covenant_scanner_skips_exact_small_direct_push_payload() {
    let key = [0x65u8; 32];
    let mut script = vec![0x02, 0xaa, 0x4d];
    append_candidate(&mut script, 0x65, 0xac);
    let candidates = scan_candidate_keys(&script).expect("small direct push scan");
    assert_eq!(candidates.len, 1);
    assert_eq!(candidates.keys[0], key);
}

#[test]
fn covenant_scanner_decodes_pushdata_lengths_as_exact_little_endian_integers() {
    let key2 = [0x62u8; 32];
    let mut pushdata2 = vec![0x4d, 0x02, 0x01]; // 0x0102 = 258 bytes
    pushdata2.extend_from_slice(&vec![0x55; 258]);
    append_candidate(&mut pushdata2, 0x62, 0xac);
    let candidates = scan_candidate_keys(&pushdata2).expect("PUSHDATA2 scan");
    assert_eq!(candidates.len, 1);
    assert_eq!(candidates.keys[0], key2);

    let key4 = [0x73u8; 32];
    let mut pushdata4 = vec![0x4e, 0x00, 0x01, 0x00, 0x00]; // 0x00000100 = 256 bytes
    pushdata4.extend_from_slice(&vec![0x44; 256]);
    append_candidate(&mut pushdata4, 0x73, 0xad);
    let candidates = scan_candidate_keys(&pushdata4).expect("PUSHDATA4 scan");
    assert_eq!(candidates.len, 1);
    assert_eq!(candidates.keys[0], key4);
}

#[test]
fn covenant_scanner_rejects_exact_push_length_overruns() {
    assert!(matches!(
        scan_candidate_keys(&[0x01]),
        Err(PsktError::InvalidModel)
    ));
    assert!(matches!(
        scan_candidate_keys(&[0x4c, 0x01]),
        Err(PsktError::InvalidModel)
    ));
    assert!(matches!(
        scan_candidate_keys(&[0x4d, 0x01, 0x00]),
        Err(PsktError::InvalidModel)
    ));
    assert!(matches!(
        scan_candidate_keys(&[0x4e, 0x01, 0x00, 0x00, 0x00]),
        Err(PsktError::InvalidModel),
    ));
}

#[test]
fn covenant_scanner_requires_strict_outer_loop_progress() {
    // Two ordinary one-byte opcodes are a valid script for the candidate-key
    // scanner and therefore must consume exactly two bytes. If the internal
    // checked-advance helper is replaced wholesale with Ok(0) or Ok(1), the
    // independent outer invariant must fail immediately instead of looping.
    let candidates = scan_candidate_keys(&[0x00, 0x00]).expect("two-byte progress");
    assert_eq!(candidates.len, 0);
}
