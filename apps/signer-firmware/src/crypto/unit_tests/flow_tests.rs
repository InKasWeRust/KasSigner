use crate::crypto::flow::{sequence_digest, Stage};

pub fn run_flow_tests() -> (u32, u32) {
    let intended = sequence_digest(&[Stage::MapStart, Stage::SegmentReady]);
    let reversed = sequence_digest(&[Stage::SegmentReady, Stage::MapStart]);
    let duplicated = sequence_digest(&[Stage::MapStart, Stage::MapStart]);
    let passed = u32::from(intended != reversed) + u32::from(intended != duplicated);
    (passed, 2)
}

#[test]
fn ordered_transcript_rejects_reordering_and_duplication() {
    let (passed, total) = run_flow_tests();
    assert_eq!(passed, total);
}
