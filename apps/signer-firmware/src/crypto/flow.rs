// Ordered anti-glitch execution transcript.
//
// A simple counter can be satisfied by skipping one stage and executing a
// different stage twice. This transcript mixes a distinct token for every
// security stage, so both the number and order of completed stages must match.

use core::sync::atomic::{compiler_fence, AtomicU32, Ordering};

const INITIAL_STATE: u32 = 0x4B41_5353;
const MIX_MULTIPLIER: u32 = 0x9E37_79B1;
static TRANSCRIPT: AtomicU32 = AtomicU32::new(INITIAL_STATE);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Stage {
    VerifyStart = 0xA1F0_0001,
    AntiRollback = 0xA1F0_0002,
    MapStart = 0xA1F0_0010,
    SegmentReady = 0xA1F0_0011,
    HashComplete = 0xA1F0_0012,
    CompareComplete = 0xA1F0_0013,
}

#[inline]
const fn mix(state: u32, stage: Stage) -> u32 {
    state
        .rotate_left(7)
        .wrapping_add(stage as u32)
        .wrapping_mul(MIX_MULTIPLIER)
        ^ 0xD3A2_64C5
}

#[inline(never)]
pub fn reset() {
    compiler_fence(Ordering::SeqCst);
    TRANSCRIPT.store(INITIAL_STATE, Ordering::SeqCst);
    compiler_fence(Ordering::SeqCst);
}

#[inline(never)]
pub fn advance(stage: Stage) {
    compiler_fence(Ordering::SeqCst);
    let mut current = TRANSCRIPT.load(Ordering::SeqCst);
    loop {
        let next = mix(current, stage);
        match TRANSCRIPT.compare_exchange(
            current,
            next,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
    compiler_fence(Ordering::SeqCst);
}

#[cfg(feature = "production")]
#[inline(never)]
pub fn verify(expected: &[Stage]) -> bool {
    let expected_state = sequence_digest(expected);
    compiler_fence(Ordering::SeqCst);
    let actual = TRANSCRIPT.load(Ordering::SeqCst);
    compiler_fence(Ordering::SeqCst);
    actual == expected_state
}

#[cfg(any(feature = "production", test, feature = "verbose-boot"))]
pub(crate) fn sequence_digest(stages: &[Stage]) -> u32 {
    stages.iter().copied().fold(INITIAL_STATE, mix)
}
