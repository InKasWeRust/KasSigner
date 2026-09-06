//! Persistent ambient-touch contribution for later cryptographic randomness.
//!
//! Touch observations are supplemental only. They never satisfy or bypass the
//! checked TRNG requirement in `fill`; they are simply domain-separated input
//! to the final hash once real movement has been observed.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use sha2::{Digest, Sha256};

use super::platform;

static STAGE: [AtomicU32; 8] = [
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
];
static STAGED: AtomicBool = AtomicBool::new(false);
static LAST_TOUCH: AtomicU32 = AtomicU32::new(u32::MAX);

fn fold(data: &[u8], source_tag: u8) {
    let mut hasher = Sha256::new();
    hasher.update(b"KasSigner-ambient-stage-v2");
    for word in &STAGE {
        hasher.update(word.load(Ordering::Relaxed).to_le_bytes());
    }
    hasher.update(data);
    hasher.update((data.len() as u32).to_le_bytes());
    hasher.update([source_tag]);
    let digest: [u8; 32] = hasher.finalize().into();
    for (index, word) in STAGE.iter().enumerate() {
        let offset = index * 4;
        let bytes = [digest[offset], digest[offset + 1], digest[offset + 2], digest[offset + 3]];
        word.store(u32::from_le_bytes(bytes), Ordering::Relaxed);
    }
    STAGED.store(true, Ordering::Release);
}

/// Fold a changed touch position and its arrival time into the ambient stage.
pub fn stage_touch(x: u16, y: u16) {
    let packed = (u32::from(x) << 16) | u32::from(y);
    if LAST_TOUCH.swap(packed, Ordering::Relaxed) == packed {
        return;
    }
    let mut observation = [0u8; 8];
    observation[..4].copy_from_slice(&platform::systimer_low().to_le_bytes());
    observation[4..6].copy_from_slice(&x.to_le_bytes());
    observation[6..].copy_from_slice(&y.to_le_bytes());
    fold(&observation, 0x23);
}

/// Mix the accumulated ambient stage into one checked `fill()` transcript.
pub(super) fn mix_staged(hasher: &mut Sha256) {
    if !STAGED.load(Ordering::Acquire) {
        return;
    }
    hasher.update(b"KasSigner-ambient-touch-v2");
    for word in &STAGE {
        hasher.update(word.load(Ordering::Relaxed).to_le_bytes());
    }
}
