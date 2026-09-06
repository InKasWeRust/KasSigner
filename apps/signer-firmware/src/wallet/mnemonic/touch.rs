//! Touchscreen entropy collection for the interactive Touch Seed workflow.
//!
//! Only movement events are admitted. Each accepted coordinate is bound to a
//! latched hardware timer observation and folded immediately into SHA-256, so
//! production builds never retain the raw gesture trace in RAM.

use sha2::{Digest, Sha256};

pub const TOUCH_ENTROPY_TARGET: usize = 2_048;
const DOMAIN: &[u8] = b"KasSigner-touch-entropy-v2";

pub struct TouchEntropyCollector {
    hasher: Option<Sha256>,
    count: usize,
    polls: u32,
    last_x: u16,
    last_y: u16,
}

impl TouchEntropyCollector {
    pub const fn new() -> Self {
        Self {
            hasher: None,
            count: 0,
            polls: 0,
            last_x: u16::MAX,
            last_y: u16::MAX,
        }
    }

    /// Destroy an in-progress transcript and restore the collector defaults.
    pub fn zeroize(&mut self) {
        if let Some(hasher) = self.hasher.take() {
            // `Sha256` has no secret-bearing heap allocation. Suppress its drop
            // after volatile-clearing the complete in-place state so a partial
            // touch transcript cannot survive a duress/device wipe.
            let mut hasher = core::mem::ManuallyDrop::new(hasher);
            // SAFETY: `hasher` is exclusively owned here. The byte slice spans
            // exactly this stack value and is never read after it is cleared.
            let bytes = unsafe {
                core::slice::from_raw_parts_mut(
                    (&mut *hasher as *mut Sha256).cast::<u8>(),
                    core::mem::size_of::<Sha256>(),
                )
            };
            shared_signer::bytes::zeroize_bytes(bytes);
        }
        shared_signer::bytes::volatile_clear(core::slice::from_mut(&mut self.count), 0usize);
        shared_signer::bytes::volatile_clear(core::slice::from_mut(&mut self.polls), 0u32);
        self.last_x = u16::MAX;
        self.last_y = u16::MAX;
    }

    pub fn reset(&mut self) {
        self.zeroize();
    }

    pub const fn count(&self) -> usize { self.count }
    pub const fn target(&self) -> usize { TOUCH_ENTROPY_TARGET }

    /// Record one raw touch-controller observation. Returns true only when a
    /// new movement sample was accepted into the entropy transcript.
    pub fn record(&mut self, timestamp: u32, x: u16, y: u16) -> bool {
        self.polls = self.polls.saturating_add(1);
        if self.count >= TOUCH_ENTROPY_TARGET || (x == self.last_x && y == self.last_y) {
            return false;
        }
        self.last_x = x;
        self.last_y = y;
        let hasher = self.hasher.get_or_insert_with(|| {
            let mut hasher = Sha256::new();
            hasher.update(DOMAIN);
            hasher
        });
        hasher.update(timestamp.to_le_bytes());
        hasher.update(x.to_le_bytes());
        hasher.update(y.to_le_bytes());
        self.count += 1;
        true
    }

    /// Finalize only after the full collection target has been reached.
    /// The collector resets immediately after extraction.
    pub fn finish(&mut self) -> Option<[u8; 32]> {
        if self.count < TOUCH_ENTROPY_TARGET {
            return None;
        }
        let mut hasher = self.hasher.take()?;
        hasher.update((self.count as u32).to_le_bytes());
        hasher.update(self.polls.to_le_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        self.reset();
        Some(digest)
    }
}

impl Default for TouchEntropyCollector {
    fn default() -> Self { Self::new() }
}
