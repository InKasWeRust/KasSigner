//! Touch Seed transcript hardening.

use sha2::{Digest, Sha256};

use super::{health::EntropyError, mixer, platform};

/// Strengthen a completed touch transcript with fresh checked hardware
/// randomness before it can become BIP39 entropy. Touch timing/coordinates are
/// an additional source, never the sole source of seed entropy.
pub fn harden_touch_entropy(touch_digest: &mut [u8; 32]) -> Result<[u8; 32], EntropyError> {
    let mut fresh = [0u8; 32];
    if let Err(error) = super::collection::fill(&mut fresh) {
        mixer::zeroize(&mut fresh);
        mixer::zeroize(touch_digest);
        return Err(error);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"KasSigner-touch-seed-v2");
    hasher.update(*touch_digest);
    hasher.update(fresh);
    platform::update_systimer(&mut hasher);
    let result: [u8; 32] = hasher.finalize().into();
    mixer::zeroize(&mut fresh);
    mixer::zeroize(touch_digest);
    Ok(result)
}

/// Latched hardware timer observation used by the touch transcript.
pub fn touch_timestamp() -> u32 { platform::systimer_low() }
