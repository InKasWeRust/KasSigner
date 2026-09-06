//! Seed-pool mixing steps that are independent of camera transport.

use sha2::{Digest, Sha256};

use super::{health::{EntropyError, HealthReport}, mixer, platform, trng};

pub(super) struct InitialEntropyEvidence {
    pub report: HealthReport,
    pub device_identity_mixed: bool,
    pub timing_mixed: bool,
}

pub(super) fn mix_initial(
    pool: &mut [u8; 32],
    idle_ticks: u32,
) -> Result<InitialEntropyEvidence, EntropyError> {
    let mut trng_bytes = [0u8; 128];
    let timing_before = platform::timing_observation();
    let report = trng::fill_words(&mut trng_bytes)?;
    let timing_after = platform::timing_observation();
    let mut hasher = Sha256::new();
    hasher.update(trng_bytes);
    let timing_mixed =
        platform::update_timing_pair_checked(&mut hasher, timing_before, timing_after);
    let device_identity_mixed = platform::update_device_identity_checked(&mut hasher);
    hasher.update(idle_ticks.to_le_bytes());
    hasher.update([0x01]);
    mixer::xor_digest(pool, &hasher.finalize());
    mixer::zeroize(&mut trng_bytes);
    Ok(InitialEntropyEvidence { report, device_identity_mixed, timing_mixed })
}

pub(super) fn whiten(pool: &mut [u8; 32], idle_ticks: u32) -> Result<(), EntropyError> {
    let mut fresh = [0u8; 128];
    trng::fill_words(&mut fresh)?;
    let mut hasher = Sha256::new();
    hasher.update(*pool);
    hasher.update(fresh);
    platform::update_adc_noise(&mut hasher, 16);
    platform::update_systimer(&mut hasher);
    // Restore the original ESP32-S3 OPTIONAL_UNIQUE_ID contribution as
    // zero-credit deterministic device binding. It cannot satisfy any
    // mandatory entropy gate and is not treated as 128 bits of entropy.
    platform::update_optional_unique_id(&mut hasher);
    hasher.update(idle_ticks.to_le_bytes());
    hasher.update([0x03]);
    pool.copy_from_slice(&hasher.finalize());
    mixer::zeroize(&mut fresh);
    Ok(())
}
