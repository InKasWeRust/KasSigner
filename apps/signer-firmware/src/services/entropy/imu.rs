//! Board-neutral IMU entropy integration.
//!
//! KasSigner owns point-of-use completeness/diversity checks and zeroization.
//! CoreS3 seed creation additionally requires at least one healthy BMI270 window;
//! later `fill()` calls always remain fail-closed on the checked hardware TRNG.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use esp_hal::{Blocking, delay::Delay, i2c::master::I2c};
use sha2::{Digest, Sha256};

use super::mixer;
#[cfg(all(feature = "waveshare", not(feature = "workflow-test-auto")))]
use super::platform;

#[cfg(feature = "m5stack")]
pub(super) const SEED_SAMPLE_BYTES: usize = 33;
#[cfg(feature = "waveshare")]
pub(super) const SEED_SAMPLE_BYTES: usize = 96;
#[cfg(all(feature = "waveshare", not(feature = "workflow-test-auto")))]
const IDLE_SAMPLE_BYTES: usize = 24;
static STAGE: [AtomicU32; 8] = [
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
];
static STAGED: AtomicBool = AtomicBool::new(false);

pub fn initialize(i2c: &mut I2c<'_, Blocking>, delay: &mut Delay) -> bool {
    crate::hw::imu::init(i2c, delay)
}

pub(super) fn collect_seed_sample(
    i2c: &mut I2c<'_, Blocking>,
    delay: &mut Delay,
    output: &mut [u8; SEED_SAMPLE_BYTES],
) -> usize {
    crate::hw::imu::collect(i2c, delay, output)
}

pub(super) fn mix_seed_sample(
    pool: &mut [u8; 32],
    sample: &mut [u8; SEED_SAMPLE_BYTES],
    count: usize,
    source_tag: u8,
) -> bool {
    let healthy = count == sample.len() && crate::hw::imu::buffer_is_healthy(sample);
    #[cfg(feature = "m5stack")]
    {
        let distinct = crate::hw::imu::axis_distinct(&sample[..count]);
        crate::log!(
            "   [imu] seed window bytes {}/{} distinct X{} Y{} Z{}",
            count, sample.len(), distinct[0], distinct[1], distinct[2]
        );
    }
    if healthy {
        let mut hasher = Sha256::new();
        hasher.update(b"KasSigner-seed-imu-v2");
        hasher.update(*sample);
        hasher.update((count as u32).to_le_bytes());
        hasher.update([source_tag]);
        mixer::xor_digest(pool, &hasher.finalize());
    }
    mixer::zeroize(sample);
    healthy
}

/// Periodically refresh the persistent IMU stage while the UI is idle.
#[cfg(all(feature = "waveshare", not(feature = "workflow-test-auto")))]
pub fn stage_idle(i2c: &mut I2c<'_, Blocking>, delay: &mut Delay) -> bool {
    let mut sample = [0u8; IDLE_SAMPLE_BYTES];
    let count = crate::hw::imu::collect(i2c, delay, &mut sample);
    let healthy = count == sample.len() && crate::hw::imu::buffer_is_healthy(&sample);
    if healthy {
        let mut hasher = Sha256::new();
        hasher.update(b"KasSigner-imu-stage-v2");
        for word in &STAGE {
            hasher.update(word.load(Ordering::Relaxed).to_le_bytes());
        }
        hasher.update(sample);
        platform::update_systimer(&mut hasher);
        let digest: [u8; 32] = hasher.finalize().into();
        for (index, word) in STAGE.iter().enumerate() {
            let offset = index * 4;
            let bytes = [digest[offset], digest[offset + 1], digest[offset + 2], digest[offset + 3]];
            word.store(u32::from_le_bytes(bytes), Ordering::Relaxed);
        }
        STAGED.store(true, Ordering::Release);
    }
    mixer::zeroize(&mut sample);
    healthy
}

pub(super) fn mix_staged(hasher: &mut Sha256) {
    if !STAGED.load(Ordering::Acquire) {
        return;
    }
    hasher.update(b"KasSigner-imu-stage-v2");
    for word in &STAGE {
        hasher.update(word.load(Ordering::Relaxed).to_le_bytes());
    }
}
