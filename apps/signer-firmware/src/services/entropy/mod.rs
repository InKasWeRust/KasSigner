// Hardware entropy façade. UI/controllers only request checked entropy.

mod ambient;
mod camera;
mod collection;
mod health;
#[cfg(any(feature = "waveshare", feature = "m5stack"))]
mod imu;
mod mixer;
mod platform;
mod seed;
mod trng;
mod touch;

pub use collection::{collect, fill};
#[cfg(all(not(feature = "hardware-tests"), not(feature = "workflow-test-auto")))]
pub use ambient::stage_touch as stage_ambient_touch;
#[cfg(any(feature = "waveshare", feature = "m5stack"))]
pub use imu::initialize as initialize_imu;
#[cfg(all(feature = "waveshare", not(feature = "workflow-test-auto")))]
pub use imu::stage_idle as stage_idle_imu;
#[cfg(not(feature = "hardware-tests"))]
pub use touch::{harden_touch_entropy, touch_timestamp};
pub use health::EntropyError;
#[cfg(any(test, feature = "verbose-boot"))]
pub(crate) use health::{inspect, HEALTH_SAMPLE_COUNT};
pub use mixer::{mix_additive_dice, zeroize};
#[cfg(not(feature = "hardware-tests"))]
pub use mixer::mix_additive_touch;

#[cfg(feature = "wdev-capture")]
pub(crate) fn wdev_capture_prepare() -> Result<(), EntropyError> { trng::enable_hardware_rng() }

#[cfg(feature = "wdev-capture")]
#[inline]
pub(crate) fn wdev_capture_sample() -> u32 { trng::sample() }

#[cfg(feature = "rng-probe")]
pub(crate) fn log_rng_probe(label: &str) {
    let (distinct, ones, zero_words, repeats) = trng::probe(256);
    crate::log!(
        "[rng-probe] {}: distinct {}/256 ones {}/8192 zeros {} repeats {}",
        label, distinct, ones, zero_words, repeats
    );
}


#[cfg(feature = "rng-probe")]
pub(crate) fn finish_rng_probe(delay: &mut esp_hal::delay::Delay) -> ! {
    log_rng_probe("after lockdown");
    crate::log!("[rng-probe] diagnostic complete; wallet routing disabled");
    crate::halt_forever(delay)
}
