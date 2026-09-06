// ESP32-S3 hardware RNG access used by the entropy service.

use super::health::{inspect, EntropyError, HealthReport, HEALTH_SAMPLE_COUNT};

/// ESP32-S3 WDEV_RND register. The older ESP32 address 0x6003_5144
/// reads zero on this chip and must never be used.
const RNG_DATA_REG: *const u32 = 0x6003_507Cu32 as *const u32;
const RTC_CLK_CONF_REG: *mut u32 = 0x6000_8074u32 as *mut u32;
const APB_CTRL_WIFI_CLK_EN_REG: *mut u32 = 0x6002_6014u32 as *mut u32;
const DIG_CLK8M_EN: u32 = 1 << 10;
const WIFI_CLK_RNG_EN: u32 = 1 << 15;
const SAMPLE_SPACING: u32 = 160;

fn set_and_verify(register: *mut u32, mask: u32) -> bool {
    unsafe {
        let current = core::ptr::read_volatile(register);
        core::ptr::write_volatile(register, current | mask);
        core::ptr::read_volatile(register) & mask == mask
    }
}

/// Enable both ESP32-S3 RNG source gates and verify that the bits latched.
pub fn enable_hardware_rng() -> Result<(), EntropyError> {
    let rc_fast = set_and_verify(RTC_CLK_CONF_REG, DIG_CLK8M_EN);
    let rng_gate = set_and_verify(APB_CTRL_WIFI_CLK_EN_REG, WIFI_CLK_RNG_EN);
    if !rc_fast || !rng_gate {
        return Err(EntropyError::ClockGateUnavailable);
    }
    for _ in 0..50_000u32 {
        core::hint::spin_loop();
    }
    Ok(())
}

#[inline]
pub fn sample() -> u32 {
    unsafe { core::ptr::read_volatile(RNG_DATA_REG) }
}

fn spaced_sample() -> u32 {
    let value = sample();
    for _ in 0..SAMPLE_SPACING {
        core::hint::spin_loop();
    }
    value
}

/// Fill bytes only after a 32-word structural health window passes.
pub fn fill_words(output: &mut [u8]) -> Result<HealthReport, EntropyError> {
    let mut samples = [0u32; HEALTH_SAMPLE_COUNT];
    for sample in &mut samples {
        *sample = spaced_sample();
    }
    let report = inspect(&samples)?;

    let mut written = 0usize;
    for value in samples {
        if written >= output.len() {
            break;
        }
        let bytes = value.to_le_bytes();
        let take = core::cmp::min(4, output.len() - written);
        output[written..written + take].copy_from_slice(&bytes[..take]);
        written += take;
    }
    while written < output.len() {
        let bytes = spaced_sample().to_le_bytes();
        let take = core::cmp::min(4, output.len() - written);
        output[written..written + take].copy_from_slice(&bytes[..take]);
        written += take;
    }
    Ok(report)
}

#[cfg(feature = "rng-probe")]
pub(super) fn probe(count: usize) -> (usize, u32, usize, usize) {
    let _ = enable_hardware_rng();
    let Ok(mut seen) = crate::services::memory::fallible_vec(count) else { return (0, 0, count, 0); };
    let mut ones = 0u32;
    let mut zero_words = 0usize;
    let mut repeats = 0usize;
    let mut previous = None;
    for _ in 0..count {
        let value = spaced_sample();
        ones = ones.saturating_add(value.count_ones());
        zero_words += usize::from(value == 0);
        repeats += usize::from(previous == Some(value));
        seen.push(value);
        previous = Some(value);
    }
    seen.sort_unstable();
    seen.dedup();
    (seen.len(), ones, zero_words, repeats)
}
