// Timing, ADC, and immutable chip-identity samples.

use esp_hal::{
    efuse::{Efuse, OPTIONAL_UNIQUE_ID},
    timer::systimer::{SystemTimer, Unit},
};
use sha2::Digest;

pub fn update_systimer(hasher: &mut impl Digest) {
    let (low, high) = systimer_words();
    hasher.update(low.to_le_bytes());
    hasher.update(high.to_le_bytes());
}

pub fn timing_observation() -> (u32, u32) {
    systimer_words()
}

/// Mix a pair of coherent timer observations spanning a real entropy operation.
pub fn update_timing_pair_checked(
    hasher: &mut impl Digest,
    first: (u32, u32),
    second: (u32, u32),
) -> bool {
    hasher.update(first.0.to_le_bytes());
    hasher.update(first.1.to_le_bytes());
    hasher.update(second.0.to_le_bytes());
    hasher.update(second.1.to_le_bytes());
    signer_firmware_core::security::timing_observations_usable(first, second)
}

pub fn systimer_low() -> u32 {
    systimer_words().0
}

pub fn update_mac(hasher: &mut impl Digest) {
    for value in mac_words() {
        hasher.update(value.to_le_bytes());
    }
}

/// Mix the factory-programmed base MAC as deterministic device binding.
/// No entropy credit is assigned to this public, immutable identifier.
pub fn update_device_identity_checked(hasher: &mut impl Digest) -> bool {
    let mac = mac_words();
    for value in mac {
        hasher.update(value.to_le_bytes());
    }
    signer_firmware_core::security::device_identity_words_usable(&mac)
}

/// Mix ESP32-S3 OPTIONAL_UNIQUE_ID as deterministic device binding.
///
/// This 128-bit eFuse field is public/readable identity context, not a
/// credited entropy source. An all-zero/unprogrammed value is still harmless
/// deterministic context and never satisfies a mandatory entropy gate.
pub fn update_optional_unique_id(hasher: &mut impl Digest) {
    hasher.update(b"KasSigner/optional-unique-id/v1");
    for value in unique_id_words() {
        hasher.update(value.to_le_bytes());
    }
}

pub fn update_adc_noise(hasher: &mut impl Digest, samples: usize) {
    for _ in 0..samples {
        let value = unsafe { core::ptr::read_volatile(0x6004_0868u32 as *const u32) };
        hasher.update(value.to_le_bytes());
    }
}

fn mac_words() -> [u32; 2] {
    let mac = Efuse::read_base_mac_address();
    [
        u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]]),
        u32::from_le_bytes([mac[4], mac[5], 0, 0]),
    ]
}

fn unique_id_words() -> [u32; 4] {
    Efuse::read_field_le(OPTIONAL_UNIQUE_ID)
}

fn systimer_words() -> (u32, u32) {
    // Use esp-hal's latched/stable SYSTIMER read. The HAL waits for the
    // hardware value-valid bit and performs a coherent LO/HI/LO read; a
    // fixed spin delay can observe the previous latch value on real CoreS3
    // hardware and falsely fail the timing-entropy health requirement.
    let value = SystemTimer::unit_value(Unit::Unit0);
    (value as u32, (value >> 32) as u32)
}
