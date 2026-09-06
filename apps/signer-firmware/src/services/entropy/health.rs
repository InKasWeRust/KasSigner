// Structural health tests for ESP32-S3 hardware RNG samples.

use signer_firmware_core::entropy::rng_health::{self, RngHealthError, RngHealthReport};

/// Number of raw words checked before entropy is accepted.
pub const HEALTH_SAMPLE_COUNT: usize = rng_health::HEALTH_SAMPLE_COUNT;

/// Structural failure detected in the hardware RNG stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyError {
    /// Every sampled word was identical.
    StuckRegister,
    /// One 16-bit half of every sampled word was identical.
    StuckHalfWord,
    /// Adjacent words repeated exactly.
    RepetitionCount,
    /// The 32-word window did not contain 32 distinct samples.
    LowDiversity,
    /// Gross bit-balance bias exceeded the continuous-health band.
    AdaptiveProportion,
    /// At least one bit position never changed across the window.
    StuckBits,
    /// Samples formed a fixed-step free-running counter.
    CounterPattern,
    /// Nearly every sample moved in the same numeric direction.
    Monotonic,
    /// Required RNG clock gates did not latch.
    ClockGateUnavailable,
    /// The camera did not provide a healthy temporal-noise contribution.
    CameraUnavailable,
    /// Immutable device identity words were unavailable.
    DeviceIdentityUnavailable,
    /// The hardware timing source returned no usable observation.
    TimingUnavailable,
    /// CoreS3 BMI270 could not provide a complete healthy seed-generation window.
    ImuUnavailable,
}

impl EntropyError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::StuckRegister => "RNG register stuck",
            Self::StuckHalfWord => "RNG half-word stuck",
            Self::RepetitionCount => "RNG repetition detected",
            Self::LowDiversity => "RNG diversity failure",
            Self::AdaptiveProportion => "RNG bit-balance failure",
            Self::StuckBits => "RNG bit position stuck",
            Self::CounterPattern => "RNG counter pattern",
            Self::Monotonic => "RNG monotonic structure",
            Self::ClockGateUnavailable => "RNG clock gate unavailable",
            Self::CameraUnavailable => "Camera entropy unavailable",
            Self::DeviceIdentityUnavailable => "Device identity unavailable",
            Self::TimingUnavailable => "Timing entropy unavailable",
            Self::ImuUnavailable => "IMU entropy unavailable",
        }
    }
}


impl From<signer_firmware_core::security::SeedEntropyError> for EntropyError {
    fn from(error: signer_firmware_core::security::SeedEntropyError) -> Self {
        match error {
            signer_firmware_core::security::SeedEntropyError::CameraUnavailable => Self::CameraUnavailable,
            signer_firmware_core::security::SeedEntropyError::HardwareRngUnavailable => Self::ClockGateUnavailable,
            signer_firmware_core::security::SeedEntropyError::DeviceIdentityUnavailable => Self::DeviceIdentityUnavailable,
            signer_firmware_core::security::SeedEntropyError::TimingUnavailable => Self::TimingUnavailable,
        }
    }
}

/// Diagnostics emitted by the boot entropy check.
pub type HealthReport = RngHealthReport;

/// Reject dead, biased, repetitive, stuck-bit, counter, and monotonic RNG windows.
pub fn inspect(samples: &[u32; HEALTH_SAMPLE_COUNT]) -> Result<HealthReport, EntropyError> {
    if samples.iter().all(|sample| *sample == samples[0]) {
        return Err(EntropyError::StuckRegister);
    }
    if half_word_is_stuck(samples) {
        return Err(EntropyError::StuckHalfWord);
    }
    rng_health::inspect(samples).map_err(map_health_error)
}

fn half_word_is_stuck(samples: &[u32; HEALTH_SAMPLE_COUNT]) -> bool {
    let low = samples[0] as u16;
    let high = (samples[0] >> 16) as u16;
    samples.iter().all(|sample| *sample as u16 == low)
        || samples.iter().all(|sample| (*sample >> 16) as u16 == high)
}

const fn map_health_error(error: RngHealthError) -> EntropyError {
    match error {
        RngHealthError::StuckRegister => EntropyError::StuckRegister,
        RngHealthError::RepetitionCount => EntropyError::RepetitionCount,
        RngHealthError::LowDiversity => EntropyError::LowDiversity,
        RngHealthError::AdaptiveProportion => EntropyError::AdaptiveProportion,
        RngHealthError::StuckBits => EntropyError::StuckBits,
        RngHealthError::CounterPattern => EntropyError::CounterPattern,
        RngHealthError::Monotonic => EntropyError::Monotonic,
    }
}
