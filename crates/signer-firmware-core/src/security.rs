//! Device-local signing authorization and seed-entropy invariants.

pub mod credential;

use crate::entropy::frame_noise::CameraEntropyReport;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAuthorizationError {
    SeedUnavailable,
    ReviewIncomplete,
    NoInputs,
    InputCountMismatch,
    InputOutOfRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigningAuthorization {
    pub seed_loaded: bool,
    pub review_authorized: bool,
    pub reviewed_inputs: usize,
    pub transaction_inputs: usize,
    pub signing_input_index: usize,
}

pub fn authorize_transaction_signing(
    authorization: SigningAuthorization,
) -> Result<(), SigningAuthorizationError> {
    if !authorization.seed_loaded {
        return Err(SigningAuthorizationError::SeedUnavailable);
    }
    if !authorization.review_authorized {
        return Err(SigningAuthorizationError::ReviewIncomplete);
    }
    if authorization.reviewed_inputs == 0 || authorization.transaction_inputs == 0 {
        return Err(SigningAuthorizationError::NoInputs);
    }
    if authorization.reviewed_inputs != authorization.transaction_inputs {
        return Err(SigningAuthorizationError::InputCountMismatch);
    }
    if authorization.signing_input_index >= authorization.transaction_inputs {
        return Err(SigningAuthorizationError::InputOutOfRange);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedEntropyError {
    CameraUnavailable,
    HardwareRngUnavailable,
    DeviceIdentityUnavailable,
    TimingUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeedEntropyEvidence {
    pub camera: CameraEntropyReport,
    pub hardware_rng_healthy: bool,
    pub device_identity_mixed: bool,
    pub timing_mixed: bool,
}

#[must_use]
pub fn timing_observations_usable(first: (u32, u32), second: (u32, u32)) -> bool {
    // Equal observations are unusable, including the all-zero pair. Keeping the
    // predicate to this single comparison also avoids an impossible coverage
    // branch: once the observations differ, they cannot both be `(0, 0)`.
    first != second
}

#[must_use]
pub fn device_identity_words_usable(words: &[u32]) -> bool {
    words.iter().any(|value| *value != 0 && *value != u32::MAX)
}

pub fn validate_seed_entropy(evidence: SeedEntropyEvidence) -> Result<(), SeedEntropyError> {
    if !evidence.camera.healthy() {
        return Err(SeedEntropyError::CameraUnavailable);
    }
    if !evidence.hardware_rng_healthy {
        return Err(SeedEntropyError::HardwareRngUnavailable);
    }
    if !evidence.device_identity_mixed {
        return Err(SeedEntropyError::DeviceIdentityUnavailable);
    }
    if !evidence.timing_mixed {
        return Err(SeedEntropyError::TimingUnavailable);
    }
    Ok(())
}
