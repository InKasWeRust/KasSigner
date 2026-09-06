//! Central transaction-time policy enforcement shared by normal and anti-klepto signing.

use signer_firmware_core::advanced_policy::{SigningDecision, SigningPolicy};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnforcementError {
    Integrity,
    #[cfg(feature = "waveshare")]
    ClockUnavailable,
    #[cfg(feature = "m5stack")]
    ClockRead,
    #[cfg(feature = "m5stack")]
    ClockLowVoltage,
    ClockInvalid,
    ClockRollback,
    BeforeNotBefore,
    OutsideWeeklyWindow,
    InvalidPolicy,
}

impl EnforcementError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::Integrity => "Advanced policy integrity failure",
            #[cfg(feature = "waveshare")]
            Self::ClockUnavailable => "Trusted hardware clock unavailable",
            #[cfg(feature = "m5stack")]
            Self::ClockRead => "Hardware clock read failed",
            #[cfg(feature = "m5stack")]
            Self::ClockLowVoltage => "Hardware clock invalid after power loss",
            Self::ClockInvalid => "Hardware clock contains invalid UTC time",
            Self::ClockRollback => "Hardware clock rollback detected",
            Self::BeforeNotBefore => "Transaction signing is time-locked",
            Self::OutsideWeeklyWindow => "Outside allowed signing window",
            Self::InvalidPolicy => "Advanced signing policy invalid",
        }
    }
}

pub fn authorize_transaction_time(
    policy: SigningPolicy,
    integrity_ok: bool,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) -> Result<Option<u64>, EnforcementError> {
    authorize_without_clock(policy, integrity_ok)?;
    if !policy.has_time_policy() || !policy.requires_clock() {
        return Ok(None);
    }
    let now = crate::services::secure_time::read_utc(i2c).map_err(map_secure_time_error)?;
    let now_unix = now
        .to_unix_seconds()
        .map_err(|_| EnforcementError::ClockInvalid)?;
    authorize_at(policy, now_unix).map(Some)
}

fn authorize_without_clock(policy: SigningPolicy, integrity_ok: bool) -> Result<(), EnforcementError> {
    if !integrity_ok { return Err(EnforcementError::Integrity); }
    policy.validate().map_err(|_| EnforcementError::InvalidPolicy)
}

fn authorize_at(policy: SigningPolicy, now_unix: u64) -> Result<u64, EnforcementError> {
    match policy.evaluate(now_unix) {
        SigningDecision::Allowed => Ok(now_unix),
        SigningDecision::ClockInvalid => Err(EnforcementError::ClockInvalid),
        SigningDecision::ClockRollback => Err(EnforcementError::ClockRollback),
        SigningDecision::BeforeNotBefore => Err(EnforcementError::BeforeNotBefore),
        SigningDecision::OutsideWeeklyWindow => Err(EnforcementError::OutsideWeeklyWindow),
        SigningDecision::PolicyInvalid => Err(EnforcementError::InvalidPolicy),
    }
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_authorize_transaction_time(
    policy: SigningPolicy,
    integrity_ok: bool,
    now_unix: u64,
) -> Result<Option<u64>, EnforcementError> {
    authorize_without_clock(policy, integrity_ok)?;
    if !policy.has_time_policy() || !policy.requires_clock() { return Ok(None); }
    authorize_at(policy, now_unix).map(Some)
}

#[cfg(feature = "waveshare")]
fn map_secure_time_error(_: crate::services::secure_time::SecureTimeError) -> EnforcementError {
    EnforcementError::ClockUnavailable
}

#[cfg(feature = "m5stack")]
fn map_secure_time_error(error: crate::services::secure_time::SecureTimeError) -> EnforcementError {
    match error {
        crate::services::secure_time::SecureTimeError::Io => EnforcementError::ClockRead,
        crate::services::secure_time::SecureTimeError::LowVoltage => EnforcementError::ClockLowVoltage,
        crate::services::secure_time::SecureTimeError::Invalid => EnforcementError::ClockInvalid,
    }
}
