//! Controller-facing audio cue service. The event loop remains the sole I2S owner.

pub(crate) fn click() { crate::hw::sound::click(); }
pub(crate) fn error() { crate::hw::sound::beep_error(); }
pub(crate) fn success() { crate::hw::sound::success(); }
pub(crate) fn task_done() { crate::hw::sound::task_done(); }
pub(crate) fn qr_found() { crate::hw::sound::qr_found(); }
pub(crate) fn qr_decoded() { crate::hw::sound::qr_decoded(); }
pub(crate) fn stop_ticking() { crate::hw::sound::stop_ticking(); }
#[cfg(feature = "m5stack")]
pub(crate) fn set_volume(value: u8) { crate::hw::sound::set_volume(value); }

/// Prevent runtime I2S feedback from overlapping the foreground-exclusive
/// credential KDF/decrypt interval. The hardware facade owns board details.
pub(crate) fn suspend_credential_cues() { crate::hw::sound::suspend_runtime_cues(); }

/// Restore ordinary runtime feedback after credential work reaches a terminal
/// or cancelled state.
pub(crate) fn resume_credential_cues() { crate::hw::sound::resume_runtime_cues(); }
