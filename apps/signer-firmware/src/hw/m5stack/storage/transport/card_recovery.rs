//! CoreS3 SD locked-card destructive recovery lifecycle.

use super::{
    Delay, SdCardType,
    capacity::log_card_register_diagnostics,
    power::{log_sd_rail_diagnostics, power_cycle_card},
    protocol::{
        ForceEraseAttempt, card_is_locked, initialize_card, unlock_card,
        force_erase_locked_card as protocol_force_erase_locked_card,
    },
};
#[cfg(all(feature = "workflow-hil-auto", feature = "m5stack"))]
const HIL_FORCE_ERASE_TIMEOUT_MS: u32 = 300_000;


pub(crate) fn unlock_locked_card_session<I2C>(
    i2c: &mut I2C,
    delay: &mut Delay,
    password: &[u8],
) -> Result<(), &'static str>
where
    I2C: embedded_hal::i2c::I2c,
{
    let card_type = prepare_locked_session(i2c, delay)?;
    if !card_is_locked(true)? { return record_already_unlocked(); }
    let result = unlock_card(card_type, password);
    record_unlock_result(card_type, result)
}

fn prepare_locked_session<I2C>(i2c: &mut I2C, delay: &mut Delay) -> Result<SdCardType, &'static str>
where
    I2C: embedded_hal::i2c::I2c,
{
    crate::hw::m5stack::storage::clear_manual_unlock_session();
    power_cycle_card(i2c, delay)?;
    initialize_card(delay)
}

fn record_already_unlocked() -> Result<(), &'static str> {
    crate::hw::m5stack::storage::record_card_lock_status(false);
    Ok(())
}

fn record_unlock_result(
    card_type: SdCardType,
    result: Result<(), &'static str>,
) -> Result<(), &'static str> {
    let locked = card_is_locked(true).unwrap_or(result.is_err());
    crate::hw::m5stack::storage::record_card_lock_status(locked);
    if result.is_ok() { record_manual_session_if_unlocked(card_type, locked); }
    result
}

fn record_manual_session_if_unlocked(card_type: SdCardType, locked: bool) {
    if !locked { crate::hw::m5stack::storage::record_manual_unlock_session(card_type); }
}

pub(crate) fn force_erase_locked_card_session<I2C>(
    i2c: &mut I2C,
    delay: &mut Delay,
    liveness: &mut dyn FnMut(),
) -> Result<bool, &'static str>
where
    I2C: embedded_hal::i2c::I2c,
{
    let card_type = prepare_locked_session(i2c, delay)?;
    log_sd_rail_diagnostics(i2c, 0);
    let mut liveness_calls = 0u64;
    let mut monitored_liveness = || {
        liveness();
        log_periodic_rail_diagnostics(i2c, liveness_calls);
        liveness_calls = liveness_calls.saturating_add(1);
    };
    let erased = force_erase_locked_card(card_type, delay, &mut monitored_liveness, None)?;
    record_force_erase_result(erased);
    Ok(erased)
}

fn log_periodic_rail_diagnostics<I2C>(i2c: &mut I2C, liveness_calls: u64)
where
    I2C: embedded_hal::i2c::I2c,
{
    if liveness_calls == 0 { return; }
    let elapsed_ms = liveness_calls.saturating_mul(1_000);
    if rail_diagnostic_due(elapsed_ms) { log_sd_rail_diagnostics(i2c, elapsed_ms); }
}

fn rail_diagnostic_due(elapsed_ms: u64) -> bool {
    matches!(elapsed_ms, 1_000 | 5_000) || elapsed_ms % 30_000 == 0
}


#[cfg(all(feature = "workflow-hil-auto", feature = "m5stack"))]
pub(crate) fn workflow_force_erase_locked_card(
    card_type: SdCardType,
    delay: &mut Delay,
) -> Result<bool, &'static str> {
    let mut liveness = || {};
    let locked = card_is_locked(true)?;
    recover_if_locked(locked, card_type, delay, &mut liveness, Some(HIL_FORCE_ERASE_TIMEOUT_MS))
}

fn record_force_erase_result(erased: bool) {
    if erased { crate::hw::m5stack::storage::record_card_lock_status(false); }
}

fn force_erase_locked_card(
    card_type: SdCardType,
    delay: &mut Delay,
    liveness: &mut dyn FnMut(),
    timeout_ms: Option<u32>,
) -> Result<bool, &'static str> {
    let locked = card_is_locked(true)?;
    recover_if_locked(locked, card_type, delay, liveness, timeout_ms)
}

fn recover_if_locked(
    locked: bool,
    card_type: SdCardType,
    delay: &mut Delay,
    liveness: &mut dyn FnMut(),
    timeout_ms: Option<u32>,
) -> Result<bool, &'static str> {
    if !locked {
        return Ok(false);
    }
    log_card_register_diagnostics();
    reject_permanent_write_protect()?;
    protocol_force_erase_locked_card(card_type, delay, liveness, timeout_ms).and_then(resolve_force_erase_attempt)
}

fn resolve_force_erase_attempt(attempt: ForceEraseAttempt) -> Result<bool, &'static str> {
    match attempt {
        ForceEraseAttempt::Completed => finish_force_erase(),
        ForceEraseAttempt::BusyTimedOut => force_erase_wait_timeout(),
    }
}

fn reject_permanent_write_protect() -> Result<(), &'static str> {
    let flags = super::capacity::sd_write_protect_flags()?;
    crate::log!(
        "[SD] CSD write protect permanent={} temporary={}",
        flags.permanent,
        flags.temporary,
    );
    if flags.permanent {
        crate::log!(
            "[SD] CMD42 force erase REFUSED - PERMANENT WRITE PROTECT"
        );
        return Err("SD card is permanently write-protected; CMD42 force erase is not permitted");
    }
    Ok(())
}

fn finish_force_erase() -> Result<bool, &'static str> {
    crate::log!("[SD] CMD42 force erase COMPLETE");
    Ok(true)
}

fn force_erase_wait_timeout() -> Result<bool, &'static str> {
    crate::log!(
        "[SD] CMD42 force erase WAIT CEILING REACHED - CARD LEFT POWERED"
    );
    Err("SD CMD42 force erase remained busy through host wait ceiling; card left powered and was not reset")
}
