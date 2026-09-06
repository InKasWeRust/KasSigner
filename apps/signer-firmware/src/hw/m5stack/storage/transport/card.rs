//! CoreS3 card-session lifecycle on the single HAL-owned SPI2 bus.

use super::{Delay, SdCardType, power::power_cycle_card, protocol::{card_is_locked, initialize_card}};

pub fn with_sd_card<I2C, F, T>(
    i2c: &mut I2C,
    delay: &mut Delay,
    f: F,
) -> Result<T, &'static str>
where
    I2C: embedded_hal::i2c::I2c,
    F: FnOnce(SdCardType) -> Result<T, &'static str>,
{
    let card_type = prepare_card(i2c, delay)?;
    crate::hw::sound::start_ticking();
    let result = f(card_type);
    finish_card_operation(&result);
    result
}

fn prepare_card<I2C>(i2c: &mut I2C, delay: &mut Delay) -> Result<SdCardType, &'static str>
where
    I2C: embedded_hal::i2c::I2c,
{
    if let Some(card_type) = crate::hw::m5stack::storage::manual_unlock_session_card_type() {
        return Ok(card_type);
    }
    power_cycle_card(i2c, delay)?;
    initialize_unlocked_card(delay)
}

fn finish_card_operation<T>(result: &Result<T, &'static str>) {
    crate::hw::sound::stop_ticking();
    if result.is_ok() { crate::hw::sound::task_done(); }
}

fn initialize_unlocked_card(delay: &mut Delay) -> Result<SdCardType, &'static str> {
    let card_type = initialize_card(delay).map_err(|error| {
        crate::log!("[SD] with_sd_card init failed: {}", error);
        error
    })?;
    require_unlocked_card()?;
    Ok(card_type)
}

fn require_unlocked_card() -> Result<(), &'static str> {
    let locked = card_is_locked(true)?;
    crate::hw::m5stack::storage::record_card_lock_status(locked);
    if !locked { return Ok(()); }
    crate::log!("[SD] card detected but password-locked; data I/O blocked before CMD17/CMD24");
    Err("SD card is locked")
}

pub(crate) fn probe_boot_card(delay: &mut Delay) -> Result<SdCardType, &'static str> {
    let card_type = initialize_card(delay)?;
    let locked = card_is_locked(true)?;
    crate::hw::m5stack::storage::record_card_lock_status(locked);
    if locked {
        crate::log!("   SD card password lock detected; MBR read skipped");
    } else {
        log_boot_mbr(card_type);
    }
    Ok(card_type)
}

fn log_boot_mbr(card_type: SdCardType) {
    let mut sector0 = [0u8; 512];
    match super::block::sd_read_block(card_type, 0, &mut sector0) {
        Ok(()) => crate::log!(
            "   MBR: {:02x}{:02x}{:02x}{:02x}..sig={:02x}{:02x} OK",
            sector0[0], sector0[1], sector0[2], sector0[3], sector0[510], sector0[511]
        ),
        Err(error) => crate::log!("   MBR read failed: {}", error),
    }
}
