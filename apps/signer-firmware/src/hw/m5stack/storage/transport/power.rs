//! Verified CoreS3 SD-card cold reset through AXP2101 ALDO4 plus SPI-line isolation.

use esp_hal::delay::Delay;

use crate::hw::pmu::{AXP2101_ADDR, AXP_REG_LDO_EN1};

use super::protocol::{quiesce_for_power_cycle, restore_after_power_on};

const ALDO4_BIT: u8 = 0x08;
const AXP_REG_ALDO4_VOLT: u8 = 0x95;
const EXPECTED_ALDO4_VOLT_CONFIG: u8 = 0x1C;

pub(crate) fn log_sd_rail_diagnostics<I2C>(i2c: &mut I2C, elapsed_ms: u64)
where
    I2C: embedded_hal::i2c::I2c,
{
    let enable = read_pmu_register(i2c, AXP_REG_LDO_EN1);
    let voltage = read_pmu_register(i2c, AXP_REG_ALDO4_VOLT);
    match (enable, voltage) {
        (Ok(ldo_en1), Ok(aldo4_cfg)) => crate::log!(
            "[SD-DIAG] PMU t={}ms LDO_EN1=0x{:02x} ALDO4_on={} ALDO4_CFG=0x{:02x} expected_CFG=0x{:02x} config_stable={}",
            elapsed_ms,
            ldo_en1,
            ldo_en1 & ALDO4_BIT != 0,
            aldo4_cfg,
            EXPECTED_ALDO4_VOLT_CONFIG,
            aldo4_cfg == EXPECTED_ALDO4_VOLT_CONFIG,
        ),
        _ => crate::log!(
            "[SD-DIAG] PMU t={}ms rail/config readback unavailable",
            elapsed_ms,
        ),
    }
}

pub(crate) fn power_cycle_card<I2C>(
    i2c: &mut I2C,
    delay: &mut Delay,
) -> Result<(), &'static str>
where
    I2C: embedded_hal::i2c::I2c,
{
    let before = read_ldo_enable(i2c, "SD rail PMU read failed before power-cycle")?;
    crate::log!("[SD] rail ALDO4 cycle begin LDO_EN1=0x{:02x}", before);
    quiesce_for_power_cycle()?;
    let result = cycle_isolated_rail(i2c, before, delay);
    if let Err(error) = result {
        recover_bus_and_rail(i2c, before, delay);
        return Err(error);
    }
    crate::log!("[SD] rail ALDO4 electrical cold-reset verified");
    Ok(())
}

fn cycle_isolated_rail<I2C>(
    i2c: &mut I2C,
    before: u8,
    delay: &mut Delay,
) -> Result<(), &'static str>
where
    I2C: embedded_hal::i2c::I2c,
{
    power_off_isolated(i2c, before, delay)?;
    power_on_and_restore(i2c, before, delay)
}

fn power_off_isolated<I2C>(i2c: &mut I2C, before: u8, delay: &mut Delay) -> Result<(), &'static str>
where
    I2C: embedded_hal::i2c::I2c,
{
    write_ldo_enable(i2c, before & !ALDO4_BIT, "SD rail power-off write failed")?;
    delay.delay_millis(100);
    verify_rail(i2c, false)
}

fn power_on_and_restore<I2C>(i2c: &mut I2C, before: u8, delay: &mut Delay) -> Result<(), &'static str>
where
    I2C: embedded_hal::i2c::I2c,
{
    write_ldo_enable(i2c, before | ALDO4_BIT, "SD rail power-on write failed")?;
    restore_after_power_on()?;
    delay.delay_millis(250);
    verify_rail(i2c, true)
}

fn recover_bus_and_rail<I2C>(i2c: &mut I2C, before: u8, delay: &mut Delay)
where
    I2C: embedded_hal::i2c::I2c,
{
    crate::log!("[SD] rail cycle recovery: forcing ALDO4 ON and restoring shared SPI routing");
    if write_ldo_enable(i2c, before | ALDO4_BIT, "SD rail recovery write failed").is_err() {
        crate::log!("[SD] rail cycle recovery: ALDO4 ON write FAILED");
    }
    if restore_after_power_on().is_err() {
        crate::log!("[SD] rail cycle recovery: shared SPI restore FAILED");
    }
    delay.delay_millis(250);
}

fn verify_rail<I2C>(i2c: &mut I2C, expected_on: bool) -> Result<(), &'static str>
where
    I2C: embedded_hal::i2c::I2c,
{
    let value = read_ldo_enable(i2c, "SD rail PMU readback failed")?;
    let on = value & ALDO4_BIT != 0;
    crate::log!(
        "[SD] rail ALDO4 readback LDO_EN1=0x{:02x} state={}",
        value, if on { "ON" } else { "OFF" },
    );
    if on == expected_on { Ok(()) } else { Err("SD rail power-cycle readback mismatch") }
}

fn read_pmu_register<I2C>(i2c: &mut I2C, register: u8) -> Result<u8, &'static str>
where
    I2C: embedded_hal::i2c::I2c,
{
    let mut value = [0u8; 1];
    i2c.write_read(AXP2101_ADDR, &[register], &mut value)
        .map_err(|_| "SD rail PMU diagnostic read failed")?;
    Ok(value[0])
}

fn read_ldo_enable<I2C>(i2c: &mut I2C, error: &'static str) -> Result<u8, &'static str>
where
    I2C: embedded_hal::i2c::I2c,
{
    let mut value = [0u8; 1];
    i2c.write_read(AXP2101_ADDR, &[AXP_REG_LDO_EN1], &mut value)
        .map_err(|_| error)?;
    Ok(value[0])
}

fn write_ldo_enable<I2C>(
    i2c: &mut I2C,
    value: u8,
    error: &'static str,
) -> Result<(), &'static str>
where
    I2C: embedded_hal::i2c::I2c,
{
    i2c.write(AXP2101_ADDR, &[AXP_REG_LDO_EN1, value])
        .map_err(|_| error)
}
