//! Serialized CoreS3 SD-line handoff around the switched ALDO4 power rail.

use super::{sd_power_lines, state};

/// Electrically isolate every microSD-facing SPI line while its ALDO4 rail is off.
pub(crate) fn quiesce_sd_power_lines() -> Result<(), &'static str> {
    let shared = state::shared_bus()?;
    let mut spi = state::borrow_spi(shared)?;
    let mut sd_cs = state::borrow_sd_cs(shared)?;
    flush_and_quiesce(&mut spi, &mut sd_cs)
}

fn flush_and_quiesce(
    spi: &mut esp_hal::spi::master::Spi<'static, esp_hal::Blocking>,
    sd_cs: &mut esp_hal::gpio::Output<'static>,
) -> Result<(), &'static str> {
    embedded_hal::spi::SpiBus::flush(spi)
        .map_err(|_| "CoreS3 SPI2 pre-power-cycle flush failed")?;
    sd_cs.set_high();
    sd_power_lines::quiesce();
    crate::log!("[SD] bus quiesced for rail cycle GPIO4/35/36/37=LOW");
    Ok(())
}

/// Restore the HAL-owned FSPI routing immediately after ALDO4 is enabled.
pub(crate) fn restore_sd_power_lines() -> Result<(), &'static str> {
    let shared = state::shared_bus()?;
    let _spi = state::borrow_spi(shared)?;
    let mut sd_cs = state::borrow_sd_cs(shared)?;
    sd_power_lines::restore();
    sd_cs.set_high();
    crate::log!("[SD] bus restored after rail enable CS=HIGH SCK/MOSI=FSPI MISO=input");
    Ok(())
}
