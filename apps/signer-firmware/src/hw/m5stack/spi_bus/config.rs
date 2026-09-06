//! CoreS3 shared-SPI frequency policy.

use core::cell::Cell;

use esp_hal::{
    Blocking,
    spi::master::{Config, Spi},
    time::Rate,
};

pub(super) const LCD_HZ: u32 = 40_000_000;
const SD_INIT_HZ: u32 = 400_000;
// CoreS3 shares GPIO35 between LCD D/C output and SD MISO. Keep the SD data
// phase conservative so legacy SDSC media remains reliable after the 400 kHz
// initialization phase; signer backup traffic does not need high-throughput SPI.
const SD_DATA_HZ: u32 = 4_000_000;

pub(super) const fn sd_frequency(initialization_speed: bool) -> u32 {
    if initialization_speed { SD_INIT_HZ } else { SD_DATA_HZ }
}

pub(super) fn ensure_frequency(
    current_hz: &Cell<u32>,
    spi: &mut Spi<'static, Blocking>,
    frequency_hz: u32,
) -> Result<(), &'static str> {
    if current_hz.get() == frequency_hz {
        return Ok(());
    }
    apply_config(spi, frequency_hz)?;
    current_hz.set(frequency_hz);
    Ok(())
}

fn apply_config(
    spi: &mut Spi<'static, Blocking>,
    frequency_hz: u32,
) -> Result<(), &'static str> {
    let config = Config::default()
        .with_frequency(Rate::from_hz(frequency_hz))
        .with_mode(esp_hal::spi::Mode::_0);
    spi.apply_config(&config)
        .map_err(|_| "CoreS3 SPI2 configuration failed")
}
