//! SD deselect release-clock handling for the shared CoreS3 SPI2 owner.

use esp_hal::{Blocking, spi::master::Spi};

pub(super) fn release_sd_clock(spi: &mut Spi<'static, Blocking>) -> Result<(), &'static str> {
    let mut release = [0xFFu8];
    embedded_hal::spi::SpiBus::transfer_in_place(spi, &mut release)
        .map_err(|_| "CoreS3 SPI2 SD release clock failed")?;
    embedded_hal::spi::SpiBus::flush(spi)
        .map_err(|_| "CoreS3 SPI2 SD release flush failed")?;
    if release[0] != 0xFF {
        crate::log!("[SD] post-CS release MISO=0x{:02x}", release[0]);
    }
    Ok(())
}
