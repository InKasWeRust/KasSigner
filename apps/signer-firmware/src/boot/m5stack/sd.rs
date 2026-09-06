//! CoreS3 SD-card probe on the board-owned shared SPI2 bus.

use esp_hal::{Blocking, delay::Delay, i2c::master::I2c};

pub(crate) fn initialize(
    i2c: &mut I2c<'_, Blocking>,
    delay: &mut Delay,
) -> Option<crate::hw::sdcard::SdCardType> {
    crate::log!("   BOOT PHASE sd BEGIN");
    crate::log!("   Shared-SPI SD probe...");
    if let Err(error) = crate::hw::sdcard::power_cycle_card(i2c, delay) {
        crate::log!("   SD rail power-cycle failed: {} (continuing without SD)", error);
        crate::log!("   BOOT PHASE sd DONE");
        return None;
    }
    let result = match crate::hw::sdcard::probe_boot_card(delay) {
        Ok(card_type) => {
            crate::log!("   SD card shared-SPI init OK: {:?}", card_type);
            Some(card_type)
        }
        Err(error) => {
            crate::log!("   SD card shared-SPI: {} (continuing without SD)", error);
            None
        }
    };
    crate::log!("   BOOT PHASE sd DONE");
    result
}
