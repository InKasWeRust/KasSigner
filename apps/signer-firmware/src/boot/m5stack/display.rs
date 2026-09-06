//! CoreS3 display initialization and earliest visible boot-liveness phase.

use esp_hal::{Blocking, delay::Delay, gpio::Output, i2c::master::I2c};

pub(crate) fn initialize<'a>(
    chip_select: Output<'a>,
    reset: Output<'a>,
    i2c: &mut I2c<'_, Blocking>,
    delay: &mut Delay,
) -> crate::hw::display::BootDisplay<'a> {
    crate::log!("   BOOT PHASE display BEGIN");
    crate::log!("   shared SPI2 + ILI9342C init...");
    let mut display = match crate::hw::display::BootDisplay::new(chip_select, reset, delay) {
        Ok(display) => {
            crate::log!("   ILI9342C display initialized OK — 320x240 color");
            display
        }
        Err(error) => {
            crate::log!("Display init error: {}", error);
            crate::runtime::power_state::continue_without_display(delay);
        }
    };
    crate::hw::pmu::set_brightness!(i2c, 102);
    let _ = display.show_logo_screen();
    crate::log!("   BOOT PHASE display DONE");
    display
}
