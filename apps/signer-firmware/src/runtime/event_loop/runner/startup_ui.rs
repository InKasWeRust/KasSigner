//! Initial production screen presentation after persistent-wallet startup.

use crate::{
    hw::{display::BootDisplay, sdcard::SdCardType},
    runtime::data::AppData,
};
use esp_hal::{i2c::master::I2c, Blocking};

#[inline(never)]
pub(super) fn render(
    ad: &mut AppData,
    boot_display: &mut BootDisplay<'_>,
    i2c: &mut I2c<'_, Blocking>,
    sd_card_type: &Option<SdCardType>,
) {
    crate::log!("   BOOT PHASE startup-ui BEGIN: {:?}", ad.navigation.app.state);
    crate::ui::redraw::redraw_screen(ad, boot_display, i2c, sd_card_type);
    ad.runtime.needs_redraw = false;
    crate::log!("   BOOT PHASE startup-ui DONE: {:?}", ad.navigation.app.state);
}
