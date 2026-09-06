use crate::runtime::interactions::feedback::{show_rejection, ErrorSound};
use crate::{
    hw::display,
    runtime::data::AppData,
};

pub(super) fn open(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
) {
    open_with_return(ad, boot_display, delay, liveness);
}

/// Frozen production action name retained while return ownership is now
/// recovered from the navigation kernel history rather than an AppState field.
pub(crate) fn open_with_return(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
) {
    if !ad.wallet.seeds.seed_loaded {
        show_rejection(boot_display, delay, "Load a seed first", 1500, ErrorSound::Silent);
        return;
    }

    if !ad.wallet.addresses.pubkeys_cached {
        boot_display.draw_saving_screen("Deriving addresses...");
        if let Err(message) = crate::runtime::signing::populate_active_pubkeys_with_checkpoint(ad, liveness) {
            show_rejection(boot_display, delay, message, 1500, ErrorSound::Silent);
            return;
        }
    }

    ad.qr.scan.address_length = 0;
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ShowAddress));
}
