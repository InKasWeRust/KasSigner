use crate::runtime::interactions::{
    feedback::{show_rejection, ErrorSound},
    menu_selection::selected_visible_item,
};
use crate::hw::{display, touch};
use crate::runtime::data::AppData;
use crate::runtime::input::Menu;

const SEED_REQUIRED_MESSAGE: &str = "No seed loaded";

pub(super) fn selected_item(
    menu: &Menu,
    list_zones: &[touch::TouchZone; 4],
    x: u16,
    y: u16,
) -> Option<u8> {
    selected_visible_item(menu, list_zones, x, y)
}

pub(super) fn require_seed(
    ad: &AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) -> bool {
    if ad.wallet.seeds.seed_loaded {
        return true;
    }
    show_rejection(
        boot_display,
        delay,
        SEED_REQUIRED_MESSAGE,
        1500,
        ErrorSound::Beep,
    );
    false
}

pub(super) fn prepare_signing_addresses(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    liveness: &mut dyn FnMut(),
) -> Result<(), &'static str> {
    if !ad.wallet.seeds.seed_loaded {
        return Err(SEED_REQUIRED_MESSAGE);
    }
    if ad.wallet.addresses.pubkeys_cached {
        return Ok(());
    }
    boot_display.draw_saving_screen("Deriving addresses...");
    crate::runtime::signing::populate_active_pubkeys_with_checkpoint(ad, liveness)
}
