// Storage screen redraw façade.
use crate::{hw::display::BootDisplay, hw::sdcard::SdCardType, runtime::data::AppData};

mod lists;
mod prompts;
mod settings;

pub(super) fn redraw(
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    sd_card_type: &Option<SdCardType>,
) -> bool {
    lists::redraw(ad, display)
        || prompts::redraw(ad, display)
        || settings::redraw(ad, display, sd_card_type)
}
