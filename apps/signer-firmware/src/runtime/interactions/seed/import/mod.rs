//! Seed import workflow façade.
use super::{AppData, display};

mod private_key;
mod restore;
mod word_entry;
mod word_flow;

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    let redraw = match ad.navigation.app.state {
        crate::runtime::input::AppState::ImportPrivKey => {
            private_key::handle(ad, boot_display, delay, x, y, is_back)
        }
        crate::runtime::input::AppState::RestoreWord { word_idx } => {
            restore::handle(ad, boot_display, delay, x, y, is_back, word_idx)
        }
        crate::runtime::input::AppState::ImportWord { word_idx, word_count } => {
            word_flow::handle(
                ad,
                boot_display,
                delay,
                word_flow::WordFlow::ImportPhrase,
                x,
                y,
                is_back,
                word_idx,
                word_count,
            )
        }
        crate::runtime::input::AppState::CalcLastWord { word_idx, word_count } => {
            word_flow::handle(
                ad,
                boot_display,
                delay,
                word_flow::WordFlow::CalculateChecksum,
                x,
                y,
                is_back,
                word_idx,
                word_count,
            )
        }
        _ => return None,
    };
    Some(redraw)
}
