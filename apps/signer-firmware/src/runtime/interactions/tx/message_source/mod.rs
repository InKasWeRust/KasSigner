//! Focused message-source controllers for reviewed typed and SD text input.

use super::{AppData, RedrawFlag, TouchInput, display, touch};
use crate::runtime::interactions::text_files::TextFileSelectionContext;

mod menu;
mod sd_files;
mod typed;

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    list_zones: &[touch::TouchZone; 4],
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    let changed = match ad.navigation.app.state {
        crate::runtime::input::AppState::SignMsgChoice => {
            menu::handle(ad, boot_display, delay, i2c, x, y, is_back)
        }
        crate::runtime::input::AppState::SignMsgType => {
            typed::handle(ad, boot_display, delay, x, y, is_back)
        }
        crate::runtime::input::AppState::SignMsgFile => {
            sd_files::handle(TextFileSelectionContext {
                ad, boot_display, delay, i2c, list_zones,
                input: TouchInput::new(x, y, is_back),
            })
        }
        _ => return None,
    };
    let mut needs_redraw = RedrawFlag::default();
    needs_redraw.set(changed);
    Some(needs_redraw.value())
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) use sd_files::workflow_accept_content as workflow_accept_file;
