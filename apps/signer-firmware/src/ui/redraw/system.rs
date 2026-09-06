// KasSigner — Air-gapped offline signing device for Kaspa
// License: GPL-3.0
// Screen redraw — system states.
use super::display;
pub(super) fn redraw(
    ad: &mut crate::runtime::data::AppData,
    boot_display: &mut display::BootDisplay<'_>,
) -> bool {
    match ad.navigation.app.state {
        crate::runtime::input::AppState::FirmwareUpdateReady => {
            boot_display.draw_firmware_update_ready_screen();
            true
        }
        _ => false,
    }
}
