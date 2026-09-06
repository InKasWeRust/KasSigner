use super::{display, draw_kpub_export};
use crate::runtime::{data::AppData, input::AppState};

pub(super) fn redraw(ad: &AppData, boot_display: &mut display::BootDisplay<'_>) -> bool {
    match ad.navigation.app.state {
        AppState::ExportKpub => draw_kpub_export(ad, boot_display),
        AppState::ExportKpubPopup => boot_display.draw_kpub_export_popup(),
        AppState::KpubScannedPopup => boot_display.draw_kpub_scanned_popup(),
        AppState::ExportPrivKey => {
            boot_display.draw_export_privkey_screen(&ad.export.export_key_hex);
        }
        AppState::ExportXprv => {
            if ad.export.xprv_len > 0 {
                boot_display.draw_export_xprv_screen(&ad.export.xprv_data, ad.export.xprv_len);
            }
        }
        _ => return false,
    }
    true
}
