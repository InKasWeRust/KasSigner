use super::display;
use crate::runtime::{data::AppData, input::AppState};

pub(super) fn redraw(ad: &AppData, boot_display: &mut display::BootDisplay<'_>) -> bool {
    match ad.navigation.app.state {
        AppState::QrExportMenu => boot_display.draw_qr_export_menu(
            &ad.navigation.qr_export_menu,
            ad.wallet.seeds.word_count,
        ),
        AppState::XprvExportMenu => {
            boot_display.update_menu_content("XPRV ACCOUNT", &ad.navigation.xprv_export_menu);
        }
        AppState::SeedBackupMenu => {
            boot_display.update_menu_content("SEED BACKUP", &ad.navigation.seed_backup_menu);
        }
        AppState::WatchOnlyMenu => {
            boot_display.update_menu_content("WATCH-ONLY", &ad.navigation.watch_only_menu);
        }
        AppState::SigningKeysMenu => {
            boot_display.update_menu_content("SIGNING KEYS", &ad.navigation.signing_keys_menu);
        }
        AppState::ExportChoice => boot_display.draw_export_choice_screen(&ad.navigation.export_menu),
        _ => return false,
    }
    true
}
