use super::{display, seed_manager};
use crate::{runtime::{data::AppData, input::AppState}, wallet::seed_manager::SeedSlot};

pub(super) fn redraw(ad: &mut AppData, boot_display: &mut display::BootDisplay<'_>) -> bool {
    match ad.navigation.app.state {
        AppState::ExportSeedQR => draw_standard(ad, boot_display),
        AppState::ExportCompactSeedQR => draw_compact(ad, boot_display),
        AppState::ExportPlainWordsQR => draw_words(ad, boot_display),
        AppState::SeedQrGrid { pan_x, pan_y, compact } => {
            draw_grid(ad, boot_display, pan_x, pan_y, compact);
        }
        _ => return false,
    }
    true
}

fn active_mnemonic(ad: &AppData) -> Option<(&SeedSlot, u8)> {
    ad.wallet.seeds.seed_mgr.active_slot()
        .and_then(|slot| slot.mnemonic_word_count().map(|count| (slot, count)))
}

fn draw_standard(ad: &AppData, boot_display: &mut display::BootDisplay<'_>) {
    let Some((slot, word_count)) = active_mnemonic(ad) else { return; };
    let mut buffer = [0u8; 96];
    let length = seed_manager::encode_seedqr(&slot.indices, word_count, &mut buffer);
    boot_display.draw_export_seed_qr_screen(&buffer[..length], word_count);
}

fn draw_compact(ad: &AppData, boot_display: &mut display::BootDisplay<'_>) {
    let Some((slot, word_count)) = active_mnemonic(ad) else { return; };
    let mut buffer = [0u8; 32];
    let length = seed_manager::encode_compact_seedqr(&slot.indices, word_count, &mut buffer);
    boot_display.draw_export_compact_seedqr_screen(&buffer[..length], word_count);
}

fn draw_words(ad: &AppData, boot_display: &mut display::BootDisplay<'_>) {
    let Some((slot, word_count)) = active_mnemonic(ad) else { return; };
    boot_display.draw_export_plain_words_qr(&slot.indices, word_count);
}

fn draw_grid(
    ad: &AppData,
    boot_display: &mut display::BootDisplay<'_>,
    pan_x: u8,
    pan_y: u8,
    compact: bool,
) {
    let Some((slot, word_count)) = active_mnemonic(ad) else { return; };
    if compact {
        let mut buffer = [0u8; 32];
        let length = seed_manager::encode_compact_seedqr(&slot.indices, word_count, &mut buffer);
        boot_display.draw_seedqr_grid(&buffer[..length], pan_x, pan_y, false);
    } else {
        let mut buffer = [0u8; 96];
        let length = seed_manager::encode_seedqr(&slot.indices, word_count, &mut buffer);
        boot_display.draw_seedqr_grid(&buffer[..length], pan_x, pan_y, true);
    }
}
