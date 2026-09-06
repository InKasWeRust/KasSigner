use super::display;
use crate::runtime::{data::AppData, input::AppState};

pub(super) fn redraw(ad: &AppData, boot_display: &mut display::BootDisplay<'_>) -> bool {
    match ad.navigation.app.state {
        AppState::SeedBackup { word_idx } => draw_backup_word(ad, boot_display, word_idx),
        AppState::ImportWord { word_idx, word_count } => boot_display.draw_import_word_screen(
            word_idx,
            word_count,
            &ad.wallet.seeds.word_input,
        ),
        AppState::CalcLastWord { word_idx, word_count } => {
            boot_display.draw_calc_last_word_screen(
                word_idx,
                word_count,
                &ad.wallet.seeds.word_input,
            );
        }
        _ => return false,
    }
    true
}

fn draw_backup_word(ad: &AppData, boot_display: &mut display::BootDisplay<'_>, word_idx: u8) {
    let imported_onboarding = ad.storage.persistence.device_storage_intent.is_seed_onboarding()
        && ad.storage.persistence.onboarding_imported_mnemonic;
    if ad.wallet.seeds.pending_add_wallet_is_restore() || imported_onboarding { return; }
    if !ad.wallet.seeds.seed_loaded && !ad.wallet.seeds.has_pending_add_wallet() { return; }
    let word = offline_signer::derivation::bip39::index_to_word(
        ad.wallet.seeds.mnemonic_indices[word_idx as usize],
    );
    boot_display.draw_word_screen(word_idx, ad.wallet.seeds.word_count, word);
}
