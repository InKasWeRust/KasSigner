use super::display;
use crate::runtime::{data::AppData, input::AppState};

pub(super) fn redraw(ad: &AppData, boot_display: &mut display::BootDisplay<'_>) -> bool {
    match ad.navigation.app.state {
        AppState::Bip85Index { word_count } => {
            boot_display.draw_bip85_index_screen(ad.wallet.seeds.bip85_index, word_count);
        }
        AppState::Bip85ShowWord { word_idx, word_count } => {
            let word = offline_signer::derivation::bip39::index_to_word(
                ad.wallet.seeds.bip85_child_indices[word_idx as usize],
            );
            boot_display.draw_bip85_word_screen(word_idx, word_count, word);
        }
        _ => return false,
    }
    true
}
