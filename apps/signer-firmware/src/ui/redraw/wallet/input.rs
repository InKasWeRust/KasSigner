use super::display;
use crate::runtime::{data::AppData, input::AppState};

pub(super) fn redraw(ad: &AppData, boot_display: &mut display::BootDisplay<'_>) -> bool {
    match ad.navigation.app.state {
        AppState::ChooseWordCount { action } => {
            boot_display.draw_choose_wc_screen(action);
        }
        AppState::PassphraseChoice => {
            boot_display.draw_passphrase_choice_screen();
        }
        AppState::PassphraseEntry => {
            boot_display.draw_passphrase_screen_full(&ad.wallet.seeds.pp_input);
        }
        AppState::WalletNameEntry { .. } => {
            boot_display.draw_keyboard_screen_full(&ad.wallet.seeds.pp_input, "WALLET NAME");
        }
        AppState::RestoreWord { word_idx } => {
            boot_display.draw_restore_word_screen(word_idx, &ad.wallet.seeds.word_input);
        }
        AppState::ImportPrivKey => boot_display.draw_import_privkey_screen(
            &ad.wallet.keys.hex_input,
            ad.wallet.keys.hex_input_len,
        ),
        AppState::DiceRoll => boot_display.draw_dice_screen(
            ad.wallet.seeds.dice_collector.count,
            ad.wallet.seeds.dice_collector.target,
        ),
        AppState::TouchEntropy => boot_display.draw_touch_entropy_screen(
            ad.wallet.seeds.touch_collector.count(),
            ad.wallet.seeds.touch_collector.target(),
        ),
        _ => return false,
    }
    true
}
