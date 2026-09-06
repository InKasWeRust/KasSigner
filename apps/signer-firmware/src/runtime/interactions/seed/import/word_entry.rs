//! Shared BIP39 word-entry keyboard and suggestion handling.

use crate::{hw::display, runtime::data::AppData, ui::keyboard::suggestion_chip};

pub(super) enum WordEntryEvent {
    Pending,
    Cancelled,
    Accepted(u16),
}

pub(super) fn read_event(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    x: u16,
    y: u16,
    is_back: bool,
) -> WordEntryEvent {
    if is_back {
        ad.wallet.seeds.word_input.reset();
        if ad.wallet.seeds.pending_add_wallet_is_restore()
            || ad.storage.persistence.device_storage_intent.is_seed_onboarding()
        {
            shared_signer::bytes::zeroize_u16(&mut ad.wallet.seeds.mnemonic_indices);
            ad.wallet.seeds.word_count = 0;
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageSeedSourceChoice));
        } else {
            crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::SeedTool);
        }
        return WordEntryEvent::Cancelled;
    }

    if let Some(index) = suggestion_chip(x, y, &ad.wallet.seeds.word_input) {
        return WordEntryEvent::Accepted(index);
    }

    use crate::ui::keyboard::{hit_test, KeyAction, KeyboardMode};
    match hit_test(x, y, KeyboardMode::Alpha, 0) {
        KeyAction::Char(character) => {
            ad.wallet.seeds.word_input.push_char(character);
            boot_display.draw_import_keyboard(&ad.wallet.seeds.word_input);
        }
        KeyAction::Backspace => {
            ad.wallet.seeds.word_input.backspace();
            boot_display.draw_import_keyboard(&ad.wallet.seeds.word_input);
        }
        KeyAction::Ok => {
            if let Some(index) = ad.wallet.seeds.word_input.matched_index {
                return WordEntryEvent::Accepted(index);
            }
        }
        _ => {}
    }
    WordEntryEvent::Pending
}
