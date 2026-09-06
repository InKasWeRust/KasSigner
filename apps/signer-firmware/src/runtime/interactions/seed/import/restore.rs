//! Recovery-word restore with automatic 12/24-word detection.

use crate::{
    runtime::interactions::feedback::{show_rejection, ErrorSound},
    hw::display,
    runtime::data::AppData,
    wallet::mnemonic,
};

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    x: u16,
    y: u16,
    is_back: bool,
    word_idx: u8,
) -> bool {
    match super::word_entry::read_event(ad, boot_display, x, y, is_back) {
        super::word_entry::WordEntryEvent::Pending => false,
        super::word_entry::WordEntryEvent::Cancelled => true,
        super::word_entry::WordEntryEvent::Accepted(index) => {
            accept_word(ad, boot_display, delay, word_idx, index)
        }
    }
}

fn accept_word(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    word_idx: u8,
    bip39_index: u16,
) -> bool {
    ad.wallet.seeds.mnemonic_indices[word_idx as usize] = bip39_index;
    ad.wallet.seeds.word_input.reset();
    if word_idx == 11 {
        if mnemonic::validate(&ad.wallet.seeds.mnemonic_indices, 12) {
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(RestoreWord12Detected));
        } else {
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(RestoreWord { word_idx: 12 }));
        }
        return true;
    }
    if word_idx == 23 {
        return finish_24(ad, boot_display, delay);
    }
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(RestoreWord { word_idx: word_idx.saturating_add(1) }));
    true
}

fn finish_24(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) -> bool {
    if !mnemonic::validate(&ad.wallet.seeds.mnemonic_indices, 24) {
        show_rejection(boot_display, delay, "Invalid recovery words", 2200, ErrorSound::Silent);
        shared_signer::bytes::zeroize_u16(&mut ad.wallet.seeds.mnemonic_indices);
        ad.wallet.seeds.word_count = 0;
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageSeedSourceChoice));
        return true;
    }
    ad.wallet.seeds.word_count = 24;
    ad.wallet.seeds.pp_input.reset();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(PassphraseChoice));
    true
}
