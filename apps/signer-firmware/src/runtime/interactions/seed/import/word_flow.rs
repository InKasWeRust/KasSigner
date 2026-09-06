//! Shared BIP39 word-entry controller.

use crate::runtime::interactions::feedback::{show_rejection, ErrorSound};
use crate::{
    hw::display,
    runtime::data::AppData,
    wallet::mnemonic,
};

#[derive(Clone, Copy)]
pub(super) enum WordFlow {
    ImportPhrase,
    CalculateChecksum,
}

fn reject_phrase(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) -> bool {
    show_rejection(boot_display, delay, "Invalid seed phrase", 2500, ErrorSound::Silent);
    if ad.storage.persistence.device_storage_intent.is_seed_onboarding() {
        shared_signer::bytes::zeroize_u16(&mut ad.wallet.seeds.mnemonic_indices);
        ad.wallet.seeds.word_count = 0;
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageSeedSourceChoice));
    } else {
        crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::SeedTool);
    }
    true
}

fn enter_passphrase(ad: &mut AppData, word_count: u8) -> bool {
    ad.wallet.seeds.word_count = word_count;
    ad.wallet.seeds.pp_input.reset();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(PassphraseChoice));
    true
}

fn finish_import(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    word_count: u8,
) -> bool {
    if !mnemonic::validate(&ad.wallet.seeds.mnemonic_indices, word_count) {
        log!("   Import FAILED — bad checksum");
        return reject_phrase(ad, boot_display, delay);
    }
    ad.wallet.seeds.word_count = word_count;
    ad.wallet.seeds.pp_input.reset();
    log!("   Import complete — {} words → passphrase choice", word_count);
    enter_passphrase(ad, word_count)
}

fn finish_checksum(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    word_count: u8,
) -> bool {
    let Some(last_index) = mnemonic::complete_last_word(
        &ad.wallet.seeds.mnemonic_indices,
        word_count,
    ) else {
        return reject_phrase(ad, boot_display, delay);
    };
    ad.wallet.seeds.mnemonic_indices[(word_count - 1) as usize] = last_index;
    let last_word = offline_signer::derivation::bip39::index_to_word(last_index);
    log!("   Last word #{} computed", word_count);
    boot_display.draw_word_screen(word_count - 1, word_count, last_word);
    crate::services::timing::pause(delay, 3000);
    enter_passphrase(ad, word_count)
}

fn accept_word(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    flow: WordFlow,
    word_index: u8,
    word_count: u8,
    bip39_index: u16,
) -> bool {
    ad.wallet.seeds.mnemonic_indices[word_index as usize] = bip39_index;
    ad.wallet.seeds.word_input.reset();
    let next = word_index + 1;

    match flow {
        WordFlow::ImportPhrase if next >= word_count => {
            finish_import(ad, boot_display, delay, word_count)
        }
        WordFlow::CalculateChecksum if next >= word_count - 1 => {
            finish_checksum(ad, boot_display, delay, word_count)
        }
        WordFlow::ImportPhrase => {
            log!("   Word {}/{} accepted", next, word_count);
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ImportWord {
                word_idx: next,
                word_count,
            }));
            boot_display.update_import_word_header(next, word_count, &ad.wallet.seeds.word_input);
            false
        }
        WordFlow::CalculateChecksum => {
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(CalcLastWord {
                word_idx: next,
                word_count,
            }));
            boot_display.update_calc_last_word_header(next, word_count, &ad.wallet.seeds.word_input);
            false
        }
    }
}

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    flow: WordFlow,
    x: u16,
    y: u16,
    is_back: bool,
    word_index: u8,
    word_count: u8,
) -> bool {
    match super::word_entry::read_event(ad, boot_display, x, y, is_back) {
        super::word_entry::WordEntryEvent::Pending => false,
        super::word_entry::WordEntryEvent::Cancelled => true,
        super::word_entry::WordEntryEvent::Accepted(index) => {
            accept_word(ad, boot_display, delay, flow, word_index, word_count, index)
        }
    }
}
