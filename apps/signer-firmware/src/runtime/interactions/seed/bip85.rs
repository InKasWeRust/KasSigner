// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use crate::runtime::interactions::feedback::{show_rejection, ErrorSound};
use crate::hw::display;
use crate::services::audio as sound;
use crate::runtime::data::AppData;
use crate::runtime::input::AppState;

mod derivation;
mod navigation;

fn present_index(boot_display: &mut display::BootDisplay<'_>, index: u8) {
    if crate::runtime::interactions::feedback::physical_presentation_enabled() {
        boot_display.update_bip85_index(index);
    }
}

fn present_deriving(boot_display: &mut display::BootDisplay<'_>) {
    if crate::runtime::interactions::feedback::physical_presentation_enabled() {
        boot_display.draw_bip85_deriving();
    }
}

fn present_derivation_result(success: bool) {
    if crate::runtime::interactions::feedback::physical_presentation_enabled() {
        if success {
            sound::success();
        } else {
            sound::error();
        }
    }
}

fn handle_index(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    word_count: u8,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::SeedTool);
        return true;
    }
    if (85..=125).contains(&x) && (98..=132).contains(&y) {
        if ad.wallet.seeds.bip85_index > 0 {
            ad.wallet.seeds.bip85_index -= 1;
            present_index(boot_display, ad.wallet.seeds.bip85_index);
        }
        return false;
    }
    if (195..=235).contains(&x) && (98..=132).contains(&y) {
        if ad.wallet.seeds.bip85_index < 99 {
            ad.wallet.seeds.bip85_index += 1;
            present_index(boot_display, ad.wallet.seeds.bip85_index);
        }
        return false;
    }
    if !(90..=230).contains(&x) || !(150..=182).contains(&y) {
        return false;
    }
    if !ad.wallet.seeds.seed_loaded {
        show_rejection(boot_display, delay, "Load a seed first", 1500, ErrorSound::Beep);
        return true;
    }
    present_deriving(boot_display);
    let success = derivation::derive_and_install(ad, word_count, liveness).is_ok();
    present_derivation_result(success);
    if !success {
        crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::SeedTool);
    }
    true
}

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    match ad.navigation.app.state {
        AppState::Bip85Index { word_count } => Some(handle_index(
            ad,
            boot_display,
            delay,
            liveness,
            word_count,
            x,
            y,
            is_back,
        )),
        AppState::Bip85ShowWord {
            word_idx,
            word_count,
        } => {
            navigation::advance_word(ad, word_idx, word_count, is_back);
            Some(true)
        }
        _ => None,
    }
}
