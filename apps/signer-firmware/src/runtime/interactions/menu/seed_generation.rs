// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
// menu controller — seed generation workflow.
mod additive;
use super::{display, AppData, DmaRxBuf, DvpCamera};
use crate::{
    runtime::interactions::feedback::{show_rejection, ErrorSound},
    wallet::mnemonic,
};
pub(crate) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    sd_card_type: &Option<crate::services::storage_device::SdCardType>,
    dvp_camera_opt: &mut Option<DvpCamera<'_>>,
    cam_dma_buf_opt: &mut Option<DmaRxBuf>,
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    match ad.navigation.app.state {
        crate::runtime::input::AppState::ChooseWordCount { action }
        | crate::runtime::input::AppState::StorageSeedWordCountChoice { action } => Some(handle_word_count(
            ad,
            boot_display,
            delay,
            liveness,
            i2c,
            sd_card_type,
            dvp_camera_opt,
            cam_dma_buf_opt,
            x,
            y,
            is_back,
            action,
        )),
        crate::runtime::input::AppState::SeedEntropyUnavailable { word_count } => Some(handle_entropy_recovery(
            ad,
            boot_display,
            delay,
            liveness,
            i2c,
            sd_card_type,
            dvp_camera_opt,
            cam_dma_buf_opt,
            x,
            y,
            is_back,
            word_count,
        )),
        crate::runtime::input::AppState::StorageSeedDiceChoice => Some(additive::handle_dice_choice(ad, x, y, is_back)),
        crate::runtime::input::AppState::StorageSeedDiceCountChoice => Some(additive::handle_dice_count(ad, x, y, is_back)),
        crate::runtime::input::AppState::StorageSeedTouchChoice => Some(additive::handle_touch_choice(ad, x, y, is_back)),
        crate::runtime::input::AppState::TouchEntropy => Some(handle_touch_entropy(ad, is_back)),
        _ => None,
    }
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_stage_word_count(
    ad: &mut AppData,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageModeChoice));
        return true;
    }
    let Some(word_count) = crate::ui::screens::word_count_choice_at(x, y) else {
        return false;
    };
    let mut pool = [0x5Au8; 32];
    pool[0] = word_count;
    ad.wallet.seeds.stage_seed_entropy(&mut pool, word_count);
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageSeedDiceChoice));
    true
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_dice_choice(ad: &mut AppData, x: u16, y: u16, is_back: bool) -> bool {
    additive::handle_dice_choice(ad, x, y, is_back)
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_dice_count(ad: &mut AppData, x: u16, y: u16, is_back: bool) -> bool {
    additive::handle_dice_count(ad, x, y, is_back)
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_touch_choice(ad: &mut AppData, x: u16, y: u16, is_back: bool) -> bool {
    additive::handle_touch_choice(ad, x, y, is_back)
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_touch_back(ad: &mut AppData, is_back: bool) -> bool {
    handle_touch_entropy(ad, is_back)
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_existing_tool_word_count(
    ad: &mut AppData,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    let crate::runtime::input::AppState::ChooseWordCount { action } = ad.navigation.app.state else {
        return false;
    };
    if !matches!(action, 3 | 4) {
        return false;
    }
    if is_back {
        crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::SeedTool);
        return true;
    }
    let Some(word_count) = crate::ui::screens::word_count_choice_at(x, y) else {
        return false;
    };
    if action == 3 {
        start_word_import(ad, word_count, true);
    } else {
        start_bip85(ad, word_count);
    }
    true
}

fn handle_word_count(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    sd_card_type: &Option<crate::services::storage_device::SdCardType>,
    dvp_camera_opt: &mut Option<DvpCamera<'_>>,
    cam_dma_buf_opt: &mut Option<DmaRxBuf>,
    x: u16,
    y: u16,
    is_back: bool,
    action: u8,
) -> bool {
    if is_back {
        if ad.storage.persistence.device_storage_intent.is_seed_onboarding() {
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageModeChoice));
        } else {
            let _ = crate::runtime::effects::return_to(
                ad, crate::runtime::navigation::ReturnScope::SeedTool,
            );
        }
        return true;
    }
    let Some(word_count) = crate::ui::screens::word_count_choice_at(x, y) else {
        return false;
    };
    // The event loop acknowledges the 12/24-word selection before entering
    // this long-running handler, so entropy collection cannot delay the beep.
    log!("   Onboarding mnemonic length selected: {} words", word_count);
    start_word_count_action(
        ad,
        boot_display,
        delay,
        liveness,
        i2c,
        sd_card_type,
        dvp_camera_opt,
        cam_dma_buf_opt,
        word_count,
        action,
    );
    true
}



fn start_word_count_action(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    sd_card_type: &Option<crate::services::storage_device::SdCardType>,
    dvp_camera_opt: &mut Option<DvpCamera<'_>>,
    cam_dma_buf_opt: &mut Option<DmaRxBuf>,
    word_count: u8,
    action: u8,
) {
    match action {
        0 => generate_random_seed(
            ad,
            boot_display,
            delay,
            liveness,
            i2c,
            sd_card_type,
            dvp_camera_opt,
            cam_dma_buf_opt,
            word_count,
        ),
        1 => start_dice_seed(ad, word_count),
        2 => start_word_import(ad, word_count, false),
        3 => start_word_import(ad, word_count, true),
        4 => start_bip85(ad, word_count),
        5 => start_touch_seed(ad, word_count),
        _ => {}
    }
}

fn generate_random_seed(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    sd_card_type: &Option<crate::services::storage_device::SdCardType>,
    dvp_camera_opt: &mut Option<DvpCamera<'_>>,
    cam_dma_buf_opt: &mut Option<DmaRxBuf>,
    word_count: u8,
) {
    // Every attempt starts from a clean staged pool. Failed camera-health windows
    // must never leave prior entropy material eligible for a later retry.
    ad.wallet.seeds.clear_pending_seed_entropy();
    draw_entropy_status(boot_display);
    match crate::services::entropy::collect(
        delay,
        liveness,
        i2c,
        ad.runtime.idle_ticks,
        dvp_camera_opt,
        cam_dma_buf_opt,
        sd_card_type,
    ) {
        Ok(mut pool) => {
            ad.wallet.seeds.stage_seed_entropy(&mut pool, word_count);
            crate::runtime::effects::route(
                ad,
                crate::runtime::navigation::route!(StorageSeedDiceChoice),
            );
        }
        Err(error) => reject_entropy(ad, boot_display, delay, error, word_count),
    }
}

fn draw_entropy_status(boot_display: &mut display::BootDisplay<'_>) {
    use crate::ui::display::*;
    boot_display.clear_screen();
    let title_width = measure_header("GENERATING");
    draw_oswald_header(
        &mut boot_display.display,
        "GENERATING",
        (320 - title_width) / 2,
        100,
        KASPA_TEAL,
    );
    let status_width = measure_body("Collecting entropy...");
    draw_lato_body(
        &mut boot_display.display,
        "Collecting entropy...",
        (320 - status_width) / 2,
        130,
        COLOR_TEXT_DIM,
    );
}

fn accept_entropy_pool(ad: &mut AppData, pool: &mut [u8], word_count: u8) {
    let entropy_bytes = if word_count == 12 { 16 } else { 32 };
    ad.wallet.seeds.mnemonic_indices =
        mnemonic::generate_from_entropy(word_count, &pool[..entropy_bytes]);
    crate::services::entropy::zeroize(pool);
    ad.wallet.seeds.word_count = word_count;
    ad.wallet.seeds.pp_input.reset();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(PassphraseChoice));
}

pub(crate) fn finalize_staged_entropy(ad: &mut AppData) -> bool {
    if !ad.wallet.seeds.pending_seed_entropy_valid {
        return false;
    }
    let mut pool = [0u8; 32];
    core::mem::swap(&mut pool, &mut ad.wallet.seeds.pending_seed_entropy);
    ad.wallet.seeds.pending_seed_entropy_valid = false;
    let word_count = ad.wallet.seeds.word_count;
    accept_entropy_pool(ad, &mut pool, word_count);
    true
}

pub(crate) fn mix_dice_into_staged(
    ad: &mut AppData,
    dice: &mut mnemonic::DiceCollector,
) -> bool {
    additive::mix_dice_into_staged(ad, dice)
}

fn reject_entropy(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    error: crate::services::entropy::EntropyError,
    word_count: u8,
) {
    let message = error.message();
    log!("   Entropy rejected: {:?} ({})", error, message);
    if error == crate::services::entropy::EntropyError::CameraUnavailable {
        // The camera is mandatory for seed generation. Keep the health threshold
        // unchanged and fail closed, but make environmental failures recoverable
        // without forcing the user to restart onboarding.
        ad.wallet.seeds.clear_pending_seed_entropy();
        crate::services::audio::error();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedEntropyUnavailable { word_count }));
        return;
    }
    if error == crate::services::entropy::EntropyError::ImuUnavailable {
        boot_display.draw_entropy_error_screen(message, "Retry seed generation");
        crate::services::audio::error();
        crate::services::timing::pause(delay, 2500);
    } else {
        show_rejection(boot_display, delay, message, 2000, ErrorSound::Silent);
    }
    let route = if ad.storage.persistence.device_storage_intent.is_seed_onboarding() {
        crate::runtime::navigation::route!(StorageSeedWordCountChoice { action: 0 })
    } else {
        crate::runtime::navigation::route!(ChooseWordCount { action: 0 })
    };
    crate::runtime::effects::route(ad, route);
}

fn handle_entropy_recovery(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    sd_card_type: &Option<crate::services::storage_device::SdCardType>,
    dvp_camera_opt: &mut Option<DvpCamera<'_>>,
    cam_dma_buf_opt: &mut Option<DmaRxBuf>,
    x: u16,
    y: u16,
    is_back: bool,
    word_count: u8,
) -> bool {
    let choice = if is_back {
        Some(crate::ui::screens::EntropyRecoveryChoice::Cancel)
    } else {
        crate::ui::screens::entropy_recovery_choice_at(x, y)
    };
    match choice {
        Some(crate::ui::screens::EntropyRecoveryChoice::Retry) => {
            log!("   Camera entropy user retry: {} words", word_count);
            generate_random_seed(
                ad,
                boot_display,
                delay,
                liveness,
                i2c,
                sd_card_type,
                dvp_camera_opt,
                cam_dma_buf_opt,
                word_count,
            );
            true
        }
        Some(crate::ui::screens::EntropyRecoveryChoice::Cancel) => {
            log!("   Camera entropy user cancel");
            ad.wallet.seeds.clear_pending_seed_entropy();
            let route = if ad.storage.persistence.device_storage_intent.is_seed_onboarding() {
                crate::runtime::navigation::route!(StorageSeedWordCountChoice { action: 0 })
            } else {
                crate::runtime::navigation::route!(ChooseWordCount { action: 0 })
            };
            crate::runtime::effects::route(ad, route);
            true
        }
        None => false,
    }
}

fn start_dice_seed(ad: &mut AppData, word_count: u8) {
    ad.wallet.seeds.dice_collector = if word_count == 24 {
        mnemonic::DiceCollector::new_24_word()
    } else {
        mnemonic::DiceCollector::new_12_word()
    };
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(DiceRoll));
}

fn start_word_import(ad: &mut AppData, word_count: u8, calculate_last: bool) {
    ad.wallet.seeds.word_input.reset();
    let route = if calculate_last {
        crate::runtime::navigation::route!(CalcLastWord { word_idx: 0, word_count })
    } else {
        crate::runtime::navigation::route!(ImportWord { word_idx: 0, word_count })
    };
    crate::runtime::effects::route(ad, route);
}

fn start_bip85(ad: &mut AppData, word_count: u8) {
    ad.wallet.seeds.bip85_index = 0;
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(Bip85Index { word_count }));
}

fn start_touch_seed(ad: &mut AppData, word_count: u8) {
    ad.wallet.seeds.word_count = word_count;
    ad.wallet.seeds.touch_collector.reset();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(TouchEntropy));
}

fn handle_touch_entropy(ad: &mut AppData, is_back: bool) -> bool {
    if !is_back { return false; }
    ad.wallet.seeds.touch_collector.reset();
    if ad.wallet.seeds.pending_seed_entropy_valid {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageSeedTouchChoice));
    } else {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedToolsMenu));
    }
    true
}
