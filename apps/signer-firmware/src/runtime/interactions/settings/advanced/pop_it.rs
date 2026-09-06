//! User-controlled Secure Boot v2 provisioning flow.
//!
//! This controller never touches eFuse registers. It persists a one-shot
//! request only after the user completes the explicit confirmation and the
//! production preflight passes. The signed ESP-IDF bootloader owns the final
//! Secure-Boot-V2 signature checks and irreversible eFuse transition.

use crate::{
    hw::display::BootDisplay,
    runtime::interactions::TouchInput,
    runtime::{data::AppData, input::AppState},
    services::persistent_wallet::PersistentWallet,
    ui::screens::device::pop_it::{
        CONTINUE_WITHOUT_BUTTON_Y, EXPLAIN_BUTTON_X, NO_BUTTON_X, OWNER_PROMPT_BUTTON_X,
        OWNER_SETUP_BUTTON_Y, PROMPT_BUTTON_Y, YES_BUTTON_X,
    },
};

#[cfg(feature = "m5stack")]
use crate::services::verify::boot_security;

use super::input::{self, EditAction};

pub(super) fn handle_pure(input_event: TouchInput, ad: &mut AppData) -> Option<bool> {
    match ad.navigation.app.state {
        AppState::PopItPrompt => pure_prompt(input_event, ad),
        AppState::PopItExplain => {
            if !input_event.is_back { return Some(false); }
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(PopItPrompt));
            Some(true)
        }
        AppState::PopItConfirm => pure_confirm(input_event, ad),
        _ => None,
    }
}

fn pure_prompt(input: TouchInput, ad: &mut AppData) -> Option<bool> {
    if input.is_back {
        return_to_saved_state(ad);
        return Some(true);
    }
    if !ad.pop_it.owner_authority_enrolled {
        if OWNER_PROMPT_BUTTON_X.contains(&input.x) && OWNER_SETUP_BUTTON_Y.contains(&input.y) {
            return None;
        }
        if !cfg!(feature = "secure-owner-only")
            && OWNER_PROMPT_BUTTON_X.contains(&input.x)
            && CONTINUE_WITHOUT_BUTTON_Y.contains(&input.y)
        {
            return None;
        }
        return Some(false);
    }
    if !PROMPT_BUTTON_Y.contains(&input.y) { return Some(false); }
    if EXPLAIN_BUTTON_X.contains(&input.x) {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(PopItExplain));
        return Some(true);
    }
    if YES_BUTTON_X.contains(&input.x) || NO_BUTTON_X.contains(&input.x) {
        return None;
    }
    Some(false)
}

fn pure_confirm(input_event: TouchInput, ad: &mut AppData) -> Option<bool> {
    if input_event.is_back {
        ad.wallet.seeds.pp_input.reset();
        ad.pop_it.error = None;
        return_to_saved_state(ad);
        return Some(true);
    }
    match input::edit(input_event, ad, false) {
        EditAction::Edited => {
            ad.pop_it.error = None;
            Some(true)
        }
        EditAction::None => Some(false),
        EditAction::Submitted => None,
    }
}

pub(super) fn handle(
    input: TouchInput,
    ad: &mut AppData,
    persistence: &mut PersistentWallet<'_>,
    display: &mut BootDisplay<'_>,
) -> Option<bool> {
    match ad.navigation.app.state {
        AppState::PopItPrompt => handle_prompt(input, ad),
        AppState::PopItConfirm => handle_confirm(input, ad, persistence, display),
        _ => None,
    }
}

pub(super) fn handle_prompt(input: TouchInput, ad: &mut AppData) -> Option<bool> {
    if !ad.pop_it.owner_authority_enrolled {
        if !OWNER_PROMPT_BUTTON_X.contains(&input.x) { return Some(false); }
        if OWNER_SETUP_BUTTON_Y.contains(&input.y) {
            ad.pop_it.error = None;
            ad.wallet.seeds.pp_input.reset();
            ad.navigation.production.owner_firmware_menu.reset();
            crate::runtime::effects::route(
                ad,
                crate::runtime::navigation::route!(OwnerFirmwareMenu),
            );
            return Some(true);
        }
        if CONTINUE_WITHOUT_BUTTON_Y.contains(&input.y) {
            if cfg!(feature = "secure-owner-only") {
                ad.pop_it.error = Some("Owner key enrollment is required");
                return Some(true);
            }
            ad.pop_it.error = None;
            ad.wallet.seeds.pp_input.reset();
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(PopItConfirm));
            return Some(true);
        }
        return Some(false);
    }

    if !PROMPT_BUTTON_Y.contains(&input.y) { return Some(false); }
    if YES_BUTTON_X.contains(&input.x) {
        ad.pop_it.error = None;
        ad.wallet.seeds.pp_input.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(PopItConfirm));
        return Some(true);
    }
    if NO_BUTTON_X.contains(&input.x) {
        ad.pop_it.error = None;
        return_to_saved_state(ad);
        return Some(true);
    }
    None
}

fn handle_confirm(
    input_event: TouchInput,
    ad: &mut AppData,
    persistence: &mut PersistentWallet<'_>,
    display: &mut BootDisplay<'_>,
) -> Option<bool> {
    if !matches!(input::edit(input_event, ad, false), EditAction::Submitted) {
        return Some(false);
    }
    if !confirmation_phrase_valid(&ad.wallet.seeds.pp_input.buf[..ad.wallet.seeds.pp_input.len]) {
        ad.pop_it.error = Some("Enter POP IT, then press OK");
        return Some(true);
    }
    #[cfg(all(feature = "m5stack", not(feature = "production")))]
    {
        let _ = persistence;
        let _ = display;
        boot_security::enable_dev_pop_it_indicator_demo();
        ad.wallet.seeds.pp_input.reset();
        ad.pop_it.error = None;
        crate::runtime::effects::home(ad);
        return Some(true);
    }

    #[cfg(feature = "secure-provisioning-core")]
    {
        if cfg!(feature = "secure-owner-only") && !boot_security::owner_authority_enrolled() {
            ad.pop_it.error = Some("Enroll the owner key before Pop It");
            return Some(true);
        }
        if let Err(error) = boot_security::pop_it_preflight() {
            ad.pop_it.error = Some(error.message());
            return Some(true);
        }
        if persistence.request_pop_it().is_err() {
            ad.pop_it.error = Some("Could not arm Secure Boot request");
            return Some(true);
        }

        ad.wallet.seeds.pp_input.reset();
        ad.pop_it.error = None;
        display.draw_pop_it_applying();
        esp_hal::system::software_reset();
    }

    #[cfg(not(feature = "m5stack"))]
    {
        let _ = persistence;
        let _ = display;
        ad.pop_it.error = Some("Pop It preview requires CoreS3");
        Some(true)
    }
}

fn return_to_saved_state(ad: &mut AppData) {
    let destination = ad.pop_it.return_state;
    crate::runtime::effects::continue_to(ad, destination);
}

/// Accepts case-insensitive `popit`, `pop it`, or `pop-it`, optional
/// surrounding/repeated whitespace or hyphens, and one optional terminal `!`.
pub(super) fn confirmation_phrase_valid(bytes: &[u8]) -> bool {
    let index = skip_ascii_whitespace(bytes, 0);
    let Some(index) = consume_ascii_word(bytes, index, b"pop") else { return false; };
    let index = consume_optional_separator(bytes, index);
    let Some(mut index) = consume_ascii_word(bytes, index, b"it") else { return false; };
    index = skip_ascii_whitespace(bytes, index);
    if bytes.get(index) == Some(&b'!') {
        index = skip_ascii_whitespace(bytes, index + 1);
    }
    index == bytes.len()
}

fn skip_ascii_whitespace(bytes: &[u8], mut index: usize) -> usize {
    while bytes.get(index).is_some_and(u8::is_ascii_whitespace) { index += 1; }
    index
}

fn consume_ascii_word(bytes: &[u8], mut index: usize, word: &[u8]) -> Option<usize> {
    for &expected in word {
        if bytes.get(index).copied()?.to_ascii_lowercase() != expected { return None; }
        index += 1;
    }
    Some(index)
}

fn consume_optional_separator(bytes: &[u8], mut index: usize) -> usize {
    while bytes.get(index).is_some_and(|byte| byte.is_ascii_whitespace() || *byte == b'-') {
        index += 1;
    }
    index
}

#[cfg(test)]
#[path = "unit_tests/pop_it_tests.rs"]
mod unit_tests;
