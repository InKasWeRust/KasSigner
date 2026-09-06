// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use super::{AppData, display, stego};
use crate::runtime::interactions::{
    feedback::{show_rejection, ErrorSound},
    keyboard::{KeyboardAction, handle_passphrase_keyboard},
};
use crate::runtime::input::AppState;
use shared_signer::bytes::zeroize_bytes;
use crate::services::credential_policy::{confirmation_digest, confirmation_matches, CredentialKind};

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    let redraw = match ad.navigation.app.state {
        AppState::StegoJpegPpAsk => handle_prompt(ad, x, y, is_back),
        AppState::StegoJpegPpInfo => handle_hint_choice(ad, x, y, is_back),
        AppState::StegoJpegPpEntry => handle_custom_hint(ad, boot_display, x, y, is_back),
        AppState::StegoPortablePassword => {
            handle_portable_password(ad, boot_display, delay, x, y, is_back, false)
        }
        AppState::StegoPortablePasswordConfirm => {
            handle_portable_password(ad, boot_display, delay, x, y, is_back, true)
        }
        _ => return None,
    };
    Some(redraw)
}

fn handle_prompt(ad: &mut AppData, x: u16, y: u16, is_back: bool) -> bool {
    if is_back {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoJpegDescPreview));
        return true;
    }
    if !(175..=215).contains(&y) { return false; }
    if (20..=150).contains(&x) {
        clear_hint_state(ad);
        advance_after_hint(ad);
        return true;
    }
    if (170..=300).contains(&x) {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoJpegPpInfo));
        return true;
    }
    false
}

fn handle_hint_choice(ad: &mut AppData, x: u16, y: u16, is_back: bool) -> bool {
    if is_back {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoJpegPpAsk));
        return true;
    }
    let Some(row) = hint_row(x, y) else { return false; };
    if row == 3 {
        ad.wallet.seeds.pp_input.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoJpegPpEntry));
        return true;
    }
    let preset = stego::HINT_PRESETS[row as usize].as_bytes();
    clear_hint_state(ad);
    ad.stego.hint.buffer[..preset.len()].copy_from_slice(preset);
    ad.stego.hint.length = preset.len();
    advance_after_hint(ad);
    true
}

fn hint_row(x: u16, y: u16) -> Option<u8> {
    if !(15..=305).contains(&x) { return None; }
    (0..4u8).find(|row| {
        let top = 68 + u16::from(*row) * 36;
        y >= top && y < top + 30
    })
}

fn handle_custom_hint(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        ad.wallet.seeds.pp_input.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoJpegPpInfo));
        return true;
    }
    match handle_passphrase_keyboard(&mut ad.wallet.seeds.pp_input, boot_display, x, y) {
        KeyboardAction::Submitted => {
            copy_custom_hint(ad);
            advance_after_hint(ad);
            true
        }
        KeyboardAction::Edited | KeyboardAction::None => false,
    }
}

fn advance_after_hint(ad: &mut AppData) {
    ad.stego.export_flow.clear_portable_confirmation();
    ad.stego.session.portable.clear();
    if ad.stego.export_flow.security == stego::StegoSecurity::Portable {
        ad.wallet.seeds.pp_input.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoPortablePassword));
    } else {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoJpegConfirm));
    }
}

fn handle_portable_password(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    x: u16,
    y: u16,
    is_back: bool,
    confirming: bool,
) -> bool {
    if is_back {
        ad.wallet.seeds.pp_input.reset();
        if confirming {
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoPortablePassword));
        } else {
            ad.stego.export_flow.clear_portable_confirmation();
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoJpegPpAsk));
        }
        return true;
    }
    match handle_passphrase_keyboard(&mut ad.wallet.seeds.pp_input, boot_display, x, y) {
        KeyboardAction::None => false,
        KeyboardAction::Edited => true,
        KeyboardAction::Submitted => submit_portable_password(ad, boot_display, delay, confirming),
    }
}

fn submit_portable_password(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    confirming: bool,
) -> bool {
    let secret = &ad.wallet.seeds.pp_input.buf[..ad.wallet.seeds.pp_input.len];
    if let Err(message) = stego::validate_portable_password(secret) {
        show_rejection(boot_display, delay, message, 1_700, ErrorSound::Beep);
        return true;
    }
    let digest = confirmation_digest(CredentialKind::Password, secret);
    if !confirming {
        ad.stego.export_flow.portable_confirmation_digest = digest;
        ad.stego.export_flow.portable_confirmation_pending = true;
        ad.wallet.seeds.pp_input.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoPortablePasswordConfirm));
        return true;
    }
    if !ad.stego.export_flow.portable_confirmation_pending
        || !confirmation_matches(&ad.stego.export_flow.portable_confirmation_digest, &digest)
    {
        ad.wallet.seeds.pp_input.reset();
        ad.stego.export_flow.clear_portable_confirmation();
        show_rejection(boot_display, delay, "Passwords do not match", 1_700, ErrorSound::Beep);
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoPortablePassword));
        return true;
    }
    ad.stego.session.portable.set_password(secret);
    ad.wallet.seeds.pp_input.reset();
    ad.stego.export_flow.clear_portable_confirmation();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoJpegConfirm));
    true
}

fn copy_custom_hint(ad: &mut AppData) {
    clear_hint_state(ad);
    let length = ad.wallet.seeds.pp_input.len.min(ad.stego.hint.buffer.len());
    ad.stego.hint.buffer[..length]
        .copy_from_slice(&ad.wallet.seeds.pp_input.buf[..length]);
    ad.stego.hint.length = length;
    ad.wallet.seeds.pp_input.reset();
}

fn clear_hint_state(ad: &mut AppData) {
    zeroize_bytes(&mut ad.stego.hint.buffer);
    ad.stego.hint.length = 0;
}
