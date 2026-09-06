use crate::{
    runtime::interactions::feedback::{show_rejection, ErrorSound},
    hw::display,
    runtime::{data::{AppData, CovenantSigningMode, CovenantSigningPhase}, input::AppState},
};

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
        AppState::CovenantSignReview => Some(handle_known(ad, boot_display, delay, liveness, x, y, is_back)),
        AppState::CovenantSignOpaqueWarning => Some(handle_opaque_warning(ad, x, y, is_back)),
        AppState::CovenantSignOpaqueConfirm => Some(handle_opaque_confirm(ad, boot_display, delay, liveness, x, y, is_back)),
        AppState::CovenantKeyResult => Some(handle_key_result(ad, boot_display, x, y, is_back)),
        AppState::CovenantKeyResultQr => Some(close_qr(ad, false, crate::runtime::navigation::route!(CovenantKeyResult))),
        AppState::CovenantSignResult => Some(handle_sign_result(ad, boot_display, x, y, is_back)),
        AppState::CovenantSignResultQr => Some(close_qr(ad, true, crate::runtime::navigation::route!(CovenantSignResult))),
        _ => None,
    }
}

fn handle_known(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        if ad.signing.covenant.context_page > 0 {
            ad.signing.covenant.context_page -= 1;
        } else {
            ad.signing.covenant.reset();
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SingleSigMenu));
        }
        return true;
    }
    if (185..=225).contains(&y) && (90..=230).contains(&x) {
        if ad.signing.covenant.context_page.saturating_add(1) < ad.signing.covenant.context_page_count() {
            ad.signing.covenant.context_page += 1;
        } else {
            sign(ad, boot_display, delay, liveness);
        }
        return true;
    }
    false
}

fn handle_opaque_warning(ad: &mut AppData, x: u16, y: u16, is_back: bool) -> bool {
    if is_back {
        ad.signing.covenant.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SingleSigMenu));
        return true;
    }
    if (178..=222).contains(&y) && (50..=270).contains(&x) {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(CovenantSignOpaqueConfirm));
        return true;
    }
    false
}

fn handle_opaque_confirm(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(CovenantSignOpaqueWarning));
        return true;
    }
    if (178..=222).contains(&y) && (70..=250).contains(&x) {
        sign(ad, boot_display, delay, liveness);
        return true;
    }
    false
}

fn sign(ad: &mut AppData, boot_display: &mut display::BootDisplay<'_>, delay: &mut esp_hal::delay::Delay, liveness: &mut dyn FnMut()) {
    let binding = matches!(ad.signing.covenant.mode, CovenantSigningMode::BindKnown | CovenantSigningMode::BindOpaque);
    if !binding && !matches!(ad.signing.covenant.mode, CovenantSigningMode::Known | CovenantSigningMode::Opaque) {
        return;
    }
    boot_display.draw_saving_screen(if binding { "Binding covenant key..." } else { "Covenant signing..." });
    let result = if binding {
        crate::services::covenant_sign::complete_binding(ad, liveness)
    } else {
        crate::services::covenant_sign::begin_signing(ad, liveness)
    };
    match result {
        Ok(()) => {
            let _ = crate::runtime::effects::route(
                ad,
                crate::runtime::navigation::route!(CovenantSignResult),
            );
        }
        Err(error) => {
            ad.signing.covenant.reset();
            show_rejection(boot_display, delay, error.message(), 1800, ErrorSound::Beep);
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SingleSigMenu));
        }
    }
}

fn handle_key_result(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        ad.signing.covenant.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SingleSigMenu));
        return true;
    }
    if (178..=222).contains(&y) && (80..=240).contains(&x) {
        boot_display.draw_qr_fullscreen(&ad.signing.covenant.response[..ad.signing.covenant.response_len]);
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(CovenantKeyResultQr));
    }
    false
}

fn handle_sign_result(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        ad.signing.covenant.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SingleSigMenu));
        return true;
    }
    if !(178..=222).contains(&y) || !(60..=260).contains(&x) { return false; }
    if ad.signing.covenant.phase == CovenantSigningPhase::AwaitingReveal
        && ad.signing.covenant.nonce_qr_shown
    {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ScanQR));
        return true;
    }
    boot_display.draw_qr_fullscreen(&ad.signing.covenant.response[..ad.signing.covenant.response_len]);
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(CovenantSignResultQr));
    true
}

fn close_qr(
    ad: &mut AppData,
    marks_nonce_shown: bool,
    route: crate::runtime::navigation::UiRoute,
) -> bool {
    if marks_nonce_shown && ad.signing.covenant.phase == CovenantSigningPhase::AwaitingReveal {
        ad.signing.covenant.nonce_qr_shown = true;
    }
    crate::runtime::effects::route(ad, route);
    true
}
