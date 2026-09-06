use crate::{
    hw::display,
    runtime::{
        data::{AppData, PrivateSwapMode, PrivateSwapPhase},
        input::AppState,
    },
    runtime::interactions::feedback::{show_rejection, ErrorSound},
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
        AppState::PrivateSwapReview => {
            Some(handle_review(ad, boot_display, delay, liveness, x, y, is_back))
        }
        AppState::PrivateSwapKeyResult => Some(handle_key(ad, boot_display, x, y, is_back)),
        AppState::PrivateSwapKeyResultQr => Some(close_qr(
            ad,
            false,
            crate::runtime::navigation::route!(PrivateSwapKeyResult),
        )),
        AppState::PrivateSwapResult => Some(handle_result(ad, boot_display, x, y, is_back)),
        AppState::PrivateSwapResultQr => Some(close_qr(
            ad,
            true,
            crate::runtime::navigation::route!(PrivateSwapResult),
        )),
        _ => None,
    }
}

fn handle_review(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        reset_to_single_sig(ad);
        return true;
    }
    if !(178..=224).contains(&y) || !(55..=265).contains(&x) {
        return false;
    }

    boot_display.draw_saving_screen("Private Swap authorization...");
    let result = match ad.signing.private_swap.mode {
        PrivateSwapMode::Bind => crate::services::private_swap::complete_binding(ad, liveness),
        PrivateSwapMode::PreSign => crate::services::private_swap::begin_presign(ad),
        PrivateSwapMode::Complete => crate::services::private_swap::complete_claim(ad, liveness),
        _ => return false,
    };
    match result {
        Ok(()) => {
            crate::runtime::effects::route(
                ad,
                crate::runtime::navigation::route!(PrivateSwapResult),
            );
        }
        Err(error) => {
            ad.signing.private_swap.reset();
            show_rejection(
                boot_display,
                delay,
                error.message(),
                1800,
                ErrorSound::Beep,
            );
            crate::runtime::effects::route(
                ad,
                crate::runtime::navigation::route!(SingleSigMenu),
            );
        }
    }
    true
}

fn handle_key(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        reset_to_single_sig(ad);
        return true;
    }
    if (178..=224).contains(&y) && (70..=250).contains(&x) {
        boot_display.draw_qr_fullscreen(
            &ad.signing.private_swap.response[..ad.signing.private_swap.response_len],
        );
        crate::runtime::effects::route(
            ad,
            crate::runtime::navigation::route!(PrivateSwapKeyResultQr),
        );
        return true;
    }
    false
}

fn handle_result(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        reset_to_single_sig(ad);
        return true;
    }
    if !(178..=224).contains(&y) || !(55..=265).contains(&x) {
        return false;
    }
    if ad.signing.private_swap.phase == PrivateSwapPhase::AwaitingReveal
        && ad.signing.private_swap.nonce_qr_shown
    {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ScanQR));
        return true;
    }

    boot_display.draw_qr_fullscreen(
        &ad.signing.private_swap.response[..ad.signing.private_swap.response_len],
    );
    crate::runtime::effects::route(
        ad,
        crate::runtime::navigation::route!(PrivateSwapResultQr),
    );
    true
}

fn close_qr(
    ad: &mut AppData,
    marks_nonce_shown: bool,
    route: crate::runtime::navigation::UiRoute,
) -> bool {
    if marks_nonce_shown && ad.signing.private_swap.phase == PrivateSwapPhase::AwaitingReveal {
        ad.signing.private_swap.nonce_qr_shown = true;
    }
    crate::runtime::effects::route(ad, route);
    true
}

fn reset_to_single_sig(ad: &mut AppData) {
    ad.signing.private_swap.reset();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SingleSigMenu));
}
