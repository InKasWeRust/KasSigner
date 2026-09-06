//! Shared overwrite confirmation and pending-write dispatch.

use super::context::SdIoContext;
use crate::runtime::data::PendingStorageAction;

pub(crate) fn handle_sd_overwrite_warning(ctx: SdIoContext<'_, '_, '_>) -> bool {
    let SdIoContext {
        ad,
        boot_display,
        delay,
        i2c,
        x,
        y,
        is_back,
        ..
    } = ctx;

    if is_back || ((165..=290).contains(&x) && (140..=185).contains(&y)) {
        crate::runtime::effects::resume(ad, crate::runtime::navigation::ResumeTarget::StorageOverwriteBack);
        return true;
    }
    if !((30..=155).contains(&x) && (140..=185).contains(&y)) {
        return false;
    }

    ad.wallet.seeds.pp_input.reset();
    let action = ad.storage.confirmation.overwrite_action;
    execute_pending_action(ad, boot_display, delay, i2c, action);
    true
}

pub(super) fn execute_pending_action(
    ad: &mut crate::runtime::data::AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    action: PendingStorageAction,
) {
    match action {
        PendingStorageAction::Navigate(route) => {
            let _ = crate::runtime::effects::continue_to(ad, route);
        }
        PendingStorageAction::SaveSignature => {
            super::super::exports::signature::save_signature(ad, boot_display, delay, i2c);
        }
    }
}
