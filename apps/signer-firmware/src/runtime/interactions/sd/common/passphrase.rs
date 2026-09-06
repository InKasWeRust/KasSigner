use crate::{
    runtime::interactions::keyboard::{handle_passphrase_keyboard, KeyboardAction},
    runtime::navigation::ContinuationRoute,
};

use super::context::SdIoContext;

#[derive(Clone, Copy)]
pub(in crate::runtime::interactions::sd) struct PassphraseWorkflow {
    pub(in crate::runtime::interactions::sd) back_state: ContinuationRoute,
}

pub(in crate::runtime::interactions::sd) type DeviceSubmitHandler = for<'display, 'i2c> fn(
    &mut crate::runtime::data::AppData,
    &mut crate::hw::display::BootDisplay<'display>,
    &mut esp_hal::delay::Delay,
    &mut dyn FnMut(),
    &mut esp_hal::i2c::master::I2c<'i2c, esp_hal::Blocking>,
    &mut dyn crate::services::backup::BackupDevice,
) -> Option<ContinuationRoute>;

pub(in crate::runtime::interactions::sd) fn run_device_bound_passphrase_workflow(
    ctx: SdIoContext<'_, '_, '_>,
    workflow: PassphraseWorkflow,
    submit: DeviceSubmitHandler,
) -> bool {
    let SdIoContext {
        ad, boot_display, delay, liveness, i2c, backup_device, x, y, is_back, ..
    } = ctx;
    if is_back {
        ad.wallet.seeds.pp_input.reset();
        crate::runtime::effects::continue_to(ad, workflow.back_state);
        return true;
    }
    match handle_passphrase_keyboard(&mut ad.wallet.seeds.pp_input, boot_display, x, y) {
        KeyboardAction::None => false,
        KeyboardAction::Edited => true,
        KeyboardAction::Submitted => {
            let next_state = submit(ad, boot_display, delay, liveness, i2c, backup_device);
            ad.wallet.seeds.pp_input.reset();
            if let Some(route) = next_state { crate::runtime::effects::continue_to(ad, route); }
            true
        }
    }
}
