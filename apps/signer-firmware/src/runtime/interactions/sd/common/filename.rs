//! Shared SD filename keyboard, normalization, existence, and overwrite workflow.

use super::{
    super::{build_filename_83, sd_file_exists},
    context::SdIoContext,
    overwrite::execute_pending_action,
};
use crate::{
    runtime::interactions::keyboard::{handle_keyboard, KeyboardAction, KeyboardPolicy},
    runtime::{data::PendingStorageAction, input::AppState, navigation::ContinuationRoute},
};

#[derive(Clone, Copy)]
pub(crate) struct FilenameWorkflow {
    pub(in crate::runtime::interactions::sd) extension: [u8; 3],
    pub(in crate::runtime::interactions::sd) back_state: ContinuationRoute,
    pub(in crate::runtime::interactions::sd) filename_state: AppState,
    pub(in crate::runtime::interactions::sd) next_state: ContinuationRoute,
    pub(in crate::runtime::interactions::sd) redraw_if_exists: bool,
    pub(in crate::runtime::interactions::sd) redraw_if_available: bool,
}

pub(crate) fn run_filename_workflow(
    ctx: SdIoContext<'_, '_, '_>,
    workflow: FilenameWorkflow,
) -> bool {
    let action = PendingStorageAction::Navigate(workflow.next_state);
    run_filename_action_workflow(ctx, workflow, action)
}

pub(crate) fn run_filename_action_workflow(
    ctx: SdIoContext<'_, '_, '_>,
    workflow: FilenameWorkflow,
    action: PendingStorageAction,
) -> bool {
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

    if is_back {
        ad.wallet.seeds.pp_input.reset();
        crate::runtime::effects::continue_to(ad, workflow.back_state);
        return true;
    }

    match handle_keyboard(
        &mut ad.wallet.seeds.pp_input,
        boot_display,
        x,
        y,
        KeyboardPolicy::COMPACT_TEXT,
    ) {
        KeyboardAction::Submitted => submit_filename(
            ad,
            boot_display,
            delay,
            i2c,
            workflow,
            action,
        ),
        KeyboardAction::Edited | KeyboardAction::None => false,
    }
}

fn submit_filename(
    ad: &mut crate::runtime::data::AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    workflow: FilenameWorkflow,
    action: PendingStorageAction,
) -> bool {
    let filename = build_filename_83(
        &ad.wallet.seeds.pp_input.buf,
        ad.wallet.seeds.pp_input.len,
        &workflow.extension,
    );
    ad.storage.export_file.filename = filename;

    if sd_file_exists(i2c, delay, &filename) {
        prepare_overwrite_prompt(ad, &filename);
        ad.storage.confirmation.overwrite_action = action;
        ad.storage.confirmation.overwrite_back = crate::runtime::navigation::continuation_from_state(workflow.filename_state);
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SdOverwriteWarning));
        return workflow.redraw_if_exists;
    }

    ad.wallet.seeds.pp_input.reset();
    execute_pending_action(ad, boot_display, delay, i2c, action);
    workflow.redraw_if_available
}

fn prepare_overwrite_prompt(ad: &mut crate::runtime::data::AppData, filename: &[u8; 11]) {
    let mut display_name = [0u8; 13];
    let display_len = crate::services::storage_device::format_83_display(filename, &mut display_name);
    let prompt = &mut ad.storage.export_file.overwrite_prompt;
    prompt.fill(0);

    let text = b"Overwrite "
        .iter()
        .chain(display_name[..display_len].iter())
        .chain(b"?".iter());
    let mut length = 0usize;
    for &byte in text.take(prompt.len()) {
        prompt[length] = byte;
        length += 1;
    }
    ad.storage.export_file.overwrite_prompt_len = length as u8;
}
