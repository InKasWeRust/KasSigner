//! Shared TXT discovery, selection, and complete bounded loading workflows.

use crate::{
    runtime::interactions::{feedback::{show_rejection, ErrorSound}, TouchInput},
    hw::{display, touch::TouchZone},
    runtime::{data::AppData, navigation::ContinuationRoute},
};

#[derive(Clone, Copy)]
pub(crate) struct TextFileScanWorkflow {
    pub maximum_bytes: u32,
    pub next_state: ContinuationRoute,
    pub empty_message: &'static str,
}

pub(crate) struct TextFileSelectionContext<'ctx, 'display, 'hal> {
    pub(crate) ad: &'ctx mut AppData,
    pub(crate) boot_display: &'ctx mut display::BootDisplay<'display>,
    pub(crate) delay: &'ctx mut esp_hal::delay::Delay,
    pub(crate) i2c: &'ctx mut esp_hal::i2c::master::I2c<'hal, esp_hal::Blocking>,
    pub(crate) list_zones: &'ctx [TouchZone; 4],
    pub(crate) input: TouchInput,
}

#[derive(Clone, Copy)]
pub(crate) struct TextFileSelectionWorkflow {
    pub back_state: ContinuationRoute,
    pub read_error_message: &'static str,
}

pub(crate) fn scan(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    workflow: TextFileScanWorkflow,
) -> bool {
    boot_display.draw_loading_screen("Scanning TXT...");
    boot_display.update_progress_bar(50);
    crate::services::timing::pause(delay, 50);
    match crate::services::storage_files::scan_text_files(workflow.maximum_bytes, delay, i2c) {
        Ok(files) if files.file_count > 0 => {
            ad.storage.text_files = files;
            crate::runtime::effects::continue_to(ad, workflow.next_state);
            true
        }
        Ok(_) => {
            show_rejection(
                boot_display,
                delay,
                workflow.empty_message,
                2_000,
                ErrorSound::Beep,
            );
            true
        }
        Err(_) => {
            show_rejection(
                boot_display,
                delay,
                "SD read error",
                2_000,
                ErrorSound::Beep,
            );
            true
        }
    }
}

pub(crate) fn handle_selection<const N: usize>(
    context: TextFileSelectionContext<'_, '_, '_>,
    workflow: TextFileSelectionWorkflow,
    mut on_loaded: impl FnMut(&mut AppData, &[u8]) -> Result<(), &'static str>,
) -> bool {
    let TextFileSelectionContext { ad, boot_display, delay, i2c, list_zones, input } = context;
    let TouchInput { x, y, is_back } = input;
    if is_back {
        crate::runtime::effects::continue_to(ad, workflow.back_state);
        return true;
    }

    let Some(index) = list_zones.iter().position(|zone| zone.contains(x, y)) else {
        return false;
    };
    if index >= ad.storage.text_files.file_count as usize {
        return false;
    }

    let filename = ad.storage.text_files.file_names[index];
    boot_display.draw_loading_screen("Reading...");
    boot_display.update_progress_bar(50);
    crate::services::timing::pause(delay, 50);

    let mut content = [0u8; N];
    let result = crate::services::storage_files::read_text_file(
        &filename,
        delay,
        i2c,
        &mut content,
    )
    .and_then(|length| on_loaded(ad, &content[..length]));
    shared_signer::bytes::zeroize_bytes(&mut content);

    if result.is_err() {
        show_rejection(
            boot_display,
            delay,
            workflow.read_error_message,
            1_500,
            ErrorSound::Beep,
        );
    }
    true
}
