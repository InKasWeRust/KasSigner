//! SD signature-export workflow using the shared filename and overwrite policy.

use crate::runtime::interactions::feedback::{show_rejection, ErrorSound, show_success};
use super::super::{
    common::{
        context::SdIoContext,
        filename::{FilenameWorkflow, run_filename_action_workflow},
    },
    write_file_to_sd,
};
use crate::runtime::{data::PendingStorageAction, input::AppState};

pub(crate) fn handle_sd_sig_filename(ctx: SdIoContext<'_, '_, '_>) -> bool {
    run_filename_action_workflow(
        ctx,
        FilenameWorkflow {
            extension: *b"TXT",
            back_state: crate::runtime::navigation::continuation!(MainMenu),
            filename_state: AppState::SdSigFilename,
            next_state: crate::runtime::navigation::continuation!(MainMenu),
            redraw_if_exists: true,
            redraw_if_available: true,
        },
        PendingStorageAction::SaveSignature,
    )
}

pub(in crate::runtime::interactions::sd) fn save_signature(
    ad: &mut crate::runtime::data::AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) {
    let filename = ad.storage.export_file.filename;
    boot_display.draw_saving_screen("Saving sig...");
    boot_display.update_progress_bar(50);
    crate::services::timing::pause(delay, 50);

    let mut encoded = [0u8; 128];
    encode_signature_hex(&ad.signing.message.signature, &mut encoded);
    let result = write_file_to_sd(i2c, delay, &filename, &encoded);
    shared_signer::bytes::zeroize_bytes(&mut encoded);

    if result.is_ok() {
        show_success(boot_display, delay, "Signature Saved!", 2_000);
    } else {
        show_rejection(boot_display, delay, "SD write failed", 1_500, ErrorSound::Beep);
    }
    ad.wallet.seeds.pp_input.reset();
    crate::runtime::effects::home(ad);
}

fn encode_signature_hex(signature: &[u8; 64], output: &mut [u8; 128]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (index, byte) in signature.iter().copied().enumerate() {
        output[index * 2] = HEX[(byte >> 4) as usize];
        output[index * 2 + 1] = HEX[(byte & 0x0f) as usize];
    }
}
