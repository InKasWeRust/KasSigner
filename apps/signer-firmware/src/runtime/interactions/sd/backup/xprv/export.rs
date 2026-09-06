use crate::runtime::interactions::feedback::{show_rejection, ErrorSound, show_success};
use crate::runtime::input::AppState;
use shared_signer::bytes::zeroize_bytes;

use super::super::super::{
    run_filename_workflow, sd_backup, write_file_to_sd,
    zeroize_buf, FilenameWorkflow,
};
use super::super::super::common::context::SdIoContext;

pub(crate) fn handle_sd_xprv_filename(ctx: SdIoContext<'_, '_, '_>) -> bool {
    run_filename_workflow(
        ctx,
        FilenameWorkflow {
            extension: *b"KAS",
            back_state: crate::runtime::navigation::continuation!(XprvExportMenu),
            filename_state: AppState::SdXprvFilename,
            next_state: crate::runtime::navigation::continuation!(SdXprvExportPassphrase),
            redraw_if_exists: true,
            redraw_if_available: true,
        },
    )
}

pub(crate) fn handle_sd_xprv_export_passphrase(ctx: SdIoContext<'_, '_, '_>) -> bool {
    super::super::super::common::run_device_bound_passphrase_workflow(
        ctx,
        super::super::super::common::PassphraseWorkflow {
            back_state: crate::runtime::navigation::continuation!(SdXprvFilename),
        },
        export_xprv,
    )
}

fn export_xprv(
    ad: &mut crate::runtime::data::AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    backup_device: &mut dyn crate::services::backup::BackupDevice,
) -> Option<crate::runtime::navigation::ContinuationRoute> {
    boot_display.draw_saving_screen("Deriving xprv...");
    boot_display.update_progress_bar(15);
    boot_display.update_progress_bar(33);

    let mut password = [0u8; 128];
    let password_len = ad.wallet.seeds.pp_input.len.min(password.len());
    password[..password_len].copy_from_slice(&ad.wallet.seeds.pp_input.buf[..password_len]);
    let mut xprv = [0u8; offline_signer::derivation::xpub::XPRV_MAX_LEN];
    let result = (|| {
        let xprv_len = crate::runtime::signing::serialize_active_xprv_with_checkpoint(ad, &mut xprv, liveness)?;
        boot_display.draw_saving_screen("Encrypting...");
        boot_display.update_progress_bar(50);
        let mut encrypted = [0u8; sd_backup::MAX_XPRV_BACKUP_SIZE];
        let operation = (|| {
            let encrypted_length = sd_backup::encrypt_xprv_backup(
                &xprv[..xprv_len],
                &password[..password_len],
                backup_device,
                &mut encrypted,
            ).map_err(|error| error.message())?;
            boot_display.draw_saving_screen("Writing to SD...");
            boot_display.update_progress_bar(70);
            write_file_to_sd(
                i2c, delay, &ad.storage.export_file.filename, &encrypted[..encrypted_length],
            ).map_err(|_| "SD write failed")?;
            log!("[SD-XPRV] Wrote {} bytes", encrypted_length);
            Ok(())
        })();
        zeroize_bytes(&mut encrypted);
        operation
    })();
    zeroize_buf(&mut xprv);
    zeroize_bytes(&mut password);

    match result {
        Ok(()) => {
            show_success(boot_display, delay, "xprv Saved!", 2_500);
        }
        Err(message) => {
            show_rejection(boot_display, delay, message, 2_000, ErrorSound::Silent);
        }
    }
    if !crate::runtime::effects::return_to(
        ad,
        crate::runtime::navigation::ReturnScope::KeyExport,
    ) {
        let _ = crate::runtime::effects::route(
            ad,
            crate::runtime::navigation::route!(BackupRecoveryMenu),
        );
    }
    None
}
