//! Device-bound mnemonic backup export workflow.

use crate::{
    runtime::interactions::feedback::{show_rejection, show_success, ErrorSound},
    runtime::input::AppState,
};
use shared_signer::{bytes::zeroize_bytes, bytes::zeroize_u16};

use super::super::{
    format_auto_name, run_filename_workflow, scan_auto_increment, sd_backup,
    write_file_to_sd, FilenameWorkflow,
};
use super::super::common::context::SdIoContext;

pub(crate) fn handle_seed_backup_warning(ctx: SdIoContext<'_, '_, '_>) -> bool {
    if ctx.is_back {
        crate::runtime::effects::return_to(ctx.ad, crate::runtime::navigation::ReturnScope::SeedBackup);
        return true;
    }
    if crate::ui::layout::MODAL_RIGHT_BUTTON_ZONE.contains(ctx.x, ctx.y) {
        crate::runtime::effects::return_to(
            ctx.ad,
            crate::runtime::navigation::ReturnScope::SeedBackup,
        );
        return true;
    }
    if !crate::ui::layout::MODAL_LEFT_BUTTON_ZONE.contains(ctx.x, ctx.y) {
        return false;
    }
    if ctx.sd_card_type.is_none() {
        show_rejection(ctx.boot_display, ctx.delay, "No SD card detected", 2_000, ErrorSound::Silent);
        return true;
    }
    let next = scan_auto_increment(ctx.i2c, ctx.delay, b"SD", b"KAS");
    prepare_seed_backup_filename(ctx.ad, next);
    true
}

fn prepare_seed_backup_filename(ad: &mut crate::runtime::data::AppData, next: u32) {
    let name = format_auto_name(b"SD", next, b"KAS");
    ad.wallet.seeds.pp_input.reset();
    for byte in name[..8].iter().copied().take_while(|byte| *byte != b' ') {
        ad.wallet.seeds.pp_input.push_char(byte);
    }
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SdSeedFilename));
}

#[cfg(all(feature = "workflow-test-auto", not(feature = "workflow-hil-auto")))]
pub(crate) fn workflow_prepare_seed_backup_filename(
    ad: &mut crate::runtime::data::AppData,
) -> bool {
    if ad.navigation.app.state != AppState::SdBackupWarning {
        return false;
    }
    // Controller E2E validates the media-present transition without probing a
    // removable card. The physical filename scan belongs to workflow-hil.
    prepare_seed_backup_filename(ad, 0);
    ad.navigation.app.state == AppState::SdSeedFilename
        && crate::runtime::navigation::reconcile(ad)
}

pub(crate) fn handle_seed_backup_filename(ctx: SdIoContext<'_, '_, '_>) -> bool {
    let back_state = crate::runtime::navigation::continuation_from_state(
        crate::runtime::navigation::return_target(
            ctx.ad, crate::runtime::navigation::ReturnScope::SeedBackup,
        ).unwrap_or(AppState::SeedBackupMenu),
    );
    run_filename_workflow(
        ctx,
        FilenameWorkflow {
            extension: *b"KAS",
            back_state,
            filename_state: AppState::SdSeedFilename,
            next_state: crate::runtime::navigation::continuation!(SdSeedExportPassphrase),
            redraw_if_exists: true,
            redraw_if_available: true,
        },
    )
}

pub(crate) fn handle_seed_backup_export_passphrase(ctx: SdIoContext<'_, '_, '_>) -> bool {
    super::super::common::run_device_bound_passphrase_workflow(
        ctx,
        super::super::common::PassphraseWorkflow { back_state: crate::runtime::navigation::continuation!(SdSeedFilename) },
        export_seed,
    )
}

fn export_seed(
    ad: &mut crate::runtime::data::AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    backup_device: &mut dyn crate::services::backup::BackupDevice,
) -> Option<crate::runtime::navigation::ContinuationRoute> {
    let Some(slot) = ad.wallet.seeds.seed_mgr.active_slot() else {
        show_rejection(boot_display, delay, "No active seed", 2_000, ErrorSound::Silent);
        return Some(crate::runtime::navigation::continuation!(SeedBackupMenu));
    };
    let Some(word_count) = slot.mnemonic_word_count() else {
        show_rejection(boot_display, delay, "No seed phrase (xprv)", 2_000, ErrorSound::Silent);
        return Some(crate::runtime::navigation::continuation!(SeedBackupMenu));
    };
    let mut indices = slot.indices;
    let mut password = [0u8; 128];
    let password_len = ad.wallet.seeds.pp_input.len.min(password.len());
    password[..password_len].copy_from_slice(&ad.wallet.seeds.pp_input.buf[..password_len]);

    liveness();
    boot_display.draw_saving_screen("Encrypting seed...");
    let mut encrypted = [0u8; sd_backup::MAX_BACKUP_SIZE];
    let result = (|| {
        let encrypted_len = sd_backup::encrypt_backup_progress(
            &indices,
            word_count,
            &password[..password_len],
            backup_device,
            &mut encrypted,
        ).map_err(|error| error.message())?;
        liveness();
        boot_display.update_progress_bar(70);
        write_file_to_sd(i2c, delay, &ad.storage.export_file.filename, &encrypted[..encrypted_len])
            .map_err(|_| "SD write failed")?;
        Ok(())
    })();
    zeroize_bytes(&mut encrypted);
    zeroize_bytes(&mut password);
    zeroize_u16(&mut indices);

    match result {
        Ok(()) => show_success(boot_display, delay, "Seed backup saved!", 2_500),
        Err(message) => show_rejection(boot_display, delay, message, 2_500, ErrorSound::Silent),
    }
    if !crate::runtime::effects::return_to(
        ad,
        crate::runtime::navigation::ReturnScope::SeedBackup,
    ) {
        let _ = crate::runtime::effects::route(
            ad,
            crate::runtime::navigation::route!(WalletBackupMethodsMenu),
        );
    }
    None
}
