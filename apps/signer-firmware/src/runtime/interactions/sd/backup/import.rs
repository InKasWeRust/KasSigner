//! Unified current-format device-bound seed/XPrv backup import.

use crate::{
    runtime::interactions::feedback::{show_rejection, ErrorSound},
    runtime::{input::AppState, navigation::ContinuationRoute},
};
use shared_signer::{bytes::zeroize_bytes, bytes::zeroize_u16};

use super::super::{sd_backup, sdcard, FileListWorkflow, run_sd_list_context};
use super::super::common::context::{SdIoContext, SdListContext};

pub(crate) fn handle_wallet_backup_file_list(context: SdListContext<'_>) -> bool {
    let back_state = crate::runtime::navigation::continuation_from_state(
        context.ad.navigation.history.peek().unwrap_or(AppState::SdImportMenu),
    );
    run_sd_list_context(
        context,
        FileListWorkflow {
            allow_delete: false,
            current_state: AppState::SdWalletBackupFileList,
            back_state,
        },
        |ad| {
            ad.wallet.seeds.pp_input.reset();
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SdWalletBackupImportPassphrase));
        },
    )
}

pub(crate) fn handle_wallet_backup_import_passphrase(ctx: SdIoContext<'_, '_, '_>) -> bool {
    super::super::common::run_device_bound_passphrase_workflow(
        ctx,
        super::super::common::PassphraseWorkflow { back_state: crate::runtime::navigation::continuation!(SdWalletBackupFileList) },
        import_selected,
    )
}

fn import_selected(
    ad: &mut crate::runtime::data::AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    backup_device: &mut dyn crate::services::backup::BackupDevice,
) -> Option<ContinuationRoute> {
    liveness();
    boot_display.draw_loading_screen("Reading backup...");
    let mut encrypted = [0u8; 256];
    let read = read_selected(ad, i2c, delay, &mut encrypted);
    let Ok(length) = read else {
        zeroize_bytes(&mut encrypted);
        show_rejection(boot_display, delay, "Backup read failed", 2_000, ErrorSound::Silent);
        return Some(crate::runtime::navigation::continuation!(SdWalletBackupFileList));
    };

    let mut password = [0u8; 128];
    let password_len = ad.wallet.seeds.pp_input.len.min(password.len());
    password[..password_len].copy_from_slice(&ad.wallet.seeds.pp_input.buf[..password_len]);
    boot_display.draw_loading_screen("Authenticating...");

    liveness();
    let next = match sd_backup::backup_kind(&encrypted[..length]) {
        Ok(sd_backup::BackupKind::Seed) => import_seed(
            ad, &encrypted[..length], &password[..password_len], backup_device,
        ),
        Ok(sd_backup::BackupKind::Xprv) => import_xprv(
            ad, boot_display, &encrypted[..length], &password[..password_len], backup_device,
        ),
        Err(error) => Err(error.message()),
    };
    liveness();
    zeroize_bytes(&mut password);
    zeroize_bytes(&mut encrypted);

    match next {
        Ok(state) => Some(state),
        Err(message) => {
            show_rejection(boot_display, delay, message, 2_500, ErrorSound::Silent);
            Some(crate::runtime::navigation::continuation!(SdWalletBackupFileList))
        }
    }
}

fn import_seed(
    ad: &mut crate::runtime::data::AppData,
    input: &[u8],
    password: &[u8],
    backup_device: &mut dyn crate::services::backup::BackupDevice,
) -> Result<ContinuationRoute, &'static str> {
    let mut indices = [0u16; 24];
    let result = (|| {
        let word_count = sd_backup::decrypt_backup_progress(
            input, password, backup_device, &mut indices,
        ).map_err(|error| error.message())?;
        ad.wallet.seeds.mnemonic_indices = indices;
        ad.wallet.seeds.word_count = word_count;
        ad.wallet.seeds.pp_input.reset();
        // The encrypted backup contains the mnemonic only, matching the original
        // feature. The user now enters the optional BIP39 passphrase through the
        // normal centralized wallet-source installation path.
        Ok(crate::runtime::navigation::continuation!(PassphraseChoice))
    })();
    zeroize_u16(&mut indices);
    result
}

fn import_xprv(
    ad: &mut crate::runtime::data::AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    input: &[u8],
    password: &[u8],
    backup_device: &mut dyn crate::services::backup::BackupDevice,
) -> Result<ContinuationRoute, &'static str> {
    let mut xprv = [0u8; sd_backup::MAX_XPRV_DATA];
    let result = (|| {
        let length = sd_backup::decrypt_xprv_backup_progress(
            input, password, backup_device, &mut xprv,
        ).map_err(|error| error.message())?;
        let imported = offline_signer::derivation::xpub::import_xprv_with_metadata(&xprv[..length])
            .map_err(|_| "Invalid xprv backup")?;
        boot_display.draw_loading_screen("Deriving addresses...");
        if ad.wallet.seeds.pending_add_wallet_is_restore() {
            let slot = crate::services::wallet_session::install_account_xprv_transient(ad, imported)?;
            let reserved = usize::from(ad.wallet.seeds.pending_add_wallet_slot);
            if slot != reserved {
                ad.wallet.seeds.seed_mgr.delete(slot);
                let _ = crate::services::wallet_session::restore_persistent_active_wallet(ad);
                return Err("Wallet creation failed");
            }
            ad.wallet.seeds.mark_pending_add_wallet_installed();
            ad.wallet.seeds.pp_input.reset();
            Ok(crate::runtime::navigation::continuation!(WalletNameEntry { purpose: 3 }))
        } else {
            crate::services::wallet_session::install_account_xprv(ad, imported)?;
            Ok(crate::runtime::navigation::continuation!(SeedList))
        }
    })();
    zeroize_bytes(&mut xprv);
    result
}

fn read_selected(
    ad: &crate::runtime::data::AppData,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    delay: &mut esp_hal::delay::Delay,
    out: &mut [u8; 256],
) -> Result<usize, &'static str> {
    let filename = ad.storage.browser.selected_file;
    sdcard::with_sd_card!(i2c, delay, |card| {
        let fat32 = sdcard::mount_fat32(card)?;
        let (entry, _, _) = sdcard::find_file_in_root(card, &fat32, &filename)?;
        if entry.file_size as usize > crate::services::backup::MAX_XPRV_BACKUP_SIZE {
            return Err("Backup too large");
        }
        sdcard::read_file(card, &fat32, &entry, out)
    })
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_import_backup_payload(
    ad: &mut crate::runtime::data::AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    payload: &[u8],
    password: &[u8],
    backup_device: &mut dyn crate::services::backup::BackupDevice,
) -> Result<ContinuationRoute, &'static str> {
    match sd_backup::backup_kind(payload) {
        Ok(sd_backup::BackupKind::Seed) => import_seed(ad, payload, password, backup_device),
        Ok(sd_backup::BackupKind::Xprv) => import_xprv(ad, boot_display, payload, password, backup_device),
        Err(error) => Err(error.message()),
    }
}
