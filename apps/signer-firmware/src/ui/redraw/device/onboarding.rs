use crate::{hw::display, runtime::{data::AppData, input::AppState}};

pub(super) fn redraw(ad: &mut AppData, boot_display: &mut display::BootDisplay<'_>) -> bool {
    match ad.navigation.app.state {
        AppState::StorageModeChoice => boot_display.draw_storage_mode_choice(),
        AppState::AddWalletChoice => boot_display.draw_add_wallet_choice(),
        AppState::StorageSeedSourceChoice => boot_display.update_menu_content("RESTORE WALLET", &ad.navigation.production.restore_menu),
        AppState::AdvancedRestoreMenu => boot_display.update_menu_content("ADVANCED RESTORE", &ad.navigation.production.advanced_restore_menu),
        AppState::RestoreWord12Detected => boot_display.draw_restore_word_12_detected(),
        AppState::StorageFinalizeChoice => boot_display.draw_storage_finalize_choice(),
        AppState::SeedEntropyUnavailable { .. } | AppState::StorageSeedDiceChoice
        | AppState::StorageSeedDiceCountChoice | AppState::StorageSeedTouchChoice
        | AppState::StorageSeedWordCountChoice { .. } => redraw_seed_setup(ad.navigation.app.state, boot_display),
        AppState::StorageRecoveryAcknowledgement => boot_display.draw_storage_recovery_acknowledgement(),
        AppState::StorageProtectionChoice => boot_display.draw_storage_protection_choice(),
        AppState::StorageCredentialType => boot_display.draw_storage_credential_type(),
        _ => return false,
    }
    true
}

fn redraw_seed_setup(state: AppState, boot_display: &mut display::BootDisplay<'_>) {
    match state {
        AppState::SeedEntropyUnavailable { .. } => boot_display.draw_camera_entropy_recovery(),
        AppState::StorageSeedDiceChoice => boot_display.draw_storage_seed_dice_choice(),
        AppState::StorageSeedDiceCountChoice => boot_display.draw_storage_seed_dice_count_choice(),
        AppState::StorageSeedTouchChoice => boot_display.draw_storage_seed_touch_choice(),
        AppState::StorageSeedWordCountChoice { .. } => boot_display.draw_storage_seed_word_count_screen(),
        _ => {}
    }
}
