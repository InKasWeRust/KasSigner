//! Production intent-menu redraws.

use super::display;
use crate::runtime::{data::AppData, input::AppState};

pub(super) fn redraw(ad: &mut AppData, boot_display: &mut display::BootDisplay<'_>) -> bool {
    match ad.navigation.app.state {
        AppState::SeedsMenu => boot_display.update_menu_content("WALLET", &ad.navigation.production.wallet_menu),
        AppState::WalletBackupMethodsMenu => boot_display.update_menu_content("BACKUP", &ad.navigation.production.wallet_backup_methods_menu),
        AppState::WalletAdvancedMenu => boot_display.update_menu_content("WALLET ADVANCED", &ad.navigation.production.wallet_advanced_menu),
        AppState::WalletDetails => boot_display.draw_wallet_details(ad),
        AppState::AdvancedMenu => boot_display.update_menu_content("ADVANCED", &ad.navigation.production.advanced_menu),
        #[cfg(feature = "provisioning-ui")]
        AppState::OwnerFirmwareMenu => boot_display.update_menu_content("OWNER FIRMWARE", &ad.navigation.production.owner_firmware_menu),
        AppState::BackupRecoveryMenu => boot_display.update_menu_content("ADVANCED BACKUP", &ad.navigation.production.backup_recovery_menu),
        #[cfg(feature = "developer-ui")]
        AppState::DeveloperMenu => boot_display.update_menu_content("DEVELOPER", &ad.navigation.production.developer_menu),
        #[cfg(feature = "developer-ui")]
        AppState::NetworkMenu => {
            let title = match ad.wallet.seeds.seed_mgr.network() {
                crate::wallet::seed_manager::WalletNetwork::Mainnet => "NETWORK Main",
                crate::wallet::seed_manager::WalletNetwork::Testnet10 => "NETWORK Test-10",
                crate::wallet::seed_manager::WalletNetwork::Testnet12 => "NETWORK Test-12",
            };
            boot_display.update_menu_content(title, &ad.navigation.production.network_menu);
        },
        _ => return false,
    }
    true
}
