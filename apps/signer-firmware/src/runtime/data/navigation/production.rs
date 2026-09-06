//! Production navigation menus and shared-screen return destinations.

use crate::runtime::input::Menu;

pub struct ProductionNavigationState {
    pub advanced_menu: Menu,
    #[cfg(feature = "provisioning-ui")]
    pub owner_firmware_menu: Menu,
    pub wallet_menu: Menu,
    pub wallet_backup_methods_menu: Menu,
    pub wallet_advanced_menu: Menu,
    pub backup_recovery_menu: Menu,
    pub restore_menu: Menu,
    pub advanced_restore_menu: Menu,
    #[cfg(feature = "developer-ui")]
    pub developer_menu: Menu,
    #[cfg(feature = "developer-ui")]
    pub network_menu: Menu,
}

impl ProductionNavigationState {
    pub(super) fn new() -> Self {
        Self {
            advanced_menu: Menu::from_items(crate::runtime::navigation::production::advanced_items()),
            #[cfg(feature = "provisioning-ui")]
            owner_firmware_menu: Menu::from_items(crate::runtime::navigation::production::OWNER_FIRMWARE_ITEMS),
            wallet_menu: Menu::from_items(crate::runtime::navigation::production::WALLET_ITEMS),
            wallet_backup_methods_menu: Menu::from_items(crate::runtime::navigation::production::WALLET_BACKUP_METHODS_ITEMS),
            wallet_advanced_menu: Menu::from_items(crate::runtime::navigation::production::WALLET_ADVANCED_ITEMS),
            backup_recovery_menu: Menu::from_items(crate::runtime::navigation::production::BACKUP_RECOVERY_ITEMS),
            restore_menu: Menu::from_items(crate::runtime::navigation::production::RESTORE_ITEMS),
            advanced_restore_menu: Menu::from_items(crate::runtime::navigation::production::ADVANCED_RESTORE_ITEMS),
            #[cfg(feature = "developer-ui")]
            developer_menu: Menu::from_items(crate::runtime::navigation::production::DEVELOPER_ITEMS),
            #[cfg(feature = "developer-ui")]
            network_menu: Menu::from_items(crate::runtime::navigation::production::NETWORK_ITEMS),
        }
    }
}
