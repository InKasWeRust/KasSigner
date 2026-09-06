//! Production information architecture and user-facing labels.
//!
//! Stage 1 sources the M5Stack production menu surface from `ui_graph` so the
//! runtime, generated documentation, and E2E inventory cannot maintain
//! independent label lists. Protocol names stay below Scan QR; top-level
//! navigation remains expressed in user goals.

use super::ui_graph;

pub(crate) const HOME_LABELS: [&str; 4] = ui_graph::MAIN_MENU_LABELS;
pub(crate) const WALLET_ITEMS: &[&str] = ui_graph::WALLET_MENU_LABELS;
#[cfg(feature = "provisioning-ui")]
pub(crate) const OWNER_FIRMWARE_ITEMS: &[&str] = &ui_graph::OWNER_FIRMWARE_MENU_LABELS;
pub(crate) const WALLET_BACKUP_METHODS_ITEMS: &[&str] = ui_graph::WALLET_BACKUP_METHODS_LABELS;
pub(crate) const WALLET_ADVANCED_ITEMS: &[&str] = ui_graph::WALLET_ADVANCED_LABELS;
pub(crate) const BACKUP_RECOVERY_ITEMS: &[&str] = ui_graph::BACKUP_RECOVERY_LABELS;
pub(crate) const RESTORE_ITEMS: &[&str] = ui_graph::RESTORE_LABELS;
pub(crate) const ADVANCED_RESTORE_ITEMS: &[&str] = ui_graph::ADVANCED_RESTORE_LABELS;

#[cfg(feature = "provisioning-ui")]
pub(crate) fn pop_it_available() -> bool {
    #[cfg(all(feature = "provisioning-ui", feature = "m5stack", feature = "secure-provisioning-core"))]
    {
        return !crate::services::verify::boot_security::secure_boot_enabled();
    }
    #[cfg(all(feature = "provisioning-ui", feature = "m5stack", not(feature = "production")))]
    {
        return !crate::services::verify::boot_security::secure_boot_enabled()
            && !crate::services::verify::boot_security::dev_pop_it_indicator_demo_active();
    }
    #[cfg(not(any(
        all(feature = "provisioning-ui", feature = "m5stack", feature = "secure-provisioning-core"),
        all(feature = "provisioning-ui", feature = "m5stack", not(feature = "production"))
    )))]
    false
}

#[cfg(all(feature = "m5stack", feature = "provisioning-ui"))]
pub(crate) fn advanced_items() -> &'static [&'static str] {
    ui_graph::advanced_labels(pop_it_available())
}

#[cfg(not(all(feature = "m5stack", feature = "provisioning-ui")))]
pub(crate) fn advanced_items() -> &'static [&'static str] {
    &ui_graph::ADVANCED_MENU_LABELS[..2]
}

#[cfg(all(feature = "m5stack", not(feature = "developer-ui")))]
pub(crate) const SETTINGS_ITEMS: &[&str] = ui_graph::M5STACK_SETTINGS_LABELS;
#[cfg(all(feature = "m5stack", feature = "developer-ui"))]
pub(crate) const SETTINGS_ITEMS: &[&str] =
    &["Display", "Audio", "Security", "Storage", "Advanced", "About", "Developer"];
#[cfg(all(feature = "waveshare", not(feature = "developer-ui")))]
pub(crate) const SETTINGS_ITEMS: &[&str] =
    &["Display", "Camera", "Security", "Storage", "Advanced", "About"];
#[cfg(all(feature = "waveshare", feature = "developer-ui"))]
pub(crate) const SETTINGS_ITEMS: &[&str] =
    &["Display", "Camera", "Security", "Storage", "Advanced", "About", "Developer"];
#[cfg(feature = "qemu")]
pub(crate) const SETTINGS_ITEMS: &[&str] = &["Security", "Advanced", "About"];

#[cfg(feature = "developer-ui")]
pub(crate) const DEVELOPER_ITEMS: &[&str] = &[
    #[cfg(feature = "workflow-tests")]
    "Workflow Tests",
    #[cfg(feature = "argon2-bench")]
    "Argon2 Bench",
    "Diagnostic Info",
    "Network",
];

#[cfg(feature = "developer-ui")]
pub(crate) const NETWORK_ITEMS: &[&str] = &["Mainnet", "Testnet-12", "Testnet-10"];
