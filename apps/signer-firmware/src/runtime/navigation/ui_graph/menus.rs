// Authoritative production menu/action inventory. Included by ../ui_graph.rs.

pub(crate) const MAIN_MENU_ITEMS: [UiMenuItemSpec; 4] = [
    ui_menu!(MainMenu, 0, "Connect", "home.connect_kassee", SeedsMenu, "seed_loaded", ConnectKasSee),
    ui_menu!(MainMenu, 1, "Scan QR", "home.scan_qr", ScanQR, "always"),
    ui_menu!(MainMenu, 2, "Wallet", "home.wallet", SeedsMenu, "always"),
    ui_menu!(MainMenu, 3, "Settings", "home.settings", SettingsMenu, "always"),
];
pub(crate) const MAIN_MENU_LABELS: [&str; 4] = [MAIN_MENU_ITEMS[0].label, MAIN_MENU_ITEMS[1].label, MAIN_MENU_ITEMS[2].label, MAIN_MENU_ITEMS[3].label];

pub(crate) const ADVANCED_MENU_BASE_ITEMS: [UiMenuItemSpec; 2] = [
    ui_menu!(AdvancedMenu, 0, "Firmware Update", "settings.advanced.firmware_update", FirmwareUpdateReady, "always"),
    ui_menu!(AdvancedMenu, 1, "Factory Reset", "settings.advanced.factory_reset", FactoryResetWarning, "always"),
];
#[cfg(feature = "provisioning-ui")]
pub(crate) const ADVANCED_MENU_PROVISIONING_ITEMS: [UiMenuItemSpec; 2] = [
    ui_menu!(AdvancedMenu, 2, "Owner Firmware", "settings.advanced.owner_firmware", OwnerFirmwareMenu, "always"),
    ui_menu!(AdvancedMenu, 3, "Pop It!", "settings.advanced.pop_it", PopItPrompt, "secure_boot_disabled"),
];
#[cfg(feature = "provisioning-ui")]
pub(crate) const ADVANCED_MENU_ITEMS: [UiMenuItemSpec; 4] = [
    ADVANCED_MENU_BASE_ITEMS[0], ADVANCED_MENU_BASE_ITEMS[1],
    ADVANCED_MENU_PROVISIONING_ITEMS[0], ADVANCED_MENU_PROVISIONING_ITEMS[1],
];
#[cfg(not(feature = "provisioning-ui"))]
pub(crate) const ADVANCED_MENU_ITEMS: [UiMenuItemSpec; 2] = ADVANCED_MENU_BASE_ITEMS;
#[cfg(feature = "provisioning-ui")]
pub(crate) const ADVANCED_MENU_LABELS: [&str; 4] = [ADVANCED_MENU_ITEMS[0].label, ADVANCED_MENU_ITEMS[1].label, ADVANCED_MENU_ITEMS[2].label, ADVANCED_MENU_ITEMS[3].label];
#[cfg(not(feature = "provisioning-ui"))]
pub(crate) const ADVANCED_MENU_LABELS: [&str; 2] = [ADVANCED_MENU_ITEMS[0].label, ADVANCED_MENU_ITEMS[1].label];

#[cfg(feature = "provisioning-ui")]
pub(crate) const OWNER_FIRMWARE_MENU_ITEMS: [UiMenuItemSpec; 2] = [
    ui_menu!(OwnerFirmwareMenu, 0, "Enroll Owner Key", "settings.owner_firmware.enroll", OwnerKeyWarning, "secure_boot_disabled"),
    ui_menu!(OwnerFirmwareMenu, 1, "Install from SD", "settings.owner_firmware.install", OwnerInstallWarning, "m5stack"),
];
#[cfg(feature = "provisioning-ui")]
pub(crate) const OWNER_FIRMWARE_MENU_LABELS: [&str; 2] = [OWNER_FIRMWARE_MENU_ITEMS[0].label, OWNER_FIRMWARE_MENU_ITEMS[1].label];

pub(crate) const SEEDS_MENU_ITEMS: [UiMenuItemSpec; 7] = [
    ui_menu!(SeedsMenu, 0, "Receive", "wallet.receive", ShowAddress, "always"),
    ui_menu!(SeedsMenu, 1, "Backup", "wallet.backup", WalletBackupMethodsMenu, "always"),
    ui_menu!(SeedsMenu, 2, "Recovery", "wallet.recovery", SdImportMenu, "always"),
    ui_menu!(SeedsMenu, 3, "Wallet Details", "wallet.details", WalletDetails, "always"),
    ui_menu!(SeedsMenu, 4, "Switch / Add Wallet", "wallet.switch_add", SeedList, "always"),
    ui_menu!(SeedsMenu, 5, "Multisig", "wallet.multisig", MultisigMenu, "always"),
    ui_menu!(SeedsMenu, 6, "Advanced", "wallet.advanced", WalletAdvancedMenu, "always"),
];
pub(crate) const SEEDS_MENU_LABELS: [&str; 7] = [SEEDS_MENU_ITEMS[0].label, SEEDS_MENU_ITEMS[1].label, SEEDS_MENU_ITEMS[2].label, SEEDS_MENU_ITEMS[3].label, SEEDS_MENU_ITEMS[4].label, SEEDS_MENU_ITEMS[5].label, SEEDS_MENU_ITEMS[6].label];

pub(crate) const WALLET_BACKUP_METHODS_MENU_ITEMS: [UiMenuItemSpec; 4] = [
    ui_menu!(WalletBackupMethodsMenu, 0, "View Words", "wallet.backup.view_words", SeedBackup, "mnemonic_wallet"),
    ui_menu!(WalletBackupMethodsMenu, 1, "SeedQR Backup", "wallet.backup.seedqr", ExportSeedQR, "mnemonic_wallet"),
    ui_menu!(WalletBackupMethodsMenu, 2, "Encrypted SD Card", "wallet.backup.sd", SdBackupWarning, "mnemonic_wallet"),
    ui_menu!(WalletBackupMethodsMenu, 3, "Advanced", "wallet.backup.advanced", BackupRecoveryMenu, "always"),
];
pub(crate) const WALLET_BACKUP_METHODS_MENU_LABELS: [&str; 4] = [WALLET_BACKUP_METHODS_MENU_ITEMS[0].label, WALLET_BACKUP_METHODS_MENU_ITEMS[1].label, WALLET_BACKUP_METHODS_MENU_ITEMS[2].label, WALLET_BACKUP_METHODS_MENU_ITEMS[3].label];

pub(crate) const WALLET_ADVANCED_MENU_ITEMS: [UiMenuItemSpec; 5] = [
    ui_menu!(WalletAdvancedMenu, 0, "BIP85 Child Wallet", "wallet.advanced.bip85", ChooseWordCount, "seed_loaded"),
    ui_menu!(WalletAdvancedMenu, 1, "BIP39 Last Word", "wallet.advanced.last_word", ChooseWordCount, "always"),
    ui_menu!(WalletAdvancedMenu, 2, "Sign Message", "wallet.advanced.sign_message", SignMsgChoice, "seed_loaded"),
    ui_menu!(WalletAdvancedMenu, 3, "Commit Secret", "wallet.advanced.commit_secret", CommitRevealType, "seed_loaded"),
    ui_menu!(WalletAdvancedMenu, 4, "Decrypt Secret", "wallet.advanced.decrypt_secret", DecryptSecretScan, "seed_loaded"),
];
pub(crate) const WALLET_ADVANCED_MENU_LABELS: [&str; 5] = [WALLET_ADVANCED_MENU_ITEMS[0].label, WALLET_ADVANCED_MENU_ITEMS[1].label, WALLET_ADVANCED_MENU_ITEMS[2].label, WALLET_ADVANCED_MENU_ITEMS[3].label, WALLET_ADVANCED_MENU_ITEMS[4].label];

pub(crate) const BACKUP_RECOVERY_MENU_ITEMS: [UiMenuItemSpec; 5] = [
    ui_menu!(BackupRecoveryMenu, 0, "Compact SeedQR", "wallet.backup.advanced.compact_seedqr", ExportCompactSeedQR, "mnemonic_wallet"),
    ui_menu!(BackupRecoveryMenu, 1, "Plain-text SeedQR", "wallet.backup.advanced.plain_seedqr", ExportPlainWordsQR, "mnemonic_wallet"),
    ui_menu!(BackupRecoveryMenu, 2, "Steganographic", "wallet.backup.advanced.stego", StegoModeSelect, "seed_loaded"),
    ui_menu!(BackupRecoveryMenu, 3, "XPrv Backup", "wallet.backup.advanced.xprv", XprvExportMenu, "seed_loaded"),
    ui_menu!(BackupRecoveryMenu, 4, "Export Key", "wallet.backup.advanced.export_key", ExportPrivKeyIndex, "seed_loaded"),
];
pub(crate) const BACKUP_RECOVERY_MENU_LABELS: [&str; 5] = [BACKUP_RECOVERY_MENU_ITEMS[0].label, BACKUP_RECOVERY_MENU_ITEMS[1].label, BACKUP_RECOVERY_MENU_ITEMS[2].label, BACKUP_RECOVERY_MENU_ITEMS[3].label, BACKUP_RECOVERY_MENU_ITEMS[4].label];

pub(crate) const STORAGE_SEED_SOURCE_CHOICE_ITEMS: [UiMenuItemSpec; 4] = [
    ui_menu!(StorageSeedSourceChoice, 0, "Words", "onboarding.restore.words", RestoreWord, "always"),
    ui_menu!(StorageSeedSourceChoice, 1, "SeedQR", "onboarding.restore.seedqr", ScanQR, "camera_available"),
    ui_menu!(StorageSeedSourceChoice, 2, "SD", "onboarding.restore.sd", SdWalletBackupFileList, "sd_present"),
    ui_menu!(StorageSeedSourceChoice, 3, "Advanced", "onboarding.restore.advanced", AdvancedRestoreMenu, "always"),
];
pub(crate) const STORAGE_SEED_SOURCE_CHOICE_LABELS: [&str; 4] = [STORAGE_SEED_SOURCE_CHOICE_ITEMS[0].label, STORAGE_SEED_SOURCE_CHOICE_ITEMS[1].label, STORAGE_SEED_SOURCE_CHOICE_ITEMS[2].label, STORAGE_SEED_SOURCE_CHOICE_ITEMS[3].label];

pub(crate) const ADVANCED_RESTORE_MENU_ITEMS: [UiMenuItemSpec; 4] = [
    ui_menu!(AdvancedRestoreMenu, 0, "Compact SeedQR", "onboarding.advanced_restore.compact_seedqr", ScanQR, "camera_available"),
    ui_menu!(AdvancedRestoreMenu, 1, "Plain-text SeedQR", "onboarding.advanced_restore.plain_seedqr", ScanQR, "camera_available"),
    ui_menu!(AdvancedRestoreMenu, 2, "Steganographic", "onboarding.advanced_restore.stego", StegoImportPick, "sd_present"),
    ui_menu!(AdvancedRestoreMenu, 3, "Raw Private Key", "onboarding.advanced_restore.raw_key", ImportPrivKey, "always"),
];
pub(crate) const ADVANCED_RESTORE_MENU_LABELS: [&str; 4] = [ADVANCED_RESTORE_MENU_ITEMS[0].label, ADVANCED_RESTORE_MENU_ITEMS[1].label, ADVANCED_RESTORE_MENU_ITEMS[2].label, ADVANCED_RESTORE_MENU_ITEMS[3].label];

pub(crate) const SETTINGS_MENU_ITEMS: [UiMenuItemSpec; 6] = [
    ui_menu!(SettingsMenu, 0, "Display", "settings.display", DisplaySettings, "always"),
    ui_menu!(SettingsMenu, 1, "Audio", "settings.audio", AudioSettings, "m5stack"),
    ui_menu!(SettingsMenu, 2, "Security", "settings.security", AdvancedFeatures, "always"),
    ui_menu!(SettingsMenu, 3, "Storage", "settings.storage", SdCardSettings, "always"),
    ui_menu!(SettingsMenu, 4, "Advanced", "settings.advanced", AdvancedMenu, "always"),
    ui_menu!(SettingsMenu, 5, "About", "settings.about", About, "always"),
];
#[cfg(all(feature = "m5stack", not(feature = "developer-ui")))]
pub(crate) const SETTINGS_MENU_LABELS: [&str; 6] = [SETTINGS_MENU_ITEMS[0].label, SETTINGS_MENU_ITEMS[1].label, SETTINGS_MENU_ITEMS[2].label, SETTINGS_MENU_ITEMS[3].label, SETTINGS_MENU_ITEMS[4].label, SETTINGS_MENU_ITEMS[5].label];

pub(crate) const SEED_TOOLS_MENU_ITEMS: [UiMenuItemSpec; 7] = [
    ui_menu!(SeedToolsMenu, 0, "New Seed", "seed_tools.new_seed", ChooseWordCount, "always"),
    ui_menu!(SeedToolsMenu, 1, "Dice Seed", "seed_tools.dice_seed", ChooseWordCount, "always"),
    ui_menu!(SeedToolsMenu, 2, "Touch Seed", "seed_tools.touch_seed", ChooseWordCount, "always"),
    ui_menu!(SeedToolsMenu, 3, "Import Words", "seed_tools.import_words", ChooseWordCount, "always"),
    ui_menu!(SeedToolsMenu, 4, "Address", "seed_tools.address", ShowAddress, "seed_loaded"),
    ui_menu!(SeedToolsMenu, 5, "BIP85 Child", "seed_tools.bip85", ChooseWordCount, "seed_loaded"),
    ui_menu!(SeedToolsMenu, 6, "Calc Last Word", "seed_tools.last_word", ChooseWordCount, "always"),
];
pub(crate) const SEED_TOOLS_MENU_LABELS: [&str; 7] = [SEED_TOOLS_MENU_ITEMS[0].label, SEED_TOOLS_MENU_ITEMS[1].label, SEED_TOOLS_MENU_ITEMS[2].label, SEED_TOOLS_MENU_ITEMS[3].label, SEED_TOOLS_MENU_ITEMS[4].label, SEED_TOOLS_MENU_ITEMS[5].label, SEED_TOOLS_MENU_ITEMS[6].label];

pub(crate) const IMPORT_MENU_ITEMS: [UiMenuItemSpec; 4] = [
    ui_menu!(ImportMenu, 0, "Import from SD", "import.sd", SdImportMenu, "always"),
    ui_menu!(ImportMenu, 1, "Stego Import", "import.stego", StegoImportPick, "sd_jpeg_available"),
    ui_menu!(ImportMenu, 2, "Import Raw Key", "import.raw_key", ImportPrivKey, "always"),
    ui_menu!(ImportMenu, 3, "Covenant Restore", "import.covenant", SdFileList, "sd_covenant_available"),
];
pub(crate) const IMPORT_MENU_LABELS: [&str; 4] = [IMPORT_MENU_ITEMS[0].label, IMPORT_MENU_ITEMS[1].label, IMPORT_MENU_ITEMS[2].label, IMPORT_MENU_ITEMS[3].label];

pub(crate) const SINGLE_SIG_MENU_ITEMS: [UiMenuItemSpec; 5] = [
    ui_menu!(SingleSigMenu, 0, "Sign TX", "signing.sign_tx", SignTxGuide, "seed_loaded"),
    ui_menu!(SingleSigMenu, 1, "Sign Message", "signing.sign_message", SignMsgChoice, "seed_loaded"),
    ui_menu!(SingleSigMenu, 2, "Covenant Sign", "signing.covenant", ScanQR, "mnemonic_wallet"),
    ui_menu!(SingleSigMenu, 3, "Commit Secret", "signing.commit_secret", CommitRevealType, "seed_loaded"),
    ui_menu!(SingleSigMenu, 4, "Decrypt Secret", "signing.decrypt_secret", DecryptSecretScan, "seed_loaded"),
];
pub(crate) const SINGLE_SIG_MENU_LABELS: [&str; 5] = [SINGLE_SIG_MENU_ITEMS[0].label, SINGLE_SIG_MENU_ITEMS[1].label, SINGLE_SIG_MENU_ITEMS[2].label, SINGLE_SIG_MENU_ITEMS[3].label, SINGLE_SIG_MENU_ITEMS[4].label];

pub(crate) const MULTISIG_MENU_ITEMS: [UiMenuItemSpec; 2] = [
    ui_menu!(MultisigMenu, 0, "Create Multisig", "multisig.create", MultisigChooseMN, "always"),
    ui_menu!(MultisigMenu, 1, "kpub Multisig QR", "multisig.kpub", MultisigMenu, "mnemonic_wallet", DeriveMultisigKpub),
];
pub(crate) const MULTISIG_MENU_LABELS: [&str; 2] = [MULTISIG_MENU_ITEMS[0].label, MULTISIG_MENU_ITEMS[1].label];

pub(crate) const EXPORT_CHOICE_ITEMS: [UiMenuItemSpec; 4] = [
    ui_menu!(ExportChoice, 0, "Seed Backup", "export.seed_backup", SeedBackupMenu, "seed_loaded"),
    ui_menu!(ExportChoice, 1, "Watch-Only", "export.watch_only", WatchOnlyMenu, "seed_loaded"),
    ui_menu!(ExportChoice, 2, "Signing Keys", "export.signing_keys", SigningKeysMenu, "seed_loaded"),
    ui_menu!(ExportChoice, 3, "Steganography", "export.stego", StegoModeSelect, "seed_loaded"),
];
pub(crate) const EXPORT_CHOICE_LABELS: [&str; 4] = [EXPORT_CHOICE_ITEMS[0].label, EXPORT_CHOICE_ITEMS[1].label, EXPORT_CHOICE_ITEMS[2].label, EXPORT_CHOICE_ITEMS[3].label];

pub(crate) const SEED_BACKUP_MENU_ITEMS: [UiMenuItemSpec; 3] = [
    ui_menu!(SeedBackupMenu, 0, "Show Seed Words", "export.seed.words", SeedBackup, "mnemonic_wallet"),
    ui_menu!(SeedBackupMenu, 1, "QR Export", "export.seed.qr", QrExportMenu, "seed_loaded"),
    ui_menu!(SeedBackupMenu, 2, "Backup to SD", "export.seed.sd", SdBackupWarning, "mnemonic_wallet"),
];
pub(crate) const SEED_BACKUP_MENU_LABELS: [&str; 3] = [SEED_BACKUP_MENU_ITEMS[0].label, SEED_BACKUP_MENU_ITEMS[1].label, SEED_BACKUP_MENU_ITEMS[2].label];

pub(crate) const WATCH_ONLY_MENU_ITEMS: [UiMenuItemSpec; 3] = [
    ui_menu!(WatchOnlyMenu, 0, "kpub as QR", "export.watch.kpub_qr", ExportKpub, "seed_loaded"),
    ui_menu!(WatchOnlyMenu, 1, "kpub to SD", "export.watch.kpub_sd", SdKpubFilename, "sd_present_and_seed_loaded"),
    ui_menu!(WatchOnlyMenu, 2, "kpub Multisig QR", "export.watch.multisig_kpub", WatchOnlyMenu, "mnemonic_wallet", DeriveMultisigKpub),
];
pub(crate) const WATCH_ONLY_MENU_LABELS: [&str; 3] = [WATCH_ONLY_MENU_ITEMS[0].label, WATCH_ONLY_MENU_ITEMS[1].label, WATCH_ONLY_MENU_ITEMS[2].label];

pub(crate) const SIGNING_KEYS_MENU_ITEMS: [UiMenuItemSpec; 2] = [
    ui_menu!(SigningKeysMenu, 0, "xprv Account", "export.keys.xprv", XprvExportMenu, "seed_loaded"),
    ui_menu!(SigningKeysMenu, 1, "Private Key", "export.keys.private", ExportPrivKeyIndex, "seed_loaded"),
];
pub(crate) const SIGNING_KEYS_MENU_LABELS: [&str; 2] = [SIGNING_KEYS_MENU_ITEMS[0].label, SIGNING_KEYS_MENU_ITEMS[1].label];

pub(crate) const QR_EXPORT_MENU_ITEMS: [UiMenuItemSpec; 3] = [
    ui_menu!(QrExportMenu, 0, "CompactSeedQR", "export.seedqr.compact", ExportCompactSeedQR, "mnemonic_wallet"),
    ui_menu!(QrExportMenu, 1, "Standard SeedQR", "export.seedqr.standard", ExportSeedQR, "mnemonic_wallet"),
    ui_menu!(QrExportMenu, 2, "Plain Text QR", "export.seedqr.plain", ExportPlainWordsQR, "mnemonic_12_words"),
];
pub(crate) const QR_EXPORT_MENU_LABELS: [&str; 3] = [QR_EXPORT_MENU_ITEMS[0].label, QR_EXPORT_MENU_ITEMS[1].label, QR_EXPORT_MENU_ITEMS[2].label];

pub(crate) const XPRV_EXPORT_MENU_ITEMS: [UiMenuItemSpec; 2] = [
    ui_menu!(XprvExportMenu, 0, "Show as QR", "export.xprv.qr", ExportXprv, "seed_loaded"),
    ui_menu!(XprvExportMenu, 1, "Encrypt to SD", "export.xprv.sd", SdXprvFilename, "sd_present_and_seed_loaded"),
];
pub(crate) const XPRV_EXPORT_MENU_LABELS: [&str; 2] = [XPRV_EXPORT_MENU_ITEMS[0].label, XPRV_EXPORT_MENU_ITEMS[1].label];

pub(crate) const SD_IMPORT_MENU_ITEMS: [UiMenuItemSpec; 7] = [
    ui_menu!(SdImportMenu, 0, "Seed / XPrv Backup", "sd.import.wallet_backup", SdWalletBackupFileList, "sd_present"),
    ui_menu!(SdImportMenu, 1, "Transaction", "sd.import.transaction", SdKsptFileList, "sd_present"),
    ui_menu!(SdImportMenu, 2, "kpub (Watch-Only)", "sd.import.kpub", SdKpubFileList, "sd_present"),
    ui_menu!(SdImportMenu, 3, "Multisig Address", "sd.import.multisig_address", SdKpubFileList, "sd_present"),
    ui_menu!(SdImportMenu, 4, "Multisig Descriptor", "sd.import.multisig_descriptor", SdKpubFileList, "sd_present"),
    ui_menu!(SdImportMenu, 5, "Covenant Restore", "sd.import.covenant", SdFileList, "sd_present"),
    ui_menu!(SdImportMenu, 6, "Import Raw Key", "recovery.import_raw_key", ImportPrivKey, "always"),
];
pub(crate) const SD_IMPORT_MENU_LABELS: [&str; 7] = [SD_IMPORT_MENU_ITEMS[0].label, SD_IMPORT_MENU_ITEMS[1].label, SD_IMPORT_MENU_ITEMS[2].label, SD_IMPORT_MENU_ITEMS[3].label, SD_IMPORT_MENU_ITEMS[4].label, SD_IMPORT_MENU_ITEMS[5].label, SD_IMPORT_MENU_ITEMS[6].label];

pub(crate) const CONFIRM_TX_ITEMS: [UiMenuItemSpec; 3] = [
    ui_menu!(ConfirmTx, 0, "Confirm", "tx.confirm", ConfirmTx, "review_complete", SignTransaction),
    ui_menu!(ConfirmTx, 1, "Cancel", "tx.cancel", Rejected, "always"),
    ui_menu!(ConfirmTx, 2, "Inspect", "tx.inspect", ReviewTx, "review_available"),
];
pub(crate) const CONFIRM_TX_LABELS: [&str; 3] = [CONFIRM_TX_ITEMS[0].label, CONFIRM_TX_ITEMS[1].label, CONFIRM_TX_ITEMS[2].label];

pub(crate) const PRODUCTION_MENUS: &[UiMenuSpec] = &[
    UiMenuSpec { state: "MainMenu", back: "-", items: &MAIN_MENU_ITEMS },
    UiMenuSpec { state: "AdvancedMenu", back: "SettingsMenu", items: &ADVANCED_MENU_ITEMS },
    #[cfg(feature = "provisioning-ui")]
    UiMenuSpec { state: "OwnerFirmwareMenu", back: "AdvancedMenu", items: &OWNER_FIRMWARE_MENU_ITEMS },
    UiMenuSpec { state: "SeedsMenu", back: "MainMenu", items: &SEEDS_MENU_ITEMS },
    UiMenuSpec { state: "WalletBackupMethodsMenu", back: "SeedsMenu", items: &WALLET_BACKUP_METHODS_MENU_ITEMS },
    UiMenuSpec { state: "WalletAdvancedMenu", back: "history", items: &WALLET_ADVANCED_MENU_ITEMS },
    UiMenuSpec { state: "BackupRecoveryMenu", back: "history", items: &BACKUP_RECOVERY_MENU_ITEMS },
    UiMenuSpec { state: "StorageSeedSourceChoice", back: "StorageModeChoice", items: &STORAGE_SEED_SOURCE_CHOICE_ITEMS },
    UiMenuSpec { state: "AdvancedRestoreMenu", back: "StorageSeedSourceChoice", items: &ADVANCED_RESTORE_MENU_ITEMS },
    UiMenuSpec { state: "SettingsMenu", back: "MainMenu", items: &SETTINGS_MENU_ITEMS },
    UiMenuSpec { state: "SeedToolsMenu", back: "SeedsMenu", items: &SEED_TOOLS_MENU_ITEMS },
    UiMenuSpec { state: "ImportMenu", back: "ImportExportChoice", items: &IMPORT_MENU_ITEMS },
    UiMenuSpec { state: "SingleSigMenu", back: "SeedsMenu", items: &SINGLE_SIG_MENU_ITEMS },
    UiMenuSpec { state: "MultisigMenu", back: "history", items: &MULTISIG_MENU_ITEMS },
    UiMenuSpec { state: "ExportChoice", back: "SeedList", items: &EXPORT_CHOICE_ITEMS },
    UiMenuSpec { state: "SeedBackupMenu", back: "ExportChoice", items: &SEED_BACKUP_MENU_ITEMS },
    UiMenuSpec { state: "WatchOnlyMenu", back: "ExportChoice", items: &WATCH_ONLY_MENU_ITEMS },
    UiMenuSpec { state: "SigningKeysMenu", back: "ExportChoice", items: &SIGNING_KEYS_MENU_ITEMS },
    UiMenuSpec { state: "QrExportMenu", back: "SeedBackupMenu", items: &QR_EXPORT_MENU_ITEMS },
    UiMenuSpec { state: "XprvExportMenu", back: "history", items: &XPRV_EXPORT_MENU_ITEMS },
    UiMenuSpec { state: "SdImportMenu", back: "history", items: &SD_IMPORT_MENU_ITEMS },
    UiMenuSpec { state: "ConfirmTx", back: "ReviewTx", items: &CONFIRM_TX_ITEMS },
];

pub(crate) const WALLET_MENU_LABELS: &[&str] = &SEEDS_MENU_LABELS;
pub(crate) const WALLET_BACKUP_METHODS_LABELS: &[&str] = &WALLET_BACKUP_METHODS_MENU_LABELS;
pub(crate) const WALLET_ADVANCED_LABELS: &[&str] = &WALLET_ADVANCED_MENU_LABELS;
pub(crate) const BACKUP_RECOVERY_LABELS: &[&str] = &BACKUP_RECOVERY_MENU_LABELS;
pub(crate) const RESTORE_LABELS: &[&str] = &STORAGE_SEED_SOURCE_CHOICE_LABELS;
pub(crate) const ADVANCED_RESTORE_LABELS: &[&str] = &ADVANCED_RESTORE_MENU_LABELS;
#[cfg(all(feature = "m5stack", not(feature = "developer-ui")))]
pub(crate) const M5STACK_SETTINGS_LABELS: &[&str] = &SETTINGS_MENU_LABELS;
pub(crate) const SEED_TOOLS_LABELS: &[&str] = &SEED_TOOLS_MENU_LABELS;
pub(crate) const IMPORT_LABELS: &[&str] = &IMPORT_MENU_LABELS;
pub(crate) const SINGLE_SIG_LABELS: &[&str] = &SINGLE_SIG_MENU_LABELS;
pub(crate) const MULTISIG_LABELS: &[&str] = &MULTISIG_MENU_LABELS;
pub(crate) const EXPORT_LABELS: &[&str] = &EXPORT_CHOICE_LABELS;
pub(crate) const SEED_BACKUP_LABELS: &[&str] = &SEED_BACKUP_MENU_LABELS;
pub(crate) const WATCH_ONLY_LABELS: &[&str] = &WATCH_ONLY_MENU_LABELS;
pub(crate) const SIGNING_KEYS_LABELS: &[&str] = &SIGNING_KEYS_MENU_LABELS;
pub(crate) const QR_EXPORT_LABELS: &[&str] = &QR_EXPORT_MENU_LABELS;
pub(crate) const XPRV_EXPORT_LABELS: &[&str] = &XPRV_EXPORT_MENU_LABELS;
pub(crate) const SD_IMPORT_LABELS: &[&str] = &SD_IMPORT_MENU_LABELS;

