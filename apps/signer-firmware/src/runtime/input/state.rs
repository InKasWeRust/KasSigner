// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0
//! Application navigation state and stable menu labels.
/// Main menu items sourced from the authoritative production UI graph.
pub const MAIN_MENU_ITEMS: &[&str] =
    &crate::runtime::navigation::ui_graph::MAIN_MENU_LABELS;
/// Confirm menu (used in TX review confirm page), also graph-owned.
pub const CONFIRM_MENU_ITEMS: &[&str] =
    &crate::runtime::navigation::ui_graph::CONFIRM_TX_LABELS;
/// Main application states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppState {
    StorageModeChoice, // Welcome: Create Wallet / Restore Wallet.
    StorageSeedSourceChoice, // Restore Wallet source choice.
    StorageSeedDiceChoice, // Optional additive dice after mandatory hardware/camera.
    StorageSeedDiceCountChoice,
    StorageSeedTouchChoice, // Optional additive touch after the dice decision.
    StorageSeedWordCountChoice { action: u8 },
    SeedEntropyUnavailable { word_count: u8 },
    AdvancedRestoreMenu,
    RestoreWord { word_idx: u8 },
    RestoreWord12Detected,
    StorageRecoveryAcknowledgement,
    StorageFinalizeChoice,
    StorageProtectionChoice, // User credential or device-only encrypted persistence.
    StorageCredentialType, // Credential class for encrypted persistence.
    StoragePinEntry,
    StoragePinConfirm,
    StoragePasswordEntry,
    StoragePasswordConfirm,
    StorageUnlockPin,
    StorageUnlockPassword,
    /// Fail-closed state when configured SD persistence cannot be trusted.
    StorageSdFailure,
    /// Main menu (2x2 grid: Connect, Scan QR, Wallet, Settings)
    MainMenu,
    /// Scan QR: waiting for camera/QR input
    ScanQR,
    SeedsMenu,
    /// Common wallet backup methods after Backup / Recovery split.
    WalletBackupMethodsMenu,
    WalletDetails,
    /// Seed backup (show words)
    SeedBackup { word_idx: u8 },
    SeedToolsMenu,
    /// Import/Export choice (2-button screen)
    ImportExportChoice,
    ImportMenu,
    SingleSigMenu,
    MultisigMenu,
    /// Production Settings and intent-based advanced menus.
    SettingsMenu,
    /// Secure-provisioning states. Normal production has no routes or handlers
    /// that can enter these states; development simulation and the dedicated
    /// secure-provisioning feature own the corresponding UI/logic modules.
    #[cfg(feature = "provisioning-ui")]
    PopItPrompt,
    #[cfg(feature = "provisioning-ui")]
    PopItExplain,
    #[cfg(feature = "provisioning-ui")]
    PopItConfirm,
    #[cfg(feature = "provisioning-ui")]
    OwnerFirmwareMenu,
    #[cfg(feature = "provisioning-ui")]
    OwnerKeyWarning,
    #[cfg(feature = "provisioning-ui")]
    OwnerKeyConfirm,
    #[cfg(feature = "provisioning-ui")]
    OwnerInstallWarning,
    #[cfg(feature = "provisioning-ui")]
    OwnerInstallConfirm,
    AdvancedMenu,
    /// USB-host firmware upgrade guidance; never opens the camera scanner.
    FirmwareUpdateReady,
    /// Irreversible full-user-data erase warning and final confirmation.
    FactoryResetWarning,
    FactoryResetConfirm,
    WalletAdvancedMenu,
    BackupRecoveryMenu,
    #[cfg(feature = "developer-ui")]
    DeveloperMenu,
    #[cfg(feature = "developer-ui")]
    NetworkMenu,
    #[cfg(feature = "developer-ui")]
    DiagnosticInfo,
    #[cfg(feature = "workflow-tests")]
    WorkflowTestsMenu,
    #[cfg(feature = "workflow-tests")]
    WorkflowTestsCategory { category: u8 },
    #[cfg(feature = "workflow-tests")]
    WorkflowTestsResult,
    /// Display settings (brightness)
    DisplaySettings,
    /// Camera settings (cam-tune: AEC, contrast, brightness, AGC, sharpness).
    /// Runs the camera live with the cam-tune overlay for on-the-fly tuning.
    /// Waveshare-only: OV5640 fixed-focus close-range LCD QR decode needs
    /// tuning. M5Stack GC0308 works well at defaults and doesn't expose
    /// this screen.
    #[cfg(feature = "waveshare")]
    CameraSettings,
    /// Audio settings (volume) — M5Stack only (Waveshare has no speaker)
    #[cfg(feature = "m5stack")]
    AudioSettings,
    /// SD Card settings (format, info)
    SdCardSettings,
    SdCardUnlockPassword,
    /// Advanced irreversible security policy overview.
    AdvancedFeatures,
    /// Full-screen permanent warning before duress credential setup.
    AdvancedDuressWarning,
    AdvancedDuressEntry,
    AdvancedDuressConfirm,
    /// Permanent migration of encrypted persistent wallet state to SD.
    AdvancedSdStorageWarning,
    /// M5Stack RTC setup and irreversible transaction-time policies.
    #[cfg(feature = "m5stack")]
    AdvancedRtcEntry,
    #[cfg(feature = "m5stack")]
    AdvancedTimeLockWarning,
    #[cfg(feature = "m5stack")]
    AdvancedTimeLockEntry,
    #[cfg(feature = "m5stack")]
    AdvancedTimeLockConfirm,
    #[cfg(feature = "m5stack")]
    AdvancedWeeklyWarning,
    #[cfg(feature = "m5stack")]
    AdvancedWeeklyEntry,
    #[cfg(feature = "m5stack")]
    AdvancedWeeklyConfirm,
    /// About screen
    About,
    /// Reviewing a transaction (page by page)
    ReviewTx { page: u8 },
    /// Advanced inspection summary for the inputs actually present in the transaction.
    InspectUtxoSummary,
    /// Two-page inspection of one transaction input: outpoint/amount, then source address.
    InspectUtxo { index: usize, address_page: bool },
    /// Confirm page with OK/Cancel selection
    ConfirmTx,
    /// Sign TX guide — step-by-step instructions before scanning KSPT
    SignTxGuide,
    /// Guided anti-klepto handoff after the signer commitment is scanned by KasSee.
    AntiKleptoRevealGuide,
    SignMsgChoice,
    SignMsgType,
    SignMsgScan,
    SignMsgFile,
    SignMsgPreview,
    SignMsgResult,
    SignMsgResultQr,
    CovenantSignReview,
    CovenantSignOpaqueWarning,
    CovenantSignOpaqueConfirm,
    CovenantKeyResult,
    CovenantKeyResultQr,
    CovenantSignResult,
    CovenantSignResultQr,
    PrivateSwapReview,
    PrivateSwapKeyResult,
    PrivateSwapKeyResultQr,
    PrivateSwapResult,
    PrivateSwapResultQr,
    CommitRevealType,
    CommitRevealPreview,
    /// Commit-Reveal — show result (hash + encrypted ciphertext QR)
    CommitRevealResult,
    /// Commit-Reveal — fullscreen QR of hash + ciphertext
    CommitRevealResultQr,
    /// Decrypt Secret — scanning ciphertext QR from KasSee
    DecryptSecretScan,
    /// Decrypt Secret — show decrypted plaintext + export preimage hex QR
    DecryptSecretResult,
    /// Decrypt Secret — fullscreen QR of preimage hex
    DecryptSecretResultQr,
    /// Showing signed QR code
    ShowQR,
    /// Transaction was rejected
    Rejected,
    /// Show address screen
    ShowAddress,
    /// Dice roll entropy collection
    DiceRoll,
    /// Touchscreen movement/timing entropy collection
    TouchEntropy,
    ShowAddressQR,
    ImportWord { word_idx: u8, word_count: u8 },
    CalcLastWord { word_idx: u8, word_count: u8 },
    ChooseWordCount { action: u8 },
    PassphraseChoice, // Explicit optional BIP39 passphrase decision.
    PassphraseEntry,
    ExportSeedQR,
    /// QR Export sub-menu (Compact, Standard, Plain Words)
    QrExportMenu,
    /// xprv export submenu: current-format QR export only
    XprvExportMenu,
    /// Recovery-word submenu: Show Words / QR Export
    SeedBackupMenu,
    /// Watch-Only submenu: kpub as QR / kpub to SD
    WatchOnlyMenu,
    /// Signing Keys submenu: xprv Account / Private Key
    SigningKeysMenu,
    /// Export plain BIP39 words as text QR code
    ExportPlainWordsQR,
    /// Export the account-level key as one compact binary QR.
    ExportKpub,
    /// kpub export popup: Save to SD / Back to QR (after showing kpub QR)
    ExportKpubPopup,
    /// kpub scanned popup: Show QR / Save to SD
    KpubScannedPopup,
    SeedList,
    AddWalletChoice,
    WalletNameEntry { purpose: u8 },
    ConfirmDeleteSeed,
    Bip85Index { word_count: u8 },
    Bip85ShowWord { word_idx: u8, word_count: u8 },
    AddrIndexPicker,
    /// Import raw private key via hex keypad
    ImportPrivKey,
    /// Export private key as hex (show on screen / QR)
    ExportPrivKey,
    ExportPrivKeyIndex,
    ExportChoice,
    ExportXprv,
    ExportCompactSeedQR,
    SeedQrGrid { pan_x: u8, pan_y: u8, compact: bool },
    /// SD import: generic file list for supported non-wallet backup artifacts
    SdFileList,
    /// SD file browser: confirm deletion of selected file
    SdDeleteConfirm,
    /// Device-bound seed backup warning and export flow.
    SdBackupWarning,
    SdSeedFilename,
    SdSeedExportPassphrase,
    /// SD xprv export: enter passphrase for encryption
    SdXprvExportPassphrase,
    /// SD wallet-secret import: list current device-bound .KAS files.
    SdWalletBackupFileList,
    /// SD wallet-secret import: enter password and dispatch authenticated purpose.
    SdWalletBackupImportPassphrase,
    /// Multisig: choose M-of-N
    MultisigChooseMN,
    /// Multisig: pick which seed to use for this key
    MultisigPickSeed { key_idx: u8 },
    /// Multisig: scan/add pubkey (which key index 0..N-1 we're collecting)
    MultisigAddKey { key_idx: u8 },
    /// Multisig: show the created multisig address as QR
    MultisigShowAddress,
    /// Multisig: show QR of multisig address
    MultisigShowAddressQR,
    /// Multisig: show wallet descriptor text (multi(M, pk1, pk2, ...))
    MultisigDescriptor,
    /// Multisig: show QR of wallet descriptor
    /// JPEG steganography: choose Descriptor or Picture carrier.
    StegoModeSelect,
    /// JPEG steganography: choose device-bound or portable security.
    StegoSecuritySelect,
    /// JPEG steganography: export result.
    StegoResult,
    StegoJpegPick,
    StegoJpegDescChoice,
    StegoJpegDescFile,
    StegoJpegDesc,
    StegoJpegDescPreview,
    StegoJpegPpAsk,
    StegoJpegPpInfo,
    StegoJpegPpEntry,
    StegoPortablePassword,
    StegoPortablePasswordConfirm,
    StegoJpegConfirm,
    /// Stego import: pick JPEG file from SD
    StegoImportPick,
    /// Stego import: choose how to enter descriptor (type / load from SD)
    StegoImportDescChoice,
    /// Stego import: pick .TXT file from SD for descriptor
    StegoImportDescFile,
    /// Stego import: enter the image descriptor.
    StegoImportPass,
    /// Stego import: portable backup password after device-bound auto-detect fails.
    StegoImportPortablePassword,
    /// Stego import: hint revealed, tap to continue to passphrase entry
    StegoHintReveal,
    /// Stego import: enter passphrase after seeing hint
    StegoHintPassphrase,
    /// Firmware update: verification result screen
    /// SD import: current transaction/public-key/covenant formats only
    SdImportMenu,
    SdKsptFileList,
    /// SD kpub file list — pick a .TXT file to import and display as QR
    SdKpubFileList,
    /// ShowQR popup: Save to SD / Back to QR / header back = menu
    ShowQrPopup,
    SdKsptFilename,
    SdKpubFilename,
    SdSigFilename,
    /// SD xprv export: keyboard for naming the .KAS file before encrypt+save
    SdXprvFilename,
    SdMsAddrFilename,
    SdMsAddrEncryptAsk,
    SdMsDescFilename,
    SdMsDescEncryptAsk,
    MultisigSaveAddrAsk,
    SdKsptEncryptAsk,
    /// SD overwrite warning: file already exists, confirm replace
    SdOverwriteWarning,
    SdKpubEncryptAsk,
    SdKsptEncryptPass,
    ShowQrModeChoice, // QR display mode: auto cycle or manual tap-to-advance.
    CovBackupName,
}

mod predicates;
pub(crate) use predicates::is_scan_state;
