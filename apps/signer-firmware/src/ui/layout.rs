// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Pure presentation/input geometry shared by rendering and touch hit-testing.

use crate::hw::touch::TouchZone;

pub(crate) const HOME_CARD_W: u16 = 148;
pub(crate) const HOME_CARD_H: u16 = 90;

pub(crate) const HOME_GRID_ZONES: [TouchZone; 4] = [
    TouchZone::new(8, 46, HOME_CARD_W, HOME_CARD_H),
    TouchZone::new(164, 46, HOME_CARD_W, HOME_CARD_H),
    TouchZone::new(8, 143, HOME_CARD_W, HOME_CARD_H),
    TouchZone::new(164, 143, HOME_CARD_W, HOME_CARD_H),
];

pub(crate) const BACK_ZONE: TouchZone = TouchZone::new(0, 0, 49, 49);

// Address presentation controls. Rendering, production hit-testing, and
// connected workflow E2E must consume these exact zones so a test can never
// "tap" a control that is not actually visible at that coordinate.
pub(crate) const ADDRESS_CHAIN_ZONE: TouchZone = TouchZone::new(34, 176, 120, 28);
pub(crate) const ADDRESS_QR_ZONE: TouchZone = TouchZone::new(166, 176, 120, 28);
pub(crate) const ADDRESS_PREV_ZONE: TouchZone = TouchZone::new(10, 210, 50, 28);
pub(crate) const ADDRESS_INDEX_ZONE: TouchZone = TouchZone::new(110, 210, 100, 28);
pub(crate) const ADDRESS_NEXT_ZONE: TouchZone = TouchZone::new(260, 210, 50, 28);

// Shared ERROR/OK geometry used by both ordinary Rejected screens and the
// stage-3 recoverable-error modal.
pub(crate) const ERROR_OK_ZONE: TouchZone = TouchZone::new(72, 178, 176, 42);

#[cfg(feature = "workflow-test-auto")]
pub(crate) const fn zone_center(zone: TouchZone) -> (u16, u16) {
    (zone.x + zone.w / 2, zone.y + zone.h / 2)
}

// CoreS3 audio is part of the top navigation rail. Keep its touch target fully
// to the right of Back so the two global controls never compete for one tap.
#[cfg(feature = "m5stack")]
pub(crate) const AUDIO_TOGGLE_ZONE: TouchZone = TouchZone::new(50, 4, 40, 40);

// Centered top headers may use the normal screen center until their left edge
// would collide with Back + Audio. Longer titles are shifted just enough to
// clear the two controls rather than reflowing the body of every screen.
pub(crate) const NAV_HEADER_CONTENT_LEFT: i32 = 92;

pub(crate) const HOME_SHORTCUT_ZONE: TouchZone = TouchZone::new(272, 0, 48, 48);

// Shared geometry for the standard two-button modal. Rendering and touch
// dispatch consume the same zones so visible Yes/No buttons cannot drift from
// their hit targets.
pub(crate) const MODAL_LEFT_BUTTON_ZONE: TouchZone = TouchZone::new(30, 140, 125, 45);
pub(crate) const MODAL_RIGHT_BUTTON_ZONE: TouchZone = TouchZone::new(165, 140, 125, 45);

pub(crate) fn is_back_tap(x: u16, y: u16) -> bool {
    BACK_ZONE.contains(x, y)
}

pub(crate) fn nav_header_x(centered_x: i32, width: i32) -> i32 {
    let shifted = centered_x.max(NAV_HEADER_CONTENT_LEFT);
    if shifted.saturating_add(width) <= 320 { shifted } else { centered_x }
}

#[cfg(feature = "m5stack")]
pub(crate) fn audio_toggle_visible(state: crate::runtime::input::AppState) -> bool {
    use crate::runtime::input::AppState;
    if matches!(
        state,
        AppState::StorageModeChoice | AppState::AddWalletChoice | AppState::StorageSeedSourceChoice
            | AppState::StorageSeedDiceChoice | AppState::StorageSeedDiceCountChoice
            | AppState::StorageSeedTouchChoice | AppState::StorageSeedWordCountChoice { .. }
            | AppState::SeedEntropyUnavailable { .. } | AppState::AdvancedRestoreMenu
            | AppState::StorageRecoveryAcknowledgement | AppState::StorageFinalizeChoice
            | AppState::PassphraseChoice | AppState::SeedBackup { .. }
            | AppState::StorageCredentialType
            | AppState::MainMenu | AppState::SeedsMenu | AppState::SeedList
            | AppState::ConfirmDeleteSeed | AppState::WalletBackupMethodsMenu
            | AppState::WalletDetails | AppState::SeedToolsMenu
            | AppState::ImportExportChoice | AppState::ImportMenu | AppState::SingleSigMenu
            | AppState::MultisigMenu | AppState::SettingsMenu
            | AppState::AdvancedMenu | AppState::FirmwareUpdateReady | AppState::FactoryResetWarning
            | AppState::FactoryResetConfirm | AppState::WalletAdvancedMenu
            | AppState::BackupRecoveryMenu
            | AppState::DisplaySettings | AppState::AudioSettings | AppState::SdCardSettings | AppState::SdCardUnlockPassword
            | AppState::AdvancedFeatures | AppState::AdvancedDuressWarning
            | AppState::AdvancedSdStorageWarning | AppState::About | AppState::SeedBackupMenu
            | AppState::WatchOnlyMenu | AppState::SigningKeysMenu | AppState::QrExportMenu
            | AppState::XprvExportMenu | AppState::StorageUnlockPin
            | AppState::StorageUnlockPassword
    ) {
        return true;
    }
    #[cfg(feature = "provisioning-ui")]
    if matches!(state, AppState::PopItPrompt | AppState::PopItExplain) {
        return true;
    }
    #[cfg(feature = "developer-ui")]
    if matches!(state, AppState::DeveloperMenu | AppState::NetworkMenu | AppState::DiagnosticInfo) { return true; }
    #[cfg(feature = "workflow-tests")]
    if matches!(
        state,
        AppState::WorkflowTestsMenu | AppState::WorkflowTestsCategory { .. }
            | AppState::WorkflowTestsResult
    ) {
        return true;
    }
    false
}

#[cfg(feature = "m5stack")]
pub(crate) fn audio_toggle_zone(state: crate::runtime::input::AppState) -> Option<TouchZone> {
    audio_toggle_visible(state).then_some(AUDIO_TOGGLE_ZONE)
}
