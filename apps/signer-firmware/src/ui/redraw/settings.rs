// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Screen redraw — settings states.

mod advanced;
#[cfg(feature = "provisioning-ui")]
mod owner_firmware;

use super::display;
use crate::runtime::{data::AppData, input::AppState};

pub(super) fn redraw(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
) -> bool {
    match ad.navigation.app.state {
        AppState::SettingsMenu => {
            boot_display.update_menu_content("SETTINGS", &ad.navigation.settings_menu);
            true
        }
        AppState::DisplaySettings => {
            let persistent = ad.storage.persistence.advanced.saved_wallet;
            let pin_lock_available = persistent
                && ad.storage.persistence.advanced.credential_kind
                    == Some(crate::services::persistent_wallet::CredentialKind::Pin);
            boot_display.draw_display_settings(
                ad.settings.brightness,
                persistent,
                ad.settings.screen_dim_timeout,
                pin_lock_available,
                ad.settings.require_pin_after_dim(),
            );
            true
        }
        #[cfg(feature = "m5stack")]
        AppState::AudioSettings => {
            boot_display.draw_audio_settings(
                ad.settings.volume,
                ad.storage.persistence.advanced.saved_wallet,
                ad.settings.startup_sound_enabled(),
            );
            true
        }
        AppState::AdvancedFeatures => {
            boot_display.draw_advanced_features(ad);
            true
        },
        #[cfg(feature = "provisioning-ui")]
        AppState::PopItPrompt => {
            boot_display.draw_pop_it_prompt(ad.pop_it.owner_authority_enrolled, ad.pop_it.error);
            true
        }
        #[cfg(feature = "provisioning-ui")]
        AppState::PopItExplain => {
            boot_display.draw_pop_it_explain();
            true
        }
        #[cfg(feature = "provisioning-ui")]
        AppState::PopItConfirm => { boot_display.draw_pop_it_confirm(&ad.wallet.seeds.pp_input, ad.pop_it.error); true }
        #[cfg(feature = "provisioning-ui")]
        AppState::OwnerKeyWarning
        | AppState::OwnerInstallWarning
        | AppState::OwnerKeyConfirm
        | AppState::OwnerInstallConfirm => owner_firmware::redraw(ad, boot_display),
        AppState::AdvancedDuressWarning
        | AppState::AdvancedDuressEntry
        | AppState::AdvancedDuressConfirm
        | AppState::AdvancedSdStorageWarning
        | AppState::FactoryResetWarning
        | AppState::FactoryResetConfirm => advanced::redraw(ad, boot_display),
        #[cfg(feature = "m5stack")]
        AppState::AdvancedRtcEntry
        | AppState::AdvancedTimeLockWarning
        | AppState::AdvancedTimeLockEntry
        | AppState::AdvancedTimeLockConfirm
        | AppState::AdvancedWeeklyWarning
        | AppState::AdvancedWeeklyEntry
        | AppState::AdvancedWeeklyConfirm => advanced::redraw(ad, boot_display),
        _ => false,
    }
}
