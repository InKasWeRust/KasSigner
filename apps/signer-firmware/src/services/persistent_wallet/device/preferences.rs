//! Device-level and saved-wallet UI preference persistence.

use super::super::{journal, PersistError, PersistentWallet, StorageMode};
use crate::runtime::data::AppData;

impl PersistentWallet<'_> {
    #[cfg(feature = "m5stack")]
    pub fn audio_muted(&mut self) -> Result<bool, PersistError> {
        Ok(journal::read_device_flags(&mut self.flash)?.audio_muted())
    }

    #[cfg(feature = "m5stack")]
    pub fn set_audio_muted(&mut self, muted: bool) -> Result<(), PersistError> {
        let flags = journal::read_device_flags(&mut self.flash)?.with_audio_muted(muted);
        journal::write_device_flags(&mut self.flash, flags)?;
        Ok(())
    }

    /// Persistent UI preferences are available only while a saved wallet
    /// backend is active. Per-wallet PIN/password protection is independent; a
    /// one-time mnemonic session never exposes or mutates these controls.
    pub const fn persistent_preferences_available(&self) -> bool {
        matches!(self.mode, Some(StorageMode::SaveWallet) | Some(StorageMode::SdCard))
            && self.credential_kind.is_some()
    }

    pub fn load_display_preferences(&mut self, ad: &mut AppData) -> Result<(), PersistError> {
        let preferences = journal::read_device_preferences(&mut self.flash)?;
        let network = preferences.wallet_network();
        if ad.wallet.seeds.seed_mgr.network() != network { crate::services::wallet_session::clear_active_wallet(ad);
            ad.wallet.seeds.seed_mgr.set_network(network);
            ad.wallet.seeds.seed_list_scroll = 0;
        }
        if !self.persistent_preferences_available() {
            ad.settings.use_session_only_defaults();
            return Ok(());
        }
        ad.settings.apply_persisted_display_preferences(
            preferences.dim_timeout_code(),
            preferences.require_pin_after_dim(),
        );
        #[cfg(feature = "m5stack")]
        { ad.settings.apply_persisted_startup_sound(preferences.startup_sound_enabled()); }
        Ok(())
    }

    pub fn save_display_preferences(&mut self, ad: &crate::runtime::data::AppData) -> Result<(), PersistError> {
        let preferences = journal::read_device_preferences(&mut self.flash)?
            .with_wallet_network(ad.wallet.seeds.seed_mgr.network());
        let preferences = if self.persistent_preferences_available() {
            preferences
                .with_dim_timeout_code(ad.settings.screen_dim_timeout.code())
                .with_require_pin_after_dim(ad.settings.require_pin_after_dim())
        } else {
            preferences
        };
        #[cfg(feature = "m5stack")]
        let preferences = if self.persistent_preferences_available() { preferences.with_startup_sound(ad.settings.startup_sound_enabled()) } else { preferences };
        journal::write_device_preferences(&mut self.flash, preferences)?;
        Ok(())
    }

}
