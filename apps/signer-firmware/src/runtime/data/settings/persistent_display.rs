//! Persistent display preference state and mutations kept with SettingsState ownership.

use super::{ScreenDimTimeout, SettingsState};

pub(super) struct DisplayPreferences {
    require_pin_after_dim: bool,
    dirty: bool,
}

impl DisplayPreferences {
    pub(super) const fn new() -> Self {
        Self {
            require_pin_after_dim: false,
            dirty: false,
        }
    }
}

impl SettingsState {
    pub(crate) const fn require_pin_after_dim(&self) -> bool {
        self.display_preferences.require_pin_after_dim
    }

    pub(crate) const fn device_preferences_dirty(&self) -> bool {
        self.display_preferences.dirty
    }

    pub(crate) fn apply_persisted_display_preferences(
        &mut self,
        dim_timeout_code: u8,
        require_pin_after_dim: bool,
    ) {
        self.screen_dim_timeout = ScreenDimTimeout::from_code(dim_timeout_code);
        self.display_preferences.require_pin_after_dim = require_pin_after_dim;
        self.display_preferences.dirty = false;
    }

    pub(crate) fn use_session_only_defaults(&mut self) {
        self.screen_dim_timeout = ScreenDimTimeout::DEFAULT;
        self.display_preferences.require_pin_after_dim = false;
        #[cfg(feature = "m5stack")]
        self.apply_session_audio_defaults();
        self.display_preferences.dirty = false;
    }

    pub(crate) fn mark_device_preferences_dirty(&mut self) {
        self.display_preferences.dirty = true;
    }

    pub(crate) fn clear_device_preferences_dirty(&mut self) {
        self.display_preferences.dirty = false;
    }

    pub(crate) fn apply_persistent_display_tap(
        &mut self,
        dim_row: bool,
        pin_row: bool,
        move_left: bool,
        pin_lock_available: bool,
    ) -> bool {
        if dim_row {
            let next = if move_left {
                self.screen_dim_timeout.previous()
            } else {
                self.screen_dim_timeout.next()
            };
            if next != self.screen_dim_timeout {
                self.screen_dim_timeout = next;
                self.mark_device_preferences_dirty();
                return true;
            }
        }
        if pin_row && pin_lock_available {
            self.display_preferences.require_pin_after_dim =
                !self.display_preferences.require_pin_after_dim;
            self.mark_device_preferences_dirty();
            return true;
        }
        false
    }
}
