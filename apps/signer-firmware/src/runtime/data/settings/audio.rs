//! CoreS3 audio preference state and volume/mute transitions.

use super::SettingsState;

pub(super) struct AudioPreferences {
    muted: bool,
    startup_sound_enabled: bool,
}

impl AudioPreferences {
    pub(super) const fn new() -> Self {
        Self {
            muted: false,
            startup_sound_enabled: true,
        }
    }
}

impl SettingsState {
    pub(crate) const fn audio_muted(&self) -> bool {
        self.audio_preferences.muted
    }

    pub(crate) const fn startup_sound_enabled(&self) -> bool {
        self.audio_preferences.startup_sound_enabled
    }

    pub(crate) fn apply_persisted_startup_sound(&mut self, enabled: bool) {
        self.audio_preferences.startup_sound_enabled = enabled;
    }

    pub(super) fn apply_session_audio_defaults(&mut self) {
        self.audio_preferences.startup_sound_enabled = true;
    }

    pub(crate) fn toggle_startup_sound(&mut self) {
        self.audio_preferences.startup_sound_enabled = !self.audio_preferences.startup_sound_enabled;
        self.mark_device_preferences_dirty();
    }

    pub fn set_volume(&mut self, value: u8) {
        self.volume = value;
        if value == 0 {
            self.audio_preferences.muted = true;
            if self.previous_volume == 0 {
                self.previous_volume = 64;
            }
        } else {
            self.audio_preferences.muted = false;
            self.previous_volume = value;
        }
    }

    pub fn apply_persisted_mute(&mut self, muted: bool) -> u8 {
        if muted {
            if self.volume != 0 {
                self.previous_volume = self.volume;
            }
            self.volume = 0;
            self.audio_preferences.muted = true;
            0
        } else {
            let restored = if self.previous_volume == 0 { 64 } else { self.previous_volume };
            self.volume = restored;
            self.audio_preferences.muted = false;
            restored
        }
    }

    pub fn toggle_mute(&mut self) -> u8 {
        if self.audio_preferences.muted || self.volume == 0 {
            let restored = if self.previous_volume == 0 { 64 } else { self.previous_volume };
            self.set_volume(restored);
            restored
        } else {
            self.previous_volume = self.volume;
            self.set_volume(0);
            0
        }
    }
}
