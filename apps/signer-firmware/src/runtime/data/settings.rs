// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0-or-later.

// runtime/data/settings.rs — SettingsState

#[cfg(feature = "m5stack")]
mod audio;
mod dim_timeout;
mod persistent_display;

#[cfg(feature = "m5stack")]
use audio::AudioPreferences;
use persistent_display::DisplayPreferences;
pub use dim_timeout::ScreenDimTimeout;

pub struct SettingsState {
    pub brightness: u8,
    pub screen_dim_timeout: ScreenDimTimeout,
    display_preferences: DisplayPreferences,
    #[cfg(feature = "m5stack")]
    pub volume: u8,
    #[cfg(feature = "m5stack")]
    pub previous_volume: u8,
    #[cfg(feature = "m5stack")]
    audio_preferences: AudioPreferences,
}

impl SettingsState {
    pub(super) fn new() -> Self {
        Self {
            brightness: 102,
            screen_dim_timeout: ScreenDimTimeout::DEFAULT,
            display_preferences: DisplayPreferences::new(),
            #[cfg(feature = "m5stack")]
            volume: 64,
            #[cfg(feature = "m5stack")]
            previous_volume: 64,
            #[cfg(feature = "m5stack")]
            audio_preferences: AudioPreferences::new(),
        }
    }
}
