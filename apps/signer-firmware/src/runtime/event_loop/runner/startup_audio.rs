//! CoreS3 persisted audio/display preference restoration before the first UI.

use crate::{runtime::data::AppData, services::persistent_wallet::PersistentWallet};
#[inline(never)]
pub(super) fn apply_audio_preference(
    ad: &mut AppData,
    persistent_wallet: &mut PersistentWallet<'_>,
    runtime_audio: &mut Option<crate::hw::sound::RuntimeAudio>,
) {
    if let Err(error) = persistent_wallet.load_display_preferences(ad) {
        crate::log!("   SETTINGS preference load failed: {:?}", error);
        ad.settings.use_session_only_defaults();
    }

    let persistent = persistent_wallet.persistent_preferences_available();
    let muted = if persistent {
        persistent_wallet.audio_muted().unwrap_or(false)
    } else {
        false
    };

    // The startup chime is an independent preference with a fixed waveform and
    // fixed 18/255 software gain. Runtime volume is restored immediately after
    // playback, so ordinary UI audio still follows the persisted mute setting.
    if ad.settings.startup_sound_enabled() {
        if let Some(audio) = runtime_audio.as_mut() {
            if !audio.play_boot_chime() {
                crate::log!("   AW88298 boot chime write failed");
            }
        }
    }

    let volume = ad.settings.apply_persisted_mute(muted);
    crate::services::audio::set_volume(volume);
    crate::log!(
        "   AUDIO CoreS3 persisted={} mute={} startup_sound={} volume={}",
        persistent,
        muted,
        ad.settings.startup_sound_enabled(),
        volume,
    );
}
