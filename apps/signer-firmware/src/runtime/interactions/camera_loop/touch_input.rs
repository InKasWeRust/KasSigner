//! Camera-screen navigation effects driven by the normal event-loop touch owner.

use super::AppData;

/// Route a camera-screen back action through the shared navigation policy.
///
/// The event loop is the sole touch transport/gesture owner. Camera capture
/// code never polls the touchscreen directly.
pub(crate) fn route_camera_back(ad: &mut AppData) {
    #[cfg(feature = "waveshare")]
    { ad.camera.cam_tune_active = false; }
    #[cfg(feature = "waveshare")]
    let camera_settings = ad.navigation.app.state == crate::runtime::input::AppState::CameraSettings;
    #[cfg(not(feature = "waveshare"))]
    let camera_settings = false;
    if ad.signing.multisig.creating.n > 0 && !ad.signing.multisig.creating.active {
        let mut key_idx = 0u8;
        for index in 0..ad.signing.multisig.creating.n {
            if ad.signing.multisig.creating.slot_empty(index as usize) {
                key_idx = index;
                break;
            }
        }
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(MultisigAddKey { key_idx }));
    } else if camera_settings {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SettingsMenu));
    } else if ad.signing.covenant.phase == crate::runtime::data::CovenantSigningPhase::AwaitingReveal {
        ad.signing.covenant.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SingleSigMenu));
    } else if ad.navigation.app.state == crate::runtime::input::AppState::DecryptSecretScan {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(WalletAdvancedMenu));
    } else if ad.navigation.app.state == crate::runtime::input::AppState::SignMsgScan {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SignMsgChoice));
    } else if ad.navigation.app.state == crate::runtime::input::AppState::ScanQR
        && ad.navigation.owner == crate::runtime::navigation::NavigationOwner::Settings
    {
        crate::runtime::effects::back(ad);
    } else if (ad.storage.persistence.device_storage_intent.is_seed_onboarding()
        || ad.wallet.seeds.pending_add_wallet_is_restore())
        && ad.navigation.app.state == crate::runtime::input::AppState::ScanQR
    {
        crate::runtime::effects::back(ad);
    } else {
        crate::runtime::effects::home(ad);
    }
    crate::runtime::effects::redraw(ad);
}
