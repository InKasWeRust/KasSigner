use crate::{
    runtime::interactions::{
        feedback::{show_rejection, ErrorSound},
        TouchInput,
    },
    hw::display::BootDisplay,
    runtime::{
        data::{AppData, ConfirmationState},
    },
    services::persistent_wallet::{PersistError, PersistentWallet},
};
use shared_signer::bytes::zeroize_bytes;
use crate::services::credential_policy::{confirmation_digest, confirmation_matches, validate, CredentialKind,};

use super::input::{edit, EditAction};

pub(super) fn handle_duress_entry(
    input: TouchInput,
    ad: &mut AppData,
    persistence: &mut PersistentWallet<'_>,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    confirming: bool,
) -> Option<bool> {
    if input.is_back {
        ad.wallet.seeds.pp_input.reset();
        ad.storage.persistence.advanced.clear_pending();
        crate::runtime::effects::replace(ad, crate::runtime::navigation::route!(AdvancedFeatures));
        return Some(true);
    }

    let kind = ad.storage.persistence.advanced.credential_kind?;
    match edit(input, ad, kind == CredentialKind::Pin) {
        EditAction::None => None,
        EditAction::Edited => Some(true),
        EditAction::Submitted => submit_duress(ad, persistence, display, delay, i2c, kind, confirming),
    }
}

fn submit_duress(
    ad: &mut AppData,
    persistence: &mut PersistentWallet<'_>,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    kind: CredentialKind,
    confirming: bool,
) -> Option<bool> {
    let len = ad.wallet.seeds.pp_input.len;
    let mut secret = [0u8; 128];
    secret[..len].copy_from_slice(&ad.wallet.seeds.pp_input.buf[..len]);

    if let Err(error) = validate(kind, &secret[..len]) {
        zeroize_bytes(&mut secret);
        restart_duress_entry(ad);
        show_rejection(
            display,
            delay,
            PersistError::from(error).message(),
            1700,
            ErrorSound::Beep,
        );
        return Some(true);
    }

    let digest = confirmation_digest(kind, &secret[..len]);
    if !confirming {
        ad.storage.persistence.advanced.pending_confirmation_digest = digest;
        ad.storage.persistence.advanced.confirmation = ConfirmationState::Pending;
        zeroize_bytes(&mut secret);
        ad.wallet.seeds.pp_input.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedDuressConfirm));
        return Some(true);
    }

    if !ad.storage.persistence.advanced.confirmation.is_pending()
        || !confirmation_matches(&ad.storage.persistence.advanced.pending_confirmation_digest, &digest)
    {
        zeroize_bytes(&mut secret);
        restart_duress_entry(ad);
        let message = if kind == CredentialKind::Pin {
            "Duress PINs do not match"
        } else {
            "Duress passwords do not match"
        };
        show_rejection(display, delay, message, 1700, ErrorSound::Beep);
        return Some(true);
    }

    let wait_message = if kind == CredentialKind::Pin {
        "Saving duress PIN..."
    } else {
        "Saving duress password..."
    };
    display.draw_wait_screen(wait_message);
    let result = persistence.enable_duress(
        &secret[..len], &ad.wallet.seeds.seed_mgr, i2c, delay,
    );
    zeroize_bytes(&mut secret);
    ad.wallet.seeds.pp_input.reset();
    ad.storage.persistence.advanced.clear_pending();
    match result {
        Ok(()) => {
            persistence.refresh_security_mirror(ad);
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedFeatures));
        }
        Err(error) => {
            restart_duress_entry(ad);
            show_rejection(display, delay, error.message(), 2000, ErrorSound::Beep);
        }
    }
    Some(true)
}

fn restart_duress_entry(ad: &mut AppData) {
    ad.wallet.seeds.pp_input.reset();
    ad.storage.persistence.advanced.clear_pending();
    crate::runtime::effects::replace(
        ad,
        crate::runtime::navigation::route!(AdvancedDuressEntry),
    );
}
