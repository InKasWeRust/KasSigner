//! Exhaustive volatile secret destruction used by duress and destructive paths.
//!
//! Domain state owns the actual scrubbing primitives. This coordinator first
//! cancels secret-bearing cross-core work, then clears every volatile wallet,
//! export, QR, signing, steganography, and persistence surface that can retain
//! secret or wallet-linkable material.

use crate::{runtime::data::AppData, services::wallet_session};

pub fn zeroize_volatile(ad: &mut AppData) {
    cancel_secret_workers();

    // Destroy active wallet/key material before clearing the broader transient
    // onboarding/import state. `clear_active_wallet` also invalidates derived
    // address ownership state through the authoritative wallet-session facade.
    wallet_session::clear_active_wallet(ad);
    ad.wallet.seeds.zeroize_transient();
    ad.wallet.keys.zeroize_sensitive();

    ad.export.zeroize_sensitive();
    ad.qr.clear_sensitive();
    ad.signing.zeroize_sensitive();
    ad.stego.zeroize_sensitive();
    ad.storage.clear_transient();

    // Review authorization must never survive a duress/device wipe.
    ad.navigation.app.review_authorized = false;
}

#[cfg(feature = "m5stack")]
fn cancel_secret_workers() {
    crate::services::wallet_keys::worker::cancel_active();
}

#[cfg(not(feature = "m5stack"))]
fn cancel_secret_workers() {}
