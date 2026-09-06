//! Explicit BIP39 passphrase opt-in after mnemonic creation/import.

use super::{AppData, display};
use crate::runtime::input::AppState;

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    if ad.navigation.app.state != AppState::PassphraseChoice { return None; }
    if is_back {
        if ((ad.storage.persistence.device_storage_intent.is_seed_onboarding()
            && !ad.storage.persistence.onboarding_imported_mnemonic)
            || (ad.wallet.seeds.has_pending_add_wallet() && !ad.wallet.seeds.pending_add_wallet_is_restore()))
            && restage_generated_entropy(ad)
        {
            ad.wallet.seeds.pp_input.reset();
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageSeedTouchChoice));
        } else {
            cancel_unstored_seed(ad);
        }
        return Some(true);
    }
    if !(18..=302).contains(&x) { return Some(false); }
    if (126..=160).contains(&y) {
        ad.wallet.seeds.pp_input.reset();
        super::passphrase::store_seed_with_passphrase(ad, boot_display, delay);
        return Some(true);
    }
    if (18..=302).contains(&x) && (176..=210).contains(&y) {
        ad.wallet.seeds.pp_input.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(PassphraseEntry));
        return Some(true);
    }
    Some(false)
}

fn cancel_unstored_seed(ad: &mut AppData) {
    ad.wallet.seeds.pp_input.reset();
    if ad.wallet.seeds.pending_add_wallet_is_restore() {
        // Keep the reserved Add Wallet transaction alive so the user can choose
        // a different restore transport without losing the parent flow.
        shared_signer::bytes::zeroize_u16(&mut ad.wallet.seeds.mnemonic_indices);
        ad.wallet.seeds.clear_pending_bip39_passphrase();
        ad.wallet.seeds.clear_pending_wallet_name();
        ad.wallet.seeds.word_count = 0;
        ad.navigation.production.restore_menu.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageSeedSourceChoice));
    } else if ad.wallet.seeds.has_pending_add_wallet() {
        // Generated Add Wallet returns to the create/restore choice.
        ad.wallet.seeds.clear_pending_add_wallet();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AddWalletChoice));
    } else if ad.storage.persistence.device_storage_intent.is_seed_onboarding() {
        if ad.storage.persistence.onboarding_imported_mnemonic {
            shared_signer::bytes::zeroize_u16(&mut ad.wallet.seeds.mnemonic_indices);
            ad.wallet.seeds.clear_pending_bip39_passphrase();
            ad.wallet.seeds.clear_pending_wallet_name();
            ad.wallet.seeds.word_count = 0;
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageSeedSourceChoice));
        } else {
            shared_signer::bytes::zeroize_u16(&mut ad.wallet.seeds.mnemonic_indices);
            ad.wallet.seeds.word_count = 0;
            crate::runtime::effects::route(
                ad,
                crate::runtime::navigation::route!(StorageSeedWordCountChoice { action: 0 }),
            );
        }
    } else {
        crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::SeedTool);
    }
}

fn restage_generated_entropy(ad: &mut AppData) -> bool {
    let word_count = ad.wallet.seeds.word_count;
    if !matches!(word_count, 12 | 24) {
        return false;
    }
    let mut entropy = [0u8; 32];
    let length = crate::wallet::seed_manager::encode_compact_seedqr(
        &ad.wallet.seeds.mnemonic_indices,
        word_count,
        &mut entropy,
    );
    if length == 0 {
        shared_signer::bytes::zeroize_bytes(&mut entropy);
        return false;
    }
    ad.wallet.seeds.stage_seed_entropy(&mut entropy, word_count);
    true
}
