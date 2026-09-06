//! Final commit paths for restored non-mnemonic Add Wallet sources.

use crate::runtime::data::AppData;
use crate::runtime::interactions::feedback::{show_rejection, ErrorSound};
use crate::services::audio as sound;
use crate::wallet::seed_manager::WalletProtection;

pub(super) fn commit_add_wallet(
    ad: &mut AppData,
    persistence: &mut crate::services::persistent_wallet::PersistentWallet<'_>,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    slot: usize,
    protection: WalletProtection,
    salt: [u8; crate::services::credential_policy::SALT_SIZE],
    verifier: [u8; 32],
) -> bool {
    if !transient_slot_ready(ad, slot) {
        reject_creation(boot_display, delay);
        return false;
    }
    if !ad.wallet.seeds.seed_mgr.promote_transient(slot) {
        cancel_installed_restore(ad, slot);
        reject_creation(boot_display, delay);
        return false;
    }
    apply_pending_wallet_name(ad, slot);
    if !ad.wallet.seeds.seed_mgr.set_slot_protection(slot, protection) {
        cancel_installed_restore(ad, slot);
        reject_creation(boot_display, delay);
        return false;
    }
    if let Err(error) = persistence.stage_wallet_activation_record(slot, protection, salt, verifier) {
        cancel_installed_restore(ad, slot);
        show_rejection(boot_display, delay, error.message(), 1_800, ErrorSound::Silent);
        return false;
    }
    if !ad.wallet.seeds.seed_mgr.set_active(slot) {
        cancel_installed_restore(ad, slot);
        reject_creation(boot_display, delay);
        return false;
    }
    super::finish_add_wallet_commit(ad);
    true
}

pub(super) fn finish_session_wallet(
    ad: &mut AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    slot: usize,
) -> bool {
    if !transient_slot_ready(ad, slot) {
        reject_creation(boot_display, delay);
        return false;
    }
    apply_pending_wallet_name(ad, slot);
    sound::success();
    ad.wallet.seeds.finish_pending_add_wallet_commit();
    ad.wallet.seeds.clear_pending_wallet_name();
    ad.wallet.seeds.clear_pending_bip39_passphrase();
    ad.wallet.seeds.seed_list_scroll = 0;
    super::super::seed_list::return_after_add_wallet(ad);
    true
}

fn transient_slot_ready(ad: &AppData, slot: usize) -> bool {
    slot < crate::wallet::seed_manager::MAX_SLOTS
        && !ad.wallet.seeds.seed_mgr.slots[slot].is_empty()
        && ad.wallet.seeds.seed_mgr.slots[slot].transient
}

pub(super) fn apply_pending_wallet_name(ad: &mut AppData, slot: usize) {
    let name_len = usize::from(ad.wallet.seeds.pending_wallet_name_len)
        .min(crate::wallet::seed_manager::WALLET_NAME_MAX);
    if name_len == 0 {
        return;
    }
    let mut name = [0u8; crate::wallet::seed_manager::WALLET_NAME_MAX];
    name[..name_len].copy_from_slice(&ad.wallet.seeds.pending_wallet_name[..name_len]);
    let _ = ad.wallet.seeds.seed_mgr.set_slot_name(slot, &name[..name_len]);
    shared_signer::bytes::zeroize_bytes(&mut name);
}

fn cancel_installed_restore(ad: &mut AppData, slot: usize) {
    ad.wallet.seeds.seed_mgr.delete(slot);
    let _ = crate::services::wallet_session::restore_persistent_active_wallet(ad);
}

fn reject_creation(
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) {
    show_rejection(
        boot_display,
        delay,
        "Wallet creation failed",
        1_800,
        ErrorSound::Silent,
    );
}
