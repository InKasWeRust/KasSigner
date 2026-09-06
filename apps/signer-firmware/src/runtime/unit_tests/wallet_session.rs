//! Transactional wallet-activation and cache-isolation regression tests.

use static_cell::StaticCell;

use crate::{
    runtime::data::AppData,
    services::wallet_session::{
        activate_slot, activate_slot_with_cache, WalletActivationError,
    },
};

static WALLET_SESSION_APP_DATA: StaticCell<AppData> = StaticCell::new();

#[derive(Clone, Copy, Eq, PartialEq)]
struct ActiveWalletSnapshot {
    active: u8,
    mnemonic_indices: [u16; 24],
    word_count: u8,
    source: crate::wallet::seed_manager::WalletSource,
    state_flags: u8,
    account_key_raw: [u8; 65],
    receive_cache: [[u8; 32]; 20],
    change_cache: [[u8; 32]; 5],
    current_addr_index: u16,
    extra_pubkey: [u8; 32],
    extra_pubkey_index: u16,
    extra_change_pubkey: [u8; 32],
    extra_change_pubkey_index: u16,
    input_buf: [u8; 5],
    input_len: u8,
    qr_address_length: usize,
}

impl ActiveWalletSnapshot {
    fn capture(ad: &AppData) -> Self {
        Self {
            active: ad.wallet.seeds.seed_mgr.active,
            mnemonic_indices: ad.wallet.seeds.mnemonic_indices,
            word_count: ad.wallet.seeds.word_count,
            source: ad.wallet.seeds.active_source,
            state_flags: snapshot_state_flags(ad),
            account_key_raw: ad.wallet.keys.acct_key_raw,
            receive_cache: ad.wallet.addresses.pubkey_cache,
            change_cache: ad.wallet.addresses.change_pubkey_cache,
            current_addr_index: ad.wallet.addresses.current_addr_index,
            extra_pubkey: ad.wallet.addresses.extra_pubkey,
            extra_pubkey_index: ad.wallet.addresses.extra_pubkey_index,
            extra_change_pubkey: ad.wallet.addresses.extra_change_pubkey,
            extra_change_pubkey_index: ad.wallet.addresses.extra_change_pubkey_index,
            input_buf: ad.wallet.addresses.input_buf,
            input_len: ad.wallet.addresses.input_len,
            qr_address_length: ad.qr.scan.address_length,
        }
    }
}

fn snapshot_state_flags(ad: &AppData) -> u8 {
    u8::from(ad.wallet.seeds.seed_loaded)
        | (u8::from(ad.wallet.addresses.pubkeys_cached) << 1)
        | (u8::from(ad.wallet.addresses.view_is_change) << 2)
        | (u8::from(ad.wallet.addresses.partial_redraw) << 3)
}

pub fn run_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 6u32;
    let ad = match AppData::try_initialize(&WALLET_SESSION_APP_DATA) {
        Ok(ad) => ad.into_mut(),
        Err(()) => return (passed, total),
    };

    let first = offline_signer::derivation::bip32::derive_account_key(&[1u8; 64]);
    let second = offline_signer::derivation::bip32::derive_account_key(&[2u8; 64]);
    let (Ok(first), Ok(second)) = (first, second) else {
        return (passed, total);
    };
    let first_raw = first.to_raw();
    let second_raw = second.to_raw();
    let Some(first_slot) = ad
        .wallet
        .seeds
        .seed_mgr
        .store_account_key(&first_raw, [9, 9, 9, 9], [1, 1, 1, 1])
    else {
        return (passed, total);
    };
    let Some(second_slot) = ad
        .wallet
        .seeds
        .seed_mgr
        .store_account_key(&second_raw, [8, 8, 8, 8], [2, 2, 2, 2])
    else {
        return (passed, total);
    };

    let mut checkpoint = || {};
    if activate_slot_with_cache(ad, first_slot, &mut checkpoint).is_ok() {
        passed += 1;
    }
    if crate::runtime::signing::derive_change_pubkey_from_acct(
        &ad.wallet.keys.acct_key_raw,
        5,
        &mut ad.wallet.addresses.extra_change_pubkey,
    ).is_err() {
        return (passed, total);
    }
    ad.wallet.addresses.extra_change_pubkey_index = 5;
    let first_extended_change = ad.wallet.addresses.extra_change_pubkey;

    if activate_slot_with_cache(ad, second_slot, &mut checkpoint).is_ok()
        && ad.wallet.addresses.extra_change_pubkey == [0; 32]
        && ad.wallet.addresses.extra_change_pubkey_index == u16::MAX
    {
        passed += 1;
    }

    let mut second_extended_change = [0u8; 32];
    let second_derived = crate::runtime::signing::derive_change_pubkey_from_acct(
        &ad.wallet.keys.acct_key_raw,
        5,
        &mut second_extended_change,
    ).is_ok();
    if second_derived && first_extended_change != second_extended_change && second_extended_change != [0; 32] {
        passed += 1;
    }

    seed_distinct_live_state(ad);
    let before_failure = ActiveWalletSnapshot::capture(ad);
    let Some(invalid_raw_slot) = ad.wallet.seeds.seed_mgr.find_free() else {
        return (passed, total);
    };
    ad.wallet.seeds.seed_mgr.slots[invalid_raw_slot].source = crate::wallet::seed_manager::WalletSource::RawPrivateKey;
    ad.wallet.seeds.seed_mgr.slots[invalid_raw_slot].fingerprint = [3, 3, 3, 3];
    if activate_slot_with_cache(ad, invalid_raw_slot, &mut checkpoint)
        == Err(WalletActivationError::InvalidRawKey)
        && ActiveWalletSnapshot::capture(ad) == before_failure
    {
        passed += 1;
    }

    let Some(invalid_account_slot) = ad.wallet.seeds.seed_mgr.find_free() else {
        return (passed, total);
    };
    ad.wallet.seeds.seed_mgr.slots[invalid_account_slot].source = crate::wallet::seed_manager::WalletSource::AccountXprv;
    ad.wallet.seeds.seed_mgr.slots[invalid_account_slot].fingerprint = [4, 4, 4, 4];
    if activate_slot(ad, invalid_account_slot)
        == Err(WalletActivationError::InvalidAccountKey)
        && ActiveWalletSnapshot::capture(ad) == before_failure
    {
        passed += 1;
    }

    if activate_slot(ad, usize::MAX)
        == Err(WalletActivationError::InvalidSlot)
        && ActiveWalletSnapshot::capture(ad) == before_failure
    {
        passed += 1;
    }
    (passed, total)
}

fn seed_distinct_live_state(ad: &mut AppData) {
    ad.wallet.addresses.current_addr_index = 9;
    ad.wallet.addresses.view_is_change = true;
    ad.wallet.addresses.partial_redraw = true;
    ad.wallet.addresses.extra_pubkey = [7; 32];
    ad.wallet.addresses.extra_pubkey_index = 21;
    ad.wallet.addresses.extra_change_pubkey = [8; 32];
    ad.wallet.addresses.extra_change_pubkey_index = 22;
    ad.wallet.addresses.input_buf = [1, 2, 3, 4, 5];
    ad.wallet.addresses.input_len = 5;
    ad.qr.scan.address_length = 17;
}
