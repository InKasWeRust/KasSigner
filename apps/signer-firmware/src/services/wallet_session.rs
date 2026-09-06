//! Authoritative, transactional active-wallet lifecycle.

use crate::{runtime::data::AppData, wallet::seed_manager::{SeedSlot, WalletSource}};

pub const SLOTS_FULL_MESSAGE: &str = "All seed slots are full";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalletActivationError {
    InvalidSlot,
    InvalidSlotType,
    InvalidMnemonic,
    InvalidRawKey,
    InvalidAccountKey,
    AccountKeyDerivationFailed,
    AddressKeyDerivationFailed,
    PublicKeyDerivationFailed,
    ChangeKeyDerivationFailed,
    ChangePublicKeyDerivationFailed,
}

impl WalletActivationError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidSlot => "Invalid wallet slot",
            Self::InvalidSlotType => "Invalid wallet slot type",
            Self::InvalidMnemonic => "Invalid mnemonic slot",
            Self::InvalidRawKey => "Invalid raw key",
            Self::InvalidAccountKey => "Invalid account key slot",
            Self::AccountKeyDerivationFailed => "Account key derivation failed",
            Self::AddressKeyDerivationFailed => "Address key derivation failed",
            Self::PublicKeyDerivationFailed => "Public key derivation failed",
            Self::ChangeKeyDerivationFailed => "Change key derivation failed",
            Self::ChangePublicKeyDerivationFailed => "Change public key derivation failed",
        }
    }
}

struct ActivationPlan {
    indices: [u16; 24],
    source: WalletSource,
    account_key_raw: [u8; 65],
    receive_cache: [[u8; 32]; 20],
    change_cache: [[u8; 32]; 5],
    pubkeys_cached: bool,
}

impl ActivationPlan {
    fn new(slot: &SeedSlot) -> Self {
        Self {
            indices: slot.indices,
            source: slot.source,
            account_key_raw: [0; 65],
            receive_cache: [[0; 32]; 20],
            change_cache: [[0; 32]; 5],
            pubkeys_cached: false,
        }
    }
}

impl Drop for ActivationPlan {
    fn drop(&mut self) {
        shared_signer::bytes::zeroize_u16(&mut self.indices);
        shared_signer::bytes::zeroize_bytes(&mut self.account_key_raw);
        for public_key in self.receive_cache.iter_mut() {
            shared_signer::bytes::zeroize_bytes(public_key);
        }
        for public_key in self.change_cache.iter_mut() {
            shared_signer::bytes::zeroize_bytes(public_key);
        }
    }
}

/// Install and activate one validated account XPrv without losing its BIP32 metadata.
pub fn install_account_xprv(
    ad: &mut AppData,
    imported: offline_signer::derivation::xpub::ImportedAccountXprv,
) -> Result<usize, &'static str> {
    install_account_xprv_with_mode(ad, imported, false)
}

pub fn install_account_xprv_transient(
    ad: &mut AppData,
    imported: offline_signer::derivation::xpub::ImportedAccountXprv,
) -> Result<usize, &'static str> {
    install_account_xprv_with_mode(ad, imported, true)
}

fn install_account_xprv_with_mode(
    ad: &mut AppData,
    imported: offline_signer::derivation::xpub::ImportedAccountXprv,
    transient: bool,
) -> Result<usize, &'static str> {
    use sha2::{Digest, Sha256};

    let mut raw = imported.key.to_raw();
    if transient
        && ad.wallet.seeds.seed_mgr.find_matching_account_key(&raw, &imported.parent_fingerprint).is_some()
    {
        shared_signer::bytes::zeroize_bytes(&mut raw);
        return Err("Wallet already exists");
    }
    let mut fingerprint_hasher = Sha256::new();
    fingerprint_hasher.update(raw);
    fingerprint_hasher.update(imported.parent_fingerprint);
    let fingerprint_hash = fingerprint_hasher.finalize();
    let fingerprint = [
        fingerprint_hash[0],
        fingerprint_hash[1],
        fingerprint_hash[2],
        fingerprint_hash[3],
    ];
    let slot_index = if transient {
        ad.wallet.seeds.seed_mgr.store_account_key_transient(
            &raw, imported.parent_fingerprint, fingerprint,
        )
    } else {
        ad.wallet.seeds.seed_mgr.store_account_key(
            &raw, imported.parent_fingerprint, fingerprint,
        )
    }
    .ok_or(SLOTS_FULL_MESSAGE);
    shared_signer::bytes::zeroize_bytes(&mut raw);
    let slot_index = slot_index?;
    activate_slot(ad, slot_index).map_err(WalletActivationError::message)?;
    Ok(slot_index)
}

pub fn activate_slot(
    ad: &mut AppData,
    slot_index: usize,
) -> Result<(), WalletActivationError> {
    let plan = prepare_activation(ad, slot_index, None)?;
    commit_activation(ad, slot_index, plan);
    Ok(())
}

/// Activate a wallet and populate its receive/change cache with mandatory
/// cooperative liveness checkpoints. Production callers that need cached
/// addresses cannot accidentally bypass watchdog feeding.
pub fn activate_slot_with_cache(
    ad: &mut AppData,
    slot_index: usize,
    checkpoint: &mut dyn FnMut(),
) -> Result<(), WalletActivationError> {
    let plan = prepare_activation(ad, slot_index, Some(checkpoint))?;
    commit_activation(ad, slot_index, plan);
    Ok(())
}

fn prepare_activation(
    ad: &AppData,
    slot_index: usize,
    checkpoint: Option<&mut dyn FnMut()>,
) -> Result<ActivationPlan, WalletActivationError> {
    if !ad.wallet.seeds.seed_mgr.slot_visible(slot_index) {
        return Err(WalletActivationError::InvalidSlot);
    }
    let slot = ad
        .wallet
        .seeds
        .seed_mgr
        .slots
        .get(slot_index)
        .ok_or(WalletActivationError::InvalidSlot)?;
    let mut plan = ActivationPlan::new(slot);

    if let Some(checkpoint) = checkpoint {
        crate::runtime::signing::derive_slot_pubkeys_with_checkpoint(
            slot,
            &mut plan.account_key_raw,
            &mut plan.receive_cache,
            &mut plan.change_cache,
            checkpoint,
        )
        .map_err(map_derivation_error)?;
        plan.pubkeys_cached = true;
    } else {
        validate_slot(slot, &mut plan.account_key_raw)?;
    }
    Ok(plan)
}

fn validate_slot(
    slot: &SeedSlot,
    account_key_raw: &mut [u8; 65],
) -> Result<(), WalletActivationError> {
    if slot.is_raw_key() {
        let mut raw_key = [0u8; 32];
        if !slot.raw_key_bytes(&mut raw_key) {
            return Err(WalletActivationError::InvalidRawKey);
        }
        let result = offline_signer::derivation::bip32::pubkey_from_raw_key(&raw_key)
            .map_err(|_| WalletActivationError::InvalidRawKey);
        shared_signer::bytes::zeroize_bytes(&mut raw_key);
        return result.map(|_| ());
    }
    if slot.is_account_key() {
        if !slot.account_key_raw(account_key_raw) {
            return Err(WalletActivationError::InvalidAccountKey);
        }
        let account = offline_signer::derivation::bip32::ExtendedPrivKey::from_raw(
            account_key_raw,
        );
        return account
            .public_key_x_only()
            .map(|_| ())
            .map_err(|_| WalletActivationError::InvalidAccountKey);
    }
    if let Some(word_count) = slot.mnemonic_word_count() {
        return crate::wallet::mnemonic::validate(&slot.indices, word_count)
            .then_some(())
            .ok_or(WalletActivationError::InvalidMnemonic);
    }
    Err(WalletActivationError::InvalidSlotType)
}

fn map_derivation_error(message: &'static str) -> WalletActivationError {
    match message {
        "Invalid raw key" => WalletActivationError::InvalidRawKey,
        "Invalid account key slot" => WalletActivationError::InvalidAccountKey,
        "Invalid mnemonic slot" => WalletActivationError::InvalidMnemonic,
        "Invalid wallet slot type" => WalletActivationError::InvalidSlotType,
        "Account key derivation failed" => WalletActivationError::AccountKeyDerivationFailed,
        "Address key derivation failed" => WalletActivationError::AddressKeyDerivationFailed,
        "Public key derivation failed" => WalletActivationError::PublicKeyDerivationFailed,
        "Change key derivation failed" => WalletActivationError::ChangeKeyDerivationFailed,
        "Change public key derivation failed" => {
            WalletActivationError::ChangePublicKeyDerivationFailed
        }
        _ => WalletActivationError::InvalidSlotType,
    }
}

fn commit_activation(ad: &mut AppData, slot_index: usize, plan: ActivationPlan) {
    reset_derived_state(ad);
    ad.wallet.seeds.mnemonic_indices = plan.indices;
    ad.wallet.seeds.active_source = plan.source;
    ad.wallet.seeds.word_count = plan.source.mnemonic_word_count().unwrap_or(0);
    ad.wallet.seeds.seed_loaded = true;
    ad.wallet.keys.acct_key_raw = plan.account_key_raw;
    ad.wallet.addresses.pubkey_cache = plan.receive_cache;
    ad.wallet.addresses.change_pubkey_cache = plan.change_cache;
    ad.wallet.addresses.pubkeys_cached = plan.pubkeys_cached;
    let _ = ad.wallet.seeds.seed_mgr.set_active(slot_index);
}

pub fn clear_active_wallet(ad: &mut AppData) {
    ad.wallet.seeds.seed_mgr.clear_active();
    shared_signer::bytes::zeroize_u16(&mut ad.wallet.seeds.mnemonic_indices);
    ad.wallet.seeds.word_count = 0;
    ad.wallet.seeds.active_source = WalletSource::Empty;
    ad.wallet.seeds.seed_loaded = false;
    reset_derived_state(ad);
}

pub fn restore_persistent_active_wallet(ad: &mut AppData) -> bool {
    let slot = usize::from(ad.wallet.seeds.seed_mgr.persistent_active());
    if slot < crate::wallet::seed_manager::MAX_SLOTS
        && ad.wallet.seeds.seed_mgr.slot_visible(slot)
        && activate_slot(ad, slot).is_ok()
    {
        return true;
    }
    clear_active_wallet(ad);
    false
}

/// Decide whether boot must stop at WALLETS before normal navigation.
///
/// With more than one wallet visible for the selected network, startup must
/// never silently reuse the serialized "last active" slot. Clear it and make
/// the owner explicitly choose/authenticate the wallet for this session. A
/// single protected wallet can also arrive here inactive, in which case the
/// same selection surface is required.
pub fn visible_wallet_count(ad: &AppData) -> usize {
    (0..crate::wallet::seed_manager::MAX_SLOTS)
        .filter(|slot| ad.wallet.seeds.seed_mgr.slot_visible(*slot))
        .count()
}

pub fn require_startup_wallet_selection(ad: &mut AppData) -> bool {
    let visible = visible_wallet_count(ad);
    if visible > 1 {
        clear_active_wallet(ad);
        ad.wallet.seeds.seed_list_scroll = 0;
        return true;
    }
    visible == 1 && ad.wallet.seeds.seed_mgr.active_slot().is_none()
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn install_workflow_wallet_inventory_fixture(ad: &mut AppData) -> bool {
    const KEYS: [[u8; 32]; 5] = [
        [0x11; 32],
        [0x22; 32],
        [0x33; 32],
        [0x44; 32],
        [0x55; 32],
    ];

    clear_active_wallet(ad);
    ad.wallet.seeds.seed_mgr.zeroize_all();
    for key in &KEYS {
        if ad.wallet.seeds.seed_mgr.store_raw_key(key).is_none() {
            return false;
        }
    }
    { let mut checkpoint = || {}; activate_slot_with_cache(ad, 0, &mut checkpoint).is_ok() }
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn install_workflow_multisig_mnemonic_inventory(ad: &mut AppData) -> bool {
    clear_active_wallet(ad);
    ad.wallet.seeds.seed_mgr.zeroize_all();
    for marker in [0x11u8, 0x22, 0x33, 0x44, 0x55] {
        let indices = crate::wallet::mnemonic::generate_from_entropy(12, &[marker; 16]);
        if ad.wallet.seeds.seed_mgr.store(&indices, 12, &[], 0).is_none() { return false; }
    }
    { let mut checkpoint = || {}; activate_slot_with_cache(ad, 0, &mut checkpoint).is_ok() }
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn install_workflow_backup_mnemonic_fixture(ad: &mut AppData) -> bool {
    // BIP39 vector: "abandon" x11 + "about". The fixture is deterministic,
    // volatile, and exists only in the workflow-test-auto image.
    let mut indices = [0u16; 24];
    indices[11] = 3;

    clear_active_wallet(ad);
    ad.wallet.seeds.seed_mgr.zeroize_all();
    let Some(slot) = ad.wallet.seeds.seed_mgr.store(&indices, 12, &[], 0) else {
        return false;
    };
    activate_slot(ad, slot).is_ok()
}

pub fn reset_derived_state(ad: &mut AppData) {
    ad.export.clear_connect_kpub_cache();
    ad.wallet.addresses.pubkeys_cached = false;
    for public_key in &mut ad.wallet.addresses.pubkey_cache {
        shared_signer::bytes::zeroize_bytes(public_key);
    }
    for public_key in &mut ad.wallet.addresses.change_pubkey_cache {
        shared_signer::bytes::zeroize_bytes(public_key);
    }
    ad.wallet.addresses.current_addr_index = 0;
    ad.wallet.addresses.view_is_change = false;
    ad.wallet.addresses.partial_redraw = false;
    shared_signer::bytes::zeroize_bytes(&mut ad.wallet.addresses.extra_pubkey);
    ad.wallet.addresses.extra_pubkey_index = u16::MAX;
    shared_signer::bytes::zeroize_bytes(&mut ad.wallet.addresses.extra_change_pubkey);
    ad.wallet.addresses.extra_change_pubkey_index = u16::MAX;
    shared_signer::bytes::zeroize_bytes(&mut ad.wallet.addresses.input_buf);
    ad.wallet.addresses.input_len = 0;
    #[cfg(feature = "m5stack")]
    {
        ad.wallet.addresses.cache_seed_derivation = None;
        ad.wallet.addresses.cache_worker_generation = None;
        ad.wallet.addresses.cache_progress = 0;
        ad.wallet.addresses.cache_started_at_ms = 0;
        ad.wallet.addresses.cache_last_progress_at_ms = 0;
    }
    shared_signer::bytes::zeroize_bytes(&mut ad.wallet.keys.acct_key_raw);
    shared_signer::bytes::zeroize_bytes(&mut ad.qr.scan.address);
    ad.qr.scan.address_length = 0;
    ad.qr.scan.address_valid = false;
}
