//! Domain-owned wallet runtime state.
use crate::wallet::{mnemonic, seed_manager};
use crate::services::credential_policy::SALT_SIZE;

mod security;
mod seed_session;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingWalletActivationState {
    Pending,
    Ready,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingAddWalletKind {
    None,
    Generated,
    Restored,
    RestoredInstalled,
}

pub struct SeedSession {
    pub seed_mgr: seed_manager::SeedManager,
    pub mnemonic_indices: [u16; 24],
    /// Current mnemonic length while importing/generating, or the active mnemonic length.
    pub word_count: u8,
    /// Authoritative type of the active wallet slot.
    pub active_source: seed_manager::WalletSource,
    pub seed_loaded: bool,
    pub seed_list_scroll: u8,
    pub pending_delete_slot: u8,
    /// Transactional Add Wallet mode while mnemonic material is staged.
    pub pending_add_wallet_kind: PendingAddWalletKind,
    pub pending_wallet_name: [u8; seed_manager::WALLET_NAME_MAX],
    pub pending_wallet_name_len: u8,
    /// Physical slot reserved for the transactional Add Wallet flow.
    pub pending_add_wallet_slot: u8,
    /// Multisig key slot to resume after an Add Wallet flow started from the wallet picker.
    pub pending_multisig_wallet_key: u8,
    pub pending_wallet_protection: seed_manager::WalletProtection,
    pub pending_wallet_activation_salt: [u8; SALT_SIZE],
    pub pending_wallet_activation_verifier: [u8; 32],
    pending_wallet_activation_state: PendingWalletActivationState,
    /// BIP39 passphrase is staged separately while wallet-protection credentials
    /// reuse the on-screen secret-entry buffer.
    pub pending_bip39_passphrase: [u8; 64],
    pub pending_bip39_passphrase_len: u8,
    pub dice_collector: mnemonic::DiceCollector,
    pub pending_seed_entropy: [u8; 32],
    pub pending_seed_entropy_valid: bool,
    pub touch_collector: mnemonic::TouchEntropyCollector,
    pub word_input: mnemonic::WordInput,
    pub pp_input: seed_manager::PassphraseInput,
    pub bip85_index: u8,
    pub bip85_child_indices: [u16; 24],
}
pub struct KeyMaterialState {
    pub acct_key_raw: [u8; 65],
    pub hex_input: [u8; 64],
    pub hex_input_len: u8,
}
impl KeyMaterialState {
    pub(in crate::runtime::data) fn new() -> Self {
        Self {
            acct_key_raw: [0; 65],
            hex_input: [0; 64],
            hex_input_len: 0,
        }
    }
}
pub struct AddressState {
    pub current_addr_index: u16,
    pub pubkey_cache: [[u8; 32]; 20],
    pub change_pubkey_cache: [[u8; 32]; 5],
    pub view_is_change: bool,
    pub partial_redraw: bool,
    pub pubkeys_cached: bool,
    pub extra_pubkey: [u8; 32],
    pub extra_pubkey_index: u16,
    pub extra_change_pubkey: [u8; 32],
    pub extra_change_pubkey_index: u16,
    pub input_buf: [u8; 5],
    pub input_len: u8,
    #[cfg(feature = "m5stack")]
    pub cache_seed_derivation: Option<offline_signer::derivation::bip39::SeedDerivation>,
    #[cfg(feature = "m5stack")]
    pub cache_worker_generation: Option<u8>,
    #[cfg(feature = "m5stack")]
    pub cache_progress: u8,
    #[cfg(feature = "m5stack")]
    pub cache_started_at_ms: u64,
    #[cfg(feature = "m5stack")]
    pub cache_last_progress_at_ms: u64,
}
impl AddressState {
    pub(in crate::runtime::data) fn new() -> Self {
        Self {
            current_addr_index: 0,
            pubkey_cache: [[0; 32]; 20],
            change_pubkey_cache: [[0; 32]; 5],
            view_is_change: false,
            partial_redraw: false,
            pubkeys_cached: false,
            extra_pubkey: [0; 32],
            extra_pubkey_index: 0xFFFF,
            extra_change_pubkey: [0; 32],
            extra_change_pubkey_index: 0xFFFF,
            input_buf: [0; 5],
            input_len: 0,
            #[cfg(feature = "m5stack")]
            cache_seed_derivation: None,
            #[cfg(feature = "m5stack")]
            cache_worker_generation: None,
            #[cfg(feature = "m5stack")]
            cache_progress: 0,
            #[cfg(feature = "m5stack")]
            cache_started_at_ms: 0,
            #[cfg(feature = "m5stack")]
            cache_last_progress_at_ms: 0,
        }
    }
}
pub struct WalletState {
    pub seeds: SeedSession,
    pub keys: KeyMaterialState,
    pub addresses: AddressState,
}
