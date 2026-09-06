//! Wallet-domain volatile scrubbing helpers.

use super::{KeyMaterialState, SeedSession};
use crate::wallet::seed_manager::WalletSource;

impl SeedSession {
    pub fn zeroize_transient(&mut self) {
        self.seed_mgr.zeroize_all();
        shared_signer::bytes::zeroize_u16(&mut self.mnemonic_indices);
        shared_signer::bytes::zeroize_u16(&mut self.bip85_child_indices);
        self.clear_pending_seed_entropy();
        self.dice_collector.zeroize();
        self.touch_collector.zeroize();
        self.word_input.reset();
        self.pp_input.reset();
        self.word_count = 0;
        self.active_source = WalletSource::Empty;
        self.seed_loaded = false;
        self.seed_list_scroll = 0;
        self.pending_delete_slot = u8::MAX;
        self.bip85_index = 0;
    }
}

impl KeyMaterialState {
    pub fn zeroize_sensitive(&mut self) {
        shared_signer::bytes::zeroize_bytes(&mut self.acct_key_raw);
        shared_signer::bytes::zeroize_bytes(&mut self.hex_input);
        self.hex_input_len = 0;
    }
}
