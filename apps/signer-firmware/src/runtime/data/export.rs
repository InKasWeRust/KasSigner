// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// runtime/data/export.rs — ExportState


pub struct ExportState {
    pub export_key_hex: [u8; 64],
    pub kpub_data: [u8; offline_signer::derivation::xpub::KPUB_MAX_LEN],
    pub kpub_len: usize,
    /// Volatile public Connect-KasSee cache. Never persisted; invalidated when
    /// the active wallet context changes and naturally disappears at power-off.
    connect_kpub_cache: [u8; offline_signer::derivation::xpub::KPUB_MAX_LEN],
    connect_kpub_cache_len: usize,
    pub kpub_progress: u8,
    #[cfg(any(feature = "m5stack", feature = "waveshare"))]
    pub kpub_seed_derivation: Option<offline_signer::derivation::bip39::SeedDerivation>,
    #[cfg(feature = "waveshare")]
    pub kpub_account_derivation: Option<offline_signer::derivation::bip32::AccountKeyDerivation>,
    #[cfg(feature = "m5stack")]
    pub kpub_worker_generation: Option<u8>,
    #[cfg(feature = "m5stack")]
    pub multisig_seed_derivation: Option<offline_signer::derivation::bip39::SeedDerivation>,
    #[cfg(feature = "m5stack")]
    pub multisig_worker_generation: Option<u8>,
    pub xprv_data: [u8; offline_signer::derivation::xpub::XPRV_MAX_LEN],
    pub xprv_len: usize,
}

impl ExportState {

    pub fn connect_kpub_cached(&self) -> bool {
        self.connect_kpub_cache_len != 0
            && self.connect_kpub_cache_len <= self.connect_kpub_cache.len()
    }

    pub fn cache_connect_kpub(&mut self, encoded: &[u8]) {
        self.clear_connect_kpub_cache();
        if encoded.is_empty() || encoded.len() > self.connect_kpub_cache.len() {
            return;
        }
        self.connect_kpub_cache[..encoded.len()].copy_from_slice(encoded);
        self.connect_kpub_cache_len = encoded.len();
    }

    pub fn restore_connect_kpub(&mut self) -> bool {
        if !self.connect_kpub_cached() {
            return false;
        }
        shared_signer::bytes::zeroize_bytes(&mut self.kpub_data);
        let length = self.connect_kpub_cache_len;
        self.kpub_data[..length].copy_from_slice(&self.connect_kpub_cache[..length]);
        self.kpub_len = length;
        self.reset_kpub_work();
        true
    }

    pub fn clear_connect_kpub_cache(&mut self) {
        shared_signer::bytes::zeroize_bytes(&mut self.connect_kpub_cache);
        self.connect_kpub_cache_len = 0;
    }
    pub fn reset_kpub_work(&mut self) {
        self.kpub_progress = 0;
        #[cfg(any(feature = "m5stack", feature = "waveshare"))]
        {
            self.kpub_seed_derivation = None;
        }
        #[cfg(feature = "waveshare")]
        {
            self.kpub_account_derivation = None;
        }
        #[cfg(feature = "m5stack")]
        {
            self.kpub_worker_generation = None;
        }
    }


    pub fn reset_multisig_kpub_work(&mut self) {
        #[cfg(feature = "m5stack")]
        {
            self.multisig_seed_derivation = None;
            self.multisig_worker_generation = None;
        }
        self.kpub_progress = 0;
    }

    pub fn zeroize_sensitive(&mut self) {
        shared_signer::bytes::zeroize_bytes(&mut self.export_key_hex);
        shared_signer::bytes::zeroize_bytes(&mut self.kpub_data);
        shared_signer::bytes::zeroize_bytes(&mut self.xprv_data);
        self.kpub_len = 0;
        self.clear_connect_kpub_cache();
        self.xprv_len = 0;
        self.reset_kpub_work();
        self.reset_multisig_kpub_work();
    }

    pub(super) fn new() -> Self {
        Self {
            export_key_hex: [0u8; 64],
            kpub_data: [0u8; offline_signer::derivation::xpub::KPUB_MAX_LEN],
            kpub_len: 0,
            connect_kpub_cache: [0u8; offline_signer::derivation::xpub::KPUB_MAX_LEN],
            connect_kpub_cache_len: 0,
            kpub_progress: 0,
            #[cfg(any(feature = "m5stack", feature = "waveshare"))]
            kpub_seed_derivation: None,
            #[cfg(feature = "waveshare")]
            kpub_account_derivation: None,
            #[cfg(feature = "m5stack")]
            kpub_worker_generation: None,
            #[cfg(feature = "m5stack")]
            multisig_seed_derivation: None,
            #[cfg(feature = "m5stack")]
            multisig_worker_generation: None,
            xprv_data: [0u8; offline_signer::derivation::xpub::XPRV_MAX_LEN],
            xprv_len: 0,
        }
    }
}
