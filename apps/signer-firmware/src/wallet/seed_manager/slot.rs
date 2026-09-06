// KasSigner — Air-gapped offline signing device for Kaspa
//! One volatile wallet-source slot and its secure lifecycle.
use sha2::{Digest, Sha256};

/// Maximum wallet slots in RAM.
pub const MAX_SLOTS: usize = 16;

use super::{WalletNetwork, WalletProtection, WalletSource};

pub const WALLET_NAME_MAX: usize = 20;

/// A single volatile wallet slot.
pub struct SeedSlot {
    /// BIP39 indices or packed raw-key/account-key bytes.
    pub indices: [u16; 24],
    pub source: WalletSource,
    /// Saved-wallet network namespace.
    pub network: WalletNetwork,
    /// User-presence policy required before this slot can become active.
    pub protection: WalletProtection,
    /// RAM-only current-session wallet; never serialized.
    pub transient: bool,
    /// User-visible non-secret wallet label, persisted separately.
    pub name: [u8; WALLET_NAME_MAX],
    pub name_len: u8,
    /// BIP39 passphrase or the second half of a packed account XPrv.
    pub passphrase: [u8; 64],
    pub passphrase_len: u8,
    /// Original BIP32 parent fingerprint for exact account-XPrv re-export.
    pub account_parent_fingerprint: [u8; 4],
    /// SHA-256-derived visual identifier.
    pub fingerprint: [u8; 4],
}

impl SeedSlot {
    pub const fn empty() -> Self {
        Self {
            indices: [0; 24],
            source: WalletSource::Empty,
            network: WalletNetwork::Mainnet,
            protection: WalletProtection::DeviceOnly,
            transient: false,
            name: [0; WALLET_NAME_MAX],
            name_len: 0,
            passphrase: [0; 64],
            passphrase_len: 0,
            account_parent_fingerprint: [0; 4],
            fingerprint: [0; 4],
        }
    }
    pub const fn is_empty(&self) -> bool {
        matches!(self.source, WalletSource::Empty)
    }
    pub const fn is_mnemonic(&self) -> bool {
        matches!(self.source, WalletSource::Mnemonic12 | WalletSource::Mnemonic24)
    }

    pub fn name_str(&self) -> &str {
        let len = usize::from(self.name_len).min(WALLET_NAME_MAX);
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }

    pub fn set_name(&mut self, value: &[u8]) -> bool {
        if value.len() > WALLET_NAME_MAX || core::str::from_utf8(value).is_err() { return false; }
        shared_signer::bytes::zeroize_bytes(&mut self.name);
        self.name[..value.len()].copy_from_slice(value);
        self.name_len = value.len() as u8;
        true
    }

    pub const fn mnemonic_word_count(&self) -> Option<u8> {
        self.source.mnemonic_word_count()
    }

    pub fn set_mnemonic_source(&mut self, word_count: u8) -> bool {
        self.source = match word_count {
            12 => WalletSource::Mnemonic12,
            24 => WalletSource::Mnemonic24,
            _ => return false,
        };
        true
    }

    pub fn set_account_key_raw(
        &mut self,
        raw: &[u8; 65],
        parent_fingerprint: [u8; 4],
        fingerprint: [u8; 4],
    ) {
        self.zeroize();
        self.source = WalletSource::AccountXprv;
        for (word, pair) in self.indices[..16].iter_mut().zip(raw[..32].chunks_exact(2)) {
            *word = u16::from_le_bytes([pair[0], pair[1]]);
        }
        self.passphrase[..32].copy_from_slice(&raw[32..64]);
        self.passphrase[32] = raw[64];
        self.passphrase_len = 33;
        self.account_parent_fingerprint = parent_fingerprint;
        self.fingerprint = fingerprint;
    }

    pub fn account_key_raw(&self, out: &mut [u8; 65]) -> bool {
        shared_signer::bytes::zeroize_bytes(out);
        if !self.is_account_key() || self.passphrase_len != 33 {
            return false;
        }
        for (word, destination) in self.indices[..16]
            .iter()
            .zip(out[..32].chunks_exact_mut(2))
        {
            destination.copy_from_slice(&word.to_le_bytes());
        }
        out[32..64].copy_from_slice(&self.passphrase[..32]);
        out[64] = self.passphrase[32];
        true
    }

    /// Compute a mnemonic fingerprint including its BIP39 passphrase.
    pub fn compute_fingerprint(&mut self) -> bool {
        let Some(word_count) = self.mnemonic_word_count() else {
            return false;
        };
        let mut entropy = [0u8; 33];
        let mut bit_position = 0usize;
        for index in self.indices.iter().take(usize::from(word_count)) {
            for bit in (0..11).rev() {
                let byte_index = bit_position / 8;
                let bit_index = 7 - bit_position % 8;
                if (index >> bit) & 1 == 1 {
                    entropy[byte_index] |= 1 << bit_index;
                }
                bit_position += 1;
            }
        }

        let entropy_len = if word_count == 12 { 16 } else { 32 };
        let mut hasher = Sha256::new();
        hasher.update(&entropy[..entropy_len]);
        let passphrase_len = usize::from(self.passphrase_len).min(self.passphrase.len());
        hasher.update(&self.passphrase[..passphrase_len]);
        self.fingerprint.copy_from_slice(&hasher.finalize()[..4]);
        shared_signer::bytes::zeroize_bytes(&mut entropy);
        true
    }

    pub fn passphrase_str(&self) -> &str {
        if !self.is_mnemonic() {
            return "";
        }
        core::str::from_utf8(&self.passphrase[..usize::from(self.passphrase_len)]).unwrap_or("")
    }

    pub fn fingerprint_hex(&self, buffer: &mut [u8; 8]) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for (index, byte) in self.fingerprint.iter().enumerate() {
            buffer[index * 2] = HEX[(byte >> 4) as usize];
            buffer[index * 2 + 1] = HEX[(byte & 0x0f) as usize];
        }
    }

    pub fn zeroize(&mut self) {
        shared_signer::bytes::zeroize_u16(&mut self.indices);
        shared_signer::bytes::zeroize_bytes(&mut self.passphrase);
        self.source = WalletSource::Empty;
        self.network = WalletNetwork::Mainnet;
        self.protection = WalletProtection::DeviceOnly;
        self.transient = false;
        shared_signer::bytes::zeroize_bytes(&mut self.name);
        shared_signer::bytes::volatile_clear(core::slice::from_mut(&mut self.name_len), 0u8);
        shared_signer::bytes::volatile_clear(core::slice::from_mut(&mut self.passphrase_len), 0u8);
        shared_signer::bytes::zeroize_bytes(&mut self.account_parent_fingerprint);
        shared_signer::bytes::zeroize_bytes(&mut self.fingerprint);
    }
}

impl Drop for SeedSlot {
    fn drop(&mut self) {
        self.zeroize();
    }
}
