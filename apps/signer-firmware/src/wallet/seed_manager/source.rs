// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Authoritative wallet-source classification.

/// Volatile wallet material accepted by the signer.
///
/// Source type and mnemonic length are intentionally distinct so raw keys and
/// account XPrvs cannot enter mnemonic-only derivation paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletSource {
    Empty,
    Mnemonic12,
    Mnemonic24,
    RawPrivateKey,
    AccountXprv,
}

impl WalletSource {
    pub const fn mnemonic_word_count(self) -> Option<u8> {
        match self {
            Self::Mnemonic12 => Some(12),
            Self::Mnemonic24 => Some(24),
            _ => None,
        }
    }

    pub const fn display_label(self) -> &'static str {
        match self {
            Self::Empty => "??",
            Self::Mnemonic12 => "12w",
            Self::Mnemonic24 => "24w",
            Self::RawPrivateKey => "KEY",
            Self::AccountXprv => "xprv",
        }
    }

    pub const fn deletion_label(self) -> &'static str {
        match self {
            Self::Empty => "wallet",
            Self::Mnemonic12 => "12-word seed",
            Self::Mnemonic24 => "24-word seed",
            Self::RawPrivateKey => "private key",
            Self::AccountXprv => "account xprv",
        }
    }
}


use super::SeedSlot;

impl SeedSlot {
    pub const fn is_raw_key(&self) -> bool {
        matches!(self.source, WalletSource::RawPrivateKey)
    }

    pub const fn is_account_key(&self) -> bool {
        matches!(self.source, WalletSource::AccountXprv)
    }

    /// The 32 raw-key bytes are packed into indices[0..16] as LE u16 pairs.
    pub fn raw_key_bytes(&self, out: &mut [u8; 32]) -> bool {
        shared_signer::bytes::zeroize_bytes(out);
        if !self.is_raw_key() { return false; }
        for index in 0..16 {
            let pair = self.indices[index].to_le_bytes();
            out[index * 2] = pair[0];
            out[index * 2 + 1] = pair[1];
        }
        true
    }
}
