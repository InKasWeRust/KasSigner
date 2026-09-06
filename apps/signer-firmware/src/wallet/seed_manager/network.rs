// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Network namespace for saved wallet slots.

/// Logical Kaspa network namespace for saved wallet slots.
///
/// Testnet-10 and Testnet-12 share Kaspa's testnet address prefix, but remain
/// separate local namespaces so saved wallets cannot be selected across them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletNetwork {
    Mainnet,
    Testnet10,
    Testnet12,
}

impl Default for WalletNetwork {
    fn default() -> Self { Self::Mainnet }
}

impl WalletNetwork {
    pub const fn short_label(self) -> &'static str {
        match self {
            Self::Mainnet => "Main",
            Self::Testnet10 => "Test-10",
            Self::Testnet12 => "Test-12",
        }
    }

    #[cfg(feature = "developer-ui")]
    pub const fn menu_label(self) -> &'static str {
        match self {
            Self::Mainnet => "Mainnet",
            Self::Testnet10 => "Testnet-10",
            Self::Testnet12 => "Testnet-12",
        }
    }

    pub const fn kaspa_network(self) -> offline_signer::address::KaspaNetwork {
        match self {
            Self::Mainnet => offline_signer::address::KaspaNetwork::Mainnet,
            Self::Testnet10 | Self::Testnet12 => offline_signer::address::KaspaNetwork::Testnet,
        }
    }

    pub const fn matches_transaction_network(
        self,
        network: offline_signer::address::KaspaNetwork,
    ) -> bool {
        self.kaspa_network() as u8 == network as u8
    }

    pub(crate) const fn preference_code(self) -> u8 {
        match self { Self::Mainnet => 0, Self::Testnet10 => 1, Self::Testnet12 => 2 }
    }

    pub(crate) const fn from_preference_code(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Mainnet),
            1 => Some(Self::Testnet10),
            2 => Some(Self::Testnet12),
            _ => None,
        }
    }

    pub(crate) const fn slot_tag(self) -> u8 { self.preference_code() }
    pub(crate) const fn from_slot_tag(value: u8) -> Option<Self> {
        Self::from_preference_code(value)
    }
}

use super::{SeedManager, MAX_SLOTS};

impl SeedManager {
    pub const fn network(&self) -> WalletNetwork { self.selected_network }

    /// Switch the visible wallet namespace and drop any active selection from
    /// the previous network. Slot material remains encrypted/persisted in its
    /// own tagged namespace.
    pub fn set_network(&mut self, network: WalletNetwork) {
        if self.selected_network == network { return; }
        self.selected_network = network;
        if self.active < MAX_SLOTS as u8 && !self.slot_visible(self.active as usize) {
            self.active = u8::MAX;
        }
    }

    pub fn slot_visible(&self, slot_idx: usize) -> bool {
        slot_idx < MAX_SLOTS
            && !self.slots[slot_idx].is_empty()
            && self.slots[slot_idx].network == self.selected_network
    }
}
