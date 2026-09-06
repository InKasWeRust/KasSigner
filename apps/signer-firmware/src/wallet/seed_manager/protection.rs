// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Per-wallet activation protection layered over device-bound persistence.

use crate::services::credential_policy::CredentialKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletProtection {
    /// No user credential; activation is intentionally available to anyone
    /// holding the device, while at-rest storage remains device-bound encrypted.
    DeviceOnly,
    Pin,
    Password,
}

impl Default for WalletProtection {
    fn default() -> Self { Self::DeviceOnly }
}

impl WalletProtection {
    pub const fn credential_kind(self) -> Option<CredentialKind> {
        match self {
            Self::Pin => Some(CredentialKind::Pin),
            Self::Password => Some(CredentialKind::Password),
            Self::DeviceOnly => None,
        }
    }

    pub(crate) const fn slot_code(self) -> u8 {
        match self {
            Self::DeviceOnly => 1,
            Self::Pin => 2,
            Self::Password => 3,
        }
    }

    pub(crate) const fn from_slot_code(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::DeviceOnly),
            2 => Some(Self::Pin),
            3 => Some(Self::Password),
            _ => None,
        }
    }
}


impl super::SeedManager {
    pub fn set_slot_protection(&mut self, slot_index: usize, protection: WalletProtection) -> bool {
        if slot_index >= super::MAX_SLOTS || self.slots[slot_index].is_empty() { return false; }
        if self.slots[slot_index].protection == protection { return true; }
        self.slots[slot_index].protection = protection;
        self.mark_changed();
        true
    }
}
