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

use super::{
    child::{derive_child, master_key_from_seed},
    constants::{HARDENED_BIT, KASPA_ACCOUNT_PATH, KASPA_MULTISIG_ACCOUNT_PREFIX},
    error::Bip32Error,
    extended_private::ExtendedPrivKey,
};

/// Derive along a complete path (e.g. m/44'/111111'/0'/0/0).
///
/// Each path element is a u32. The HARDENED_BIT (0x80000000)
/// indicates hardened derivation (marked with ' in notation).
pub fn derive_path(seed: &[u8; 64], path: &[u32]) -> Result<ExtendedPrivKey, Bip32Error> {
    if path.is_empty() {
        return Err(Bip32Error::EmptyPath);
    }

    let mut current = master_key_from_seed(seed)?;

    for &index in path.iter() {
        let child = derive_child(&current, index)?;
        current.zeroize(); // Zeroize parent before overwriting
        current = child;
    }

    Ok(current)
}

/// Resumable account-key derivation for constrained embedded stacks.
///
/// Each call to [`advance_one`] performs at most one BIP32 child derivation.
/// The current extended private key stays inside this object between calls and
/// is zeroized automatically through `ExtendedPrivKey`'s drop implementation.
pub struct AccountKeyDerivation {
    current: ExtendedPrivKey,
    next_step: usize,
}

impl AccountKeyDerivation {
    /// Start at the BIP32 master key. No child derivation is performed here.
    #[inline(never)]
    pub fn new(seed: &[u8; 64]) -> Result<Self, Bip32Error> {
        Ok(Self {
            current: master_key_from_seed(seed)?,
            next_step: 0,
        })
    }

    /// Wrap an already-derived account key so serialization can be deferred to
    /// its own shallow call frame.
    pub fn from_account_key(account: ExtendedPrivKey) -> Self {
        Self {
            current: account,
            next_step: KASPA_ACCOUNT_PATH.len(),
        }
    }

    /// Advance by exactly one account-path component. Returns `true` once the
    /// account key at m/44'/111111'/0' is ready.
    #[inline(never)]
    pub fn advance_one(&mut self) -> Result<bool, Bip32Error> {
        if self.is_complete() {
            return Ok(true);
        }
        let child = derive_child(&self.current, KASPA_ACCOUNT_PATH[self.next_step])?;
        self.current.zeroize();
        self.current = child;
        self.next_step += 1;
        Ok(self.is_complete())
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.next_step == KASPA_ACCOUNT_PATH.len()
    }

    #[must_use]
    pub fn completed_steps(&self) -> usize {
        self.next_step
    }

    /// Consume a completed derivation. Incomplete work fails closed.
    pub fn finish(self) -> Result<ExtendedPrivKey, Bip32Error> {
        if !self.is_complete() {
            return Err(Bip32Error::InvalidKey);
        }
        Ok(self.current)
    }
}

/// Derive the Kaspa account key at m/44'/111111'/0'.
/// This is expensive (3 hardened derivations with HMAC-SHA512 each),
/// but only needs to be done once per seed load.
pub fn derive_account_key(seed: &[u8; 64]) -> Result<ExtendedPrivKey, Bip32Error> {
    derive_path(seed, &KASPA_ACCOUNT_PATH)
}

/// From an account key (m/44'/111111'/0'), derive the key at /0/index.
/// This is cheap: just 2 normal (non-hardened) child derivations.
/// Any index up to 2^31-1 is valid (BIP32 normal child).
pub fn derive_address_key(
    account_key: &ExtendedPrivKey,
    index: u32,
) -> Result<ExtendedPrivKey, Bip32Error> {
    // m/44'/111111'/0' → /0 (external chain)
    let change_key = derive_child(account_key, 0)?;
    // /0 → /index (address index)
    let addr_key = derive_child(&change_key, index)?;
    Ok(addr_key)
}

/// From an account key (m/44'/111111'/0'), derive the CHANGE key at /1/index.
/// Change addresses use the internal chain (index 1) per BIP44.
/// Used to verify that TX outputs returning funds to our wallet are legitimate.
pub fn derive_change_key(
    account_key: &ExtendedPrivKey,
    index: u32,
) -> Result<ExtendedPrivKey, Bip32Error> {
    // m/44'/111111'/0' → /1 (internal/change chain)
    let internal_key = derive_child(account_key, 1)?;
    // /1 → /index (change address index)
    let addr_key = derive_child(&internal_key, index)?;
    Ok(addr_key)
}

/// Derive a full Kaspa address key at m/44'/111111'/0'/0/{index} from seed.
/// Convenience function when you don't have a cached account key.
pub fn derive_path_for_index(seed: &[u8; 64], index: u32) -> Result<ExtendedPrivKey, Bip32Error> {
    let path: [u32; 5] = [
        KASPA_ACCOUNT_PATH[0],
        KASPA_ACCOUNT_PATH[1],
        KASPA_ACCOUNT_PATH[2],
        0,
        index,
    ];
    derive_path(seed, &path)
}

/// Derive the coordinated multisig account key at
/// `m/45'/111111'/account'`. New multisig wallets use account 0.
pub fn derive_multisig_account_key(
    seed: &[u8; 64],
    account: u32,
) -> Result<ExtendedPrivKey, Bip32Error> {
    if account >= 0x8000_0000 {
        return Err(Bip32Error::InvalidKey);
    }
    let path = [
        KASPA_MULTISIG_ACCOUNT_PREFIX[0],
        KASPA_MULTISIG_ACCOUNT_PREFIX[1],
        HARDENED_BIT + account,
    ];
    derive_path(seed, &path)
}

/// Derive a coordinated-multisig address key beneath a 45' account key.
/// The child path is `/cosigner/chain/index`; all three components are
/// non-hardened so every cosigner can reconstruct the same redeem script.
pub fn derive_multisig_address_key(
    account_key: &ExtendedPrivKey,
    cosigner: u32,
    chain: u32,
    index: u32,
) -> Result<ExtendedPrivKey, Bip32Error> {
    if cosigner >= 0x8000_0000 || chain > 1 || index >= 0x8000_0000 {
        return Err(Bip32Error::InvalidKey);
    }
    let cosigner_key = derive_child(account_key, cosigner)?;
    let chain_key = derive_child(&cosigner_key, chain)?;
    derive_child(&chain_key, index)
}
