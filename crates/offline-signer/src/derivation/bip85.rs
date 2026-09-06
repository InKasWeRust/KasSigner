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

// KasSigner — BIP85 Deterministic Entropy From BIP32 Keychains
// 100% Rust, no-std, no-alloc
//
// BIP85 derives child entropy (and thus child mnemonics) from a master seed.
// Each child mnemonic is a standalone wallet — deterministically reproducible
// from the parent but cryptographically independent.
//
// Derivation path: m/83_696_968'/39'/language'/words'/index'
//   - 83_696_968 = BIP number in hex (0x04F4B490... no, it's decimal for the purpose code)
//   - 39 = BIP39 mnemonic application
//   - language = 0 (English)
//   - words = 12 or 24
//   - index = child index (0, 1, 2, ...)
//
// Process:
//   1. Derive BIP32 key at the path above (all hardened)
//   2. Take the derived private key (32 bytes)
//   3. HMAC-SHA512(key="bip-entropy-from-k", message=derived_private_key) → 64 bytes
//   4. Take first 16 bytes (for 12-word) or 32 bytes (for 24-word) as entropy
//   5. Feed entropy to BIP39 mnemonic generation
//
// Security:
//   - All intermediate keys and entropy are zeroized
//   - Child mnemonics are cryptographically independent from parent
//   - Knowing a child mnemonic does NOT reveal the parent or other children

use super::bip32;
use super::bip39;
use super::bip39::{Mnemonic12, Mnemonic24};
use super::hmac::{hmac_sha512, zeroize_buf};

/// BIP32 hardened derivation bit
const HARDENED_BIT: u32 = 0x8000_0000;

// ─── Constants ──────────────────────────────────────────────────────

/// HMAC key for entropy derivation (BIP85 spec)
const BIP85_HMAC_KEY: &[u8] = b"bip-entropy-from-k";

// ─── Errors ─────────────────────────────────────────────────────────

#[derive(Debug, PartialEq)]
/// Errors during BIP85 child mnemonic derivation.
pub enum Bip85Error {
    /// BIP32 derivation failed
    DerivationFailed,
    /// Invalid word count (must be 12 or 24)
    InvalidWordCount,
}

// ─── Core BIP85 Entropy Derivation ──────────────────────────────────

/// Derive 64 bytes of entropy from a BIP39 seed at the given BIP85 path.
///
/// Path: m/83_696_968'/39'/0'/words'/index'
///
/// Returns 64 bytes of raw entropy (caller takes first 16 or 32 as needed).
fn derive_bip85_entropy(seed: &[u8; 64], words: u32, index: u32) -> Result<[u8; 64], Bip85Error> {
    // Build the BIP85 derivation path (all hardened). Fixed components use
    // their canonical serialized values; dynamic components must not already
    // carry the hardened bit.
    let hardened_words = words
        .checked_add(HARDENED_BIT)
        .ok_or(Bip85Error::DerivationFailed)?;
    let hardened_index = index
        .checked_add(HARDENED_BIT)
        .ok_or(Bip85Error::DerivationFailed)?;
    let path: [u32; 5] = [
        0x84fd_1d48, // 83_696_968'
        0x8000_0027, // 39'
        0x8000_0000, // English language 0'
        hardened_words,
        hardened_index,
    ];

    // Derive the BIP32 key at this path
    let mut derived = bip32::derive_path(seed, &path).map_err(|_| Bip85Error::DerivationFailed)?;

    // Get the derived private key
    let private_key = *derived.private_key_bytes();

    // Zeroize the extended key — we only need the raw private key bytes
    derived.zeroize();

    // HMAC-SHA512 with BIP85-specific key
    let entropy = hmac_sha512(BIP85_HMAC_KEY, &private_key);

    // Zeroize the private key copy
    let mut pk_copy = private_key;
    zeroize_buf(&mut pk_copy);

    Ok(entropy)
}

// ─── Public API ─────────────────────────────────────────────────────

/// Derive a 12-word child mnemonic from a master seed.
///
/// `seed` — 64-byte BIP39 seed (from master mnemonic + passphrase)
/// `index` — child index (0, 1, 2, ...) — each produces a different mnemonic
///
/// Returns a `Mnemonic12` with 12 word indices.
pub fn derive_mnemonic_12(seed: &[u8; 64], index: u32) -> Result<Mnemonic12, Bip85Error> {
    let mut entropy = derive_bip85_entropy(seed, 12, index)?;

    // Take first 16 bytes as BIP39 entropy for 12-word mnemonic
    let mut ent16 = [0u8; 16];
    ent16.copy_from_slice(&entropy[..16]);

    // Zeroize full 64-byte entropy
    zeroize_buf(&mut entropy);

    // Generate mnemonic from entropy
    let mnemonic = bip39::mnemonic_from_entropy_12(&ent16);

    // Zeroize the 16-byte entropy
    zeroize_buf(&mut ent16);

    crate::log!("[BIP85] Derived 12-word mnemonic at index {}", index);

    Ok(mnemonic)
}

/// Derive a 24-word child mnemonic from a master seed.
///
/// `seed` — 64-byte BIP39 seed (from master mnemonic + passphrase)
/// `index` — child index (0, 1, 2, ...) — each produces a different mnemonic
///
/// Returns a `Mnemonic24` with 24 word indices.
pub fn derive_mnemonic_24(seed: &[u8; 64], index: u32) -> Result<Mnemonic24, Bip85Error> {
    let mut entropy = derive_bip85_entropy(seed, 24, index)?;

    // Take first 32 bytes as BIP39 entropy for 24-word mnemonic
    let mut ent32 = [0u8; 32];
    ent32.copy_from_slice(&entropy[..32]);

    // Zeroize full 64-byte entropy
    zeroize_buf(&mut entropy);

    // Generate mnemonic from entropy
    let mnemonic = bip39::mnemonic_from_entropy_24(&ent32);

    // Zeroize the 32-byte entropy
    zeroize_buf(&mut ent32);

    crate::log!("[BIP85] Derived 24-word mnemonic at index {}", index);

    Ok(mnemonic)
}

#[cfg(not(feature = "skip-tests"))]
#[path = "unit_tests/bip85_tests.rs"]
pub mod unit_tests;
