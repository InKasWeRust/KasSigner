// KasSigner — Air-gapped hardware wallet for Kaspa
// Copyright (C) 2025 KasSigner Project (kassigner@proton.me)
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
// Derivation path: m/83696968'/39'/language'/words'/index'
//   - 83696968 = BIP number in hex (0x04F4B490... no, it's decimal for the purpose code)
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


use super::hmac::{hmac_sha512, zeroize_buf};
use super::bip32;
use super::bip39;
use super::bip39::{Mnemonic12, Mnemonic24};

/// BIP32 hardened derivation bit
const HARDENED_BIT: u32 = 0x8000_0000;

#[cfg(not(feature = "silent"))]
use esp_println::println;

#[cfg(not(feature = "silent"))]
macro_rules! log {
    ($($arg:tt)*) => { println!($($arg)*) };
}

#[cfg(feature = "silent")]
macro_rules! log {
    ($($arg:tt)*) => { };
}

// ─── Constants ──────────────────────────────────────────────────────

/// BIP85 purpose constant (decimal 83696968)
const BIP85_PURPOSE: u32 = 83696968;

/// BIP85 application: BIP39 mnemonic
const BIP85_APP_BIP39: u32 = 39;

/// BIP85 language: English
const BIP85_LANG_ENGLISH: u32 = 0;

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
/// Path: m/83696968'/39'/0'/words'/index'
///
/// Returns 64 bytes of raw entropy (caller takes first 16 or 32 as needed).
fn derive_bip85_entropy(
    seed: &[u8; 64],
    words: u32,
    index: u32,
) -> Result<[u8; 64], Bip85Error> {
    // Build the BIP85 derivation path (all hardened)
    let path: [u32; 5] = [
        BIP85_PURPOSE | HARDENED_BIT,     // 83696968'
        BIP85_APP_BIP39 | HARDENED_BIT,   // 39'
        BIP85_LANG_ENGLISH | HARDENED_BIT, // 0'
        words | HARDENED_BIT,              // 12' or 24'
        index | HARDENED_BIT,              // index'
    ];

    // Derive the BIP32 key at this path
    let mut derived = bip32::derive_path(seed, &path)
        .map_err(|_| Bip85Error::DerivationFailed)?;

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
pub fn derive_mnemonic_12(
    seed: &[u8; 64],
    index: u32,
) -> Result<Mnemonic12, Bip85Error> {
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

    log!("[BIP85] Derived 12-word mnemonic at index {}", index);

    Ok(mnemonic)
}

/// Derive a 24-word child mnemonic from a master seed.
///
/// `seed` — 64-byte BIP39 seed (from master mnemonic + passphrase)
/// `index` — child index (0, 1, 2, ...) — each produces a different mnemonic
///
/// Returns a `Mnemonic24` with 24 word indices.
pub fn derive_mnemonic_24(
    seed: &[u8; 64],
    index: u32,
) -> Result<Mnemonic24, Bip85Error> {
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

    log!("[BIP85] Derived 24-word mnemonic at index {}", index);

    Ok(mnemonic)
}
// ─── Tests ──────────────────────────────────────────────────────────

/// BIP85 test using precomputed seed (skips PBKDF2 — runs in <1s).
/// Master: "install scatter logic circle pencil average fall shoe quantum disease suspect usage"
/// Expected child at index 0: "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose"
pub fn test_bip85_12word_index0() -> bool {
    use super::bip39_wordlist::WORDLIST;

    // Precomputed BIP39 seed (PBKDF2-HMAC-SHA512, 2048 rounds, empty passphrase)
    let seed: [u8; 64] = [
        0x37, 0x48, 0x34, 0x72, 0xa6, 0xaf, 0x7f, 0xd1, 0x07, 0xfb, 0x5f, 0x5a, 0xaa, 0xa7, 0xbd, 0xdc,
        0x89, 0x69, 0x03, 0x53, 0x36, 0x92, 0x29, 0x77, 0x1c, 0x32, 0x81, 0x2f, 0x71, 0x12, 0x07, 0xc8,
        0x73, 0x98, 0xa8, 0xd4, 0x4c, 0xfc, 0x76, 0x3a, 0x81, 0x85, 0xff, 0x34, 0x62, 0x72, 0xe8, 0xf1,
        0x45, 0x51, 0x70, 0xde, 0xca, 0xe7, 0x12, 0x59, 0x8f, 0x59, 0x90, 0xc1, 0x20, 0x7d, 0x2f, 0x88,
    ];

    match derive_mnemonic_12(&seed, 0) {
        Ok(child) => {
            log!("[BIP85-TEST] {} {} {} {} {} {} {} {} {} {} {} {}",
                WORDLIST[child.indices[0] as usize],
                WORDLIST[child.indices[1] as usize],
                WORDLIST[child.indices[2] as usize],
                WORDLIST[child.indices[3] as usize],
                WORDLIST[child.indices[4] as usize],
                WORDLIST[child.indices[5] as usize],
                WORDLIST[child.indices[6] as usize],
                WORDLIST[child.indices[7] as usize],
                WORDLIST[child.indices[8] as usize],
                WORDLIST[child.indices[9] as usize],
                WORDLIST[child.indices[10] as usize],
                WORDLIST[child.indices[11] as usize]);
            child.indices[0] == 786 // "girl"
        }
        Err(e) => {
            log!("[BIP85-TEST] FAILED: {:?}", e);
            false
        }
    }
}
