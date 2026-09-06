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

// ─── Constants ───────────────────────────────────────────────────────

/// BIP32 key for master key HMAC
pub(super) const BITCOIN_SEED: &[u8] = b"Bitcoin seed";

/// secp256k1 curve order (n)
/// n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
pub(super) const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// Hardened derivation flag bit (0x80000000)
pub(super) const HARDENED_BIT: u32 = 0x8000_0000;

// ─── Kaspa derivation paths ───────────────────────────────────────────

/// Kaspa mainnet path: m/44'/111111'/0'/0/0
pub const KASPA_MAINNET_PATH: &[u32] = &[
    0x8000_002c, // purpose (BIP44)
    0x8001_b207, // coin_type (Kaspa, SLIP-44)
    0x8000_0000, // account 0
    0,           // change (external)
    0,           // address_index 0
];

/// Kaspa testnet path: m/44'/1'/0'/0/0
pub const KASPA_TESTNET_PATH: &[u32] = &[0x8000_002c, 0x8000_0001, 0x8000_0000, 0, 0];

/// Kaspa account-level path: m/44'/111111'/0' (3 hardened levels)
/// From here we derive /0/index for each receive address.
pub(super) const KASPA_ACCOUNT_PATH: [u32; 3] = [
    0x8000_002c, // purpose (BIP44)
    0x8001_b207, // coin_type (Kaspa)
    0x8000_0000, // account 0
];

/// Kaspa coordinated multisig account prefix: m/45'/111111'.
/// The account component is appended hardened by `derive_multisig_account_key`.
pub(super) const KASPA_MULTISIG_ACCOUNT_PREFIX: [u32; 2] = [
    0x8000_002d, // purpose 45' (coordinated multisig)
    0x8001_b207, // coin_type 111111' (Kaspa)
];
/// Number of addresses pre-cached on seed load (0..=19)
pub const CACHED_ADDR_COUNT: usize = 20;
