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

// wallet/mod.rs — Kaspa wallet library
//
// Submodules:
//   - bip39: Mnemonic generation, validation, seed derivation
//   - bip32: HD derivation (master key → child keys → Kaspa path)
//   - bip85: Child mnemonic derivation
//   - schnorr: Schnorr signing (Kaspa-compatible)
//   - hmac: HMAC-SHA512, PBKDF2
//   - address: Kaspa address encoding
//   - pskt: KSPT parse/sign/serialize
//   - sighash: Transaction sighash computation
//   - transaction: Transaction/Input/Output structs
//   - xpub: Extended public key (kpub/xprv)
//   - storage: Key storage utilities

pub mod bip39;
pub mod bip32;
pub mod bip85;
pub mod schnorr;
pub mod hmac;
pub mod address;
pub mod pskt;
pub mod std_pskt;
pub mod sighash;
pub mod transaction;
pub mod xpub;
pub mod storage;
pub mod bip39_wordlist;
