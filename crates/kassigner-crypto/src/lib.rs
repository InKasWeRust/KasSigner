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

//! Key material.
//!
//! Everything that touches a private key lives here, and nothing here is
//! published. `cargo tree -p kassigner-sdk` must never list this crate; the
//! level model exists to make that checkable, and `kassigner-sdk`'s
//! `tests/no_keys.rs` checks it at every test run.
//!
//! BIP32 is split at the private key: `CKDpub` is at level 0, in
//! `kassigner_kaspa::bip32_public`, for an integrator deriving addresses from
//! an extended public key, who must never reach `CKDpriv`, which is here.
//!
//! Nothing here generates randomness: a seed generator takes it as an
//! argument. Its source is level 3's hardware question, and an RNG here would
//! be untestable and pull `getrandom` into a `no_std` build.
//!
//! Every type holding key material wipes itself on drop, and a signing nonce
//! is wiped at its last use like the key: a released signature and its nonce
//! give the private key, `d = (s - k) * e^-1`.

#![no_std]
#![forbid(unsafe_code)]

pub mod backup;
pub mod bip32;
pub mod bip39;
pub mod bip85;
pub mod container;
mod curve;
pub mod ecies;
/// Known answers for a device to run at boot.
pub mod kat;
pub mod password;
pub mod seed;
pub mod sign;
pub mod slot;
pub mod stego;
pub mod wallet;
pub mod wordlist;
