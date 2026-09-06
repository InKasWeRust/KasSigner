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

// Stable seed-management facade. Storage, QR codecs, and passphrase
// editing remain independently owned.

mod manager;
mod matching;
mod mnemonic_store;
mod network;
mod passphrase;
mod protection;
mod seedqr;
mod slot;
mod source;

pub use manager::SeedManager;
pub use network::WalletNetwork;
pub use passphrase::PassphraseInput;
pub use protection::WalletProtection;
pub use seedqr::{decode_compact_seedqr, decode_seedqr, encode_compact_seedqr, encode_seedqr};
pub use slot::{SeedSlot, MAX_SLOTS, WALLET_NAME_MAX};
pub use source::WalletSource;

#[cfg(any(test, feature = "verbose-boot"))]
#[path = "../unit_tests/seed_manager_tests.rs"]
pub mod unit_tests;
