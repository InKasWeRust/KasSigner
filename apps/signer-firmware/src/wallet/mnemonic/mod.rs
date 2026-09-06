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

// Stable mnemonic-domain facade. Focused modules own dice entropy,
// mnemonic generation, checksum calculation, and word input.

mod checksum;
mod generation;
mod dice;
mod touch;
mod word_input;
mod validation;

pub use checksum::{calc_last_word_12, calc_last_word_24};
pub use generation::{generate_from_dice, generate_from_entropy};
pub use dice::DiceCollector;
pub use touch::TouchEntropyCollector;
pub use word_input::WordInput;
pub use validation::{complete_last_word, validate};

#[cfg(any(test, feature = "verbose-boot"))]
use offline_signer::derivation::bip39;

#[cfg(any(test, feature = "verbose-boot"))]
#[path = "../unit_tests/mnemonic_tests.rs"]
pub mod unit_tests;
