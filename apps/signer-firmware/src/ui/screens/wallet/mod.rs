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


// Wallet, seed, address, export, and multisig screens.

// One geometry source for both rendering and touch hit-testing.
pub(super) const WORD_COUNT_BUTTON_X: u16 = 30;
pub(super) const WORD_COUNT_BUTTON_WIDTH: u16 = 260;
pub(super) const WORD_COUNT_BUTTON_HEIGHT: u16 = 60;
pub(super) const WORD_COUNT_12_Y: u16 = 70;
pub(super) const WORD_COUNT_24_Y: u16 = 150;

pub(crate) fn word_count_choice_at(x: u16, y: u16) -> Option<u8> {
    let x_end = WORD_COUNT_BUTTON_X + WORD_COUNT_BUTTON_WIDTH;
    if x < WORD_COUNT_BUTTON_X || x > x_end {
        return None;
    }
    let y12_end = WORD_COUNT_12_Y + WORD_COUNT_BUTTON_HEIGHT;
    if y >= WORD_COUNT_12_Y && y <= y12_end {
        return Some(12);
    }
    let y24_end = WORD_COUNT_24_Y + WORD_COUNT_BUTTON_HEIGHT;
    if y >= WORD_COUNT_24_Y && y <= y24_end {
        return Some(24);
    }
    None
}


pub(super) const ENTROPY_RECOVERY_BUTTON_Y: u16 = 172;
pub(super) const ENTROPY_RECOVERY_BUTTON_HEIGHT: u16 = 44;
pub(super) const ENTROPY_RECOVERY_LEFT_X: u16 = 18;
pub(super) const ENTROPY_RECOVERY_RIGHT_X: u16 = 166;
pub(super) const ENTROPY_RECOVERY_BUTTON_WIDTH: u16 = 136;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntropyRecoveryChoice {
    Retry,
    Cancel,
}

pub(crate) fn entropy_recovery_choice_at(x: u16, y: u16) -> Option<EntropyRecoveryChoice> {
    let y_end = ENTROPY_RECOVERY_BUTTON_Y + ENTROPY_RECOVERY_BUTTON_HEIGHT;
    if y < ENTROPY_RECOVERY_BUTTON_Y || y > y_end { return None; }
    if (ENTROPY_RECOVERY_LEFT_X..=ENTROPY_RECOVERY_LEFT_X + ENTROPY_RECOVERY_BUTTON_WIDTH).contains(&x) {
        return Some(EntropyRecoveryChoice::Retry);
    }
    if (ENTROPY_RECOVERY_RIGHT_X..=ENTROPY_RECOVERY_RIGHT_X + ENTROPY_RECOVERY_BUTTON_WIDTH).contains(&x) {
        return Some(EntropyRecoveryChoice::Cancel);
    }
    None
}

mod address;
mod details;
mod keyboard;
mod mnemonic_word;
mod multisig;
mod qr_export;
mod seed_generation;
mod seed_management;
mod seed_slots;
