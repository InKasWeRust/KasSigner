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

// Kaspa extended-key serialization constants.

pub(super) const KASPA_XPRV_VERSION: [u8; 4] = [0x03, 0x8f, 0x2e, 0xf4];
pub const XPUB_PAYLOAD_LEN: usize = shared_signer::account_key::ACCOUNT_KEY_PAYLOAD_LEN;
pub const KPUB_TEXT_PREFIX: &[u8; 6] = shared_signer::account_key::ACCOUNT_KEY_TEXT_PREFIX;
pub const KPUB_MAX_LEN: usize = shared_signer::account_key::ACCOUNT_KEY_TEXT_LEN;
pub const XPRV_MAX_LEN: usize = 120;
pub(super) const KASPA_ACCOUNT_PATH: [u32; 3] = [0x8000_002C, 0x8001_B207, 0x8000_0000];
