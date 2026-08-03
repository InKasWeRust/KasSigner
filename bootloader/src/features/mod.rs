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

// features/mod.rs — Feature modules (stego, KRC-20, firmware verify, self-test)
// features/ — Steganography, KRC-20, firmware update, NVS, verification

pub mod stego;
// Traversal primitive for coefficient-domain stego. Not yet wired to
// anything: the JPEG entropy codec that would use it is unwritten. Present
// so the design and its validation are in the tree rather than in a chat log.
pub mod stego_perm;
// JPEG entropy-layer codec that uses it. Validated against a reference
// implementation but NOT yet called from any handler: wiring it into the
// export/import flow, and deciding whether it runs alongside the EXIF path
// or instead of it, is a separate change.
pub mod stego_dct;
pub mod krc20;
pub mod fw_update;
pub mod verify;
pub mod self_test;
