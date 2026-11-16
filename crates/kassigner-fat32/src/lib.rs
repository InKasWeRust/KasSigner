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

//! FAT32 over a device that reads and writes numbered blocks: Microsoft's
//! FAT specification with its long names, the MBR partition table, and the
//! SD card's CSD register for a card's size.
//!
//! Level 0, beside Kaspa's consensus rules and ISO/IEC 18004: level 1 holds
//! formats this project designed, and nothing here is ours. The block device
//! trait is here because the filesystem reads through it.
//!
//! No hardware: a block device is numbered 512-byte sectors, which the tests
//! back with an array. The card driver, its bus and the power around an
//! access are the board crates'.
//!
//! No allocator: [`fat32::allocate_chain`] keeps only a chain's first and
//! last clusters and finds the rest again as it links them.

#![no_std]
#![forbid(unsafe_code)]

pub mod block;
pub mod fat32;
