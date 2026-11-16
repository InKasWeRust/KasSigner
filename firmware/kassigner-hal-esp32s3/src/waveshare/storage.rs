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

//! [`BlockDevice`] over the SDHOST controller.
//!
//! The trait is `kassigner_fat32::block`, not a HAL one: a block device is a
//! numbered array of sectors, and `kassigner_fat32::fat32`, a format and so
//! level 0, cannot depend on level 3.
//!
//! A translation layer over [`super::sdhost`], the ESP32-S3's SD host
//! peripheral driven directly: card initialisation, the CSD read and the
//! multi-block paths.
//!
//! # Native SD, not SPI
//!
//! This board wires the card to the SDHOST peripheral and talks the SD
//! protocol. The M5 bangs SPI on a bus it shares with the display, saving and
//! restoring the SPI2 and IO_MUX state around every access. The trait shows
//! neither.
//!
//! # The size can be unknown
//!
//! The sector count comes from CMD9, legal only while the card is in
//! stand-by: after CMD3 assigns the address and before CMD7 selects it. At
//! any other time it times out, so the value is taken then and kept.
//!
//! A card that did not answer leaves it zero, which [`BlockDevice::blocks`]
//! reports as unknown, not empty: bounds checking is skipped rather than
//! every access refused, and a read past the end fails at the card.

use kassigner_fat32::block::{whole_blocks, BlockDevice, Error, BLOCK_SIZE};
use kassigner_hal::card::Kind;

use super::sdhost;

/// The SD card.
pub struct WaveshareStorage {
    card: Kind,
    sectors: u32,
}

impl WaveshareStorage {
    /// Wrap a card the host has already initialised; `None` for no card,
    /// which an absent or unreadable one leaves.
    pub fn new(card: Option<Kind>) -> Option<Self> {
        Some(Self {
            card: card?,
            sectors: sdhost::card_sectors(),
        })
    }

    /// The card type: standard-capacity cards address by byte, high-capacity
    /// ones by block. The driver handles that; this is for a diagnostic
    /// screen.
    pub fn card_type(&self) -> Kind {
        self.card
    }
}

/// Map the driver's string errors onto the trait's: the card is gone, or the
/// transfer failed.
///
/// Gone is a response timeout, which the block paths name `RTO`: no card
/// answered the command, as the P4's host reports `ResponseTimeout`. The
/// board has no card-detect line to ask instead. A card missing before a
/// session never reaches here: `with_sd_card` refuses the session first.
fn map(e: &'static str) -> Error {
    if e.ends_with("RTO") {
        Error::NotPresent
    } else {
        Error::Io
    }
}

impl BlockDevice for WaveshareStorage {
    fn blocks(&self) -> u32 {
        self.sectors
    }

    fn read(&mut self, block: u32, buf: &mut [u8; BLOCK_SIZE]) -> Result<(), Error> {
        self.check_range(block, 1)?;
        sdhost::sd_read_block(self.card, block, buf).map_err(map)
    }

    fn write(&mut self, block: u32, data: &[u8; BLOCK_SIZE]) -> Result<(), Error> {
        self.check_range(block, 1)?;
        sdhost::fast_write_multi_block(self.card, block, data, 1).map_err(map)
    }

    /// Overridden for the controller's multi-block command: the default is
    /// one command and one wait per 512 bytes, and a container is hundreds
    /// of blocks.
    fn read_many(&mut self, block: u32, out: &mut [u8]) -> Result<(), Error> {
        let count = whole_blocks(out.len())?;
        self.check_range(block, count)?;
        sdhost::fast_read_multi_block(self.card, block, out, count).map_err(map)
    }

    /// Overridden, for the same reason as [`WaveshareStorage::read_many`].
    fn write_many(&mut self, block: u32, data: &[u8]) -> Result<(), Error> {
        let count = whole_blocks(data.len())?;
        self.check_range(block, count)?;
        sdhost::fast_write_multi_block(self.card, block, data, count).map_err(map)
    }
}
