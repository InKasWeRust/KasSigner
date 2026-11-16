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

//! Block storage as an interface, not a hardware abstraction: numbered
//! 512-byte sectors, which [`crate::fat32`] reads through and the board
//! crates implement. [`Memory`] holds them in memory.
//!
//! Access is by `&mut self`: it needs the device to itself, and a driver
//! that owns a bus cannot be `Copy`.

/// Bytes in a block. Fixed by the SD specification.
pub const BLOCK_SIZE: usize = 512;

/// Why an access failed: a removed card and a failed transfer want
/// different responses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No card, or the card stopped answering.
    NotPresent,
    /// The block index is past the end of the device.
    OutOfRange { block: u32, blocks: u32 },
    /// The buffer is not a whole number of blocks: a caller bug, not a
    /// device condition.
    Unaligned { len: usize },
    /// The device reported a failure, or the transfer timed out.
    Io,
}

/// A device that reads and writes fixed-size blocks.
pub trait BlockDevice {
    /// How many blocks it has. Zero means unknown, not empty: some cards'
    /// count comes from a register readable only during initialisation.
    fn blocks(&self) -> u32;

    /// Read one block.
    ///
    /// # Errors
    ///
    /// `NotPresent` if the device is gone, `OutOfRange` past the end, `Io` on a
    /// transfer failure.
    fn read(&mut self, block: u32, buf: &mut [u8; BLOCK_SIZE]) -> Result<(), Error>;

    /// Write one block.
    ///
    /// # Errors
    ///
    /// As [`BlockDevice::read`].
    fn write(&mut self, block: u32, data: &[u8; BLOCK_SIZE]) -> Result<(), Error>;

    /// Read consecutive blocks into `out`, whose length, a whole number of
    /// blocks, is the count.
    ///
    /// The default reads a block at a time; a device with a multi-block
    /// command should override it, or pay a command and a wait per block.
    ///
    /// # Errors
    ///
    /// `Unaligned` before any transfer, then as [`BlockDevice::read`].
    fn read_many(&mut self, block: u32, out: &mut [u8]) -> Result<(), Error> {
        let count = whole_blocks(out.len())?;
        self.check_range(block, count)?;
        for (i, chunk) in out.chunks_exact_mut(BLOCK_SIZE).enumerate() {
            let buf: &mut [u8; BLOCK_SIZE] = chunk.try_into().expect("chunks_exact_mut");
            self.read(block + i as u32, buf)?;
        }
        Ok(())
    }

    /// Write consecutive blocks from `data`.
    ///
    /// # Errors
    ///
    /// As [`BlockDevice::read_many`].
    fn write_many(&mut self, block: u32, data: &[u8]) -> Result<(), Error> {
        let count = whole_blocks(data.len())?;
        self.check_range(block, count)?;
        for (i, chunk) in data.chunks_exact(BLOCK_SIZE).enumerate() {
            let buf: &[u8; BLOCK_SIZE] = chunk.try_into().expect("chunks_exact");
            self.write(block + i as u32, buf)?;
        }
        Ok(())
    }

    /// Whether `count` blocks from `block` fit.
    ///
    /// # Errors
    ///
    /// `OutOfRange` if they do not; never when [`BlockDevice::blocks`] is
    /// zero, which is unknown.
    fn check_range(&self, block: u32, count: u32) -> Result<(), Error> {
        let blocks = self.blocks();
        if blocks == 0 {
            return Ok(());
        }
        match block.checked_add(count) {
            Some(end) if end <= blocks => Ok(()),
            _ => Err(Error::OutOfRange { block, blocks }),
        }
    }
}

/// A block device in memory, over blocks the caller lends (`S`, a `Vec` in
/// a test): the card this crate's tests and the firmware's card tests use.
/// With `present` false every access fails as for a pulled card.
pub struct Memory<S> {
    blocks: S,
    /// Whether the card is in the slot.
    pub present: bool,
}

impl<S> Memory<S>
where
    S: AsRef<[[u8; BLOCK_SIZE]]> + AsMut<[[u8; BLOCK_SIZE]]>,
{
    /// A card made of `blocks`, in the slot.
    pub const fn new(blocks: S) -> Self {
        Self {
            blocks,
            present: true,
        }
    }
}

impl<S> BlockDevice for Memory<S>
where
    S: AsRef<[[u8; BLOCK_SIZE]]> + AsMut<[[u8; BLOCK_SIZE]]>,
{
    fn blocks(&self) -> u32 {
        u32::try_from(self.blocks.as_ref().len()).unwrap_or(u32::MAX)
    }

    /// A block past the store is `OutOfRange`, an empty store's included:
    /// `check_range` passes everything for a size of zero, unknown.
    fn read(&mut self, block: u32, buf: &mut [u8; BLOCK_SIZE]) -> Result<(), Error> {
        if !self.present {
            return Err(Error::NotPresent);
        }
        let blocks = self.blocks();
        let stored = self.blocks.as_ref().get(block as usize);
        *buf = *stored.ok_or(Error::OutOfRange { block, blocks })?;
        Ok(())
    }

    /// As `read`: a block past the store is `OutOfRange`.
    fn write(&mut self, block: u32, data: &[u8; BLOCK_SIZE]) -> Result<(), Error> {
        if !self.present {
            return Err(Error::NotPresent);
        }
        let blocks = self.blocks();
        let stored = self.blocks.as_mut().get_mut(block as usize);
        *stored.ok_or(Error::OutOfRange { block, blocks })? = *data;
        Ok(())
    }
}

/// The blocks in a buffer of `len` bytes.
///
/// # Errors
///
/// `Unaligned` for a length that is not a multiple of [`BLOCK_SIZE`], or
/// zero: an empty transfer is almost always a miscomputed count.
pub fn whole_blocks(len: usize) -> Result<u32, Error> {
    if len == 0 || !len.is_multiple_of(BLOCK_SIZE) {
        return Err(Error::Unaligned { len });
    }
    Ok((len / BLOCK_SIZE) as u32)
}
