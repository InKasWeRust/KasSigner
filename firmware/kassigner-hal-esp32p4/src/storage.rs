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

//! The microSD card, over the chip's SD host, slot 1 (GPIO 43 clock, 44
//! command, 39 to 42 data), behind `kassigner_fat32::block::BlockDevice`.
//!
//! The host is set up once, at bring-up, and kept in the unit as a [`Card`]
//! (pins configured, card supply on, no command sent). Each [`with_card`] is
//! a session: the first brings the card up from CMD0 at 400 kHz and keeps
//! its address and kind; a later one asks that address for its state
//! (CMD13) and reselects it, as the S3 Waveshare does, and starts from CMD0
//! only when nothing answers there. The host is never taken down and a
//! selected card never sent back to CMD0: a card left selected did not
//! answer a new bring-up on a host set up again.
//!
//! No card-detect line, and esp-hal's `is_card_present` says yes with the
//! slot empty (measured): a card is there when it answers.
//!
//! One data line at 20 MHz, as on the S3 Waveshare: four are wired, but
//! using them needs ACMD6 and an untested bus-width switch, not worth it
//! for files of a few kilobytes.
//!
//! The host's DMA needs an internal-RAM buffer, cache-line aligned and whole
//! lines long, so every transfer goes through the [`Card`]'s own,
//! [`BOUNCE_BLOCKS`] blocks at a time, zeroed when each session ends.

use esp_hal::delay::Delay;
use esp_hal::dma::aligned::{DmaAlignedMut, InternalMemory};
use esp_hal::peripherals::{GPIO39, GPIO40, GPIO41, GPIO42, GPIO43, GPIO44, SDHOST};
use esp_hal::sdmmc::{
    BlockingError, BusWidth, CommandFlags, Config, Error as HostError, ResponseLen,
    SdHostController, Slot, SlotConfig,
};
use esp_hal::Blocking;
use kassigner_fat32::block::{whole_blocks, BlockDevice, Error, BLOCK_SIZE};
use kassigner_fat32::fat32::{csd_plausible, csd_sectors};
use kassigner_hal::card::Kind;
use static_cell::StaticCell;

/// The card's clock while it is brought up: the SD specification's ceiling.
const INIT_HZ: u32 = 400_000;
/// Its clock for data, as the Waveshare runs its card.
const DATA_HZ: u32 = 20_000_000;
/// Blocks a transfer moves at most: one pass through the bounce buffer.
pub const BOUNCE_BLOCKS: usize = 8;
const BOUNCE_BYTES: usize = BOUNCE_BLOCKS * BLOCK_SIZE;
/// ACMD41 asked this many times, a millisecond apart, before the card is
/// taken for not ready.
const READY_TRIES: u32 = 1000;
/// A card's states in CMD13's answer: stand-by (deselected) and transfer
/// (selected).
const STATE_STANDBY: u32 = 3;
const STATE_TRANSFER: u32 = 4;

/// The host, set up once.
static HOST: StaticCell<SdHostController<'static>> = StaticCell::new();

/// Why a session did not start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SdError {
    /// The host or its slot would not configure, or was set up already.
    Host,
    /// No card answered, as with an empty slot (at CMD55 or ACMD41).
    NoCard {
        /// The command.
        cmd: u8,
        /// The host's error.
        error: BlockingError,
    },
    /// A card answered ACMD41 but never left busy.
    NotReady,
    /// A step of the initialisation failed after the card answered.
    Init {
        /// The command that failed.
        cmd: u8,
        /// The host's error.
        error: BlockingError,
    },
}

/// What the last bring-up found, kept for the next session.
#[derive(Clone, Copy, Debug)]
struct Known {
    rca: u32,
    card: Kind,
    sectors: u32,
}

/// The SD host and its slot, for the life of the unit, and the card last
/// found in it.
pub struct Card {
    slot: Slot<'static, 1, Blocking>,
    known: Option<Known>,
    bounce: InternalMemory<[u8; BOUNCE_BYTES]>,
}

impl Card {
    /// Set the host up and configure the slot's pins, the card's supply on
    /// and nothing sent to it. Once, at bring-up.
    ///
    /// # Errors
    ///
    /// [`SdError::Host`] if the host would not configure or was set up
    /// already.
    pub fn new() -> Result<Self, SdError> {
        // SAFETY: the SD host and its six pins are taken nowhere else
        // (`board::init` drops them unused), and this runs once: its one
        // caller, `unit::bring_up`, refuses a second bring-up first. The
        // `StaticCell` below is not that guarantee: a second call would
        // configure the host again before the cell refused it.
        let (host, clk, cmd, d0, d1, d2, d3) = unsafe {
            (
                SDHOST::steal(),
                GPIO43::steal(),
                GPIO44::steal(),
                GPIO39::steal(),
                GPIO40::steal(),
                GPIO41::steal(),
                GPIO42::steal(),
            )
        };
        let controller =
            SdHostController::new(host, Config::default()).map_err(|_| SdError::Host)?;
        let controller: &'static SdHostController<'static> =
            HOST.try_init(controller).ok_or(SdError::Host)?;
        let slot = controller
            .slot::<1>(SlotConfig::default())
            .map_err(|_| SdError::Host)?
            .with_clk(clk)
            .with_cmd(cmd)
            .with_data0(d0)
            .with_data1(d1)
            .with_data2(d2)
            .with_data3(d3);
        Ok(Self {
            slot,
            known: None,
            bounce: InternalMemory::new([0; BOUNCE_BYTES]),
        })
    }

    /// One command, its response words.
    fn command(
        &mut self,
        index: u8,
        arg: u32,
        resp: ResponseLen,
        crc: bool,
        busy: bool,
    ) -> Result<[u32; 4], BlockingError> {
        let flags = CommandFlags {
            busy,
            ..CommandFlags::default()
        };
        self.slot.command_blocking(index, arg, resp, crc, flags)
    }

    /// The card to work with: the one last found, selected again, or one
    /// brought up from CMD0.
    fn attach(&mut self, delay: &Delay) -> Result<Known, SdError> {
        if let Some(known) = self.known {
            if self.reselect(known).is_ok() {
                return Ok(known);
            }
            self.known = None;
        }
        let known = self.bring_up(delay)?;
        self.known = Some(known);
        Ok(known)
    }

    /// Ask the card at `known`'s address for its state, select it if in
    /// stand-by (keep it if in transfer), and set the block size and data
    /// clock. Any other state is refused.
    fn reselect(&mut self, known: Known) -> Result<(), SdError> {
        let init = |cmd, error| SdError::Init { cmd, error };
        self.slot
            .set_bus_low_level(BusWidth::Bit1, INIT_HZ)
            .map_err(|_| SdError::Host)?;
        let status = self
            .command(13, known.rca << 16, ResponseLen::Short, true, false)
            .map_err(|e| init(13, e))?[0];
        match (status >> 9) & 0xF {
            STATE_TRANSFER => {}
            STATE_STANDBY => {
                self.command(7, known.rca << 16, ResponseLen::Short, true, true)
                    .map_err(|e| init(7, e))?;
            }
            // Mid-transfer or not ready: brought up again instead.
            _ => return Err(SdError::NotReady),
        }
        self.command(16, BLOCK_SIZE as u32, ResponseLen::Short, true, false)
            .map_err(|e| init(16, e))?;
        self.slot
            .set_bus_low_level(BusWidth::Bit1, DATA_HZ)
            .map_err(|_| SdError::Host)
    }

    /// Identify, select and set the block size at 400 kHz, then the data
    /// clock.
    fn bring_up(&mut self, delay: &Delay) -> Result<Known, SdError> {
        let init = |cmd, error| SdError::Init { cmd, error };
        self.slot
            .set_bus_low_level(BusWidth::Bit1, INIT_HZ)
            .map_err(|_| SdError::Host)?;
        delay.delay_millis(10);
        // The 80 clocks, and CMD0 with them.
        self.slot.send_init_sequence().map_err(|e| init(0, e))?;

        // CMD0 again, no response: it says nothing about a card being there.
        let _ = self.command(0, 0, ResponseLen::None, false, false);
        delay.delay_millis(2);

        // CMD8: an SD v2 card echoes the check pattern; v1 says nothing.
        let v2 = self
            .command(8, 0x1AA, ResponseLen::Short, true, false)
            .is_ok_and(|r| r[0] & 0xFFF == 0x1AA);

        // ACMD41 until the card leaves busy; no answer to either command is
        // no card.
        let hcs = if v2 { 1u32 << 30 } else { 0 };
        let mut ocr = 0u32;
        let mut ready = false;
        for _ in 0..READY_TRIES {
            self.command(55, 0, ResponseLen::Short, true, false)
                .map_err(|error| SdError::NoCard { cmd: 55, error })?;
            ocr = self
                .command(41, hcs | 0x00FF_8000, ResponseLen::Short, false, false)
                .map_err(|error| SdError::NoCard { cmd: 41, error })?[0];
            if ocr & (1 << 31) != 0 {
                ready = true;
                break;
            }
            delay.delay_millis(1);
        }
        if !ready {
            return Err(SdError::NotReady);
        }
        let card = match (v2, ocr & (1 << 30) != 0) {
            (true, true) => Kind::SdV2High,
            (true, false) => Kind::SdV2Standard,
            (false, _) => Kind::SdV1,
        };

        // CMD2, CMD3: identity, then the card's address. The long replies
        // (CMD2, CMD9) have their CRC checked, as ESP-IDF's R2 flags and the
        // Waveshare's DesignWare controller do, so a corrupted reply is not
        // taken for the size.
        self.command(2, 0, ResponseLen::Long, true, false)
            .map_err(|e| init(2, e))?;
        let rca = self
            .command(3, 0, ResponseLen::Short, true, false)
            .map_err(|e| init(3, e))?[0]
            >> 16;

        // CMD9 in stand-by: the size. The most significant word comes last,
        // so the bytes run from word 3 down; a size no FAT32 volume could
        // have is left unknown, as on the S3 units.
        let sectors = match self.command(9, rca << 16, ResponseLen::Long, true, false) {
            Ok(r) => {
                let mut csd = [0u8; 16];
                for (i, w) in [r[3], r[2], r[1], r[0]].iter().enumerate() {
                    csd[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
                }
                match csd_sectors(&csd) {
                    Ok(n) if csd_plausible(n) => n,
                    _ => 0,
                }
            }
            Err(_) => 0,
        };

        // CMD7 selects it, with busy on the data line; CMD16 sets 512-byte
        // blocks, which a high-capacity card has anyway.
        self.command(7, rca << 16, ResponseLen::Short, true, true)
            .map_err(|e| init(7, e))?;
        self.command(16, BLOCK_SIZE as u32, ResponseLen::Short, true, false)
            .map_err(|e| init(16, e))?;

        self.slot
            .set_bus_low_level(BusWidth::Bit1, DATA_HZ)
            .map_err(|_| SdError::Host)?;
        Ok(Known { rca, card, sectors })
    }
}

/// The card, for the length of one session.
pub struct P4Storage<'c> {
    card: &'c mut Card,
    kind: Kind,
    sectors: u32,
}

impl P4Storage<'_> {
    /// What kind of card answered.
    pub fn card_type(&self) -> Kind {
        self.kind
    }

    /// The address a command takes for `block`: the block on a
    /// high-capacity card, else its byte offset, refused where that does
    /// not fit 32 bits ([`Kind::address`]) rather than saturated.
    fn address(&self, block: u32) -> Result<u32, Error> {
        self.kind.address(block).ok_or(Error::OutOfRange {
            block,
            blocks: self.sectors,
        })
    }

    /// Where chunk `i` of a transfer from `block` starts, refused past the
    /// last block number: on a card of unknown size the range check lets any
    /// block through, and a plain sum would panic with overflow checks on.
    fn chunk_start(&self, block: u32, i: usize) -> Result<u32, Error> {
        u32::try_from(i.saturating_mul(BOUNCE_BLOCKS))
            .ok()
            .and_then(|step| block.checked_add(step))
            .ok_or(Error::OutOfRange {
                block,
                blocks: self.sectors,
            })
    }
}

/// The first `n` blocks of a bounce buffer, as the host's DMA takes them.
fn window(
    bounce: &mut InternalMemory<[u8; BOUNCE_BYTES]>,
    n: usize,
) -> Result<DmaAlignedMut<'_, [u8]>, Error> {
    let whole: &mut [u8; BOUNCE_BYTES] = bounce.get_mut().into_inner();
    DmaAlignedMut::new(&mut whole[..n * BLOCK_SIZE]).map_err(|_| Error::Io)
}

/// The host's error as the trait's: no card, or a transfer that failed.
fn map(e: BlockingError) -> Error {
    match e {
        BlockingError::Op(HostError::NoCard | HostError::ResponseTimeout) => Error::NotPresent,
        _ => Error::Io,
    }
}

impl BlockDevice for P4Storage<'_> {
    fn blocks(&self) -> u32 {
        self.sectors
    }

    fn read(&mut self, block: u32, buf: &mut [u8; BLOCK_SIZE]) -> Result<(), Error> {
        self.read_many(block, buf)
    }

    fn write(&mut self, block: u32, data: &[u8; BLOCK_SIZE]) -> Result<(), Error> {
        self.write_many(block, data)
    }

    /// CMD17 for one block, CMD18 for more, through the bounce buffer.
    fn read_many(&mut self, block: u32, out: &mut [u8]) -> Result<(), Error> {
        let count = whole_blocks(out.len())?;
        self.check_range(block, count)?;
        for (i, chunk) in out.chunks_mut(BOUNCE_BYTES).enumerate() {
            let n = chunk.len() / BLOCK_SIZE;
            let first = self.chunk_start(block, i)?;
            let (cmd, arg) = (if n > 1 { 18 } else { 17 }, self.address(first)?);
            let card = &mut *self.card;
            let dma = window(&mut card.bounce, n)?;
            card.slot
                .read_blocks_blocking(cmd, arg, dma, BLOCK_SIZE as u16, n as u32)
                .map_err(map)?;
            let whole: &mut [u8; BOUNCE_BYTES] = card.bounce.get_mut().into_inner();
            chunk.copy_from_slice(&whole[..chunk.len()]);
        }
        Ok(())
    }

    /// CMD24 for one block, CMD25 for more, through the bounce buffer. The
    /// host waits out the card's busy after each.
    fn write_many(&mut self, block: u32, data: &[u8]) -> Result<(), Error> {
        let count = whole_blocks(data.len())?;
        self.check_range(block, count)?;
        for (i, chunk) in data.chunks(BOUNCE_BYTES).enumerate() {
            let n = chunk.len() / BLOCK_SIZE;
            let first = self.chunk_start(block, i)?;
            let (cmd, arg) = (if n > 1 { 25 } else { 24 }, self.address(first)?);
            let card = &mut *self.card;
            let whole: &mut [u8; BOUNCE_BYTES] = card.bounce.get_mut().into_inner();
            whole[..chunk.len()].copy_from_slice(chunk);
            let dma = window(&mut card.bounce, n)?;
            card.slot
                .write_blocks_blocking(cmd, arg, dma, BLOCK_SIZE as u16, n as u32)
                .map_err(map)?;
        }
        Ok(())
    }
}

/// A session: the card attached, `f` run on it, and the bounce buffer
/// zeroed so the card's data does not stay behind in it.
///
/// # Errors
///
/// [`SdError`] if the session did not start; `f` returns its own errors.
pub fn with_card<F, T>(card: &mut Card, f: F) -> Result<T, SdError>
where
    F: FnOnce(&mut P4Storage<'_>) -> T,
{
    let known = card.attach(&Delay::new())?;
    let result = f(&mut P4Storage {
        card: &mut *card,
        kind: known.card,
        sectors: known.sectors,
    });
    card.bounce.get_mut().into_inner().fill(0);
    Ok(result)
}
