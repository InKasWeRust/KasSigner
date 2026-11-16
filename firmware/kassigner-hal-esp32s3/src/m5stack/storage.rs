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

//! [`BlockDevice`] for the M5's card, which shares a bus and a pin with the
//! display, and the session it lives in.
//!
//! [`with_card`] takes the bus from the display, power-cycles and
//! initialises the card, runs a closure with the [`M5Storage`] and gives the
//! bus back. There is no other way to get one, so a block access with the
//! pins still routed to SPI2, which would clock the display's D/C line as
//! card data, cannot be written. Nothing may draw inside the closure: the
//! display's pins are the card's until it returns.
//!
//! The power cycle, through [`pmu::set_rails`], is 300 ms off and 200 ms
//! on: the display's bus traffic may leave the card in a state no command
//! recovers. The card's size is read from its CSD once per session, so
//! [`BlockDevice::blocks`] can bound every access.

use embedded_hal::i2c::I2c;
use kassigner_fat32::block::{whole_blocks, BlockDevice, Error, BLOCK_SIZE};
use kassigner_fat32::fat32::{csd_plausible, csd_sectors};
use kassigner_hal::card::Kind;
use kassigner_hal::timer::Timer;

use crate::systimer::SysTimer;

use super::pmu;
use super::sdspi::{self, SdError};

/// Card rail off for this long, so its capacitors drain.
const POWER_OFF_MS: u32 = 300;
/// Card rail on for this long before the first clock.
const POWER_ON_MS: u32 = 200;

/// The card, for the length of one session.
pub struct M5Storage {
    card: Kind,
    sectors: u32,
}

impl M5Storage {
    /// The card's kind, for a diagnostic screen; the driver handles byte or
    /// block addressing itself.
    pub fn card_type(&self) -> Kind {
        self.card
    }
}

/// A driver error as the trait's. No card, no power, or a command that drew
/// no answer (R1 `0xFF`, a card pulled mid-session) is `NotPresent`;
/// anything else is `Io`.
fn map(e: SdError) -> Error {
    match e {
        SdError::NoCard | SdError::Power | SdError::Command { r1: 0xFF, .. } => Error::NotPresent,
        _ => Error::Io,
    }
}

impl BlockDevice for M5Storage {
    fn blocks(&self) -> u32 {
        self.sectors
    }

    fn read(&mut self, block: u32, buf: &mut [u8; BLOCK_SIZE]) -> Result<(), Error> {
        self.check_range(block, 1)?;
        sdspi::read_block(self.card, block, buf).map_err(map)
    }

    fn write(&mut self, block: u32, data: &[u8; BLOCK_SIZE]) -> Result<(), Error> {
        self.check_range(block, 1)?;
        sdspi::write_block(self.card, block, data).map_err(map)
    }

    /// Overridden: one CMD18 for the whole run rather than a command a block.
    fn read_many(&mut self, block: u32, out: &mut [u8]) -> Result<(), Error> {
        let count = whole_blocks(out.len())?;
        self.check_range(block, count)?;
        sdspi::read_blocks(self.card, block, out).map_err(map)
    }

    /// Overridden, for the same reason, with CMD25.
    fn write_many(&mut self, block: u32, data: &[u8]) -> Result<(), Error> {
        let count = whole_blocks(data.len())?;
        self.check_range(block, count)?;
        sdspi::write_blocks(self.card, block, data).map_err(map)
    }
}

/// Take the bus, power-cycle and initialise the card, run `f`, give the bus
/// back.
///
/// `i2c` reaches the card slot's rail. The bus is given back on every path,
/// failed ones included.
///
/// # Errors
///
/// `Power` if the rail would not switch, else what the card's
/// initialisation failed on. `f` returns its own errors in its value.
pub fn with_card<I, F, T>(i2c: &mut I, f: F) -> Result<T, SdError>
where
    I: I2c,
    F: FnOnce(&mut M5Storage) -> T,
{
    let mut timer = SysTimer;

    let saved = sdspi::save_and_reclaim();
    sdspi::float_pins();

    if pmu::set_rails(i2c, pmu::SD_CARD, false).is_err() {
        sdspi::restore(&saved);
        return Err(SdError::Power);
    }
    timer.delay_ms(POWER_OFF_MS);
    if pmu::set_rails(i2c, pmu::SD_CARD, true).is_err() {
        sdspi::restore(&saved);
        return Err(SdError::Power);
    }
    timer.delay_ms(POWER_ON_MS);

    sdspi::claim_pins();
    let card = match sdspi::init() {
        Ok(card) => card,
        Err(e) => {
            sdspi::restore(&saved);
            return Err(e);
        }
    };

    // Zero, read by the trait as unknown, when the CSD does not answer or
    // gives no size a FAT32 volume could have.
    let sectors = match sdspi::read_csd().map(|csd| csd_sectors(&csd)) {
        Ok(Ok(n)) if csd_plausible(n) => n,
        _ => 0,
    };

    let mut storage = M5Storage { card, sectors };
    let result = f(&mut storage);

    sdspi::deselect();
    sdspi::restore(&saved);
    Ok(result)
}
