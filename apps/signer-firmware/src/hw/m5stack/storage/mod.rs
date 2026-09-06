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

//! CoreS3 microSD storage facade.
//!
//! GPIO36/37 carry the shared SPI2 clock/MOSI signals. GPIO35 is SD MISO
//! whenever the LCD is deselected and LCD D/C only while LCD CS is asserted.
//! `hw::m5stack::spi_bus` owns SPI2 for the entire firmware lifetime; this
//! storage layer is only an SD protocol client and never reclaims or rewrites
//! the display peripheral.

use esp_hal::delay::Delay;

use core::sync::atomic::{AtomicU8, Ordering};

const CARD_LOCK_UNKNOWN: u8 = 0;
const CARD_LOCK_UNLOCKED: u8 = 1;
const CARD_LOCK_LOCKED: u8 = 2;
static CARD_LOCK_STATUS: AtomicU8 = AtomicU8::new(CARD_LOCK_UNKNOWN);
const SESSION_NONE: u8 = 0;
const SESSION_SDV1: u8 = 1;
const SESSION_SDV2_SC: u8 = 2;
const SESSION_SDV2_HC: u8 = 3;
static MANUAL_UNLOCK_SESSION: AtomicU8 = AtomicU8::new(SESSION_NONE);

pub(crate) fn record_card_lock_status(locked: bool) {
    let value = if locked { CARD_LOCK_LOCKED } else { CARD_LOCK_UNLOCKED };
    CARD_LOCK_STATUS.store(value, Ordering::Relaxed);
}

pub(crate) fn card_is_known_locked() -> bool {
    CARD_LOCK_STATUS.load(Ordering::Relaxed) == CARD_LOCK_LOCKED
}

pub(crate) fn record_manual_unlock_session(card_type: SdCardType) {
    let value = match card_type {
        SdCardType::SdV1 => SESSION_SDV1,
        SdCardType::SdV2Sc => SESSION_SDV2_SC,
        SdCardType::SdV2Hc => SESSION_SDV2_HC,
    };
    MANUAL_UNLOCK_SESSION.store(value, Ordering::Relaxed);
    record_card_lock_status(false);
}

pub(crate) fn manual_unlock_session_card_type() -> Option<SdCardType> {
    let value = MANUAL_UNLOCK_SESSION.load(Ordering::Relaxed);
    if value == SESSION_SDV1 { return Some(SdCardType::SdV1); }
    decode_v2_session(value)
}

fn decode_v2_session(value: u8) -> Option<SdCardType> {
    match value {
        SESSION_SDV2_SC => Some(SdCardType::SdV2Sc),
        SESSION_SDV2_HC => Some(SdCardType::SdV2Hc),
        _ => None,
    }
}

pub(crate) fn clear_manual_unlock_session() {
    MANUAL_UNLOCK_SESSION.store(SESSION_NONE, Ordering::Relaxed);
}

mod transport;
pub use transport::sd_read_block;
pub(crate) use transport::{fast_read_multi_block, fast_write_multi_block, sd_sector_count, sd_write_block};
pub(crate) use transport::{power_cycle_card, probe_boot_card};
pub(crate) use transport::with_sd_card as with_sd_card_impl;
pub(crate) use transport::{force_erase_locked_card_session, unlock_locked_card_session};
#[cfg(all(feature = "workflow-hil-auto", feature = "m5stack"))]
pub(crate) use transport::workflow_force_erase_locked_card;

macro_rules! with_sd_card {
    ($i2c:expr, $delay:expr, $operation:expr) => {
        $crate::hw::sdcard::with_sd_card_impl($i2c, $delay, $operation)
    };
}
pub(crate) use with_sd_card;

pub use crate::hw::shared::storage::fat32::{
    DirEntry, Fat32Info, SdCardType, create_file, delete_file, find_file_in_root,
    format_83_display, format_fat32, list_root_dir, list_root_dir_lfn, mount_fat32,
    overwrite_file, read_file, to_83_name,
};
