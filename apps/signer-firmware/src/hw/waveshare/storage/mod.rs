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

// hw/storage/sdcard_ws/mod.rs — MicroSD card driver (SDHOST controller + FAT32 + LFN)
// 100% Rust, no-std, no-alloc
//
// Hardware: Waveshare ESP32-S3-Touch-LCD-2
//   - SD_CLK  = GPIO39 (shared with LCD SPI2 SCK)
//   - SD_CMD  = GPIO38 (shared with LCD SPI2 MOSI)
//   - SD_D0   = GPIO40 (dedicated to SD)
//   - SD_D3   = GPIO41 (dedicated to SD, directly tied to card detect)
//   - LCD_CS  = GPIO45
//   - LCD_DC  = GPIO42
//
// Architecture:
//   - SDHOST controller at 0x60028000 (TRM Chapter 34)
//   - 1-bit SD native mode (CLK + CMD + D0)
//   - FIFO mode (non-DMA, polled via BUFFIFO register at 0x200)
//   - GPIO matrix routing for display coexistence
//   - `with_sd_card` pattern: save SPI2 routing → SDHOST → restore
//
// SD Native Protocol (not SPI mode):
//   CMD0   → GO_IDLE_STATE (no response)
//   CMD8   → SEND_IF_COND (R7 response)
//   CMD55  → APP_CMD prefix
//   ACMD41 → SD_SEND_OP_COND (R3 response)
//   CMD2   → ALL_SEND_CID (R2 long response)
//   CMD3   → SEND_RELATIVE_ADDR (R6 response)
//   CMD7   → SELECT_CARD (R1b response)
//   CMD16  → SET_BLOCKLEN (R1 response)
//   CMD17  → READ_SINGLE_BLOCK (R1 + data)
//   CMD24  → WRITE_BLOCK (R1 + data)
//   CMD18  → READ_MULTIPLE_BLOCK (R1 + data stream)
//   CMD25  → WRITE_MULTIPLE_BLOCK (R1 + data stream)
//   CMD12  → STOP_TRANSMISSION (R1b response)

use esp_hal::delay::Delay;

/// SD password locking is a SPI-mode CoreS3 concern in the current firmware.
/// The Waveshare SDHOST implementation does not expose that status.
pub(crate) const fn card_is_known_locked() -> bool { false }

/// Password locking is not implemented by the Waveshare SDHOST path.
pub(crate) fn unlock_locked_card_session<I2C>(
    i2c: &mut I2C, delay: &mut Delay, password: &[u8],
) -> Result<(), &'static str> {
    let _driver_identity = core::mem::size_of_val(i2c);
    delay.delay_millis(0);
    let _password_length = password.len();
    Err("SD password unlock unsupported on this board")
}

pub(crate) fn force_erase_locked_card_session<I2C>(
    i2c: &mut I2C, delay: &mut Delay, liveness: &mut dyn FnMut(),
) -> Result<bool, &'static str> {
    let _driver_identity = core::mem::size_of_val(i2c);
    delay.delay_millis(0);
    liveness();
    Err("SD password force erase unsupported on this board")
}

mod transport;
pub use transport::{init_sdhost, sd_power_up_clocks, sd_pre_init, sd_read_block};
pub(crate) use transport::{fast_read_multi_block, fast_write_multi_block, sd_sector_count, sd_write_block};
pub(crate) use transport::with_sd_card as with_sd_card_impl;

macro_rules! with_sd_card {
    ($i2c:expr, $delay:expr, $operation:expr) => {{
        let _ = &$i2c;
        $crate::hw::sdcard::with_sd_card_impl($delay, $operation)
    }};
}
pub(crate) use with_sd_card;


pub use crate::hw::shared::storage::fat32::{
    DirEntry, Fat32Info, SdCardType, create_file, delete_file, find_file_in_root,
    format_83_display, format_fat32, list_root_dir, list_root_dir_lfn, mount_fat32,
    overwrite_file, read_file, to_83_name,
};
