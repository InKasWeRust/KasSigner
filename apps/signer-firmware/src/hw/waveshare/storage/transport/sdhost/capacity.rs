//! SD CSD capacity query for the Waveshare native SDHOST controller.

use signer_firmware_core::storage::card::csd_sector_count;

use super::sdhost_send_cmd;
use super::super::registers::{
    CMD_CHECK_RESP_CRC, CMD_RESP_EXPECT, CMD_RESP_LONG,
    SDHOST_RESP0, SDHOST_RESP1, SDHOST_RESP2, SDHOST_RESP3,
    cached_card_sector_count, reg_read, set_card_sector_count,
};

pub(super) fn capture_sector_count(rca: u16) -> Result<(), &'static str> {
    let sectors = read_csd_sector_count(rca)?;
    set_card_sector_count(sectors);
    Ok(())
}

pub(crate) fn sd_sector_count() -> Result<u32, &'static str> {
    cached_card_sector_count().ok_or("SD card capacity unavailable")
}

fn read_csd_sector_count(rca: u16) -> Result<u32, &'static str> {
    sdhost_send_cmd(
        9,
        u32::from(rca) << 16,
        CMD_RESP_EXPECT | CMD_RESP_LONG | CMD_CHECK_RESP_CRC,
    )?;
    csd_sector_count(&read_long_response())
}

fn read_long_response() -> [u8; 16] {
    let words = unsafe {
        [reg_read(SDHOST_RESP3), reg_read(SDHOST_RESP2), reg_read(SDHOST_RESP1), reg_read(SDHOST_RESP0)]
    };
    let mut response = [0u8; 16];
    for (chunk, word) in response.chunks_exact_mut(4).zip(words) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    response
}
