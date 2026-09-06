//! Single-block SD I/O over the CoreS3 shared SPI2 owner.

use signer_firmware_core::storage::retry::{
    poll_not_busy, poll_read_token, write_response_accepted,
};

use super::{
    SdCardType,
    protocol::{
        command_data_at, finish_transaction_at, read_exact, require_success, transfer_byte, write_all,
    },
};

mod adaptive;

pub use adaptive::sd_read_block;
pub(crate) use adaptive::sd_write_block;

const CMD17: u8 = 17;
const CMD24: u8 = 24;

fn read_block_at(
    address: u32,
    slow: bool,
    buffer: &mut [u8; 512],
) -> Result<(), &'static str> {
    command_data_at(CMD17, address, slow, |spi, response| {
        read_payload(spi, response, buffer)
    })?;
    finish_transaction_at(slow)
}

fn write_block_at(
    address: u32,
    slow: bool,
    buffer: &[u8; 512],
) -> Result<(), &'static str> {
    command_data_at(CMD24, address, slow, |spi, response| {
        write_payload(spi, response, buffer)
    })?;
    finish_transaction_at(slow)
}

fn read_payload(
    spi: &mut esp_hal::spi::master::Spi<'static, esp_hal::Blocking>,
    response: u8,
    buffer: &mut [u8; 512],
) -> Result<(), &'static str> {
    if response != 0x00 {
        crate::log!("[SD] CMD17 rejected: R1=0x{:02x}", response);
    }
    require_success(response, "CMD17 failed")
        .and_then(|_| wait_read_token(spi))
        .and_then(|_| read_exact(spi, buffer))
        .and_then(|_| discard_crc(spi))
}

fn wait_read_token(
    spi: &mut esp_hal::spi::master::Spi<'static, esp_hal::Blocking>,
) -> Result<(), &'static str> {
    poll_read_token(10_000, || transfer_byte(spi, 0xFF).unwrap_or(0xFF))
        .map_err(|error| error.message("Read error token", "Read timeout"))
}

fn discard_crc(
    spi: &mut esp_hal::spi::master::Spi<'static, esp_hal::Blocking>,
) -> Result<(), &'static str> {
    let mut crc = [0u8; 2];
    read_exact(spi, &mut crc)
}

fn write_payload(
    spi: &mut esp_hal::spi::master::Spi<'static, esp_hal::Blocking>,
    response: u8,
    buffer: &[u8; 512],
) -> Result<(), &'static str> {
    require_success(response, "CMD24 failed")
        .and_then(|_| write_all(spi, &[0xFF, 0xFE]))
        .and_then(|_| write_all(spi, buffer))
        .and_then(|_| write_all(spi, &[0xFF, 0xFF]))
        .and_then(|_| read_write_response(spi))
        .and_then(|response| validate_write_response(spi, response))
}

fn read_write_response(
    spi: &mut esp_hal::spi::master::Spi<'static, esp_hal::Blocking>,
) -> Result<u8, &'static str> {
    transfer_byte(spi, 0xFF)
}

fn validate_write_response(
    spi: &mut esp_hal::spi::master::Spi<'static, esp_hal::Blocking>,
    response: u8,
) -> Result<(), &'static str> {
    if !write_response_accepted(response) { return Err("Write rejected"); }
    wait_not_busy(spi)
}

fn wait_not_busy(
    spi: &mut esp_hal::spi::master::Spi<'static, esp_hal::Blocking>,
) -> Result<(), &'static str> {
    if poll_not_busy(500_000, || transfer_byte(spi, 0xFF).unwrap_or(0x00)) {
        Ok(())
    } else {
        Err("Write busy timeout")
    }
}

fn block_address(card_type: SdCardType, block: u32) -> Result<u32, &'static str> {
    signer_firmware_core::storage::fifo::plan_transfer(
        card_type == SdCardType::SdV2Hc,
        block,
        0,
        0,
    )
    .map(|plan| plan.address)
    .map_err(|_| "Block address overflow")
}
