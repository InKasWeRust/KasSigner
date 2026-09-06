//! Adaptive single-block transfer entrypoints.

use super::{block_address, read_block_at, write_block_at};
use crate::hw::m5stack::storage::transport::protocol::{
    force_conservative_data_rate, legacy_data_speed, log_read_rejection_status,
};
use crate::hw::m5stack::storage::SdCardType;

pub fn sd_read_block(
    card_type: SdCardType,
    block: u32,
    buffer: &mut [u8; 512],
) -> Result<(), &'static str> {
    let address = block_address(card_type, block)?;
    let slow = legacy_data_speed(card_type);
    match read_block_at(address, slow, buffer) {
        Ok(()) => Ok(()),
        Err(error) => recover_read(address, slow, buffer, error),
    }
}

fn recover_read(
    address: u32,
    slow: bool,
    buffer: &mut [u8; 512],
    first_error: &'static str,
) -> Result<(), &'static str> {
    log_read_rejection_status(slow);
    if slow {
        return Err(first_error);
    }
    crate::log!("[SD] CMD17 fast-rate read failed; retrying at initialization rate");
    retry_read_conservative(address, buffer, first_error)
}

fn retry_read_conservative(
    address: u32,
    buffer: &mut [u8; 512],
    first_error: &'static str,
) -> Result<(), &'static str> {
    match read_block_at(address, true, buffer) {
        Ok(()) => {
            force_conservative_data_rate();
            Ok(())
        }
        Err(_) => Err(first_error),
    }
}

pub(crate) fn sd_write_block(
    card_type: SdCardType,
    block: u32,
    buffer: &[u8; 512],
) -> Result<(), &'static str> {
    let address = block_address(card_type, block)?;
    let slow = legacy_data_speed(card_type);
    match write_block_at(address, slow, buffer) {
        Ok(()) => Ok(()),
        Err(error) => recover_write(address, slow, buffer, error),
    }
}

fn recover_write(
    address: u32,
    slow: bool,
    buffer: &[u8; 512],
    error: &'static str,
) -> Result<(), &'static str> {
    if slow || error != "CMD24 failed" {
        return Err(error);
    }
    crate::log!("[SD] CMD24 fast-rate command failed; retrying at initialization rate");
    write_block_at(address, true, buffer).map(|_| force_conservative_data_rate())
}
