//! Bounded multi-block compatibility facade.
//!
//! CoreS3 uses repeated HAL-owned single-block transactions. This deliberately
//! favors bus ownership correctness over the retired raw-GPIO CMD18/CMD25 path.

use super::{
    SdCardType,
    block::{sd_read_block, sd_write_block},
};

pub fn fast_read_multi_block(
    card_type: SdCardType,
    block: u32,
    output: &mut [u8],
    count: u32,
) -> Result<(), &'static str> {
    validate_buffer(output.len(), count)?;
    for offset in 0..count {
        read_sector(card_type, block, output, offset)?;
    }
    Ok(())
}

pub fn fast_write_multi_block(
    card_type: SdCardType,
    block: u32,
    data: &[u8],
    count: u32,
) -> Result<(), &'static str> {
    validate_buffer(data.len(), count)?;
    for offset in 0..count {
        write_sector(card_type, block, data, offset)?;
    }
    Ok(())
}

fn read_sector(
    card_type: SdCardType,
    block: u32,
    output: &mut [u8],
    offset: u32,
) -> Result<(), &'static str> {
    let sector_block = block.checked_add(offset).ok_or("Multi-read address overflow")?;
    let sector = mutable_sector(output, offset)?;
    sd_read_block(card_type, sector_block, sector)
}

fn write_sector(
    card_type: SdCardType,
    block: u32,
    data: &[u8],
    offset: u32,
) -> Result<(), &'static str> {
    let sector_block = block.checked_add(offset).ok_or("Multi-write address overflow")?;
    let sector = sector(data, offset)?;
    sd_write_block(card_type, sector_block, sector)
}

fn mutable_sector(output: &mut [u8], offset: u32) -> Result<&mut [u8; 512], &'static str> {
    let start = offset as usize * 512;
    let end = start + 512;
    (&mut output[start..end])
        .try_into()
        .map_err(|_| "Multi-read buffer alignment")
}

fn sector(data: &[u8], offset: u32) -> Result<&[u8; 512], &'static str> {
    let start = offset as usize * 512;
    let end = start + 512;
    data[start..end]
        .try_into()
        .map_err(|_| "Multi-write buffer alignment")
}

fn validate_buffer(length: usize, count: u32) -> Result<(), &'static str> {
    let required = (count as usize)
        .checked_mul(512)
        .ok_or("Multi-block size overflow")?;
    if length < required { return Err("Multi-block buffer too small"); }
    Ok(())
}
