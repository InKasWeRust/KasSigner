mod geometry;
mod io;

use geometry::{MAX_FORMAT_SECTORS, format_geometry};
use io::{clear_root_cluster, initialize_fats, verify_format, write_reserved_region};
use super::{Delay, SdCardType, sd_read_block, sd_sector_count};
// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// Shared FAT32 superfloppy formatter. Geometry is derived from the card CSD;
// media larger than 32 GB is intentionally capped to a 32 GB FAT32 volume.

pub fn format_fat32<I2C: embedded_hal::i2c::I2c>(
    i2c: &mut I2C,
    delay: &mut Delay,
    liveness: &mut dyn FnMut(),
) -> bool {
    let _ = &mut *i2c;
    log!("[SD-FMT] Formatting card as FAT32...");
    match crate::hw::sdcard::with_sd_card!(i2c, delay, |ct| do_format_fat32(ct, liveness)) {
        Ok(()) => {
            log!("[SD-FMT] Format complete!");
            true
        }
        Err(error) => {
            log!("[SD-FMT] Format failed: {}", error);
            false
        }
    }
}

pub(super) fn do_format_fat32(
    card_type: SdCardType,
    liveness: &mut dyn FnMut(),
) -> Result<(), &'static str> {
    let mut probe = [0u8; 512];
    sd_read_block(card_type, 0, &mut probe)?;
    let card_sectors = sd_sector_count()?;
    let geometry = format_geometry(card_sectors.min(MAX_FORMAT_SECTORS))?;
    log!(
        "[SD-FMT] sectors={} spc={} fat={} clusters={}",
        geometry.total_sectors,
        geometry.sectors_per_cluster,
        geometry.fat_size,
        geometry.cluster_count,
    );
    write_reserved_region(card_type, geometry, liveness)?;
    initialize_fats(card_type, geometry, liveness)?;
    clear_root_cluster(card_type, geometry, liveness)?;
    verify_format(card_type, geometry)
}
