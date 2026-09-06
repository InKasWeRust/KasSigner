mod boot;
mod read;
use read::{checked_chain_step, checked_file_size, read_file_cluster};
use super::{DirEntry, Fat32Info, SdCardType, sd_read_block};
// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Shared FAT32 parsing and read policy. Board modules provide only the
// block-transport functions used below (`sd_read_block` and
// `fast_read_multi_block`). Keeping this policy in one source file prevents
// safety checks from drifting between the Waveshare and M5Stack drivers.

pub(super) const FAT32_SECTOR_BYTES: u32 = 512;
pub(super) const FAT32_END_OF_CHAIN: u32 = 0x0FFF_FFF8;
pub(super) const MAX_FAT_CHAIN_STEPS: u32 = 16_384;

impl Fat32Info {
    /// Parse a FAT32 BIOS parameter block from a 512-byte boot sector.
    pub fn from_boot_sector(sector: &[u8; 512]) -> Result<Self, &'static str> {
        let info = boot::parse_boot_sector(sector)?;
        log!(
            "[FAT32] spc={} fats={} fat_sz={} root_cl={} data_start={}",
            info.sectors_per_cluster,
            info.num_fats,
            info.fat_size_32,
            info.root_cluster,
            info.data_start_sector
        );
        Ok(info)
    }

    /// Convert a cluster number to its first sector without wrapping.
    pub fn cluster_to_sector(&self, cluster: u32) -> u32 {
        if cluster < 2 {
            return self.data_start_sector;
        }
        self.data_start_sector.saturating_add(
            (cluster - 2).saturating_mul(self.sectors_per_cluster as u32),
        )
    }
    pub fn cluster_bytes(&self) -> u32 {
        self.sectors_per_cluster as u32 * FAT32_SECTOR_BYTES
    }
}

impl DirEntry {
    /// Parse a normal FAT32 directory entry from its 32-byte representation.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let parsed = signer_firmware_core::storage::fat32_metadata::parse_directory_entry(data)?;
        Some(Self {
            name: parsed.name,
            attr: parsed.attr,
            cluster_hi: parsed.cluster_hi,
            cluster_lo: parsed.cluster_lo,
            file_size: parsed.file_size,
        })
    }

    pub fn first_cluster(&self) -> u32 {
        ((self.cluster_hi as u32) << 16) | self.cluster_lo as u32
    }

    pub fn is_dir(&self) -> bool {
        self.attr & 0x10 != 0
    }

    pub fn matches(&self, name_83: &[u8; 11]) -> bool {
        self.name
            .iter()
            .zip(name_83.iter())
            .all(|(&left, &right)| left.eq_ignore_ascii_case(&right))
    }
}

pub fn to_83_name(filename: &[u8]) -> [u8; 11] {
    let mut result = [b' '; 11];
    let dot_pos = filename
        .iter()
        .position(|&byte| byte == b'.')
        .unwrap_or(filename.len());

    for (destination, &source) in result[..8]
        .iter_mut()
        .zip(filename[..dot_pos.min(filename.len())].iter().take(8))
    {
        *destination = source.to_ascii_uppercase();
    }

    if dot_pos < filename.len() {
        for (destination, &source) in result[8..]
            .iter_mut()
            .zip(filename[dot_pos + 1..].iter().take(3))
        {
            *destination = source.to_ascii_uppercase();
        }
    }

    result
}

pub(super) fn checked_fat_entry_location(
    fat32: &Fat32Info,
    cluster: u32,
) -> Result<(u32, usize), &'static str> {
    let fat_offset = cluster.checked_mul(4).ok_or("FAT offset overflow")?;
    let sector = fat32
        .fat_start_sector
        .checked_add(fat_offset / FAT32_SECTOR_BYTES)
        .ok_or("FAT sector overflow")?;
    let offset = (fat_offset % FAT32_SECTOR_BYTES) as usize;
    if offset
        .checked_add(4)
        .map_or(true, |end| end > FAT32_SECTOR_BYTES as usize)
    {
        return Err("FAT offset out of range");
    }
    Ok((sector, offset))
}

pub fn read_fat_entry(card_type: SdCardType, fat32: &Fat32Info, cluster: u32) -> Result<u32, &'static str> {
    let (sector, offset) = checked_fat_entry_location(fat32, cluster)?;

    let mut buffer = [0u8; 512];
    sd_read_block(card_type, sector, &mut buffer)?;
    let entry = u32::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ]);
    Ok(entry & 0x0FFF_FFFF)
}

pub fn read_file_progress(
    card_type: SdCardType,
    fat32: &Fat32Info,
    entry: &DirEntry,
    out: &mut [u8],
    progress: &mut dyn FnMut(usize, usize),
) -> Result<usize, &'static str> {
    let file_size = checked_file_size(entry, out)?;
    if file_size == 0 {
        return Ok(0);
    }
    let cluster_bytes = fat32.cluster_bytes();
    if cluster_bytes == 0 {
        return Err("Invalid cluster size");
    }

    let mut cluster = entry.first_cluster();
    let mut remaining = file_size;
    let mut position = 0usize;
    let max_chain = (entry.file_size / cluster_bytes)
        .saturating_add(2)
        .min(MAX_FAT_CHAIN_STEPS);
    let mut chain_steps = 0u32;

    while remaining > 0 && (2..FAT32_END_OF_CHAIN).contains(&cluster) {
        chain_steps = checked_chain_step(chain_steps, max_chain)?;
        read_file_cluster(
            card_type,
            fat32,
            cluster,
            out,
            &mut position,
            &mut remaining,
        )?;
        progress(position, file_size);
        if remaining > 0 {
            cluster = read_fat_entry(card_type, fat32, cluster)?;
        }
    }
    if remaining != 0 {
        return Err("FAT chain ended before file size");
    }
    Ok(position)
}


pub(crate) fn detect_fat32_partition(mbr: &[u8; 512]) -> Result<u32, &'static str> {
    if mbr[510] != 0x55 || mbr[511] != 0xAA {
        return Err("Invalid MBR signature");
    }

    for partition_index in 0..4 {
        let base = 0x1BE + partition_index * 16;
        let partition_type = mbr[base + 4];
        if partition_type == 0x0B || partition_type == 0x0C {
            let lba = u32::from_le_bytes([
                mbr[base + 8],
                mbr[base + 9],
                mbr[base + 10],
                mbr[base + 11],
            ]);
            log!(
                "[MBR] FAT32 partition {} at LBA {}",
                partition_index,
                lba
            );
            return Ok(lba);
        }
    }

    if mbr[0] == 0xEB || mbr[0] == 0xE9 {
        log!("[MBR] No partition table, trying superfloppy");
        return Ok(0);
    }

    Err("No FAT32 partition found")
}
