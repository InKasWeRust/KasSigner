mod helpers;
use helpers::{hydrate_fsinfo_hint, next_directory_cluster, probe_common_offsets, try_mbr_partition, try_superfloppy, write_entry_into_sector};
pub(super) use helpers::{mark_dir_entry_deleted, replace_dir_entry_at};
use super::{
    DirEntry,
    Fat32Info,
    SdCardType,
    read_fat_entry,
    sd_read_block,
    sd_write_block,
};
// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Shared FAT32 directory implementation.

pub fn mount_fat32(card_type: SdCardType) -> Result<Fat32Info, &'static str> {
    let mut sector = [0u8; 512];
    sd_read_block(card_type, 0, &mut sector)?;
    log!("[FAT32] Sector 0: {:02x} {:02x} {:02x} .. sig={:02x}{:02x}",
        sector[0], sector[1], sector[2], sector[510], sector[511]);
    if let Some(info) = try_superfloppy(&sector) {
        return hydrate_fsinfo_hint(card_type, info);
    }
    let sector_zero = sector;
    if let Some(info) = try_mbr_partition(card_type, &sector_zero, &mut sector)? {
        return hydrate_fsinfo_hint(card_type, info);
    }
    if let Some(info) = probe_common_offsets(card_type, &mut sector)? {
        return hydrate_fsinfo_hint(card_type, info);
    }
    Err("No FAT32 filesystem found")
}


pub fn find_file_in_root(
    card_type: SdCardType,
    fat32: &Fat32Info,
    name_83: &[u8; 11],
) -> Result<(DirEntry, u32, usize), &'static str> {
    let mut cluster = fat32.root_cluster;
    let mut buf = [0u8; 512];

    loop {
        let base_sector = fat32.cluster_to_sector(cluster);
        for s in 0..fat32.sectors_per_cluster as u32 {
            sd_read_block(card_type, base_sector + s, &mut buf)?;
            for i in 0..16 { // 16 entries per 512-byte sector
                let off = i * 32;
                if buf[off] == 0x00 { return Err("File not found"); } // end of dir
                if let Some(entry) = DirEntry::from_bytes(&buf[off..off+32]) {
                    if entry.matches(name_83) {
                        return Ok((entry, base_sector + s, off));
                    }
                }
            }
        }
        // Follow cluster chain
        let next = read_fat_entry(card_type, fat32, cluster)?;
        if next >= 0x0FFF_FFF8 { break; } // EOC
        cluster = next;
    }
    Err("File not found")
}

pub(super) fn write_dir_entry_to_root(
    card_type: SdCardType,
    fat32: &Fat32Info,
    entry: &DirEntry,
) -> Result<(), &'static str> {
    let mut cluster = fat32.root_cluster;
    let mut buf = [0u8; 512];
    loop {
        let base_sector = fat32.cluster_to_sector(cluster);
        for sector in 0..fat32.sectors_per_cluster as u32 {
            let lba = base_sector + sector;
            sd_read_block(card_type, lba, &mut buf)?;
            if write_entry_into_sector(&mut buf, entry) {
                sd_write_block(card_type, lba, &buf)?;
                return Ok(());
            }
        }
        cluster = next_directory_cluster(card_type, fat32, cluster)?;
    }
}




pub fn list_root_dir<F>(
    card_type: SdCardType,
    fat32: &Fat32Info,
    mut callback: F,
) -> Result<(), &'static str>
where
    F: FnMut(&DirEntry) -> bool,
{
    let mut cluster = fat32.root_cluster;
    let mut buf = [0u8; 512];

    loop {
        let base_sector = fat32.cluster_to_sector(cluster);
        for s in 0..fat32.sectors_per_cluster as u32 {
            sd_read_block(card_type, base_sector + s, &mut buf)?;
            for i in 0..16 {
                let off = i * 32;
                if buf[off] == 0x00 { return Ok(()); } // end of dir
                if let Some(entry) = DirEntry::from_bytes(&buf[off..off+32]) {
                    // Skip volume label entries
                    if entry.attr & 0x08 != 0 { continue; }
                    if !callback(&entry) { return Ok(()); }
                }
            }
        }
        let next = read_fat_entry(card_type, fat32, cluster)?;
        if next >= 0x0FFF_FFF8 { break; }
        cluster = next;
    }
    Ok(())
}
