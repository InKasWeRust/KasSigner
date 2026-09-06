
// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Shared no-alloc FAT32 data types.

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdCardType {
    SdV1 = 1,    // SD v1 (byte addressing)
    SdV2Sc = 2,  // SD v2 Standard Capacity (byte addressing)
    SdV2Hc = 3,  // SD v2 High/Extended Capacity (block addressing)
}

pub struct Fat32Info {
    pub sectors_per_cluster: u8,
    pub num_fats: u8,
    pub fat_size_32: u32,
    pub root_cluster: u32,
    pub total_sectors: u32,
    pub fat_start_sector: u32,
    pub data_start_sector: u32,
    pub cluster_count: u32,
    pub fs_info_sector: Option<u32>,
    pub backup_fs_info_sector: Option<u32>,
    pub next_free_cluster: u32,
}

pub struct DirEntry {
    pub name: [u8; 11],
    pub attr: u8,
    pub cluster_hi: u16,
    pub cluster_lo: u16,
    pub file_size: u32,
}

/// Format an 8.3 name for display — trim trailing spaces, no dot if no extension.
pub fn format_83_display(name: &[u8; 11], out: &mut [u8; 13]) -> usize {
    signer_firmware_core::storage::fat32_lfn::format_83_display(name, out)
}
