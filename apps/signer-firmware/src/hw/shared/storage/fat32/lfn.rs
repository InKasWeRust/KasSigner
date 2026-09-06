// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Shared FAT32 long-file-name directory traversal.

mod scanner;

use signer_firmware_core::storage::fat32_lfn::LfnAccumulator;
use scanner::{scan_cluster, ScanControl};

use super::{DirEntry, Fat32Info, SdCardType, read_fat_entry};

pub fn list_root_dir_lfn<F>(
    card_type: SdCardType,
    fat32: &Fat32Info,
    mut callback: F,
) -> Result<(), &'static str>
where
    F: FnMut(&DirEntry, &[u8; 64], usize) -> bool,
{
    let mut cluster = fat32.root_cluster;
    let mut names = LfnAccumulator::new();

    loop {
        if scan_cluster(card_type, fat32, cluster, &mut names, &mut callback)?
            == ScanControl::Stop
        {
            return Ok(());
        }
        let next = read_fat_entry(card_type, fat32, cluster)?;
        if next >= 0x0FFF_FFF8 {
            return Ok(());
        }
        cluster = next;
    }
}
