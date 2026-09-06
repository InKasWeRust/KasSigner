mod helpers;
use helpers::{
    allocate_file_chain, clusters_for_file, file_entry, replace_existing_file,
    write_new_file_payload,
};
use super::allocation::release_chain;
use super::directory::{mark_dir_entry_deleted, write_dir_entry_to_root};
use super::{
    DirEntry,
    Fat32Info,
    SdCardType,
    find_file_in_root,
    read_file_progress,
};
// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Shared FAT32 files implementation. Metadata ordering favors never leaving a
// live directory entry pointing at clusters that have already been freed.

pub fn read_file(
    card_type: SdCardType,
    fat32: &Fat32Info,
    entry: &DirEntry,
    out: &mut [u8],
) -> Result<usize, &'static str> {
    read_file_progress(card_type, fat32, entry, out, &mut |_, _| {})
}

pub fn create_file(
    card_type: SdCardType,
    fat32: &Fat32Info,
    name_83: &[u8; 11],
    data: &[u8],
) -> Result<DirEntry, &'static str> {
    create_file_progress(card_type, fat32, name_83, data, &mut |_, _| {})
}

pub fn create_file_progress(
    card_type: SdCardType,
    fat32: &Fat32Info,
    name_83: &[u8; 11],
    data: &[u8],
    progress: &mut dyn FnMut(usize, usize),
) -> Result<DirEntry, &'static str> {
    let file_size = data.len() as u32;
    let clusters_needed = clusters_for_file(fat32, file_size);
    let first_cluster = allocate_file_chain(card_type, fat32, clusters_needed)?;
    if let Err(error) = write_new_file_payload(card_type, fat32, first_cluster, data, progress) {
        let _ = release_chain(card_type, fat32, first_cluster);
        return Err(error);
    }
    let entry = file_entry(name_83, first_cluster, file_size);
    if let Err(error) = write_dir_entry_to_root(card_type, fat32, &entry) {
        let _ = release_chain(card_type, fat32, first_cluster);
        return Err(error);
    }
    log!("[FAT32] Created file size={} cluster={}", file_size, first_cluster);
    Ok(entry)
}

pub fn delete_file(
    card_type: SdCardType,
    fat32: &Fat32Info,
    name_83: &[u8; 11],
) -> Result<(), &'static str> {
    let (entry, sector, offset) = find_file_in_root(card_type, fat32, name_83)?;
    // Commit deletion first. A power loss after this point may leak clusters,
    // but no live directory entry can point into a chain that is being freed.
    mark_dir_entry_deleted(card_type, sector, offset)?;
    release_chain(card_type, fat32, entry.first_cluster())?;
    log!("[FAT32] Deleted file");
    Ok(())
}

pub fn overwrite_file(
    card_type: SdCardType,
    fat32: &Fat32Info,
    name_83: &[u8; 11],
    data: &[u8],
) -> Result<(), &'static str> {
    let existing = match find_file_in_root(card_type, fat32, name_83) {
        Ok(found) => found,
        Err("File not found") => {
            create_file(card_type, fat32, name_83, data)?;
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    replace_existing_file(card_type, fat32, name_83, data, existing)
}
