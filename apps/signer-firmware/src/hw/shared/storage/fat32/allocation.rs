mod cache;
mod fsinfo;

use cache::{FatSectorCache, claim_free_cluster, extend_chain, next_candidate};
pub(super) use cache::release_chain;
use fsinfo::update_fsinfo_hint;
use super::{Fat32Info, SdCardType};
// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// Shared FAT32 allocation implementation. Sequential mutations are cached and
// flushed to every FAT copy together.

pub fn write_fat_entry(
    card_type: SdCardType,
    fat32: &Fat32Info,
    cluster: u32,
    value: u32,
) -> Result<(), &'static str> {
    let mut cache = FatSectorCache::new(card_type, fat32);
    cache.write_entry(cluster, value)?;
    cache.flush()
}

pub fn allocate_cluster(
    card_type: SdCardType,
    fat32: &Fat32Info,
    start_hint: u32,
) -> Result<u32, &'static str> {
    let mut cache = FatSectorCache::new(card_type, fat32);
    let cluster = claim_free_cluster(&mut cache, start_hint)?;
    cache.flush()?;
    update_fsinfo_hint(card_type, fat32, next_candidate(fat32, cluster));
    log!("[FAT32] Allocated cluster {}", cluster);
    Ok(cluster)
}

pub fn allocate_chain(
    card_type: SdCardType,
    fat32: &Fat32Info,
    count: u32,
) -> Result<u32, &'static str> {
    if count == 0 { return Err("Zero clusters requested"); }
    let mut cache = FatSectorCache::new(card_type, fat32);
    let first = claim_free_cluster(&mut cache, fat32.next_free_cluster)?;
    match extend_chain(&mut cache, first, count) {
        Ok(last) => {
            cache.flush()?;
            update_fsinfo_hint(card_type, fat32, next_candidate(fat32, last));
            Ok(first)
        }
        Err(error) => {
            let _ = cache.flush();
            let _ = release_chain(card_type, fat32, first);
            Err(error)
        }
    }
}
