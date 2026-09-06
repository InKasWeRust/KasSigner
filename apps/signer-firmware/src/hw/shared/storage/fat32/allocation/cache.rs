use super::super::{Fat32Info, SdCardType, sd_read_block, sd_write_block};
use super::super::policy::{MAX_FAT_CHAIN_STEPS, checked_fat_entry_location};

pub(super) struct FatSectorCache<'a> {
    card_type: SdCardType,
    fat32: &'a Fat32Info,
    sector: Option<u32>,
    data: [u8; 512],
    dirty: bool,
}

impl<'a> FatSectorCache<'a> {
    pub(super) fn new(card_type: SdCardType, fat32: &'a Fat32Info) -> Self {
        Self { card_type, fat32, sector: None, data: [0; 512], dirty: false }
    }

    fn load_cluster(&mut self, cluster: u32) -> Result<usize, &'static str> {
        let (sector, offset) = checked_fat_entry_location(self.fat32, cluster)?;
        if self.sector != Some(sector) {
            self.flush()?;
            sd_read_block(self.card_type, sector, &mut self.data)?;
            self.sector = Some(sector);
        }
        Ok(offset)
    }

    pub(super) fn read_entry(&mut self, cluster: u32) -> Result<u32, &'static str> {
        let offset = self.load_cluster(cluster)?;
        let bytes = [self.data[offset], self.data[offset + 1], self.data[offset + 2], self.data[offset + 3]];
        Ok(u32::from_le_bytes(bytes) & 0x0FFF_FFFF)
    }

    pub(super) fn write_entry(&mut self, cluster: u32, value: u32) -> Result<(), &'static str> {
        let offset = self.load_cluster(cluster)?;
        let bytes = [self.data[offset], self.data[offset + 1], self.data[offset + 2], self.data[offset + 3]];
        let existing = u32::from_le_bytes(bytes);
        self.data[offset..offset + 4]
            .copy_from_slice(&((existing & 0xF000_0000) | (value & 0x0FFF_FFFF)).to_le_bytes());
        self.dirty = true;
        Ok(())
    }

    pub(super) fn flush(&mut self) -> Result<(), &'static str> {
        if !self.dirty { return Ok(()); }
        let sector = self.sector.ok_or("Dirty FAT cache has no sector")?;
        for copy in 0..u32::from(self.fat32.num_fats) {
            let offset = copy.checked_mul(self.fat32.fat_size_32).ok_or("FAT mirror offset overflow")?;
            let target = sector.checked_add(offset).ok_or("FAT mirror sector overflow")?;
            sd_write_block(self.card_type, target, &self.data)?;
        }
        self.dirty = false;
        Ok(())
    }
}

pub(super) fn claim_free_cluster(
    cache: &mut FatSectorCache<'_>,
    start_hint: u32,
) -> Result<u32, &'static str> {
    let mut cluster = normalized_hint(cache.fat32, start_hint);
    let start = cluster;
    loop {
        if cache.read_entry(cluster)? == 0 {
            cache.write_entry(cluster, 0x0FFF_FFFF)?;
            return Ok(cluster);
        }
        cluster = next_candidate(cache.fat32, cluster);
        if cluster == start { return Err("Disk full"); }
    }
}

pub(super) fn extend_chain(
    cache: &mut FatSectorCache<'_>,
    first: u32,
    count: u32,
) -> Result<u32, &'static str> {
    let mut previous = first;
    for _ in 1..count {
        let next = claim_free_cluster(cache, next_candidate(cache.fat32, previous))?;
        cache.write_entry(previous, next)?;
        previous = next;
    }
    Ok(previous)
}

pub(in crate::hw::shared::storage::fat32) fn release_chain(
    card_type: SdCardType,
    fat32: &Fat32Info,
    first_cluster: u32,
) -> Result<(), &'static str> {
    if first_cluster < 2 { return Ok(()); }
    let mut cache = FatSectorCache::new(card_type, fat32);
    let mut cluster = first_cluster;
    for _ in 0..MAX_FAT_CHAIN_STEPS {
        if !(2..max_cluster_exclusive(fat32)).contains(&cluster) {
            cache.flush()?;
            super::fsinfo::update_fsinfo_hint(card_type, fat32, first_cluster);
            return Err("FAT chain contains invalid cluster");
        }
        let next = cache.read_entry(cluster)?;
        cache.write_entry(cluster, 0)?;
        if next >= 0x0FFF_FFF8 || next < 2 {
            cache.flush()?;
            super::fsinfo::update_fsinfo_hint(card_type, fat32, first_cluster);
            return Ok(());
        }
        cluster = next;
    }
    cache.flush()?;
    super::fsinfo::update_fsinfo_hint(card_type, fat32, first_cluster);
    Err("FAT chain exceeds traversal limit")
}

pub(super) fn normalized_hint(fat32: &Fat32Info, hint: u32) -> u32 {
    if (2..max_cluster_exclusive(fat32)).contains(&hint) { hint } else { 2 }
}

pub(super) fn next_candidate(fat32: &Fat32Info, cluster: u32) -> u32 {
    let next = cluster.saturating_add(1);
    if next < max_cluster_exclusive(fat32) { next } else { 2 }
}

pub(super) fn max_cluster_exclusive(fat32: &Fat32Info) -> u32 {
    fat32.cluster_count.saturating_add(2)
}
