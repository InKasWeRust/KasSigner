use super::super::{
    DirEntry, Fat32Info, SdCardType, allocate_cluster, read_fat_entry, sd_read_block, sd_write_block, write_fat_entry,
};
use super::super::policy::detect_fat32_partition;

pub(super) fn has_boot_signature(sector: &[u8; 512]) -> bool {
    sector[510] == 0x55 && sector[511] == 0xAA
}

pub(super) fn looks_like_bpb(sector: &[u8; 512]) -> bool {
    matches!(sector[0], 0xEB | 0xE9) && has_boot_signature(sector)
}

pub(super) fn try_superfloppy(sector: &[u8; 512]) -> Option<Fat32Info> {
    if !looks_like_bpb(sector) {
        return None;
    }
    log!("[FAT32] Trying superfloppy (BPB at sector 0)");
    Fat32Info::from_boot_sector(sector).ok()
}

pub(super) fn try_mbr_partition(
    card_type: SdCardType,
    sector_zero: &[u8; 512],
    scratch: &mut [u8; 512],
) -> Result<Option<Fat32Info>, &'static str> {
    if !has_boot_signature(sector_zero) {
        return Ok(None);
    }
    log!("[FAT32] Trying MBR partition table");
    let Ok(lba) = detect_fat32_partition(sector_zero) else {
        return Ok(None);
    };
    if lba == 0 {
        return Ok(None);
    }
    sd_read_block(card_type, lba, scratch)?;
    let info = Fat32Info::from_boot_sector(scratch)?;
    Ok(Some(offset_fat32(info, lba)))
}

pub(super) fn probe_common_offsets(
    card_type: SdCardType,
    sector: &mut [u8; 512],
) -> Result<Option<Fat32Info>, &'static str> {
    for &probe_lba in &[2048u32, 8192, 32768, 1] {
        if sd_read_block(card_type, probe_lba, sector).is_err() || !looks_like_bpb(sector) {
            continue;
        }
        log!("[FAT32] Found BPB at sector {}", probe_lba);
        if let Ok(info) = Fat32Info::from_boot_sector(sector) {
            return Ok(Some(offset_fat32(info, probe_lba)));
        }
    }
    Ok(None)
}

pub(super) fn offset_fat32(mut info: Fat32Info, lba: u32) -> Fat32Info {
    info.fat_start_sector += lba;
    info.data_start_sector += lba;
    info.fs_info_sector = info.fs_info_sector.and_then(|sector| sector.checked_add(lba));
    info.backup_fs_info_sector = info.backup_fs_info_sector.and_then(|sector| sector.checked_add(lba));
    info
}

pub(super) fn write_entry_into_sector(buf: &mut [u8; 512], entry: &DirEntry) -> bool {
    for index in 0..16 {
        let offset = index * 32;
        if !matches!(buf[offset], 0x00 | 0xE5) {
            continue;
        }
        write_dir_entry_bytes(&mut buf[offset..offset + 32], entry);
        return true;
    }
    false
}

pub(super) fn write_dir_entry_bytes(slot: &mut [u8], entry: &DirEntry) {
    slot[0..11].copy_from_slice(&entry.name);
    slot[11] = entry.attr;
    slot[12..20].fill(0);
    slot[20..22].copy_from_slice(&entry.cluster_hi.to_le_bytes());
    slot[22..26].fill(0);
    slot[26..28].copy_from_slice(&entry.cluster_lo.to_le_bytes());
    slot[28..32].copy_from_slice(&entry.file_size.to_le_bytes());
}

pub(super) fn next_directory_cluster(
    card_type: SdCardType,
    fat32: &Fat32Info,
    cluster: u32,
) -> Result<u32, &'static str> {
    let next = read_fat_entry(card_type, fat32, cluster)?;
    if next < 0x0FFF_FFF8 {
        return Ok(next);
    }
    allocate_directory_cluster(card_type, fat32, cluster)
}

pub(super) fn allocate_directory_cluster(
    card_type: SdCardType,
    fat32: &Fat32Info,
    cluster: u32,
) -> Result<u32, &'static str> {
    let new_cluster = allocate_cluster(card_type, fat32, cluster + 1)?;
    write_fat_entry(card_type, fat32, cluster, new_cluster)?;
    let zeros = [0u8; 512];
    let base_sector = fat32.cluster_to_sector(new_cluster);
    for sector in 0..fat32.sectors_per_cluster as u32 {
        sd_write_block(card_type, base_sector + sector, &zeros)?;
    }
    Ok(new_cluster)
}

pub(super) fn hydrate_fsinfo_hint(
    card_type: SdCardType,
    mut info: Fat32Info,
) -> Result<Fat32Info, &'static str> {
    let Some(sector) = info.fs_info_sector else { return Ok(info); };
    let mut buf = [0u8; 512];
    if sd_read_block(card_type, sector, &mut buf).is_err() { return Ok(info); }
    if &buf[0..4] != b"RRaA" || &buf[484..488] != b"rrAa" || buf[510..512] != [0x55, 0xAA] {
        return Ok(info);
    }
    let hint = u32::from_le_bytes([buf[492], buf[493], buf[494], buf[495]]);
    let max_cluster = info.cluster_count.saturating_add(2);
    if (2..max_cluster).contains(&hint) { info.next_free_cluster = hint; }
    Ok(info)
}

pub(in crate::hw::shared::storage::fat32) fn replace_dir_entry_at(
    card_type: SdCardType,
    sector: u32,
    offset: usize,
    entry: &DirEntry,
) -> Result<(), &'static str> {
    if offset.checked_add(32).map_or(true, |end| end > 512) {
        return Err("Directory entry offset out of range");
    }
    let mut buf = [0u8; 512];
    sd_read_block(card_type, sector, &mut buf)?;
    write_dir_entry_bytes(&mut buf[offset..offset + 32], entry);
    sd_write_block(card_type, sector, &buf)
}

pub(in crate::hw::shared::storage::fat32) fn mark_dir_entry_deleted(
    card_type: SdCardType,
    sector: u32,
    offset: usize,
) -> Result<(), &'static str> {
    if offset >= 512 { return Err("Directory entry offset out of range"); }
    let mut buf = [0u8; 512];
    sd_read_block(card_type, sector, &mut buf)?;
    buf[offset] = 0xE5;
    sd_write_block(card_type, sector, &buf)
}
