use super::super::{
    DirEntry, Fat32Info, SdCardType, allocate_chain, fast_write_multi_block, read_fat_entry, sd_write_block,
};

pub(super) fn clusters_for_file(fat32: &Fat32Info, file_size: u32) -> u32 {
    if file_size == 0 {
        return 0;
    }
    let cluster_bytes = fat32.cluster_bytes();
    (file_size + cluster_bytes - 1) / cluster_bytes
}

pub(super) fn allocate_file_chain(
    card_type: SdCardType,
    fat32: &Fat32Info,
    clusters_needed: u32,
) -> Result<u32, &'static str> {
    if clusters_needed == 0 {
        Ok(0)
    } else {
        allocate_chain(card_type, fat32, clusters_needed)
    }
}

pub(super) fn write_file_chain(
    card_type: SdCardType,
    fat32: &Fat32Info,
    first_cluster: u32,
    data: &[u8],
    progress: &mut dyn FnMut(usize, usize),
) -> Result<(), &'static str> {
    let mut cluster = first_cluster;
    let mut remaining = data.len();
    let mut position = 0usize;
    while remaining > 0 && (2..0x0FFF_FFF8).contains(&cluster) {
        let base_sector = fat32.cluster_to_sector(cluster);
        write_cluster_data(
            card_type,
            fat32.sectors_per_cluster as u32,
            base_sector,
            data,
            &mut position,
            &mut remaining,
        )?;
        progress(position, data.len());
        if remaining > 0 {
            cluster = read_fat_entry(card_type, fat32, cluster)?;
        }
    }
    Ok(())
}

pub(super) fn write_cluster_data(
    card_type: SdCardType,
    sectors_per_cluster: u32,
    base_sector: u32,
    data: &[u8],
    position: &mut usize,
    remaining: &mut usize,
) -> Result<(), &'static str> {
    let full_sectors = (*remaining / 512).min(sectors_per_cluster as usize) as u32;
    if full_sectors > 0 {
        let write_bytes = full_sectors as usize * 512;
        fast_write_multi_block(
            card_type,
            base_sector,
            &data[*position..*position + write_bytes],
            full_sectors,
        )?;
        *position += write_bytes;
        *remaining -= write_bytes;
    }
    for sector in full_sectors..sectors_per_cluster {
        write_partial_sector(card_type, base_sector + sector, data, position, remaining)?;
    }
    Ok(())
}

pub(super) fn write_partial_sector(
    card_type: SdCardType,
    sector: u32,
    data: &[u8],
    position: &mut usize,
    remaining: &mut usize,
) -> Result<(), &'static str> {
    let mut sector_buf = [0u8; 512];
    if *remaining > 0 {
        let chunk = (*remaining).min(512);
        sector_buf[..chunk].copy_from_slice(&data[*position..*position + chunk]);
        *position += chunk;
        *remaining -= chunk;
    }
    sd_write_block(card_type, sector, &sector_buf)
}

pub(super) fn file_entry(name_83: &[u8; 11], first_cluster: u32, file_size: u32) -> DirEntry {
    DirEntry {
        name: *name_83,
        attr: 0x20,
        cluster_hi: (first_cluster >> 16) as u16,
        cluster_lo: first_cluster as u16,
        file_size,
    }
}

pub(super) fn replace_existing_file(
    card_type: SdCardType,
    fat32: &Fat32Info,
    name_83: &[u8; 11],
    data: &[u8],
    existing: (DirEntry, u32, usize),
) -> Result<(), &'static str> {
    let (old_entry, sector, offset) = existing;
    let file_size = data.len() as u32;
    let first_cluster = allocate_file_chain(card_type, fat32, clusters_for_file(fat32, file_size))?;
    if let Err(error) = write_new_file_payload(card_type, fat32, first_cluster, data, &mut |_, _| {}) {
        let _ = super::super::allocation::release_chain(card_type, fat32, first_cluster);
        return Err(error);
    }
    let new_entry = file_entry(name_83, first_cluster, file_size);
    if let Err(error) = super::super::directory::replace_dir_entry_at(card_type, sector, offset, &new_entry) {
        let _ = super::super::allocation::release_chain(card_type, fat32, first_cluster);
        return Err(error);
    }
    super::super::allocation::release_chain(card_type, fat32, old_entry.first_cluster())
}

pub(super) fn write_new_file_payload(
    card_type: SdCardType,
    fat32: &Fat32Info,
    first_cluster: u32,
    data: &[u8],
    progress: &mut dyn FnMut(usize, usize),
) -> Result<(), &'static str> {
    if data.is_empty() { return Ok(()); }
    write_file_chain(card_type, fat32, first_cluster, data, progress)
}
