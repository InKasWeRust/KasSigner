use super::super::{DirEntry, Fat32Info, SdCardType, fast_read_multi_block, sd_read_block};
use super::super::policy::{FAT32_SECTOR_BYTES};

pub(super) fn checked_file_size(entry: &DirEntry, out: &[u8]) -> Result<usize, &'static str> {
    let file_size = entry.file_size as usize;
    if out.len() < file_size {
        return Err("Buffer too small");
    }
    Ok(file_size)
}

pub(super) fn checked_chain_step(chain_steps: u32, max_chain: u32) -> Result<u32, &'static str> {
    let next = chain_steps.saturating_add(1);
    if next > max_chain {
        return Err("FAT chain too long");
    }
    Ok(next)
}

pub(super) fn read_file_cluster(
    card_type: SdCardType,
    fat32: &Fat32Info,
    cluster: u32,
    out: &mut [u8],
    position: &mut usize,
    remaining: &mut usize,
) -> Result<(), &'static str> {
    let base_sector = fat32.cluster_to_sector(cluster);
    let sectors_per_cluster = fat32.sectors_per_cluster as u32;
    let sectors_needed = (remaining.saturating_add(FAT32_SECTOR_BYTES as usize - 1)
        / FAT32_SECTOR_BYTES as usize)
        .min(sectors_per_cluster as usize) as u32;
    let transfer_bytes = sectors_needed as usize * FAT32_SECTOR_BYTES as usize;
    if can_read_multi(out.len(), *position, sectors_needed, transfer_bytes) {
        read_cluster_multi(card_type, base_sector, out, position, remaining, sectors_needed, transfer_bytes)
    } else {
        read_cluster_sectors(card_type, base_sector, out, position, remaining, sectors_per_cluster)
    }
}

pub(super) fn can_read_multi(out_len: usize, position: usize, sectors: u32, bytes: usize) -> bool {
    sectors > 1 && position.checked_add(bytes).is_some_and(|end| end <= out_len)
}

pub(super) fn read_cluster_multi(
    card_type: SdCardType,
    base_sector: u32,
    out: &mut [u8],
    position: &mut usize,
    remaining: &mut usize,
    sectors_needed: u32,
    transfer_bytes: usize,
) -> Result<(), &'static str> {
    fast_read_multi_block(card_type, base_sector, &mut out[*position..], sectors_needed)?;
    let actual = (*remaining).min(transfer_bytes);
    *position += actual;
    *remaining -= actual;
    Ok(())
}

pub(super) fn read_cluster_sectors(
    card_type: SdCardType,
    base_sector: u32,
    out: &mut [u8],
    position: &mut usize,
    remaining: &mut usize,
    sectors_per_cluster: u32,
) -> Result<(), &'static str> {
    let mut sector_buffer = [0u8; 512];
    for sector_index in 0..sectors_per_cluster {
        if *remaining == 0 {
            break;
        }
        let sector = base_sector.checked_add(sector_index).ok_or("Sector number overflow")?;
        sd_read_block(card_type, sector, &mut sector_buffer)?;
        let chunk = (*remaining).min(FAT32_SECTOR_BYTES as usize);
        let end = position.checked_add(chunk).ok_or("File offset overflow")?;
        out[*position..end].copy_from_slice(&sector_buffer[..chunk]);
        *position = end;
        *remaining -= chunk;
    }
    Ok(())
}
