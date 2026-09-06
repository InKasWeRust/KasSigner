use super::geometry::{
    BACKUP_BOOT_SECTOR, FSINFO_SECTOR, FormatGeometry, NUM_FATS, RESERVED_SECTORS, ROOT_CLUSTER,
};
use super::super::{Fat32Info, SdCardType, sd_read_block, sd_write_block};

pub(super) fn write_reserved_region(
    card_type: SdCardType,
    geometry: FormatGeometry,
    liveness: &mut dyn FnMut(),
) -> Result<(), &'static str> {
    let bpb = build_bpb(geometry);
    let fsinfo = build_fsinfo(geometry.cluster_count);
    sd_write_block(card_type, 0, &bpb)?;
    sd_write_block(card_type, u32::from(FSINFO_SECTOR), &fsinfo)?;
    sd_write_block(card_type, u32::from(BACKUP_BOOT_SECTOR), &bpb)?;
    sd_write_block(card_type, u32::from(BACKUP_BOOT_SECTOR + FSINFO_SECTOR), &fsinfo)?;
    let zeros = [0u8; 512];
    for sector in 2..u32::from(RESERVED_SECTORS) {
        if sector == u32::from(BACKUP_BOOT_SECTOR)
            || sector == u32::from(BACKUP_BOOT_SECTOR + FSINFO_SECTOR)
        {
            continue;
        }
        sd_write_block(card_type, sector, &zeros)?;
        liveness();
    }
    Ok(())
}

pub(super) fn initialize_fats(
    card_type: SdCardType,
    geometry: FormatGeometry,
    liveness: &mut dyn FnMut(),
) -> Result<(), &'static str> {
    let mut first = [0u8; 512];
    first[0..4].copy_from_slice(&0x0FFF_FFF8u32.to_le_bytes());
    first[4..8].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
    first[8..12].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
    let zeros = [0u8; 512];
    let fat1 = u32::from(RESERVED_SECTORS);
    let fat2 = fat1.checked_add(geometry.fat_size).ok_or("FAT2 offset overflow")?;
    for index in 0..geometry.fat_size {
        let sector = if index == 0 { &first } else { &zeros };
        sd_write_block(card_type, fat1 + index, sector)?;
        sd_write_block(card_type, fat2 + index, sector)?;
        liveness();
    }
    Ok(())
}

pub(super) fn clear_root_cluster(
    card_type: SdCardType,
    geometry: FormatGeometry,
    liveness: &mut dyn FnMut(),
) -> Result<(), &'static str> {
    let zeros = [0u8; 512];
    for offset in 0..u32::from(geometry.sectors_per_cluster) {
        sd_write_block(card_type, geometry.data_start + offset, &zeros)?;
        liveness();
    }
    Ok(())
}

pub(super) fn verify_format(card_type: SdCardType, geometry: FormatGeometry) -> Result<(), &'static str> {
    let mut sector = [0u8; 512];
    sd_read_block(card_type, 0, &mut sector)?;
    let parsed = Fat32Info::from_boot_sector(&sector)?;
    if parsed.total_sectors != geometry.total_sectors || parsed.fat_size_32 != geometry.fat_size {
        return Err("FAT32 BPB readback mismatch");
    }
    sd_read_block(card_type, u32::from(FSINFO_SECTOR), &mut sector)?;
    if &sector[0..4] != b"RRaA" || &sector[484..488] != b"rrAa" || sector[492..496] != 3u32.to_le_bytes() {
        return Err("FAT32 FSInfo readback mismatch");
    }
    let fat1 = u32::from(RESERVED_SECTORS);
    sd_read_block(card_type, fat1, &mut sector)?;
    let root = u32::from_le_bytes([sector[8], sector[9], sector[10], sector[11]]) & 0x0FFF_FFFF;
    if root != 0x0FFF_FFFF { return Err("FAT32 root cluster was not reserved"); }
    sd_read_block(card_type, geometry.data_start, &mut sector)?;
    if sector.iter().any(|byte| *byte != 0) { return Err("FAT32 root directory was not cleared"); }
    Ok(())
}

fn build_bpb(geometry: FormatGeometry) -> [u8; 512] {
    let mut bpb = [0u8; 512];
    bpb[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
    bpb[3..11].copy_from_slice(b"MSDOS5.0");
    bpb[11..13].copy_from_slice(&512u16.to_le_bytes());
    bpb[13] = geometry.sectors_per_cluster;
    bpb[14..16].copy_from_slice(&RESERVED_SECTORS.to_le_bytes());
    bpb[16] = NUM_FATS;
    bpb[21] = 0xF8;
    bpb[24..26].copy_from_slice(&63u16.to_le_bytes());
    bpb[26..28].copy_from_slice(&255u16.to_le_bytes());
    bpb[32..36].copy_from_slice(&geometry.total_sectors.to_le_bytes());
    bpb[36..40].copy_from_slice(&geometry.fat_size.to_le_bytes());
    bpb[44..48].copy_from_slice(&ROOT_CLUSTER.to_le_bytes());
    bpb[48..50].copy_from_slice(&FSINFO_SECTOR.to_le_bytes());
    bpb[50..52].copy_from_slice(&BACKUP_BOOT_SECTOR.to_le_bytes());
    bpb[64] = 0x80;
    bpb[66] = 0x29;
    bpb[67..71].copy_from_slice(&0x0053_534Bu32.to_le_bytes());
    bpb[71..82].copy_from_slice(b"KASSIGNER  ");
    bpb[82..90].copy_from_slice(b"FAT32   ");
    bpb[510..512].copy_from_slice(&[0x55, 0xAA]);
    bpb
}

fn build_fsinfo(cluster_count: u32) -> [u8; 512] {
    let mut fsinfo = [0u8; 512];
    fsinfo[0..4].copy_from_slice(b"RRaA");
    fsinfo[484..488].copy_from_slice(b"rrAa");
    fsinfo[488..492].copy_from_slice(&cluster_count.saturating_sub(1).to_le_bytes());
    fsinfo[492..496].copy_from_slice(&3u32.to_le_bytes());
    fsinfo[510..512].copy_from_slice(&[0x55, 0xAA]);
    fsinfo
}
