pub(super) const RESERVED_SECTORS: u16 = 32;
pub(super) const NUM_FATS: u8 = 2;
pub(super) const ROOT_CLUSTER: u32 = 2;
pub(super) const FSINFO_SECTOR: u16 = 1;
pub(super) const BACKUP_BOOT_SECTOR: u16 = 6;
pub(super) const MAX_FORMAT_SECTORS: u32 = 62_500_000;

#[derive(Clone, Copy)]
pub(super) struct FormatGeometry {
    pub(super) total_sectors: u32,
    pub(super) sectors_per_cluster: u8,
    pub(super) fat_size: u32,
    pub(super) data_start: u32,
    pub(super) cluster_count: u32,
}

pub(super) fn format_geometry(total_sectors: u32) -> Result<FormatGeometry, &'static str> {
    if total_sectors <= u32::from(RESERVED_SECTORS) { return Err("SD card is too small"); }
    let sectors_per_cluster = cluster_size_for(total_sectors);
    let fat_size = required_fat_size(total_sectors, sectors_per_cluster)?;
    let fat_span = u32::from(NUM_FATS).checked_mul(fat_size).ok_or("FAT span overflow")?;
    let data_start = u32::from(RESERVED_SECTORS).checked_add(fat_span).ok_or("FAT data offset overflow")?;
    if data_start >= total_sectors { return Err("FAT32 data area is empty"); }
    let cluster_count = (total_sectors - data_start) / u32::from(sectors_per_cluster);
    if !(65_525..=0x0FFF_FFF5).contains(&cluster_count) {
        return Err("Card geometry cannot be represented as FAT32");
    }
    Ok(FormatGeometry { total_sectors, sectors_per_cluster, fat_size, data_start, cluster_count })
}

fn cluster_size_for(total_sectors: u32) -> u8 {
    if total_sectors <= 4_194_304 { 8 }
    else if total_sectors <= 8_388_608 { 16 }
    else if total_sectors <= 16_777_216 { 32 }
    else { 64 }
}

fn required_fat_size(total_sectors: u32, sectors_per_cluster: u8) -> Result<u32, &'static str> {
    let mut fat_size = 1u32;
    loop {
        let fat_span = u32::from(NUM_FATS).checked_mul(fat_size).ok_or("FAT size overflow")?;
        let overhead = u32::from(RESERVED_SECTORS).checked_add(fat_span).ok_or("FAT size overflow")?;
        if overhead >= total_sectors { return Err("FAT32 geometry overflow"); }
        let clusters = (total_sectors - overhead) / u32::from(sectors_per_cluster);
        let bytes = clusters.checked_add(2).and_then(|entries| entries.checked_mul(4)).ok_or("FAT entry overflow")?;
        let needed = bytes.checked_add(511).ok_or("FAT rounding overflow")? / 512;
        if needed <= fat_size { return Ok(fat_size); }
        fat_size = needed;
    }
}
