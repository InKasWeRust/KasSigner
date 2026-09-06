use super::Fat32Info;

pub(super) fn parse_boot_sector(sector: &[u8; 512]) -> Result<Fat32Info, &'static str> {
    let parsed = signer_firmware_core::storage::fat32_metadata::parse_boot_sector(sector)
        .map_err(|error| error.message())?;
    Ok(Fat32Info {
        sectors_per_cluster: parsed.sectors_per_cluster,
        num_fats: parsed.num_fats,
        fat_size_32: parsed.fat_size_32,
        root_cluster: parsed.root_cluster,
        total_sectors: parsed.total_sectors,
        fat_start_sector: parsed.fat_start_sector,
        data_start_sector: parsed.data_start_sector,
        cluster_count: parsed.cluster_count,
        fs_info_sector: parsed.fs_info_sector,
        backup_fs_info_sector: parsed.backup_fs_info_sector,
        next_free_cluster: 2,
    })
}
