use super::*;

fn valid_sector() -> [u8; 512] {
    let mut sector = [0u8; 512];
    sector[11..13].copy_from_slice(&512u16.to_le_bytes());
    sector[13] = 1;
    sector[14..16].copy_from_slice(&32u16.to_le_bytes());
    sector[16] = 2;
    sector[32..36].copy_from_slice(&70_000u32.to_le_bytes());
    sector[36..40].copy_from_slice(&600u32.to_le_bytes());
    sector[44..48].copy_from_slice(&2u32.to_le_bytes());
    sector[48..50].copy_from_slice(&1u16.to_le_bytes());
    sector[50..52].copy_from_slice(&6u16.to_le_bytes());
    sector[510] = 0x55;
    sector[511] = 0xaa;
    sector
}

#[test]
fn fat32_error_messages_cover_every_variant() {
    let cases = [
        (Fat32Error::BootSignature, "Invalid boot sector signature"),
        (Fat32Error::SectorSize, "Only 512-byte sectors supported"),
        (Fat32Error::ClusterSize, "Invalid sectors per cluster"),
        (Fat32Error::FatCount, "Invalid number of FATs"),
        (Fat32Error::FatSize, "Invalid FAT32 size"),
        (Fat32Error::GeometryOverflow, "FAT geometry overflow"),
        (Fat32Error::DataGeometry, "Invalid FAT32 data geometry"),
        (Fat32Error::ClusterCount, "FAT32 cluster count too small"),
        (Fat32Error::EntryCountOverflow, "FAT entry count overflow"),
        (Fat32Error::ByteCountOverflow, "FAT byte count overflow"),
        (
            Fat32Error::SectorRoundingOverflow,
            "FAT sector rounding overflow",
        ),
        (
            Fat32Error::FatCapacity,
            "FAT32 table is undersized for declared data area",
        ),
        (Fat32Error::BackupFsInfoOverflow, "Backup FSInfo overflow"),
    ];
    for (error, message) in cases {
        assert_eq!(error.message(), message);
    }
}

#[test]
fn valid_fat32_boot_sector_and_directory_entry_round_trip_metadata() {
    let sector = valid_sector();
    let info = parse_boot_sector(&sector).expect("valid FAT32 metadata");
    assert_eq!(info.sectors_per_cluster, 1);
    assert_eq!(info.num_fats, 2);
    assert_eq!(info.fat_size_32, 600);
    assert_eq!(info.root_cluster, 2);
    assert_eq!(info.total_sectors, 70_000);
    assert_eq!(info.fat_start_sector, 32);
    assert_eq!(info.data_start_sector, 1_232);
    assert_eq!(info.cluster_count, 68_768);
    assert_eq!(info.fs_info_sector, Some(1));
    assert_eq!(info.backup_fs_info_sector, Some(7));

    let mut entry = [0u8; 32];
    entry[..11].copy_from_slice(b"WALLET  BIN");
    entry[11] = 0x20;
    entry[20..22].copy_from_slice(&0x1234u16.to_le_bytes());
    entry[26..28].copy_from_slice(&0x5678u16.to_le_bytes());
    entry[28..32].copy_from_slice(&0x0102_0304u32.to_le_bytes());
    let parsed = parse_directory_entry(&entry).expect("directory entry");
    assert_eq!(&parsed.name, b"WALLET  BIN");
    assert_eq!(parsed.attr, 0x20);
    assert_eq!(parsed.cluster_hi, 0x1234);
    assert_eq!(parsed.cluster_lo, 0x5678);
    assert_eq!(parsed.file_size, 0x0102_0304);

    assert_eq!(parse_directory_entry(&entry[..31]), None);
    for first in [0x00, 0xe5] {
        let mut rejected = entry;
        rejected[0] = first;
        assert_eq!(parse_directory_entry(&rejected), None);
    }
    let mut lfn = entry;
    lfn[11] = 0x0f;
    assert_eq!(parse_directory_entry(&lfn), None);
}

#[test]
fn boot_sector_validation_covers_every_reachable_fail_closed_boundary() {
    let base = valid_sector();

    let mut sector = base;
    sector[510] = 0;
    assert_eq!(parse_boot_sector(&sector), Err(Fat32Error::BootSignature));

    let mut sector = base;
    sector[11..13].copy_from_slice(&1024u16.to_le_bytes());
    assert_eq!(parse_boot_sector(&sector), Err(Fat32Error::SectorSize));

    for cluster_size in [0u8, 3] {
        let mut sector = base;
        sector[13] = cluster_size;
        assert_eq!(parse_boot_sector(&sector), Err(Fat32Error::ClusterSize));
    }

    for fat_count in [0u8, 3] {
        let mut sector = base;
        sector[16] = fat_count;
        assert_eq!(parse_boot_sector(&sector), Err(Fat32Error::FatCount));
    }

    let mut sector = base;
    sector[36..40].fill(0);
    assert_eq!(parse_boot_sector(&sector), Err(Fat32Error::FatSize));

    let mut sector = base;
    sector[32..36].copy_from_slice(&1_000u32.to_le_bytes());
    assert_eq!(parse_boot_sector(&sector), Err(Fat32Error::DataGeometry));

    let mut sector = base;
    sector[32..36].copy_from_slice(&60_000u32.to_le_bytes());
    assert_eq!(parse_boot_sector(&sector), Err(Fat32Error::ClusterCount));

    let mut sector = base;
    sector[16] = 1;
    sector[36..40].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(parse_boot_sector(&sector), Err(Fat32Error::FatCapacity));
}

#[test]
fn geometry_capacity_fsinfo_and_total_sector_helpers_cover_overflow_and_optional_paths() {
    assert_eq!(
        data_geometry(u32::MAX, 0, 2, u32::MAX, 1),
        Err(Fat32Error::GeometryOverflow)
    );
    assert_eq!(
        validate_fat_capacity(u32::MAX, u32::MAX),
        Err(Fat32Error::EntryCountOverflow)
    );
    assert_eq!(
        validate_fat_capacity(u32::MAX - 2, u32::MAX),
        Err(Fat32Error::ByteCountOverflow),
    );
    assert_eq!(
        validate_fat_capacity(1_073_741_821, u32::MAX),
        Err(Fat32Error::SectorRoundingOverflow),
    );
    assert_eq!(validate_fat_capacity(65_525, 513), Ok(()));

    assert_eq!(optional_relative_sector(0), None);
    assert_eq!(optional_relative_sector(u16::MAX), None);
    assert_eq!(optional_relative_sector(1), Some(1));

    let mut sector = valid_sector();
    sector[48..50].fill(0);
    assert_eq!(parse_fsinfo_sectors(&sector), Ok((None, None)));
    sector[48..50].copy_from_slice(&2u16.to_le_bytes());
    sector[50..52].fill(0);
    assert_eq!(parse_fsinfo_sectors(&sector), Ok((Some(2), None)));
    sector[50..52].copy_from_slice(&u16::MAX.to_le_bytes());
    assert_eq!(parse_fsinfo_sectors(&sector), Ok((Some(2), None)));
    sector[50..52].copy_from_slice(&8u16.to_le_bytes());
    assert_eq!(parse_fsinfo_sectors(&sector), Ok((Some(2), Some(10))));

    let mut total = [0u8; 512];
    total[19..21].copy_from_slice(&123u16.to_le_bytes());
    total[32..36].copy_from_slice(&999u32.to_le_bytes());
    assert_eq!(parse_total_sectors(&total), 123);
    total[19..21].fill(0);
    assert_eq!(parse_total_sectors(&total), 999);
}
