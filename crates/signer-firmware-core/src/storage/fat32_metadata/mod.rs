//! Pure FAT32 metadata parsers for untrusted removable media.
//!
//! Board drivers provide block transport only. Boot-sector and directory-entry
//! interpretation lives here so host property tests/fuzzers exercise the exact
//! parsing used by firmware.

pub const SECTOR_BYTES: u32 = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fat32Error {
    BootSignature,
    SectorSize,
    ClusterSize,
    FatCount,
    FatSize,
    GeometryOverflow,
    DataGeometry,
    ClusterCount,
    EntryCountOverflow,
    ByteCountOverflow,
    SectorRoundingOverflow,
    FatCapacity,
    BackupFsInfoOverflow,
}

const FAT32_ERROR_MESSAGES: [&str; 13] = [
    "Invalid boot sector signature",
    "Only 512-byte sectors supported",
    "Invalid sectors per cluster",
    "Invalid number of FATs",
    "Invalid FAT32 size",
    "FAT geometry overflow",
    "Invalid FAT32 data geometry",
    "FAT32 cluster count too small",
    "FAT entry count overflow",
    "FAT byte count overflow",
    "FAT sector rounding overflow",
    "FAT32 table is undersized for declared data area",
    "Backup FSInfo overflow",
];

impl Fat32Error {
    pub const fn message(self) -> &'static str {
        FAT32_ERROR_MESSAGES[self as usize]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fat32BootInfo {
    pub sectors_per_cluster: u8,
    pub num_fats: u8,
    pub fat_size_32: u32,
    pub root_cluster: u32,
    pub total_sectors: u32,
    pub fat_start_sector: u32,
    pub data_start_sector: u32,
    pub cluster_count: u32,
    pub fs_info_sector: Option<u32>,
    pub backup_fs_info_sector: Option<u32>,
}

pub fn parse_boot_sector(sector: &[u8; 512]) -> Result<Fat32BootInfo, Fat32Error> {
    validate_header(sector)?;
    let sectors_per_cluster = parse_cluster_size(sector)?;
    let (reserved_sectors, num_fats, fat_size_32) = parse_fat_fields(sector)?;
    let total_sectors = parse_total_sectors(sector);
    let (fat_start_sector, data_start_sector, cluster_count) = data_geometry(
        total_sectors,
        reserved_sectors,
        num_fats,
        fat_size_32,
        sectors_per_cluster,
    )?;
    validate_fat_capacity(cluster_count, fat_size_32)?;
    let (fs_info_sector, backup_fs_info_sector) = parse_fsinfo_sectors(sector)?;
    let root_cluster = u32::from_le_bytes([sector[44], sector[45], sector[46], sector[47]]);
    Ok(Fat32BootInfo {
        sectors_per_cluster,
        num_fats,
        fat_size_32,
        root_cluster,
        total_sectors,
        fat_start_sector,
        data_start_sector,
        cluster_count,
        fs_info_sector,
        backup_fs_info_sector,
    })
}

fn validate_header(sector: &[u8; 512]) -> Result<(), Fat32Error> {
    if sector[510] != 0x55 || sector[511] != 0xAA {
        return Err(Fat32Error::BootSignature);
    }
    if u16::from_le_bytes([sector[11], sector[12]]) != 512 {
        return Err(Fat32Error::SectorSize);
    }
    Ok(())
}

fn parse_cluster_size(sector: &[u8; 512]) -> Result<u8, Fat32Error> {
    let value = sector[13];
    if value == 0 || !value.is_power_of_two() {
        Err(Fat32Error::ClusterSize)
    } else {
        Ok(value)
    }
}

fn parse_fat_fields(sector: &[u8; 512]) -> Result<(u16, u8, u32), Fat32Error> {
    let reserved = u16::from_le_bytes([sector[14], sector[15]]);
    let fats = sector[16];
    if fats == 0 || fats > 2 {
        return Err(Fat32Error::FatCount);
    }
    let size = u32::from_le_bytes([sector[36], sector[37], sector[38], sector[39]]);
    if size == 0 {
        return Err(Fat32Error::FatSize);
    }
    Ok((reserved, fats, size))
}

fn parse_total_sectors(sector: &[u8; 512]) -> u32 {
    let short = u16::from_le_bytes([sector[19], sector[20]]);
    if short != 0 {
        u32::from(short)
    } else {
        u32::from_le_bytes([sector[32], sector[33], sector[34], sector[35]])
    }
}

fn data_geometry(
    total_sectors: u32,
    reserved_sectors: u16,
    num_fats: u8,
    fat_size_32: u32,
    sectors_per_cluster: u8,
) -> Result<(u32, u32, u32), Fat32Error> {
    let fat_start = u32::from(reserved_sectors);
    let fat_span = u32::from(num_fats)
        .checked_mul(fat_size_32)
        .ok_or(Fat32Error::GeometryOverflow)?;
    let data_start = fat_start
        .checked_add(fat_span)
        .ok_or(Fat32Error::GeometryOverflow)?;
    if total_sectors <= data_start {
        return Err(Fat32Error::DataGeometry);
    }
    let clusters = (total_sectors - data_start) / u32::from(sectors_per_cluster);
    if clusters < 65_525 {
        return Err(Fat32Error::ClusterCount);
    }
    Ok((fat_start, data_start, clusters))
}

fn validate_fat_capacity(cluster_count: u32, fat_size_32: u32) -> Result<(), Fat32Error> {
    let entries = cluster_count
        .checked_add(2)
        .ok_or(Fat32Error::EntryCountOverflow)?;
    let bytes = entries
        .checked_mul(4)
        .ok_or(Fat32Error::ByteCountOverflow)?;
    let sectors = bytes
        .checked_add(SECTOR_BYTES - 1)
        .ok_or(Fat32Error::SectorRoundingOverflow)?
        / SECTOR_BYTES;
    if fat_size_32 < sectors {
        Err(Fat32Error::FatCapacity)
    } else {
        Ok(())
    }
}

fn parse_fsinfo_sectors(sector: &[u8; 512]) -> Result<(Option<u32>, Option<u32>), Fat32Error> {
    let primary = optional_relative_sector(u16::from_le_bytes([sector[48], sector[49]]));
    let backup_boot = u16::from_le_bytes([sector[50], sector[51]]);
    let backup = match primary {
        None => None,
        Some(_) if backup_boot == 0 || backup_boot == u16::MAX => None,
        Some(fsinfo) => Some(
            u32::from(backup_boot)
                .checked_add(fsinfo)
                .ok_or(Fat32Error::BackupFsInfoOverflow)?,
        ),
    };
    Ok((primary, backup))
}

fn optional_relative_sector(relative: u16) -> Option<u32> {
    if relative == 0 || relative == u16::MAX {
        None
    } else {
        Some(u32::from(relative))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fat32DirectoryEntry {
    pub name: [u8; 11],
    pub attr: u8,
    pub cluster_hi: u16,
    pub cluster_lo: u16,
    pub file_size: u32,
}

pub fn parse_directory_entry(data: &[u8]) -> Option<Fat32DirectoryEntry> {
    let data = data.get(..32)?;
    if data[0] == 0x00 || data[0] == 0xE5 || data[11] == 0x0F {
        return None;
    }
    let mut name = [0u8; 11];
    name.copy_from_slice(&data[..11]);
    Some(Fat32DirectoryEntry {
        name,
        attr: data[11],
        cluster_hi: u16::from_le_bytes([data[20], data[21]]),
        cluster_lo: u16::from_le_bytes([data[26], data[27]]),
        file_size: u32::from_le_bytes([data[28], data[29], data[30], data[31]]),
    })
}

#[cfg(test)]
mod unit_tests;
