// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// fat32: the FAT32 layer, over a block-device trait. The transport
// (bit-banged SPI on the M5, SDHOST on the Waveshare, the P4's own host) and
// each unit's card session stay in the board crates, which implement
// `BlockDevice`. `tests/fat32.rs` runs the layer against an in-memory card.
//
// Here: the volume and its entries, 8.3 names, the mount and the partition
// table. `table`: the FAT, from one entry to allocating and freeing chains.
// `file`: finding, reading, writing, deleting and overwriting a file.
// `dir`: the root directory's slots and listings, and long names. `format`:
// a card's size and a fresh volume. Everything public is re-exported here,
// so a caller names `fat32::` alone.

use crate::block::{self, BlockDevice};

mod dir;
mod file;
mod format;
mod table;

pub use dir::*;
pub use file::*;
pub use format::*;
pub use table::*;

/// Why a filesystem operation failed: `Device`, the card failed and the
/// filesystem may be fine; `Format`, the bytes on the card do not describe a
/// filesystem this can use, and retrying will not help.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fat32Error {
    /// The block device failed underneath.
    Device(block::Error),
    /// The card does not hold a filesystem this can use; the message says
    /// what was wrong.
    Format(&'static str),
}

impl From<block::Error> for Fat32Error {
    fn from(e: block::Error) -> Self {
        Fat32Error::Device(e)
    }
}

// ═══════════════════════════════════════════════════════════════
// FAT32 Filesystem Structures
// ═══════════════════════════════════════════════════════════════

/// FAT32 Boot Sector / BPB (BIOS Parameter Block)
#[derive(Debug, Clone)]
pub struct Fat32Info {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub num_fats: u8,
    pub fat_size_32: u32,
    pub root_cluster: u32,
    /// The volume's size in sectors, counted from its own first sector.
    pub total_sectors: u32,
    /// Where the first FAT starts, as a sector on the card: the partition's
    /// start is added at mount.
    pub fat_start_sector: u32,
    /// Where cluster 2 starts, as a sector on the card, like the FAT's.
    pub data_start_sector: u32,
    /// Where the FSInfo sector is, as a sector on the card, like the two
    /// starts; 0 when the volume names none.
    pub fsinfo_sector: u32,
}

impl Fat32Info {
    /// Parse FAT32 BPB from boot sector
    pub fn from_boot_sector(sector: &[u8; 512]) -> Result<Self, Fat32Error> {
        if sector[510] != 0x55 || sector[511] != 0xAA {
            return Err(Fat32Error::Format("Invalid boot sector signature"));
        }
        let bytes_per_sector = u16::from_le_bytes([sector[11], sector[12]]);
        if bytes_per_sector != 512 {
            return Err(Fat32Error::Format("Only 512-byte sectors supported"));
        }
        let sectors_per_cluster = sector[13];
        if sectors_per_cluster == 0 || !sectors_per_cluster.is_power_of_two() {
            return Err(Fat32Error::Format("Invalid sectors per cluster"));
        }
        let reserved_sectors = u16::from_le_bytes([sector[14], sector[15]]);
        // `BPB_RsvdSecCnt`, where the first FAT starts, must be non-zero: zero
        // puts the FAT on the boot sector, which the first allocation would
        // overwrite.
        if reserved_sectors == 0 {
            return Err(Fat32Error::Format("Zero reserved sectors"));
        }
        let num_fats = sector[16];
        if num_fats == 0 || num_fats > 2 {
            return Err(Fat32Error::Format("Invalid number of FATs"));
        }
        let fat_size_16 = u16::from_le_bytes([sector[22], sector[23]]);
        let fat_size_32 = u32::from_le_bytes([sector[36], sector[37], sector[38], sector[39]]);
        // The FAT type: FAT32 keeps its FAT size in the 32-bit field and
        // `BPB_FATSz16` zero, FAT12 and FAT16 the reverse. A FAT16 card (usual
        // at 2 GB or less) mounted as FAT32 would have its data area on its
        // FAT, and a save would overwrite that FAT and its root directory.
        if fat_size_32 == 0 {
            return Err(Fat32Error::Format("Zero FAT size"));
        }
        if fat_size_16 != 0 {
            return Err(Fat32Error::Format(
                "Not FAT32: FAT size is in the 16-bit field",
            ));
        }
        // `BPB_ExtFlags` bit 7: one FAT active, the others not copies. This
        // driver reads the first and writes both, so such a volume is refused.
        // Computers and `do_format_fat32` leave mirroring on.
        let ext_flags = u16::from_le_bytes([sector[40], sector[41]]);
        if ext_flags & 0x0080 != 0 {
            return Err(Fat32Error::Format("FAT mirroring off"));
        }
        let root_cluster = u32::from_le_bytes([sector[44], sector[45], sector[46], sector[47]]);
        // `BPB_TotSec16` is zero on FAT32, which keeps its size in
        // `BPB_TotSec32`: a card claiming two sizes is refused.
        let total_sectors_16 = u16::from_le_bytes([sector[19], sector[20]]);
        if total_sectors_16 != 0 {
            return Err(Fat32Error::Format(
                "Not FAT32: sector count in the 16-bit field",
            ));
        }
        let total_sectors = u32::from_le_bytes([sector[32], sector[33], sector[34], sector[35]]);
        let fat_start_sector = reserved_sectors as u32;
        // Checked: both factors come off the card.
        let data_start_sector = (num_fats as u32)
            .checked_mul(fat_size_32)
            .and_then(|fat_total| fat_start_sector.checked_add(fat_total))
            .ok_or(Fat32Error::Format("FAT does not fit the volume"))?;
        // The data area must start inside the volume, or the subtraction
        // below overflows (a panic: overflow checks stay on in release).
        if data_start_sector >= total_sectors {
            return Err(Fat32Error::Format(
                "Data area starts past the end of the volume",
            ));
        }
        let clusters = (total_sectors - data_start_sector) / sectors_per_cluster as u32;
        // The FAT must hold an entry for every cluster (128 a sector, from
        // cluster 2), or `read_fat_entry` reads past it and takes file data
        // for links. In 64 bits: both sides come off the card.
        if fat_size_32 as u64 * 128 < clusters as u64 + 2 {
            return Err(Fat32Error::Format("FAT too small for the cluster count"));
        }
        // The root cluster, checked once here as every root walk starts from
        // it: 0 and 1 are reserved (`cluster_to_sector` maps them to cluster
        // 2), and a root past the last cluster reads outside the data area.
        if root_cluster < 2 || root_cluster as u64 >= clusters as u64 + 2 {
            return Err(Fat32Error::Format("Invalid root cluster"));
        }
        // `BPB_FSInfo`: in the reserved area, after the boot sector. 0, 0xFFFF
        // or a sector outside that area means none.
        let fsinfo = u16::from_le_bytes([sector[48], sector[49]]);
        let fsinfo_sector = if fsinfo != 0 && fsinfo < reserved_sectors {
            fsinfo as u32
        } else {
            0
        };

        Ok(Self {
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sectors,
            num_fats,
            fat_size_32,
            root_cluster,
            total_sectors,
            fat_start_sector,
            data_start_sector,
            fsinfo_sector,
        })
    }

    /// The volume as it sits `lba` sectors into the card: every sector it
    /// names, FSInfo included, moves by `lba`, and its size does not.
    fn moved_to(mut self, lba: u32) -> Result<Self, Fat32Error> {
        let past = Fat32Error::Format("Volume past the last sector");
        self.fat_start_sector = self.fat_start_sector.checked_add(lba).ok_or(past)?;
        self.data_start_sector = self.data_start_sector.checked_add(lba).ok_or(past)?;
        if self.fsinfo_sector != 0 {
            self.fsinfo_sector = self.fsinfo_sector.checked_add(lba).ok_or(past)?;
        }
        Ok(self)
    }

    /// One past the volume's last cluster number. `total_sectors` counts from
    /// the volume's start and the data start from the card's, so the data
    /// start is taken back to the volume's first.
    fn cluster_limit(&self) -> u32 {
        let volume_start = self
            .fat_start_sector
            .saturating_sub(self.reserved_sectors as u32);
        let data = self.data_start_sector.saturating_sub(volume_start);
        2 + self.total_sectors.saturating_sub(data) / self.sectors_per_cluster as u32
    }

    /// One past the last cluster the free-cluster searches look at: the
    /// volume's last, and never FAT32's bad-cluster mark or above, whatever
    /// size the volume claims.
    fn alloc_limit(&self) -> u32 {
        self.cluster_limit().min(BAD_CLUSTER)
    }

    /// Whether `cluster` is one of this volume's data clusters: from 2 to its
    /// last, below FAT32's bad-cluster mark. The test for every cluster number
    /// read off the card: one past the volume's end would have `delete_file`
    /// clear words past FAT1, in FAT2 and in another file's data.
    pub fn is_data_cluster(&self, cluster: u32) -> bool {
        (2..self.cluster_limit().min(BAD_CLUSTER)).contains(&cluster)
    }

    /// Convert cluster number to first sector number
    pub fn cluster_to_sector(&self, cluster: u32) -> u32 {
        // `cluster - 2` would overflow on 0 and 1, which never name data.
        // Callers gate on [`Self::is_data_cluster`]; this backs it up.
        if cluster < 2 {
            return self.data_start_sector;
        } // guard: cluster 0,1 = invalid
        self.data_start_sector
            .saturating_add((cluster - 2).saturating_mul(self.sectors_per_cluster as u32))
    }

    /// Get FAT sector and byte offset for a cluster entry
    pub fn fat_sector_for_cluster(&self, cluster: u32) -> (u32, usize) {
        // Saturating: `cluster * 4` overflows above 2^30, a panic in release.
        // Unreachable: FAT32 has under 2^28 clusters and callers gate on
        // [`Self::is_data_cluster`].
        let fat_offset = cluster.saturating_mul(4);
        let sector = self.fat_start_sector.saturating_add(fat_offset / 512);
        let offset = (fat_offset % 512) as usize;
        (sector, offset)
    }

    /// Bytes per cluster
    pub fn cluster_bytes(&self) -> u32 {
        self.sectors_per_cluster as u32 * 512
    }
}

/// FAT32 directory entry (32 bytes)
#[derive(Clone, Copy)]
pub struct DirEntry {
    pub name: [u8; 11],
    pub attr: u8,
    pub cluster_hi: u16,
    pub cluster_lo: u16,
    pub file_size: u32,
}

impl DirEntry {
    /// Parse a FAT32 directory entry from 32 raw bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 32 {
            return None;
        }
        if data[0] == 0x00 {
            return None;
        } // end of dir
        if data[0] == 0xE5 {
            return None;
        } // deleted
        let attr = data[11];
        if attr == 0x0F {
            return None;
        } // LFN

        let mut name = [0u8; 11];
        name.copy_from_slice(&data[0..11]);
        let cluster_hi = u16::from_le_bytes([data[20], data[21]]);
        let cluster_lo = u16::from_le_bytes([data[26], data[27]]);
        let file_size = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);

        Some(Self {
            name,
            attr,
            cluster_hi,
            cluster_lo,
            file_size,
        })
    }

    /// Get the starting cluster number of this entry.
    pub fn first_cluster(&self) -> u32 {
        ((self.cluster_hi as u32) << 16) | (self.cluster_lo as u32)
    }

    /// Returns true if this entry is a directory.
    pub fn is_dir(&self) -> bool {
        self.attr & 0x10 != 0
    }

    /// Match against 8.3 name (case-insensitive)
    ///
    /// A first byte `0x05` stands for `0xE5`, which marks a deleted entry.
    /// Read so on both sides, a name matches spelled either way.
    pub fn matches(&self, name_83: &[u8; 11]) -> bool {
        // Both are 11 bytes: zip walks them together with no bounds checks.
        self.name
            .iter()
            .zip(name_83.iter())
            .enumerate()
            .all(|(i, (&x, &y))| {
                let (x, y) = match i {
                    0 => (unkept(x), unkept(y)),
                    _ => (x, y),
                };
                let a = if x.is_ascii_lowercase() { x - 32 } else { x };
                let b = if y.is_ascii_lowercase() { y - 32 } else { y };
                a == b
            })
    }
}

/// A name's first byte as meant: `0x05` is FAT's way of keeping `0xE5`.
const fn unkept(first: u8) -> u8 {
    if first == 0x05 {
        0xE5
    } else {
        first
    }
}

/// Refuse a name whose first byte the directory reads as a marker (`0x00`
/// ends it, `0xE5` deletes the entry): the file would never be seen.
/// [`to_83_name`] writes `0xE5` as `0x05`.
fn writable(name_83: &[u8; 11]) -> Result<(), Fat32Error> {
    match name_83[0] {
        0x00 | 0xE5 => Err(Fat32Error::Format("Name starts with a marker")),
        _ => Ok(()),
    }
}

/// Convert filename like "IMAGE.BMP" to 8.3 format (11 bytes, space-padded)
pub fn to_83_name(filename: &[u8]) -> [u8; 11] {
    let mut result = [b' '; 11];
    let mut dot_pos = filename.len();
    for (i, &c) in filename.iter().enumerate() {
        if c == b'.' {
            dot_pos = i;
            break;
        }
    }
    let base_len = if dot_pos < 8 { dot_pos } else { 8 };
    for (dst, &c) in result.iter_mut().zip(filename.iter()).take(base_len) {
        *dst = if c.is_ascii_lowercase() { c - 32 } else { c };
    }
    if dot_pos < filename.len() {
        let ext_start = dot_pos + 1;
        for i in 0..3 {
            if ext_start + i < filename.len() {
                result[8 + i] =
                    if filename[ext_start + i] >= b'a' && filename[ext_start + i] <= b'z' {
                        filename[ext_start + i] - 32
                    } else {
                        filename[ext_start + i]
                    };
            }
        }
    }
    // A first byte that reads as a marker is never written: `0xE5` is kept as
    // FAT keeps it, `0x05`, and `0x00` becomes a space.
    result[0] = match result[0] {
        0xE5 => 0x05,
        0x00 => b' ',
        c => c,
    };
    result
}

// ═══════════════════════════════════════════════════════════════
// Mounting
// ═══════════════════════════════════════════════════════════════

/// Mount FAT32: read BPB, return Fat32Info. Call inside a board's card session.
/// Handles superfloppy (BPB at sector 0), MBR with FAT32 partition, and
/// cards reformatted by macOS/Windows (which may add a partition table).
pub fn mount_fat32<D: BlockDevice>(dev: &mut D) -> Result<Fat32Info, Fat32Error> {
    let mut sector = [0u8; 512];
    dev.read(0, &mut sector)?;

    // Strategy 1: Sector 0 is a BPB (superfloppy) — jump byte + 0x55AA
    if (sector[0] == 0xEB || sector[0] == 0xE9) && sector[510] == 0x55 && sector[511] == 0xAA {
        if let Ok(info) = Fat32Info::from_boot_sector(&sector) {
            return on_the_card(dev, 0, info);
        }
    }

    // Strategy 2: Sector 0 is an MBR — find FAT32 partition
    //
    // A partition past the card, or whose first sector is no boot sector,
    // falls through to strategy 3: the table can be wrong while the volume
    // sits where the probes look. Other read errors (a card pulled out) are
    // returned. A volume larger than its partition ends the mount: the
    // probes could find the same boot sector and mount it over what follows.
    if sector[510] == 0x55 && sector[511] == 0xAA {
        if let Ok((lba, sectors)) = find_fat32_partition(&sector) {
            if lba > 0 {
                match dev.read(lba, &mut sector) {
                    Ok(()) => {
                        if let Ok(info) = Fat32Info::from_boot_sector(&sector) {
                            if info.total_sectors > sectors {
                                return Err(Fat32Error::Format("Volume past its partition"));
                            }
                            return on_the_card(dev, lba, info)?.moved_to(lba);
                        }
                    }
                    Err(block::Error::OutOfRange { .. }) => {}
                    Err(e) => return Err(e.into()),
                }
            }
            // lba == 0 means superfloppy fallback — already tried above
        }
    }

    // Strategy 3: Maybe sector 0 is a protective MBR (GPT) or unknown layout.
    // Try the usual partition starts, and sector 1.
    for &probe_lba in &[2048u32, 8192, 32768, 1] {
        if dev.read(probe_lba, &mut sector).is_ok()
            && (sector[0] == 0xEB || sector[0] == 0xE9)
            && sector[510] == 0x55
            && sector[511] == 0xAA
        {
            if let Ok(info) = Fat32Info::from_boot_sector(&sector) {
                return on_the_card(dev, probe_lba, info)?.moved_to(probe_lba);
            }
        }
    }

    Err(Fat32Error::Format("No FAT32 filesystem found"))
}

/// `info`, a volume `lba` sectors into the card, if it ends on the card; one
/// past the end has clusters the card refuses or wraps. A card of unknown
/// size takes the volume's word.
fn on_the_card<D: BlockDevice>(
    dev: &D,
    lba: u32,
    info: Fat32Info,
) -> Result<Fat32Info, Fat32Error> {
    let past = Fat32Error::Format("Volume past the last sector");
    let end = lba.checked_add(info.total_sectors).ok_or(past)?;
    let blocks = dev.blocks();
    if blocks != 0 && end > blocks {
        return Err(past);
    }
    Ok(info)
}

// ═══════════════════════════════════════════════════════════════
// MBR / Partition Table
// ═══════════════════════════════════════════════════════════════

/// Find the first FAT32 partition in an MBR: its first sector and how many
/// sectors it has, the entry's two fields. `(0, 0)` for a sector 0 that is
/// no table but a boot sector, which the mount has tried already.
pub fn find_fat32_partition(mbr: &[u8; 512]) -> Result<(u32, u32), Fat32Error> {
    if mbr[510] != 0x55 || mbr[511] != 0xAA {
        return Err(Fat32Error::Format("Invalid MBR signature"));
    }
    for i in 0..4 {
        let base = 446 + i * 16;
        let part_type = mbr[base + 4];
        if part_type == 0x0B || part_type == 0x0C {
            let field =
                |at: usize| u32::from_le_bytes([mbr[at], mbr[at + 1], mbr[at + 2], mbr[at + 3]]);
            return Ok((field(base + 8), field(base + 12)));
        }
    }
    if mbr[0] == 0xEB || mbr[0] == 0xE9 {
        return Ok((0, 0));
    }
    Err(Fat32Error::Format("No FAT32 partition found"))
}

/// An 8.3 name for display: spaces trimmed, no dot without an extension.
pub fn format_83_display(name: &[u8; 11], out: &mut [u8; 13]) -> usize {
    let mut pos = 0;
    // Base name (trim trailing spaces)
    let mut base_len = 8;
    while base_len > 0 && name[base_len - 1] == b' ' {
        base_len -= 1;
    }
    for &c in name.iter().take(base_len) {
        out[pos] = c;
        pos += 1;
    }
    // Extension (trim trailing spaces)
    let mut ext_len = 3;
    while ext_len > 0 && name[8 + ext_len - 1] == b' ' {
        ext_len -= 1;
    }
    if ext_len > 0 {
        out[pos] = b'.';
        pos += 1;
        for &c in name[8..].iter().take(ext_len) {
            out[pos] = c;
            pos += 1;
        }
    }
    pos
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The free-cluster searches stop below the bad-cluster mark.**
    ///
    /// A volume can claim more clusters than FAT32 numbers: its size and FAT
    /// size are its own word. A search to that claim would read FAT sectors
    /// past `0x0FFF_FFF7`, where no data cluster is, all the way to a "Disk
    /// full". One-sector clusters over every sector a volume can count, a
    /// FAT big enough for them all.
    #[test]
    fn the_free_cluster_searches_stop_below_the_bad_cluster_mark() {
        let fat = 0x0200_0000;
        let info = Fat32Info {
            bytes_per_sector: 512,
            sectors_per_cluster: 1,
            reserved_sectors: 32,
            num_fats: 1,
            fat_size_32: fat,
            root_cluster: 2,
            total_sectors: u32::MAX,
            fat_start_sector: 32,
            data_start_sector: 32 + fat,
            fsinfo_sector: 0,
        };
        assert!(
            info.cluster_limit() > BAD_CLUSTER,
            "the claim runs past the mark"
        );
        assert_eq!(info.alloc_limit(), BAD_CLUSTER);
        assert!(info.is_data_cluster(BAD_CLUSTER - 1));
        assert!(!info.is_data_cluster(BAD_CLUSTER));
    }
}
