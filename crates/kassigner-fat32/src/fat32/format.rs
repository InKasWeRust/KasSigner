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

// A card's size from its CSD, the geometry of a fresh volume, and the
// format itself, each sector it writes read back.

use super::*;

/// Read a sector back and compare it against the bytes just written.
///
/// A card that accepts a write has not necessarily kept it: a driver's write
/// sees only the data-response token and the busy release, both of which a
/// card can give for a write it then discards. A mismatch is the error
/// `label` names, so a failure says which structure did not stick.
pub fn verify_sector<D: BlockDevice>(
    dev: &mut D,
    sector: u32,
    expect: &[u8; 512],
    label: &'static str,
) -> Result<(), Fat32Error> {
    let mut back = [0u8; 512];
    dev.read(sector, &mut back)?;
    if back != *expect {
        return Err(Fat32Error::Format(label));
    }
    Ok(())
}

/// Reserved sectors before the first FAT, the FAT32 default.
const RESERVED_SECTORS: u16 = 32;
/// Two FATs, the FAT32 default: the second is the spare copy.
const NUM_FATS: u8 = 2;

/// FAT32 is only valid at 65,525 clusters or more; below that the count
/// makes it FAT16 by definition and a host will read it as one.
const FAT32_MIN_CLUSTERS: u32 = 65_525;

/// Sector count from a 16-byte CSD register.
///
/// Both layouts are handled: CSD v2 (SDHC and SDXC) states capacity directly,
/// v1 (standard capacity) states it as a size and a multiplier.
pub fn csd_sectors(csd: &[u8; 16]) -> Result<u32, Fat32Error> {
    match csd[0] >> 6 {
        1 => {
            // v2: C_SIZE is CSD bits 69:48, capacity is (C_SIZE + 1) * 512 KB.
            let c_size =
                (((csd[7] & 0x3F) as u32) << 16) | ((csd[8] as u32) << 8) | (csd[9] as u32);
            c_size
                .checked_add(1)
                .and_then(|n| n.checked_mul(1024))
                .ok_or(Fat32Error::Format("CSD capacity overflow"))
        }
        0 => {
            // v1: bits 73:62 size, 49:47 multiplier, 83:80 block length.
            let read_bl_len = (csd[5] & 0x0F) as u32;
            if !(9..=11).contains(&read_bl_len) {
                return Err(Fat32Error::Format("CSD block length invalid"));
            }
            let c_size =
                (((csd[6] & 0x03) as u32) << 10) | ((csd[7] as u32) << 2) | ((csd[8] as u32) >> 6);
            let c_size_mult = (((csd[9] & 0x03) as u32) << 1) | ((csd[10] as u32) >> 7);
            let blocks = (c_size + 1) * (1u32 << (c_size_mult + 2));
            let per_block = 1u32 << (read_bl_len - 9);
            blocks
                .checked_mul(per_block)
                .ok_or(Fat32Error::Format("CSD capacity overflow"))
        }
        _ => Err(Fat32Error::Format("Unknown CSD version")),
    }
}

/// A capacity is only believed if it could hold a FAT32 volume and stays
/// inside 32-bit sector arithmetic: a misparsed CSD almost always lands
/// outside this range.
pub fn csd_plausible(sectors: u32) -> bool {
    (131_072..=0x8000_0000).contains(&sectors)
}

/// Geometry derived from the card in front of us, not assumed.
pub struct FormatGeometry {
    pub total_sectors: u32,
    pub sectors_per_cluster: u8,
    pub fat_size: u32,
    pub clusters: u32,
}

/// Solve cluster size and FAT size against the measured sector count, so
/// the FAT has an entry for every cluster the BPB claims: a host filling a
/// card whose FAT is too short walks off the end of the table.
pub fn derive_geometry(total_sectors: u32) -> Result<FormatGeometry, Fat32Error> {
    let reserved = RESERVED_SECTORS as u32;
    let num_fats = NUM_FATS as u32;

    // Largest clusters first: fewer FAT sectors to write, and a handful of
    // small files waste little. Smaller only if the card cannot reach the
    // FAT32 cluster floor at that size.
    for spc in [64u32, 32, 16, 8, 4, 2, 1] {
        if total_sectors <= reserved {
            break;
        }
        // 128 entries a sector. One pass suffices: a FAT sized for the whole
        // region is never smaller than one sized for it less the FAT.
        let approx_clusters = (total_sectors - reserved) / spc;
        let fat_size = (approx_clusters + 2).div_ceil(128);
        let fat_total = num_fats * fat_size;
        if total_sectors <= reserved + fat_total {
            continue;
        }
        let clusters = (total_sectors - reserved - fat_total) / spc;
        if clusters < FAT32_MIN_CLUSTERS {
            continue;
        }
        // The FAT must describe every cluster the BPB claims.
        if fat_size * 128 < clusters + 2 {
            continue;
        }
        return Ok(FormatGeometry {
            total_sectors: reserved + fat_total + clusters * spc,
            sectors_per_cluster: spc as u8,
            fat_size,
            clusters,
        });
    }
    Err(Fat32Error::Format("Card too small for FAT32"))
}

/// Blocks the formatter clears with one multi-block write: 8 KB of zeros on
/// the stack, a size every board's driver takes in one command or splits
/// itself.
pub const CLEAR_RUN: usize = 16;

/// Format the card as FAT32. Runs inside a board's card session.
pub fn do_format_fat32<D: BlockDevice>(dev: &mut D) -> Result<(), Fat32Error> {
    let mut test = [0u8; 512];
    dev.read(0, &mut test)?;

    // Geometry comes from the card, not from constants. `blocks()` is zero
    // for unknown: a reader can work without the capacity, a formatter
    // cannot.
    let probed = match dev.blocks() {
        0 => return Err(Fat32Error::Format("Card capacity unknown")),
        n => n,
    };
    let geo = derive_geometry(probed)?;
    let sectors_per_cluster: u8 = geo.sectors_per_cluster;
    let reserved_sectors: u16 = RESERVED_SECTORS;
    let num_fats: u8 = NUM_FATS;
    let fat_size: u32 = geo.fat_size;
    let root_cluster: u32 = 2;
    let total_sectors: u32 = geo.total_sectors;

    let mut bpb = [0u8; 512];
    bpb[0] = 0xEB;
    bpb[1] = 0x58;
    bpb[2] = 0x90;
    bpb[3..11].copy_from_slice(b"MSDOS5.0");
    bpb[11] = 0x00;
    bpb[12] = 0x02; // 512 bytes/sector
    bpb[13] = sectors_per_cluster;
    bpb[14] = reserved_sectors as u8;
    bpb[15] = (reserved_sectors >> 8) as u8;
    bpb[16] = num_fats;
    bpb[21] = 0xF8; // media type
    bpb[24] = 0x3F;
    bpb[26] = 0xFF; // sectors per track / heads
    bpb[32] = total_sectors as u8;
    bpb[33] = (total_sectors >> 8) as u8;
    bpb[34] = (total_sectors >> 16) as u8;
    bpb[35] = (total_sectors >> 24) as u8;
    bpb[36] = fat_size as u8;
    bpb[37] = (fat_size >> 8) as u8;
    bpb[38] = (fat_size >> 16) as u8;
    bpb[39] = (fat_size >> 24) as u8;
    bpb[44] = root_cluster as u8;
    bpb[45] = (root_cluster >> 8) as u8;
    bpb[48] = 1;
    bpb[50] = 6; // FSInfo=1, backup BPB=6
    bpb[66] = 0x29; // extended boot sig
    bpb[67] = 0x4B;
    bpb[68] = 0x53;
    bpb[69] = 0x53;
    bpb[70] = 0x00; // serial
    bpb[71..82].copy_from_slice(b"KASSIGNER  ");
    bpb[82..90].copy_from_slice(b"FAT32   ");
    bpb[510] = 0x55;
    bpb[511] = 0xAA;

    dev.write(0, &bpb)?;
    dev.write(6, &bpb)?; // backup
                         // At once, before thousands more writes: a card
                         // that never keeps a write differs from one that
                         // loses it later.
    verify_sector(dev, 0, &bpb, "Verify BPB early")?;

    // Free count and next free cluster are real values rather than
    // "unknown": cluster 2 is the root directory, everything above is free.
    let free_count = geo.clusters - 1;
    let mut fsinfo = [0u8; 512];
    fsinfo[0] = 0x52;
    fsinfo[1] = 0x52;
    fsinfo[2] = 0x61;
    fsinfo[3] = 0x41;
    fsinfo[484] = 0x72;
    fsinfo[485] = 0x72;
    fsinfo[486] = 0x41;
    fsinfo[487] = 0x61;
    fsinfo[488..492].copy_from_slice(&free_count.to_le_bytes());
    fsinfo[492..496].copy_from_slice(&3u32.to_le_bytes());
    fsinfo[510] = 0x55;
    fsinfo[511] = 0xAA;
    dev.write(1, &fsinfo)?;
    // Sector 7 is the backup FSInfo, mirroring sector 1 the way 6 mirrors 0.
    dev.write(7, &fsinfo)?;

    // Every write from here is checked: a format that failed halfway must
    // not report success with a BPB describing a filesystem its FAT does not.
    let zeros = [0u8; 512];
    for s in 2..reserved_sectors as u32 {
        if s == 6 || s == 7 {
            continue;
        } // already written
        dev.write(s, &zeros)?;
    }

    // The FATs' first sector: media byte, end marks for clusters 0, 1 and 2.
    let mut fat_first = [0u8; 512];
    fat_first[0] = 0xF8;
    fat_first[1] = 0xFF;
    fat_first[2] = 0xFF;
    fat_first[3] = 0x0F;
    fat_first[4] = 0xFF;
    fat_first[5] = 0xFF;
    fat_first[6] = 0xFF;
    fat_first[7] = 0x0F;
    fat_first[8] = 0xFF;
    fat_first[9] = 0xFF;
    fat_first[10] = 0xFF;
    fat_first[11] = 0x0F;
    let fat1_start = reserved_sectors as u32;
    let fat2_start = fat1_start + fat_size;
    dev.write(fat1_start, &fat_first)?;
    dev.write(fat2_start, &fat_first)?;
    // The whole table: old entries past a cleared range would read as
    // chains on a card that reports empty. [`CLEAR_RUN`] blocks a command:
    // one block a command took 32 s on the M5 for a 16 GB card, nearly all
    // of it per-command overhead.
    let run = [0u8; block::BLOCK_SIZE * CLEAR_RUN];
    for start in [fat1_start, fat2_start] {
        let mut i = 1u32;
        while i < fat_size {
            let n = (fat_size - i).min(CLEAR_RUN as u32);
            dev.write_many(start + i, &run[..n as usize * block::BLOCK_SIZE])?;
            i += n;
        }
    }

    // Clear root directory cluster
    let data_start = reserved_sectors as u32 + num_fats as u32 * fat_size;
    for i in 0..sectors_per_cluster as u32 {
        dev.write(data_start + i, &zeros)?;
    }

    // Read back every structure that decides whether the card is usable,
    // the last FAT sector included (a partial clear leaves it stale).
    // Checked early and at the end, so a write later lost looks different
    // from one never kept.
    verify_sector(dev, 0, &bpb, "Verify BPB")?;
    verify_sector(dev, 6, &bpb, "Verify BPB backup")?;
    verify_sector(dev, 1, &fsinfo, "Verify FSInfo")?;
    verify_sector(dev, fat1_start, &fat_first, "Verify FAT1")?;
    verify_sector(dev, fat2_start, &fat_first, "Verify FAT2")?;
    verify_sector(dev, fat1_start + fat_size - 1, &zeros, "Verify FAT1 tail")?;
    verify_sector(dev, fat2_start + fat_size - 1, &zeros, "Verify FAT2 tail")?;
    verify_sector(dev, data_start, &zeros, "Verify root")?;

    Ok(())
}
