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

// fat32.rs — the FAT32 layer, once, over a block-device trait.
//
// Until 1.0.7 this code existed twice, as the second half of
// bootloader/src/hw/sdcard_m5.rs and of sdcard_ws.rs, 55% line-identical
// and drifting: a guard added to one copy was routinely missed in the other
// (three such asymmetries in one week of hardening). This file is the M5
// copy's text with the transport calls replaced by `BlockDevice` methods and
// the stricter of each pair of differences kept:
//   - `read_fat_entry` carries the Waveshare offset guard (unreachable);
//   - `find_fat32_partition` carries the M5 MBR signature check, which the
//     Waveshare copy lacked. That is the one behaviour change of the move:
//     a Waveshare card whose sector 0 is neither a BPB nor a signed MBR now
//     fails mount strategy 2 and falls through to strategy 3 instead of
//     reading partition offsets out of an unsigned sector.
//
// The transport (bitbang / SPI2 on M5, SDHOST on Waveshare, and the
// `with_sd_card` bracket around every use) stays in the drivers, which
// implement `BlockDevice` for their `SdCardType` and re-export this API so
// every `sdcard::mount_fat32(ct)` call in the firmware is unchanged.
//
// Being here means the whole layer runs on the host against an in-memory
// card image under `cargo test` (see fat32_tests.rs).

/// A 512-byte-sector block device.
///
/// `Copy` and by-value on purpose: on both boards the transport state is
/// global (statics behind free functions) and the value passed around is
/// the detected `SdCardType`, which is what the 89 existing call sites
/// already hand to every FAT function. The host test device is a `Copy`
/// handle to an in-memory image. The trait therefore costs the callers
/// nothing and changes no signature they see.
pub trait BlockDevice: Copy {
    /// Read one 512-byte sector.
    fn read_block(self, block: u32, buf: &mut [u8; 512]) -> Result<(), &'static str>;
    /// Write one 512-byte sector.
    fn write_block(self, block: u32, buf: &[u8; 512]) -> Result<(), &'static str>;
    /// Read `count` consecutive sectors into `out` (`out.len() >= count*512`).
    fn read_multi(self, block: u32, out: &mut [u8], count: u32) -> Result<(), &'static str>;
    /// Write `count` consecutive sectors from `data` (`data.len() >= count*512`).
    fn write_multi(self, block: u32, data: &[u8], count: u32) -> Result<(), &'static str>;
    /// Sector count of the card, from its CSD. Used only by the formatter.
    fn card_sectors(self) -> Result<u32, &'static str>;
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
    pub total_sectors: u32,
    pub fat_start_sector: u32,
    pub data_start_sector: u32,
}

impl Fat32Info {
    /// Parse FAT32 BPB from boot sector
    pub fn from_boot_sector(sector: &[u8; 512]) -> Result<Self, &'static str> {
        if sector[510] != 0x55 || sector[511] != 0xAA {
            return Err("Invalid boot sector signature");
        }
        let bytes_per_sector = u16::from_le_bytes([sector[11], sector[12]]);
        if bytes_per_sector != 512 {
            return Err("Only 512-byte sectors supported");
        }
        let sectors_per_cluster = sector[13];
        if sectors_per_cluster == 0 || !sectors_per_cluster.is_power_of_two() {
            return Err("Invalid sectors per cluster");
        }
        let reserved_sectors = u16::from_le_bytes([sector[14], sector[15]]);
        let num_fats = sector[16];
        if num_fats == 0 || num_fats > 2 {
            return Err("Invalid number of FATs");
        }
        let fat_size_32 = u32::from_le_bytes([sector[36], sector[37], sector[38], sector[39]]);
        let root_cluster = u32::from_le_bytes([sector[44], sector[45], sector[46], sector[47]]);
        // Clusters 0 and 1 are reserved and never name data. `root_cluster` was
        // the one BPB field taken straight from the card with no check, and the
        // four root-directory walkers all seed their chain from it, so a hostile
        // 0 or 1 reached `cluster_to_sector`, hit its `< 2` guard, and got
        // `data_start_sector` back: the walk then read cluster 2's directory as
        // though it were the root. Refused at the mount instead of guarded four
        // times downstream. `do_format_fat32` writes 2 here (:1231).
        if root_cluster < 2 {
            return Err("Invalid root cluster");
        }
        let total_sectors_16 = u16::from_le_bytes([sector[19], sector[20]]);
        let total_sectors_32 = u32::from_le_bytes([sector[32], sector[33], sector[34], sector[35]]);
        let total_sectors = if total_sectors_16 != 0 { total_sectors_16 as u32 } else { total_sectors_32 };
        let fat_start_sector = reserved_sectors as u32;
        let data_start_sector = fat_start_sector + (num_fats as u32 * fat_size_32);

        log!("[FAT32] spc={} reserved={} fats={} fat_sz={} root_cl={} data_start={}",
            sectors_per_cluster, reserved_sectors, num_fats, fat_size_32, root_cluster, data_start_sector);

        Ok(Self {
            bytes_per_sector, sectors_per_cluster, reserved_sectors, num_fats,
            fat_size_32, root_cluster, total_sectors, fat_start_sector, data_start_sector,
        })
    }

    /// Convert cluster number to first sector number
    pub fn cluster_to_sector(&self, cluster: u32) -> u32 {
        // Same guard and saturating arithmetic as the Waveshare driver, which
        // had both while this copy had neither. Clusters 0 and 1 are reserved
        // and never name data; `cluster - 2` on either is a subtract overflow,
        // which the release profile traps, so the failure was a panic rather
        // than a bad sector number. Callers already gate on `2..0x0FFF_FFF8`,
        // so this is the copy of an invariant, not a new one.
        if cluster < 2 { return self.data_start_sector; } // guard: cluster 0,1 = invalid
        self.data_start_sector.saturating_add(
            (cluster - 2).saturating_mul(self.sectors_per_cluster as u32)
        )
    }

    /// Get FAT sector and byte offset for a cluster entry
    pub fn fat_sector_for_cluster(&self, cluster: u32) -> (u32, usize) {
        // Saturating, as the Waveshare copy already was. `cluster * 4` traps
        // above 2^30 on the release profile and the sector sum can trap too,
        // so the failure mode was a panic rather than a wrong sector. Not
        // reachable: FAT32 tops out near 2^28 clusters and callers gate on
        // `2..0x0FFF_FFF8`. Copied so the two drivers stop diverging on the
        // same function.
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
        if data.len() < 32 { return None; }
        if data[0] == 0x00 { return None; } // end of dir
        if data[0] == 0xE5 { return None; } // deleted
        let attr = data[11];
        if attr == 0x0F { return None; } // LFN

        let mut name = [0u8; 11];
        name.copy_from_slice(&data[0..11]);
        let cluster_hi = u16::from_le_bytes([data[20], data[21]]);
        let cluster_lo = u16::from_le_bytes([data[26], data[27]]);
        let file_size = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);

        Some(Self { name, attr, cluster_hi, cluster_lo, file_size })
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
    pub fn matches(&self, name_83: &[u8; 11]) -> bool {
        for i in 0..11 {
            let a = if self.name[i] >= b'a' && self.name[i] <= b'z' { self.name[i] - 32 } else { self.name[i] };
            let b = if name_83[i] >= b'a' && name_83[i] <= b'z' { name_83[i] - 32 } else { name_83[i] };
            if a != b { return false; }
        }
        true
    }
}

/// Convert filename like "IMAGE.BMP" to 8.3 format (11 bytes, space-padded)
pub fn to_83_name(filename: &[u8]) -> [u8; 11] {
    let mut result = [b' '; 11];
    let mut dot_pos = filename.len();
    for i in 0..filename.len() {
        if filename[i] == b'.' { dot_pos = i; break; }
    }
    let base_len = if dot_pos < 8 { dot_pos } else { 8 };
    for i in 0..base_len {
        result[i] = if filename[i] >= b'a' && filename[i] <= b'z' { filename[i] - 32 } else { filename[i] };
    }
    if dot_pos < filename.len() {
        let ext_start = dot_pos + 1;
        for i in 0..3 {
            if ext_start + i < filename.len() {
                result[8 + i] = if filename[ext_start + i] >= b'a' && filename[ext_start + i] <= b'z' {
                    filename[ext_start + i] - 32
                } else {
                    filename[ext_start + i]
                };
            }
        }
    }
    result
}


// ═══════════════════════════════════════════════════════════════
// FAT32 Cluster Chain Operations
// ═══════════════════════════════════════════════════════════════

/// Read a FAT entry for the given cluster. Returns the next cluster or EOC marker.
pub fn read_fat_entry<D: BlockDevice>(dev: D, fat32: &Fat32Info, cluster: u32) -> Result<u32, &'static str> {
    let (sector, offset) = fat32.fat_sector_for_cluster(cluster);
    let mut buf = [0u8; 512];
    dev.read_block(sector, &mut buf)?;
    // Guard from the Waveshare copy. Unreachable (`offset` is `cluster*4 % 512`,
    // at most 508) and kept so the two former copies agree line for line.
    if offset + 3 >= 512 { return Err("FAT offset out of range"); }
    let entry = u32::from_le_bytes([buf[offset], buf[offset+1], buf[offset+2], buf[offset+3]]);
    Ok(entry & 0x0FFF_FFFF) // mask upper 4 bits (reserved)
}

/// Sectors any one root-directory walk may read before it gives up.
///
/// 8,192 sectors is 131,072 directory entries, which no card a person uses
/// comes near, and it bounds the cost uniformly regardless of cluster size.
/// A cluster cap would not: at one sector per cluster it is 16 entries and at
/// 64 it is 1,024, so the same number would be both too tight and far too
/// slow depending on the card.
pub const MAX_DIR_SECTORS: u32 = 8192;

/// Advance a root-directory chain by one cluster, with the two bounds every
/// such walk in this file needs and none of them had.
///
/// `Ok(None)` is end of chain. `Err` is a chain that must not be walked.
///
/// FOUR CALLERS, all previously identical and all previously unbounded:
/// `find_file_in_root`, `write_dir_entry_to_root`, `list_root_dir` and
/// `list_root_dir_lfn`. Each seeded from `root_cluster` and looped with
/// `next >= 0x0FFF_FFF8` as its only exit, so a FAT with A to B to A never
/// terminated. `write_dir_entry_to_root` was the worst of them: its only exit
/// is finding a free slot, so a cycle with no free slot never ends, and on a
/// genuine end-of-chain it allocates and extends rather than stopping.
///
/// This is a HARD bound, not the partial cycle check at `read_file_progress`.
/// That one compares against the current and first clusters and says so: it
/// catches a self-loop and a jump back to the start, and a cycle closing
/// mid-chain still passes it. Counting sectors catches every cycle, needs no
/// visited set and no second FAT read, and costs one counter.
///
/// Rejecting `next < 2` also closes the residual in `cluster_to_sector`, whose
/// guard returns `data_start_sector` for a reserved cluster rather than
/// failing, so a chain pointing at 0 or 1 silently re-read cluster 2.
fn next_dir_cluster<D: BlockDevice>(
    dev: D,
    fat32: &Fat32Info,
    cluster: u32,
    sectors_walked: &mut u32,
) -> Result<Option<u32>, &'static str> {
    let next = read_fat_entry(dev, fat32, cluster)?;
    if next >= 0x0FFF_FFF8 {
        return Ok(None); // end of chain
    }
    if next < 2 {
        return Err("Bad FAT chain");
    }
    *sectors_walked = sectors_walked.saturating_add(fat32.sectors_per_cluster as u32);
    if *sectors_walked > MAX_DIR_SECTORS {
        return Err("Circular FAT chain");
    }
    Ok(Some(next))
}

/// Write a FAT entry. Writes to both FAT1 and FAT2.
pub fn write_fat_entry<D: BlockDevice>(dev: D, fat32: &Fat32Info, cluster: u32, value: u32) -> Result<(), &'static str> {
    let (sector, offset) = fat32.fat_sector_for_cluster(cluster);
    let mut buf = [0u8; 512];

    // Write FAT1
    dev.read_block(sector, &mut buf)?;
    let existing = u32::from_le_bytes([buf[offset], buf[offset+1], buf[offset+2], buf[offset+3]]);
    let new_val = (existing & 0xF000_0000) | (value & 0x0FFF_FFFF);
    let bytes = new_val.to_le_bytes();
    buf[offset] = bytes[0]; buf[offset+1] = bytes[1];
    buf[offset+2] = bytes[2]; buf[offset+3] = bytes[3];
    dev.write_block(sector, &buf)?;

    // Write FAT2
    if fat32.num_fats > 1 {
        let fat2_sector = sector + fat32.fat_size_32;
        dev.read_block(fat2_sector, &mut buf)?;
        let existing2 = u32::from_le_bytes([buf[offset], buf[offset+1], buf[offset+2], buf[offset+3]]);
        let new_val2 = (existing2 & 0xF000_0000) | (value & 0x0FFF_FFFF);
        let bytes2 = new_val2.to_le_bytes();
        buf[offset] = bytes2[0]; buf[offset+1] = bytes2[1];
        buf[offset+2] = bytes2[2]; buf[offset+3] = bytes2[3];
        dev.write_block(fat2_sector, &buf)?;
    }

    Ok(())
}

/// Allocate a free cluster. Scans FAT from `start_hint` and marks it as EOC.
/// Returns the allocated cluster number.
pub fn allocate_cluster<D: BlockDevice>(dev: D, fat32: &Fat32Info, start_hint: u32) -> Result<u32, &'static str> {
    let max_cluster = 2 + (fat32.total_sectors - fat32.data_start_sector) / fat32.sectors_per_cluster as u32;
    let mut buf = [0u8; 512];
    let mut last_sector = 0xFFFF_FFFFu32;

    // Scan from hint, then wrap around
    let mut cluster = if (2..max_cluster).contains(&start_hint) { start_hint } else { 2 };
    let start = cluster;
    loop {
        let (sector, offset) = fat32.fat_sector_for_cluster(cluster);
        if sector != last_sector {
            dev.read_block(sector, &mut buf)?;
            last_sector = sector;
        }
        let entry = u32::from_le_bytes([buf[offset], buf[offset+1], buf[offset+2], buf[offset+3]]);
        if (entry & 0x0FFF_FFFF) == 0 {
            // Free cluster found — mark as EOC
            write_fat_entry(dev, fat32, cluster, 0x0FFF_FFFF)?;
            log!("[FAT32] Allocated cluster {}", cluster);
            return Ok(cluster);
        }
        cluster += 1;
        if cluster >= max_cluster { cluster = 2; }
        if cluster == start { return Err("Disk full"); }
    }
}

/// Allocate a chain of `count` clusters. Returns the first cluster.
///
/// N-21. Until 1.0.7 this claimed each cluster with `allocate_cluster` (a
/// scan plus a 4-I/O EOC write) and then linked the previous one with a
/// second 4-I/O `write_fat_entry`: a 7-cluster file cost 26 FAT sector
/// writes and 26 reads. Now the scan runs once and finds all `count`
/// clusters (same first-fit order from cluster 2, same wrap), the links and
/// the final EOC are patched into each touched FAT sector in memory, and
/// every touched sector is read once and written once to FAT1 and once to
/// FAT2. Seven clusters in one FAT sector: 2 reads, 2 writes.
///
/// Sectors are written from the highest down. The chain ascends, so every
/// link points into its own sector or a higher one; writing high sectors
/// first means a power loss between two sector writes leaves at most a
/// fully written tail whose predecessors are still free, never a written
/// link into a cluster that is not yet claimed. The old claim-then-link
/// order had that property and this keeps it.
pub fn allocate_chain<D: BlockDevice>(dev: D, fat32: &Fat32Info, count: u32) -> Result<u32, &'static str> {
    if count == 0 { return Err("Zero clusters requested"); }

    // Pass 1: find `count` free clusters, first fit from 2, wrapping once.
    let max_cluster = 2 + (fat32.total_sectors - fat32.data_start_sector) / fat32.sectors_per_cluster as u32;
    let mut chain: alloc::vec::Vec<u32> = alloc::vec::Vec::new();
    if chain.try_reserve_exact(count as usize).is_err() {
        return Err("allocation failed");
    }
    let mut buf = [0u8; 512];
    let mut last_sector = 0xFFFF_FFFFu32;
    let mut cluster = 2u32;
    let mut scanned = 0u32;
    let mut wrapped = false;
    let span = max_cluster.saturating_sub(2);
    while (chain.len() as u32) < count {
        if scanned >= span { return Err("Disk full"); }
        let (sector, offset) = fat32.fat_sector_for_cluster(cluster);
        if sector != last_sector {
            dev.read_block(sector, &mut buf)?;
            last_sector = sector;
        }
        let entry = u32::from_le_bytes([buf[offset], buf[offset+1], buf[offset+2], buf[offset+3]]);
        if (entry & 0x0FFF_FFFF) == 0 {
            chain.push(cluster);
        }
        cluster += 1;
        scanned += 1;
        if cluster >= max_cluster { cluster = 2; wrapped = true; }
    }

    // Pass 2: patch each touched FAT sector once, highest sector first.
    // `chain` is ascending (first fit from 2 without a wrap in practice; a
    // wrap could only make it non-monotonic on a nearly full card, and the
    // grouping below is by sector regardless of order).
    let first = chain[0];
    let n = chain.len();
    let mut i_end = n;
    while i_end > 0 {
        // The run of chain entries sharing the sector of chain[i_end-1].
        let (sector, _) = fat32.fat_sector_for_cluster(chain[i_end - 1]);
        let mut i_start = i_end - 1;
        while i_start > 0 && fat32.fat_sector_for_cluster(chain[i_start - 1]).0 == sector {
            i_start -= 1;
        }
        // Only a wrapped scan can revisit a sector in a later run; an
        // unwrapped chain is ascending and each sector is one run. When it
        // did wrap, entries from the whole chain that land in this sector
        // are patched below in one go, so skip the sector if a later run
        // already covered it.
        if wrapped && chain[i_end..].iter().any(|&c| fat32.fat_sector_for_cluster(c).0 == sector) {
            i_end = i_start;
            continue;
        }
        for fat_copy in 0..fat32.num_fats.max(1) as u32 {
            let target = sector + fat_copy * fat32.fat_size_32;
            dev.read_block(target, &mut buf)?;
            // Unwrapped: exactly this run. Wrapped: any entry in the sector.
            let (k0, k1) = if wrapped { (0, n) } else { (i_start, i_end) };
            for k in k0..k1 {
                let (s, offset) = fat32.fat_sector_for_cluster(chain[k]);
                if s != sector { continue; }
                let value = if k + 1 < n { chain[k + 1] } else { 0x0FFF_FFFF };
                let existing = u32::from_le_bytes([buf[offset], buf[offset+1], buf[offset+2], buf[offset+3]]);
                let new_val = (existing & 0xF000_0000) | (value & 0x0FFF_FFFF);
                buf[offset..offset + 4].copy_from_slice(&new_val.to_le_bytes());
            }
            dev.write_block(target, &buf)?;
        }
        i_end = i_start;
    }

    log!("[FAT32] Allocated chain {}..{} ({} clusters)", first, chain[n - 1], n);
    Ok(first)
}


// ═══════════════════════════════════════════════════════════════
// FAT32 Directory Operations
// ═══════════════════════════════════════════════════════════════

/// Mount FAT32: read BPB, return Fat32Info. Call inside the driver's with_sd_card closure.
/// Handles superfloppy (BPB at sector 0), MBR with FAT32 partition, and
/// cards reformatted by macOS/Windows (which may add a partition table).
pub fn mount_fat32<D: BlockDevice>(dev: D) -> Result<Fat32Info, &'static str> {
    let mut sector = [0u8; 512];
    dev.read_block(0, &mut sector)?;

    log!("[FAT32] Sector 0: {:02x} {:02x} {:02x} .. sig={:02x}{:02x}",
        sector[0], sector[1], sector[2], sector[510], sector[511]);

    // Strategy 1: Sector 0 is a BPB (superfloppy) — jump byte + 0x55AA
    if (sector[0] == 0xEB || sector[0] == 0xE9) && sector[510] == 0x55 && sector[511] == 0xAA {
        log!("[FAT32] Trying superfloppy (BPB at sector 0)");
        if let Ok(info) = Fat32Info::from_boot_sector(&sector) {
            return Ok(info);
        }
    }

    // Strategy 2: Sector 0 is an MBR — find FAT32 partition
    if sector[510] == 0x55 && sector[511] == 0xAA {
        log!("[FAT32] Trying MBR partition table");
        if let Ok(lba) = find_fat32_partition(&sector) {
            if lba > 0 {
                dev.read_block(lba, &mut sector)?;
                let mut info = Fat32Info::from_boot_sector(&sector)?;
                info.fat_start_sector += lba;
                info.data_start_sector += lba;
                return Ok(info);
            }
            // lba == 0 means superfloppy fallback — already tried above
        }
    }

    // Strategy 3: Maybe sector 0 is a protective MBR (GPT) or unknown layout.
    // Try common partition offsets: sector 1, 2048 (common for macOS/Windows)
    for &probe_lba in &[2048u32, 8192, 32768, 1] {
        if dev.read_block(probe_lba, &mut sector).is_ok()
            && (sector[0] == 0xEB || sector[0] == 0xE9) && sector[510] == 0x55 && sector[511] == 0xAA
        {
                log!("[FAT32] Found BPB at sector {}", probe_lba);
                if let Ok(mut info) = Fat32Info::from_boot_sector(&sector) {
                    info.fat_start_sector += probe_lba;
                    info.data_start_sector += probe_lba;
                    return Ok(info);
                }
        }
    }

    Err("No FAT32 filesystem found")
}

/// Find a file in the root directory by 8.3 name.
/// Returns (DirEntry, sector_of_entry, offset_in_sector) so we can update it.
pub fn find_file_in_root<D: BlockDevice>(
    dev: D,
    fat32: &Fat32Info,
    name_83: &[u8; 11],
) -> Result<(DirEntry, u32, usize), &'static str> {
    let mut cluster = fat32.root_cluster;
    let mut buf = [0u8; 512];
    let mut sectors_walked = 0u32;

    loop {
        let base_sector = fat32.cluster_to_sector(cluster);
        for s in 0..fat32.sectors_per_cluster as u32 {
            dev.read_block(base_sector + s, &mut buf)?;
            for i in 0..16 { // 16 entries per 512-byte sector
                let off = i * 32;
                if buf[off] == 0x00 { return Err("File not found"); } // end of dir
                if let Some(entry) = DirEntry::from_bytes(&buf[off..off+32]) {
                    if entry.matches(name_83) {
                        return Ok((entry, base_sector + s, off));
                    }
                }
            }
        }
        // Follow cluster chain
        match next_dir_cluster(dev, fat32, cluster, &mut sectors_walked)? {
            Some(next) => cluster = next,
            None => break, // EOC
        }
    }
    Err("File not found")
}

/// Read a file's contents into the provided buffer. Returns bytes read.
/// Buffer must be large enough for the file (file_size bytes).
pub fn read_file<D: BlockDevice>(
    dev: D,
    fat32: &Fat32Info,
    entry: &DirEntry,
    out: &mut [u8],
) -> Result<usize, &'static str> {
    read_file_progress(dev, fat32, entry, out, &mut |_, _| {})
}

/// Read a file with progress callback. Callback receives (bytes_read, total_bytes).
pub fn read_file_progress<D: BlockDevice>(
    dev: D,
    fat32: &Fat32Info,
    entry: &DirEntry,
    out: &mut [u8],
    progress: &mut dyn FnMut(usize, usize),
) -> Result<usize, &'static str> {
    let file_size = entry.file_size as usize;
    if out.len() < file_size {
        return Err("Buffer too small");
    }

    let mut cluster = entry.first_cluster();
    let first_cluster = cluster; // N-09: loop check anchor
    let mut remaining = file_size;
    let mut pos = 0usize;
    let spc = fat32.sectors_per_cluster as u32;

    // Terminates without an explicit bound: every iteration consumes
    // min(remaining, cluster_bytes) and `mount_fat32` has already rejected
    // a zero sectors_per_cluster, so the walk is bounded by
    // ceil(file_size / cluster_bytes) steps whatever the chain does.
    //
    // A circular chain therefore ends too, having read the right number of
    // bytes from the wrong clusters. The check after the loop catches a
    // chain that stops early, not one that loops; every consumer of this
    // function authenticates its data, so repeated clusters fail there.
    while remaining > 0 && (2..0x0FFF_FFF8).contains(&cluster) {
        let base_sector = fat32.cluster_to_sector(cluster);
        // How many full sectors do we need from this cluster?
        let sectors_needed = ((remaining + 511) / 512).min(spc as usize) as u32;
        let _bytes_in_cluster = (sectors_needed as usize * 512).min(remaining + 511);

        if sectors_needed > 1 && pos + (sectors_needed as usize * 512) <= out.len() {
            // Multi-block read: all sectors in this cluster at once
            dev.read_multi(base_sector, &mut out[pos..], sectors_needed)?;
            let actual = remaining.min(sectors_needed as usize * 512);
            pos += actual;
            remaining -= actual;
        } else {
            // Fallback: single-block for partial cluster or buffer edge
            let mut sector_buf = [0u8; 512];
            for s in 0..spc {
                if remaining == 0 { break; }
                dev.read_block(base_sector + s, &mut sector_buf)?;
                let chunk = if remaining >= 512 { 512 } else { remaining };
                out[pos..pos+chunk].copy_from_slice(&sector_buf[..chunk]);
                pos += chunk;
                remaining -= chunk;
            }
        }
        progress(pos, file_size);
        if remaining > 0 {
            let next = read_fat_entry(dev, fat32, cluster)?;
            // N-09: reject the two chain loops that corruption actually produces.
            // A circular chain still terminates here, because the walk is bounded by
            // bytes consumed rather than by an end-of-chain marker, so without this
            // it returns a full-length file assembled from repeated clusters and
            // reports success. Nothing downstream is fooled, since AES-256-GCM and
            // the firmware hash both fail on the content, but the user is: a damaged
            // card presents as a wrong passphrase.
            //
            // PARTIAL BY CHOICE. Catches a self-loop and a jump back to the first
            // cluster; a cycle closing mid-chain still passes. Complete detection
            // needs Floyd's, and `read_fat_entry` has no cache, so that is one extra
            // 512-byte SD read per two clusters, up to ~625 on a 5 MB stego import,
            // for a fault with no security consequence. Two comparisons and no extra
            // I/O was judged the right price. See INTERNAL_FINDINGS.md N-09.
            //
            // `delete_file` deliberately has no such check: it zeroes each entry as
            // it walks, so a loop is destroyed as it is traversed and the walk ends
            // on the freed cluster.
            if next == cluster || next == first_cluster {
                return Err("Circular FAT chain");
            }
            cluster = next;
        }
    }

    // The loop has two exits: everything was read, or the chain stopped
    // being a data cluster (end-of-chain marker, free cluster, bad
    // cluster). Both used to return `Ok(pos)`, so a truncated chain was
    // reported as a successful short read.
    //
    // Also catches a non-empty file whose directory entry has no first
    // cluster: the loop never runs and `pos` stays 0.
    if pos != file_size {
        return Err("Short FAT chain");
    }

    Ok(pos)
}
/// Create a new file in the root directory. Allocates clusters and writes data.
/// Returns the created DirEntry.
pub fn create_file<D: BlockDevice>(
    dev: D,
    fat32: &Fat32Info,
    name_83: &[u8; 11],
    data: &[u8],
) -> Result<DirEntry, &'static str> {
    create_file_progress(dev, fat32, name_83, data, &mut |_, _| {})
}

/// Create a file on SD with progress callback. Callback receives (bytes_written, total_bytes).
pub fn create_file_progress<D: BlockDevice>(
    dev: D,
    fat32: &Fat32Info,
    name_83: &[u8; 11],
    data: &[u8],
    progress: &mut dyn FnMut(usize, usize),
) -> Result<DirEntry, &'static str> {
    let file_size = data.len() as u32;
    let cluster_bytes = fat32.cluster_bytes();
    let clusters_needed = if file_size == 0 { 0 } else { (file_size + cluster_bytes - 1) / cluster_bytes };

    let first_cluster = if clusters_needed > 0 {
        allocate_chain(dev, fat32, clusters_needed)?
    } else {
        0
    };

    if clusters_needed > 0 {
        let mut cluster = first_cluster;
        let mut remaining = data.len();
        let mut pos = 0usize;
        let total = data.len();
        let spc = fat32.sectors_per_cluster as u32;

        while remaining > 0 && (2..0x0FFF_FFF8).contains(&cluster) {
            let base_sector = fat32.cluster_to_sector(cluster);
            // How many full sectors can we write from the data?
            let full_sectors = (remaining / 512).min(spc as usize) as u32;

            if full_sectors >= 1 {
                // Multi-block write for full sectors
                let write_bytes = full_sectors as usize * 512;
                dev.write_multi(base_sector, &data[pos..pos + write_bytes], full_sectors)?;
                pos += write_bytes;
                remaining -= write_bytes;
            }

            // Handle remaining sectors in this cluster (partial last sector or single sector)
            let sectors_done = full_sectors;
            for s in sectors_done..spc {
                let mut sector_buf = [0u8; 512];
                if remaining == 0 {
                    dev.write_block(base_sector + s, &sector_buf)?;
                    continue;
                }
                let chunk = if remaining >= 512 { 512 } else { remaining };
                sector_buf[..chunk].copy_from_slice(&data[pos..pos+chunk]);
                dev.write_block(base_sector + s, &sector_buf)?;
                pos += chunk;
                remaining -= chunk;
            }

            progress(pos, total);
            if remaining > 0 {
                let next = read_fat_entry(dev, fat32, cluster)?;
                // N-09: reject the two chain loops that corruption actually produces.
                // A circular chain still terminates here, because the walk is bounded by
                // bytes consumed rather than by an end-of-chain marker, so without this
                // it returns a full-length file assembled from repeated clusters and
                // reports success. Nothing downstream is fooled, since AES-256-GCM and
                // the firmware hash both fail on the content, but the user is: a damaged
                // card presents as a wrong passphrase.
                //
                // PARTIAL BY CHOICE. Catches a self-loop and a jump back to the first
                // cluster; a cycle closing mid-chain still passes. Complete detection
                // needs Floyd's, and `read_fat_entry` has no cache, so that is one extra
                // 512-byte SD read per two clusters, up to ~625 on a 5 MB stego import,
                // for a fault with no security consequence. Two comparisons and no extra
                // I/O was judged the right price. See INTERNAL_FINDINGS.md N-09.
                //
                // `delete_file` deliberately has no such check: it zeroes each entry as
                // it walks, so a loop is destroyed as it is traversed and the walk ends
                // on the freed cluster.
                //
                // On this write path the chain came from `allocate_chain`, so a loop is
                // our own bug rather than card damage, and it would write one cluster
                // twice instead of laying the file out.
                if next == cluster || next == first_cluster {
                    return Err("Circular FAT chain");
                }
                cluster = next;
            }
        }
    }

    let entry = DirEntry {
        name: *name_83,
        attr: 0x20,
        cluster_hi: (first_cluster >> 16) as u16,
        cluster_lo: first_cluster as u16,
        file_size,
    };

    write_dir_entry_to_root(dev, fat32, &entry)?;

    log!("[FAT32] Created file {:?} size={} cluster={}", 
        core::str::from_utf8(name_83).unwrap_or("?"), file_size, first_cluster);

    Ok(entry)
}

/// Write a DirEntry into the first free slot in root directory.
fn write_dir_entry_to_root<D: BlockDevice>(
    dev: D,
    fat32: &Fat32Info,
    entry: &DirEntry,
) -> Result<(), &'static str> {
    let mut cluster = fat32.root_cluster;
    let mut buf = [0u8; 512];
    let mut sectors_walked = 0u32;

    loop {
        let base_sector = fat32.cluster_to_sector(cluster);
        for s in 0..fat32.sectors_per_cluster as u32 {
            dev.read_block(base_sector + s, &mut buf)?;
            for i in 0..16 {
                let off = i * 32;
                // Free slot: 0x00 (end of dir) or 0xE5 (deleted)
                if buf[off] == 0x00 || buf[off] == 0xE5 {
                    // Write the entry
                    buf[off..off+11].copy_from_slice(&entry.name);
                    buf[off+11] = entry.attr;
                    buf[off+12..off+20].fill(0); // reserved + create time/date
                    let chi = entry.cluster_hi.to_le_bytes();
                    buf[off+20] = chi[0]; buf[off+21] = chi[1];
                    buf[off+22..off+26].fill(0); // modify time/date
                    let clo = entry.cluster_lo.to_le_bytes();
                    buf[off+26] = clo[0]; buf[off+27] = clo[1];
                    let fsz = entry.file_size.to_le_bytes();
                    buf[off+28] = fsz[0]; buf[off+29] = fsz[1];
                    buf[off+30] = fsz[2]; buf[off+31] = fsz[3];

                    // If this was end-of-dir marker, add new end marker after
                    if off + 32 < 512 && buf[off] == 0x00 {
                        // Actually we just overwrote 0x00, so mark next entry as end
                        // (only if within same sector and next slot is also 0x00 already)
                    }

                    dev.write_block(base_sector + s, &buf)?;
                    return Ok(());
                }
            }
        }
        // Follow cluster chain; allocate new cluster if needed
        match next_dir_cluster(dev, fat32, cluster, &mut sectors_walked)? {
            Some(next) => cluster = next,
            None => {
                // Genuine end of chain: extend the directory.
                let new_cl = allocate_cluster(dev, fat32, cluster + 1)?;
                write_fat_entry(dev, fat32, cluster, new_cl)?;
                // Zero out the new cluster
                let zeros = [0u8; 512];
                let new_base = fat32.cluster_to_sector(new_cl);
                for s in 0..fat32.sectors_per_cluster as u32 {
                    dev.write_block(new_base + s, &zeros)?;
                }
                // The extension is a cluster this walk will now read, so it is
                // charged against the same budget. Without this an appending
                // caller on a full directory could extend without limit.
                sectors_walked =
                    sectors_walked.saturating_add(fat32.sectors_per_cluster as u32);
                if sectors_walked > MAX_DIR_SECTORS {
                    return Err("Directory too large");
                }
                cluster = new_cl;
            }
        }
    }
}

/// Delete a file from the root directory (marks entry as deleted, frees cluster chain).
pub fn delete_file<D: BlockDevice>(
    dev: D,
    fat32: &Fat32Info,
    name_83: &[u8; 11],
) -> Result<(), &'static str> {
    let (entry, sector, offset) = find_file_in_root(dev, fat32, name_83)?;

    // Directory entry first, chain second (reordered in 1.0.7; both the old
    // per-cluster loop and the first batched version freed the chain first).
    // A power loss between the two steps then leaves clusters that are
    // still marked used but no longer named: a leak, recoverable by a
    // format. The old order left the opposite: a live directory entry
    // pointing at clusters already free, which the next create can hand to
    // another file, and the stale entry then reads that file's data. Same
    // write count either way; only the order changes.
    let mut buf = [0u8; 512];
    dev.read_block(sector, &mut buf)?;
    buf[offset] = 0xE5;
    dev.write_block(sector, &buf)?;

    // Free the cluster chain, batched by FAT sector (the delete mirror of
    // the N-21 allocator). Until 1.0.7 this called `write_fat_entry` per
    // cluster (4 I/O each: read+write FAT1, read+write FAT2), so a 7-cluster
    // file cost 14 writes and 21 reads. Now the walk stays inside one FAT
    // sector for as long as the chain does: the sector is read once, every
    // entry the chain visits in it is zeroed in the buffer as the walk
    // passes, and the sector is written once to FAT1 (and the same offsets
    // zeroed and written once to FAT2) when the chain leaves it. A chain
    // inside one FAT sector: 2 writes.
    //
    // This keeps the property N-09 documents for the old loop: entries are
    // zeroed as they are traversed, so a corrupt circular chain destroys
    // itself. Within a sector the buffer already holds the zero; across
    // sectors the sector is re-read from the card after it was written.
    // Either way the walk lands on a freed entry, reads 0, and ends. No
    // chain buffer, no bound, no cycle check is needed.
    let mut cluster = entry.first_cluster();
    let mut freed = 0u32;
    while (2..0x0FFF_FFF8).contains(&cluster) {
        let (fsector, _) = fat32.fat_sector_for_cluster(cluster);
        dev.read_block(fsector, &mut buf)?;
        // Offsets zeroed in this sector, replayed onto FAT2 below. A FAT
        // sector holds 128 entries, so this cannot overflow.
        let mut offs = [0u16; 128];
        let mut n_offs = 0usize;
        loop {
            let (s, foffset) = fat32.fat_sector_for_cluster(cluster);
            if s != fsector { break; }
            if foffset + 3 >= 512 { return Err("FAT offset out of range"); }
            let existing = u32::from_le_bytes([buf[foffset], buf[foffset+1], buf[foffset+2], buf[foffset+3]]);
            let next = existing & 0x0FFF_FFFF;
            let cleared = existing & 0xF000_0000; // reserved high nibble kept, value 0
            buf[foffset..foffset + 4].copy_from_slice(&cleared.to_le_bytes());
            if n_offs < offs.len() { offs[n_offs] = foffset as u16; n_offs += 1; }
            freed += 1;
            cluster = next;
            if !(2..0x0FFF_FFF8).contains(&cluster) { break; }
        }
        dev.write_block(fsector, &buf)?;
        if fat32.num_fats > 1 {
            let fat2_sector = fsector + fat32.fat_size_32;
            dev.read_block(fat2_sector, &mut buf)?;
            for &o in &offs[..n_offs] {
                let o = o as usize;
                let existing = u32::from_le_bytes([buf[o], buf[o+1], buf[o+2], buf[o+3]]);
                buf[o..o + 4].copy_from_slice(&(existing & 0xF000_0000).to_le_bytes());
            }
            dev.write_block(fat2_sector, &buf)?;
        }
    }

    log!("[FAT32] Deleted file ({} clusters freed)", freed);
    Ok(())
}

/// Overwrite an existing file's contents. If new data is larger, extends the chain.
/// If smaller, truncates. Updates the directory entry's file_size.
pub fn overwrite_file<D: BlockDevice>(
    dev: D,
    fat32: &Fat32Info,
    name_83: &[u8; 11],
    data: &[u8],
) -> Result<(), &'static str> {
    // "Not found" is the one acceptable outcome to ignore: overwriting a
    // file that does not exist yet is a create. Any other failure means the
    // old chain or its directory entry is still live, and creating on top of
    // it leaves the card with two entries for one name and clusters no
    // longer owned by either. Fail instead of writing into that.
    match delete_file(dev, fat32, name_83) {
        Ok(()) => {}
        Err("File not found") => {}
        Err(e) => return Err(e),
    }
    create_file(dev, fat32, name_83, data)?;
    Ok(())
}
/// List files in root directory. Calls callback for each entry.
/// Callback returns true to continue, false to stop.
pub fn list_root_dir<D: BlockDevice, F>(
    dev: D,
    fat32: &Fat32Info,
    mut callback: F,
) -> Result<(), &'static str>
where
    F: FnMut(&DirEntry) -> bool,
{
    let mut cluster = fat32.root_cluster;
    let mut buf = [0u8; 512];
    let mut sectors_walked = 0u32;

    loop {
        let base_sector = fat32.cluster_to_sector(cluster);
        for s in 0..fat32.sectors_per_cluster as u32 {
            dev.read_block(base_sector + s, &mut buf)?;
            for i in 0..16 {
                let off = i * 32;
                if buf[off] == 0x00 { return Ok(()); } // end of dir
                if let Some(entry) = DirEntry::from_bytes(&buf[off..off+32]) {
                    // Skip volume label entries
                    if entry.attr & 0x08 != 0 { continue; }
                    if !callback(&entry) { return Ok(()); }
                }
            }
        }
        match next_dir_cluster(dev, fat32, cluster, &mut sectors_walked)? {
            Some(next) => cluster = next,
            None => break,
        }
    }
    Ok(())
}

/// List root directory with LFN (Long File Name) support.
/// Callback receives (&DirEntry, &display_name, display_name_len).
/// display_name contains the LFN if available, otherwise the formatted 8.3 name.
pub fn list_root_dir_lfn<D: BlockDevice, F>(
    dev: D,
    fat32: &Fat32Info,
    mut callback: F,
) -> Result<(), &'static str>
where
    F: FnMut(&DirEntry, &[u8; 64], usize) -> bool,
{
    let mut cluster = fat32.root_cluster;
    let mut buf = [0u8; 512];
    // LFN accumulator: up to 4 LFN entries = 52 chars max
    let mut lfn_buf = [0u8; 64];
    #[allow(unused_assignments)]
    let mut lfn_len: usize = 0;
    let mut lfn_parts: [([u8; 26], u8); 4] = [([0; 26], 0); 4]; // (utf16_bytes, seq_num)
    let mut lfn_part_count: usize = 0;
    let mut sectors_walked = 0u32;

    loop {
        let base_sector = fat32.cluster_to_sector(cluster);
        for s in 0..fat32.sectors_per_cluster as u32 {
            dev.read_block(base_sector + s, &mut buf)?;
            for i in 0..16 {
                let off = i * 32;
                if buf[off] == 0x00 { return Ok(()); }
                if buf[off] == 0xE5 {
                    lfn_part_count = 0;
                    continue;
                }

                let attr = buf[off + 11];
                if attr == 0x0F {
                    // LFN entry: extract sequence number and UTF-16 chars
                    let seq = buf[off] & 0x3F;
                    if (1..=4).contains(&seq) && (lfn_part_count < 4) {
                        let idx = (seq - 1) as usize;
                        // Extract 13 UTF-16LE chars (26 bytes) from specific offsets
                        let mut utf16 = [0u8; 26];
                        // Chars 1-5: offset 1..10
                        utf16[0..10].copy_from_slice(&buf[off+1..off+11]);
                        // Chars 6-11: offset 14..25
                        utf16[10..22].copy_from_slice(&buf[off+14..off+26]);
                        // Chars 12-13: offset 28..31
                        utf16[22..26].copy_from_slice(&buf[off+28..off+32]);
                        lfn_parts[idx] = (utf16, seq);
                        if idx + 1 > lfn_part_count { lfn_part_count = idx + 1; }
                    }
                    continue;
                }

                // Regular entry — check if we have LFN parts
                if let Some(entry) = DirEntry::from_bytes(&buf[off..off+32]) {
                    if entry.attr & 0x08 != 0 {
                        lfn_part_count = 0;
                        continue;
                    }

                    // Build display name
                    lfn_len = 0;
                    if lfn_part_count > 0 {
                        // Reconstruct LFN from parts (in order: part 1, 2, 3...)
                        for p in 0..lfn_part_count {
                            let (ref utf16, _) = lfn_parts[p];
                            // Convert UTF-16LE to ASCII (13 chars per part)
                            for c in 0..13 {
                                let lo = utf16[c * 2];
                                let hi = utf16[c * 2 + 1];
                                if lo == 0xFF && hi == 0xFF { break; } // padding
                                if lo == 0x00 && hi == 0x00 { break; } // null terminator
                                if lfn_len >= 63 { break; }
                                // ASCII printable range + extended Latin-1 common chars
                                if hi == 0 && (0x20..0x7F).contains(&lo) {
                                    lfn_buf[lfn_len] = lo;
                                    lfn_len += 1;
                                } else if hi == 0 && lo >= 0x80 {
                                    // Extended Latin-1 — map to closest ASCII
                                    let mapped = match lo {
                                        0xC0..=0xC5 => b'A', // À-Å
                                        0xC7 => b'C',        // Ç
                                        0xC8..=0xCB => b'E', // È-Ë
                                        0xCC..=0xCF => b'I', // Ì-Ï
                                        0xD1 => b'N',        // Ñ
                                        0xD2..=0xD6 => b'O', // Ò-Ö
                                        0xD9..=0xDC => b'U', // Ù-Ü
                                        0xE0..=0xE5 => b'a', // à-å
                                        0xE7 => b'c',        // ç
                                        0xE8..=0xEB => b'e', // è-ë
                                        0xEC..=0xEF => b'i', // ì-ï
                                        0xF1 => b'n',        // ñ
                                        0xF2..=0xF6 => b'o', // ò-ö
                                        0xF9..=0xFC => b'u', // ù-ü
                                        0xA0 => b' ',        // non-breaking space
                                        _ => b'_',           // other extended → underscore
                                    };
                                    lfn_buf[lfn_len] = mapped;
                                    lfn_len += 1;
                                } else if hi > 0 {
                                    // True Unicode (hi byte set) — replace with underscore
                                    lfn_buf[lfn_len] = b'_';
                                    lfn_len += 1;
                                }
                            }
                        }
                    }

                    if lfn_len == 0 {
                        // No LFN — format 8.3 name
                        let mut disp = [0u8; 13];
                        let dlen = format_83_display(&entry.name, &mut disp);
                        lfn_buf[..dlen].copy_from_slice(&disp[..dlen]);
                        lfn_len = dlen;
                    }

                    lfn_part_count = 0;
                    if !callback(&entry, &lfn_buf, lfn_len) { return Ok(()); }
                } else {
                    lfn_part_count = 0;
                }
            }
        }
        match next_dir_cluster(dev, fat32, cluster, &mut sectors_walked)? {
            Some(next) => cluster = next,
            None => break,
        }
    }
    Ok(())
}


// ═══════════════════════════════════════════════════════════════
// BMP Image Parser
// ═══════════════════════════════════════════════════════════════

#[derive(Debug)]
/// Parsed BMP image header information.
pub struct BmpInfo {
    pub width: u32,
    pub height: u32,
    pub bits_per_pixel: u16,
    pub data_offset: u32,
    pub row_stride: u32,
    pub top_down: bool,
}

impl BmpInfo {
}


// ═══════════════════════════════════════════════════════════════
// MBR / Partition Table
// ═══════════════════════════════════════════════════════════════

/// Find the first FAT32 partition in an MBR. Returns the LBA offset.
pub fn find_fat32_partition(mbr: &[u8; 512]) -> Result<u32, &'static str> {
    if mbr[510] != 0x55 || mbr[511] != 0xAA {
        return Err("Invalid MBR signature");
    }
    for i in 0..4 {
        let base = 446 + i * 16;
        let part_type = mbr[base + 4];
        if part_type == 0x0B || part_type == 0x0C {
            let lba = u32::from_le_bytes([
                mbr[base + 8], mbr[base + 9], mbr[base + 10], mbr[base + 11]
            ]);
            log!("[MBR] FAT32 partition {} at LBA {}", i, lba);
            return Ok(lba);
        }
    }
    if mbr[0] == 0xEB || mbr[0] == 0xE9 {
        log!("[MBR] No partition table, trying superfloppy");
        return Ok(0);
    }
    Err("No FAT32 partition found")
}



/// Internal format logic — runs inside the driver's with_sd_card closure.
/// Read a sector back and compare it against the bytes just written.
///
/// A card that accepts a write has not necessarily kept it: `fast_write_block`
/// only sees the data-response token and the busy release, both of which a
/// card can give for a write it then discards. The first differing byte is
/// logged so a failure names the structure and the offset instead of only the
/// fact that something is wrong.
pub fn verify_sector<D: BlockDevice>(
    dev: D,
    sector: u32,
    expect: &[u8; 512],
    label: &'static str,
) -> Result<(), &'static str> {
    let mut back = [0u8; 512];
    dev.read_block(sector, &mut back)?;
    if back != *expect {
        for i in 0..512 {
            if back[i] != expect[i] {
                log!("[SD-FMT] {} sector {} offset {}: wrote {:02x} read {:02x}",
                    label, sector, i, expect[i], back[i]);
                break;
            }
        }
        // Head and tail of what came back, then the same sector read a second
        // time. A read taken immediately after a write can be reporting the
        // bus rather than the card: if the retry differs from the first read,
        // the write landed and the read was wrong; if both agree, the sector
        // really holds this. All-FF means neither the new nor the old content
        // is being returned at all.
        log!("[SD-FMT]   read[0..4]={:02x} {:02x} {:02x} {:02x} read[510..512]={:02x} {:02x}",
            back[0], back[1], back[2], back[3], back[510], back[511]);
        let mut again = [0u8; 512];
        dev.read_block(sector, &mut again)?;
        log!("[SD-FMT]   retry[0..4]={:02x} {:02x} {:02x} {:02x} retry[510..512]={:02x} {:02x}",
            again[0], again[1], again[2], again[3], again[510], again[511]);
        if again == *expect {
            log!("[SD-FMT]   retry MATCHES what was written");
        }
        return Err(label);
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
pub fn csd_sectors(csd: &[u8; 16]) -> Result<u32, &'static str> {
    match csd[0] >> 6 {
        1 => {
            // v2: C_SIZE is CSD bits 69:48, capacity is (C_SIZE + 1) * 512 KB.
            let c_size = (((csd[7] & 0x3F) as u32) << 16)
                | ((csd[8] as u32) << 8)
                | (csd[9] as u32);
            c_size.checked_add(1)
                .and_then(|n| n.checked_mul(1024))
                .ok_or("CSD capacity overflow")
        }
        0 => {
            // v1: bits 73:62 size, 49:47 multiplier, 83:80 block length.
            let read_bl_len = (csd[5] & 0x0F) as u32;
            if !(9..=11).contains(&read_bl_len) {
                return Err("CSD block length invalid");
            }
            let c_size = (((csd[6] & 0x03) as u32) << 10)
                | ((csd[7] as u32) << 2)
                | ((csd[8] as u32) >> 6);
            let c_size_mult = (((csd[9] & 0x03) as u32) << 1) | ((csd[10] as u32) >> 7);
            let blocks = (c_size + 1) * (1u32 << (c_size_mult + 2));
            let per_block = 1u32 << (read_bl_len - 9);
            blocks.checked_mul(per_block).ok_or("CSD capacity overflow")
        }
        _ => Err("Unknown CSD version"),
    }
}

/// A capacity is only believed if it could hold a FAT32 volume at all and
/// stays inside what 32-bit sector arithmetic addresses. A misparsed CSD
/// almost always lands outside this range, which is the point.
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

/// Solve cluster size and FAT size against the measured sector count.
///
/// The old constants declared 7.5 GiB of filesystem with a 1,024-sector FAT
/// behind it. That FAT addresses 131,070 clusters, about 4 GiB at 32 KB
/// each, so roughly half of what the BPB advertised had no FAT entry to
/// describe it: a host filling the card walks off the end of the table.
/// Every field below is derived from the card instead.
pub fn derive_geometry(total_sectors: u32) -> Result<FormatGeometry, &'static str> {
    let reserved = RESERVED_SECTORS as u32;
    let num_fats = NUM_FATS as u32;

    // Largest clusters first: fewer FAT sectors to write and to clear, and
    // the card holds a handful of small files, so slack per file is not
    // worth a longer format. Drop down only if the card is too small to
    // reach the FAT32 cluster floor at that size.
    for spc in [64u32, 32, 16, 8, 4, 2, 1] {
        if total_sectors <= reserved {
            break;
        }
        // 128 FAT32 entries per 512-byte sector. One pass converges: a FAT
        // sized for the whole data region is never smaller than one sized
        // for that region minus the FAT itself. Manual ceiling, matching the
        // `clippy::manual_div_ceil` allow in main.rs: `div_ceil` is not
        // stable in this no_std toolchain.
        let approx_clusters = (total_sectors - reserved) / spc;
        let fat_size = (approx_clusters + 2 + 127) / 128;
        let fat_total = num_fats * fat_size;
        if total_sectors <= reserved + fat_total {
            continue;
        }
        let clusters = (total_sectors - reserved - fat_total) / spc;
        if clusters < FAT32_MIN_CLUSTERS {
            continue;
        }
        // The FAT must describe every cluster the BPB claims, which is the
        // invariant the old constants broke.
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
    Err("Card too small for FAT32")
}

/// Internal format logic — runs inside the driver's with_sd_card closure.
pub fn do_format_fat32<D: BlockDevice>(dev: D) -> Result<(), &'static str> {
    let mut test = [0u8; 512];
    dev.read_block(0, &mut test)?;
    log!("[SD-FMT] MBR read OK sig={:02x}{:02x}", test[510], test[511]);

    // Geometry comes from the card, not from constants.
    let probed = dev.card_sectors()?;
    let geo = derive_geometry(probed)?;
    let sectors_per_cluster: u8 = geo.sectors_per_cluster;
    let reserved_sectors: u16 = RESERVED_SECTORS;
    let num_fats: u8 = NUM_FATS;
    let fat_size: u32 = geo.fat_size;
    let root_cluster: u32 = 2;
    let total_sectors: u32 = geo.total_sectors;
    log!("[SD-FMT] card {} sectors, fs {}, spc {}, fat {} sectors, {} clusters",
        probed, total_sectors, sectors_per_cluster, fat_size, geo.clusters);

    let mut bpb = [0u8; 512];
    bpb[0] = 0xEB; bpb[1] = 0x58; bpb[2] = 0x90;
    bpb[3..11].copy_from_slice(b"MSDOS5.0");
    bpb[11] = 0x00; bpb[12] = 0x02; // 512 bytes/sector
    bpb[13] = sectors_per_cluster;
    bpb[14] = reserved_sectors as u8; bpb[15] = (reserved_sectors >> 8) as u8;
    bpb[16] = num_fats;
    bpb[21] = 0xF8; // media type
    bpb[24] = 0x3F; bpb[26] = 0xFF; // sectors per track / heads
    bpb[32] = total_sectors as u8; bpb[33] = (total_sectors >> 8) as u8;
    bpb[34] = (total_sectors >> 16) as u8; bpb[35] = (total_sectors >> 24) as u8;
    bpb[36] = fat_size as u8; bpb[37] = (fat_size >> 8) as u8;
    bpb[38] = (fat_size >> 16) as u8; bpb[39] = (fat_size >> 24) as u8;
    bpb[44] = root_cluster as u8; bpb[45] = (root_cluster >> 8) as u8;
    bpb[48] = 1; bpb[50] = 6; // FSInfo=1, backup BPB=6
    bpb[66] = 0x29; // extended boot sig
    bpb[67] = 0x4B; bpb[68] = 0x53; bpb[69] = 0x53; bpb[70] = 0x00; // serial
    bpb[71..82].copy_from_slice(b"KASSIGNER  ");
    bpb[82..90].copy_from_slice(b"FAT32   ");
    bpb[510] = 0x55; bpb[511] = 0xAA;

    dev.write_block(0, &bpb)?;
    dev.write_block(6, &bpb)?; // backup
    // Immediately, before the thousands of writes that follow: this
    // separates a card that never keeps a write from one that keeps it and
    // loses it later.
    verify_sector(dev, 0, &bpb, "Verify BPB early")?;

    // Free count and next free cluster are real values rather than
    // "unknown": cluster 2 is the root directory, everything above is free.
    let free_count = geo.clusters - 1;
    let mut fsinfo = [0u8; 512];
    fsinfo[0] = 0x52; fsinfo[1] = 0x52; fsinfo[2] = 0x61; fsinfo[3] = 0x41;
    fsinfo[484] = 0x72; fsinfo[485] = 0x72; fsinfo[486] = 0x41; fsinfo[487] = 0x61;
    fsinfo[488..492].copy_from_slice(&free_count.to_le_bytes());
    fsinfo[492..496].copy_from_slice(&3u32.to_le_bytes());
    fsinfo[510] = 0x55; fsinfo[511] = 0xAA;
    dev.write_block(1, &fsinfo)?;
    // Sector 7 is the backup FSInfo, mirroring sector 1 the way 6 mirrors 0.
    dev.write_block(7, &fsinfo)?;

    // Every write from here is checked. Discarding these errors let a
    // format that failed halfway report success, leaving a card whose BPB
    // describes a filesystem its FAT does not.
    let zeros = [0u8; 512];
    for s in 2..reserved_sectors as u32 {
        if s == 6 || s == 7 { continue; } // already written
        dev.write_block(s, &zeros)?;
    }

    // FAT tables — first sector has media byte + EOC markers for clusters 0,1,2
    let mut fat_first = [0u8; 512];
    fat_first[0] = 0xF8; fat_first[1] = 0xFF; fat_first[2] = 0xFF; fat_first[3] = 0x0F;
    fat_first[4] = 0xFF; fat_first[5] = 0xFF; fat_first[6] = 0xFF; fat_first[7] = 0x0F;
    fat_first[8] = 0xFF; fat_first[9] = 0xFF; fat_first[10] = 0xFF; fat_first[11] = 0x0F;
    let fat1_start = reserved_sectors as u32;
    let fat2_start = fat1_start + fat_size;
    dev.write_block(fat1_start, &fat_first)?;
    dev.write_block(fat2_start, &fat_first)?;
    // The whole table, not its first 32 sectors. Clearing part of it left a
    // previous filesystem's entries in place beyond the cleared range,
    // where they read as allocated chains on a card that reports empty.
    for i in 1..fat_size {
        dev.write_block(fat1_start + i, &zeros)?;
        dev.write_block(fat2_start + i, &zeros)?;
    }

    // Clear root directory cluster
    let data_start = reserved_sectors as u32 + num_fats as u32 * fat_size;
    for i in 0..sectors_per_cluster as u32 {
        dev.write_block(data_start + i, &zeros)?;
    }

    // Read back every structure that decides whether the card is usable,
    // including the last FAT sector, which is the one a partial clear leaves
    // stale. Checked at the end as well as early, so a write that lands and
    // is later lost looks different from one that never lands at all.
    verify_sector(dev, 0, &bpb, "Verify BPB")?;
    verify_sector(dev, 6, &bpb, "Verify BPB backup")?;
    verify_sector(dev, 1, &fsinfo, "Verify FSInfo")?;
    verify_sector(dev, fat1_start, &fat_first, "Verify FAT1")?;
    verify_sector(dev, fat2_start, &fat_first, "Verify FAT2")?;
    verify_sector(dev, fat1_start + fat_size - 1, &zeros, "Verify FAT1 tail")?;
    verify_sector(dev, fat2_start + fat_size - 1, &zeros, "Verify FAT2 tail")?;
    verify_sector(dev, data_start, &zeros, "Verify root")?;
    log!("[SD-FMT] Verified: BPB, FSInfo, both FATs, root");

    Ok(())
}

/// Format an 8.3 name for display — trim trailing spaces, no dot if no extension
pub fn format_83_display(name: &[u8; 11], out: &mut [u8; 13]) -> usize {
    let mut pos = 0;
    // Base name (trim trailing spaces)
    let mut base_len = 8;
    while base_len > 0 && name[base_len - 1] == b' ' { base_len -= 1; }
    for i in 0..base_len {
        out[pos] = name[i];
        pos += 1;
    }
    // Extension (trim trailing spaces)
    let mut ext_len = 3;
    while ext_len > 0 && name[8 + ext_len - 1] == b' ' { ext_len -= 1; }
    if ext_len > 0 {
        out[pos] = b'.';
        pos += 1;
        for i in 0..ext_len {
            out[pos] = name[8 + i];
            pos += 1;
        }
    }
    pos
}
