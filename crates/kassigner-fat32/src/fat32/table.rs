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

// The FAT: one entry read or written (both copies), the FSInfo counts, a
// free cluster or a chain allocated, and a deleted or overwritten file's
// chain freed without taking a cluster another entry still names.

use super::*;

/// Read the FAT entry for `cluster`: the next cluster or an end-of-chain mark.
pub fn read_fat_entry<D: BlockDevice>(
    dev: &mut D,
    fat32: &Fat32Info,
    cluster: u32,
) -> Result<u32, Fat32Error> {
    if !fat32.is_data_cluster(cluster) {
        return Err(Fat32Error::Format("Cluster outside the volume"));
    }
    let (sector, offset) = fat32.fat_sector_for_cluster(cluster);
    let mut buf = [0u8; 512];
    dev.read(sector, &mut buf)?;
    // Unreachable: `offset` is `cluster * 4 % 512`, at most 508.
    if offset + 3 >= 512 {
        return Err(Fat32Error::Format("FAT offset out of range"));
    }
    let entry = u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ]);
    Ok(entry & 0x0FFF_FFFF) // mask upper 4 bits (reserved)
}

/// Sectors any one root-directory walk may read before it gives up: 131,072
/// entries, far more than any card in use holds. In sectors, so the bound
/// is the same at every cluster size.
pub const MAX_DIR_SECTORS: u32 = 8192;

/// FAT32's mark for a bad cluster; above it, the end-of-chain marks. No data
/// cluster is numbered from here up, whatever a volume claims its size is.
pub(super) const BAD_CLUSTER: u32 = 0x0FFF_FFF7;

/// Advance a root-directory chain by one cluster, under the two bounds every
/// root walk needs. `Ok(None)` is end of chain. `Err` is a link outside the
/// data clusters (0 or 1 would read as cluster 2), more than
/// [`MAX_DIR_SECTORS`] walked (which ends any FAT loop with no visited
/// set), or a read error.
pub(super) fn next_dir_cluster<D: BlockDevice>(
    dev: &mut D,
    fat32: &Fat32Info,
    cluster: u32,
    sectors_walked: &mut u32,
) -> Result<Option<u32>, Fat32Error> {
    let next = read_fat_entry(dev, fat32, cluster)?;
    if next >= 0x0FFF_FFF8 {
        return Ok(None); // end of chain
    }
    if !fat32.is_data_cluster(next) {
        return Err(Fat32Error::Format("Bad FAT chain"));
    }
    *sectors_walked = sectors_walked.saturating_add(fat32.sectors_per_cluster as u32);
    if *sectors_walked > MAX_DIR_SECTORS {
        return Err(Fat32Error::Format("Circular FAT chain"));
    }
    Ok(Some(next))
}

/// Write a FAT entry. Writes to both FAT1 and FAT2.
pub fn write_fat_entry<D: BlockDevice>(
    dev: &mut D,
    fat32: &Fat32Info,
    cluster: u32,
    value: u32,
) -> Result<(), Fat32Error> {
    // Only for the volume's clusters: past the last, the sector is past FAT1.
    if !fat32.is_data_cluster(cluster) {
        return Err(Fat32Error::Format("Cluster outside the volume"));
    }
    let (sector, offset) = fat32.fat_sector_for_cluster(cluster);
    let mut buf = [0u8; 512];

    // Write FAT1
    dev.read(sector, &mut buf)?;
    let existing = u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ]);
    let new_val = (existing & 0xF000_0000) | (value & 0x0FFF_FFFF);
    let bytes = new_val.to_le_bytes();
    buf[offset] = bytes[0];
    buf[offset + 1] = bytes[1];
    buf[offset + 2] = bytes[2];
    buf[offset + 3] = bytes[3];
    dev.write(sector, &buf)?;

    // Write FAT2
    if fat32.num_fats > 1 {
        let fat2_sector = sector + fat32.fat_size_32;
        dev.read(fat2_sector, &mut buf)?;
        let existing2 = u32::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]);
        let new_val2 = (existing2 & 0xF000_0000) | (value & 0x0FFF_FFFF);
        let bytes2 = new_val2.to_le_bytes();
        buf[offset] = bytes2[0];
        buf[offset + 1] = bytes2[1];
        buf[offset + 2] = bytes2[2];
        buf[offset + 3] = bytes2[3];
        dev.write(fat2_sector, &buf)?;
    }

    Ok(())
}

// The FSInfo sector: a free-cluster count and a next-free hint, which the
// specification says a driver must not trust. Nothing here decides by them;
// they are kept current for a computer, which shows free space from them.
// The BPB says where it is: [`Fat32Info::fsinfo_sector`].

/// Signature at the top of FSInfo, `RRaA`.
const FSINFO_LEAD_SIG: [u8; 4] = [0x52, 0x52, 0x61, 0x41];
/// Signature before the counters, `rrAa`.
const FSINFO_STRUC_SIG: [u8; 4] = [0x72, 0x72, 0x41, 0x61];

/// Adjust the free count by `delta` (negative to allocate, positive to free),
/// and make `next_free` the hint when it names a data cluster.
///
/// Errors are swallowed: FSInfo only caches the FAT, and must not fail an
/// allocation the FAT already holds.
fn update_fsinfo<D: BlockDevice>(dev: &mut D, fat32: &Fat32Info, delta: i32, next_free: u32) {
    let at = fat32.fsinfo_sector;
    let mut buf = [0u8; 512];
    if at == 0 || dev.read(at, &mut buf).is_err() {
        return;
    }
    // Only a sector that really is FSInfo: both signatures, as the first is
    // short enough to appear by accident.
    if buf[0..4] != FSINFO_LEAD_SIG || buf[484..488] != FSINFO_STRUC_SIG {
        return;
    }

    let free = u32::from_le_bytes([buf[488], buf[489], buf[490], buf[491]]);
    // 0xFFFF_FFFF means unknown, and stays so.
    if free != u32::MAX {
        let updated = if delta < 0 {
            free.saturating_sub(delta.unsigned_abs())
        } else {
            free.saturating_add(delta as u32)
        };
        buf[488..492].copy_from_slice(&updated.to_le_bytes());
    }

    if fat32.is_data_cluster(next_free) {
        buf[492..496].copy_from_slice(&next_free.to_le_bytes());
    }

    let _ = dev.write(at, &buf);
}

/// Allocate a free cluster. Scans FAT from `start_hint` and marks it as EOC.
/// Returns the allocated cluster number.
pub fn allocate_cluster<D: BlockDevice>(
    dev: &mut D,
    fat32: &Fat32Info,
    start_hint: u32,
) -> Result<u32, Fat32Error> {
    let max_cluster = fat32.alloc_limit();
    let mut buf = [0u8; 512];
    let mut last_sector = 0xFFFF_FFFFu32;

    // Scan from hint, then wrap around
    let mut cluster = if (2..max_cluster).contains(&start_hint) {
        start_hint
    } else {
        2
    };
    let start = cluster;
    loop {
        let (sector, offset) = fat32.fat_sector_for_cluster(cluster);
        if sector != last_sector {
            dev.read(sector, &mut buf)?;
            last_sector = sector;
        }
        let entry = u32::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]);
        if (entry & 0x0FFF_FFFF) == 0 {
            // Free cluster found — mark as EOC
            write_fat_entry(dev, fat32, cluster, 0x0FFF_FFFF)?;
            // One fewer free, and the next search can start after this one.
            update_fsinfo(dev, fat32, -1, cluster + 1);
            return Ok(cluster);
        }
        cluster += 1;
        if cluster >= max_cluster {
            cluster = 2;
        }
        if cluster == start {
            return Err(Fat32Error::Format("Disk full"));
        }
    }
}

/// Allocate a chain of `count` clusters. Returns the first cluster.
///
/// One first-fit scan from cluster 2, then each FAT sector touched is read
/// and written once per copy. First fit takes every free cluster it meets,
/// so the chain is all the free clusters from the first to the last, and no
/// list is kept.
///
/// Sectors are written highest first. The chain ascends, so a link points
/// into its own sector or a higher one: a power loss between writes leaves
/// at most a linked tail whose predecessors are still free, never a link
/// into an unclaimed cluster.
pub fn allocate_chain<D: BlockDevice>(
    dev: &mut D,
    fat32: &Fat32Info,
    count: u32,
) -> Result<u32, Fat32Error> {
    if count == 0 {
        return Err(Fat32Error::Format("Zero clusters requested"));
    }
    let entry = |buf: &[u8; 512], offset: usize| {
        u32::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ])
    };

    // First pass: the first and the last of the first `count` free clusters.
    let max_cluster = fat32.alloc_limit();
    let mut buf = [0u8; 512];
    let mut last_sector = u32::MAX;
    let (mut first, mut last, mut found) = (0u32, 0u32, 0u32);
    let mut cluster = 2u32;
    while found < count {
        if cluster >= max_cluster {
            return Err(Fat32Error::Format("Disk full"));
        }
        let (sector, offset) = fat32.fat_sector_for_cluster(cluster);
        if sector != last_sector {
            dev.read(sector, &mut buf)?;
            last_sector = sector;
        }
        if entry(&buf, offset) & 0x0FFF_FFFF == 0 {
            if found == 0 {
                first = cluster;
            }
            last = cluster;
            found += 1;
        }
        cluster += 1;
    }

    // Second pass, from the last cluster's FAT sector down to the first's:
    // the free entries between `first` and `last` are the chain's, each
    // linked to the next, the last to end-of-chain. A mask of the patched
    // offsets copies the links to every FAT under its own top four bits.
    const PER_SECTOR: u32 = 512 / 4;
    let (low_sector, _) = fat32.fat_sector_for_cluster(first);
    let (mut sector, _) = fat32.fat_sector_for_cluster(last);
    let mut next = 0x0FFF_FFFFu32;
    loop {
        let base = (sector - fat32.fat_start_sector) * PER_SECTOR;
        let lo = first.max(base);
        let hi = last.min(base + PER_SECTOR - 1);
        let mut links = [0u8; 512];
        dev.read(sector, &mut links)?;
        let mut members = [0u32; PER_SECTOR as usize / 32];
        for c in (lo..=hi).rev() {
            let offset = ((c - base) * 4) as usize;
            let existing = entry(&links, offset);
            if existing & 0x0FFF_FFFF != 0 {
                continue;
            }
            let value = (existing & 0xF000_0000) | (next & 0x0FFF_FFFF);
            links[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            members[(c - base) as usize / 32] |= 1 << ((c - base) % 32);
            next = c;
        }
        if members.iter().any(|&m| m != 0) {
            dev.write(sector, &links)?;
            for fat_copy in 1..fat32.num_fats.max(1) as u32 {
                let target = sector + fat_copy * fat32.fat_size_32;
                dev.read(target, &mut buf)?;
                for i in 0..PER_SECTOR as usize {
                    if members[i / 32] & (1 << (i % 32)) == 0 {
                        continue;
                    }
                    let offset = i * 4;
                    let value =
                        (entry(&buf, offset) & 0xF000_0000) | (entry(&links, offset) & 0x0FFF_FFFF);
                    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
                }
                dev.write(target, &buf)?;
            }
        }
        if sector == low_sector {
            break;
        }
        sector -= 1;
    }

    // The whole chain in one adjustment, as its FAT writes are batched.
    update_fsinfo(dev, fat32, -(count as i32), last + 1);

    Ok(first)
}

/// The most clusters one round of a delete or an overwrite frees: the list
/// a round checks against the card ([`keep_named`]) and frees, on the stack.
/// A file is freed in as many rounds as its size takes, up to
/// [`FREE_MOST`] clusters.
const FREE_MAX: usize = 64;

/// The most clusters one delete or overwrite frees, in rounds of
/// [`FREE_MAX`]: 2 MB at 512-byte clusters, the smallest, so the largest
/// file this device writes, a photo, is freed whole on any card. Every round
/// walks the card's entries again, so this also bounds a delete's time.
/// Past it, a file a computer wrote keeps the rest of its clusters used and
/// named by nothing, as a cut delete leaves them, for a disk check or a
/// format to take back.
const FREE_MOST: u32 = 64 * FREE_MAX as u32;

/// The most FAT sectors `keep_named` reads for the root's entries' chains,
/// files' and folders' together, before it gives up and frees nothing.
///
/// Each chain is bounded, but one that jumps to another FAT sector at every
/// link costs a read a link: a 4 GB file in 512-byte clusters is 8.4
/// million links, and as every read feeds the watchdog, such a card could
/// hold a delete for hours. A full 32 GB card of 32 KB clusters has a FAT
/// of 8,192 sectors, which files laid out in order read about once. Past
/// the bound the clusters to free stay used and named by nothing, as a cut
/// delete leaves them; the delete or overwrite itself is done.
pub const KEEP_FAT_READS: u32 = MAX_DIR_SECTORS;

/// One FAT sector held while a walk stays in it, so a chain laid out in
/// order costs a read a sector, not a read a link.
struct FatCursor {
    sector: Option<u32>,
    buf: [u8; 512],
    /// Sectors read.
    reads: u32,
}

impl FatCursor {
    const fn new() -> Self {
        Self {
            sector: None,
            buf: [0; 512],
            reads: 0,
        }
    }

    /// The FAT's word for `cluster`, its upper four bits masked, as
    /// [`read_fat_entry`] reads it.
    fn link<D: BlockDevice>(
        &mut self,
        dev: &mut D,
        fat32: &Fat32Info,
        cluster: u32,
    ) -> Result<u32, Fat32Error> {
        if !fat32.is_data_cluster(cluster) {
            return Err(Fat32Error::Format("Cluster outside the volume"));
        }
        let (sector, offset) = fat32.fat_sector_for_cluster(cluster);
        if self.sector != Some(sector) {
            self.sector = None;
            self.reads = self.reads.saturating_add(1);
            dev.read(sector, &mut self.buf)?;
            self.sector = Some(sector);
        }
        if offset + 3 >= 512 {
            return Err(Fat32Error::Format("FAT offset out of range"));
        }
        let word = u32::from_le_bytes([
            self.buf[offset],
            self.buf[offset + 1],
            self.buf[offset + 2],
            self.buf[offset + 3],
        ]);
        Ok(word & 0x0FFF_FFFF)
    }
}

/// Whether a FAT word says its cluster is in use: a link to another
/// cluster, or an end of chain. Zero is free, one is reserved, and from
/// `0x0FFF_FFF0` to the bad-cluster mark are reserved values and the mark.
fn in_use(word: u32) -> bool {
    (2..0x0FFF_FFF0).contains(&word) || word >= 0x0FFF_FFF8
}

/// Take out of `chain[..*n]` every cluster the card still names: the root
/// directory's whole chain, and every cluster of every live entry in it, a
/// file's as many as its size takes and a folder's to its end.
///
/// The entry being deleted is already marked so, and an overwritten one
/// already names its new chain, so neither keeps its old clusters; a second
/// entry naming them, by damage or on purpose, does. Folders' contents are
/// not walked: this device writes everything to the root.
///
/// Past [`KEEP_FAT_READS`] FAT sectors read, every cluster is kept (`*n` is
/// zero): none is freed whose owner was not looked for to the end.
fn keep_named<D: BlockDevice>(
    dev: &mut D,
    fat32: &Fat32Info,
    chain: &mut [u32; FREE_MAX],
    n: &mut usize,
) -> Result<(), Fat32Error> {
    // `cluster` out of the list, if it is there.
    fn keep(chain: &mut [u32; FREE_MAX], n: &mut usize, cluster: u32) {
        if let Some(i) = chain[..*n].iter().position(|&c| c == cluster) {
            *n -= 1;
            chain[i] = chain[*n];
        }
    }
    let mut fat = FatCursor::new();
    // FAT sectors read for folders' chains, which go one read a link
    // through `next_dir_cluster`; the cursor counts the files'.
    let mut folder_reads = 0u32;
    let mut cluster = fat32.root_cluster;
    let mut buf = [0u8; 512];
    let mut sectors_walked = 0u32;
    let mut entries = true;
    loop {
        keep(chain, n, cluster);
        if entries {
            let base = fat32.cluster_to_sector(cluster);
            'sectors: for s in 0..fat32.sectors_per_cluster as u32 {
                dev.read(base + s, &mut buf)?;
                for i in 0..16 {
                    let off = i * 32;
                    if buf[off] == 0x00 {
                        // The last entry: the root's later clusters are
                        // still its own, and are kept as the walk goes on.
                        entries = false;
                        break 'sectors;
                    }
                    let Some(entry) = DirEntry::from_bytes(&buf[off..off + 32]) else {
                        continue;
                    };
                    if entry.attr & ATTR_VOLUME_ID != 0 {
                        continue;
                    }
                    let mut c = entry.first_cluster();
                    if entry.is_dir() {
                        let mut walked = 0u32;
                        while fat32.is_data_cluster(c) {
                            keep(chain, n, c);
                            if fat.reads.saturating_add(folder_reads) >= KEEP_FAT_READS {
                                *n = 0;
                                return Ok(());
                            }
                            folder_reads += 1;
                            match next_dir_cluster(dev, fat32, c, &mut walked) {
                                Ok(Some(next)) => c = next,
                                _ => break,
                            }
                        }
                    } else {
                        // A loop is walked round once, not for as many steps
                        // as a size of gigabytes allows. Two numbers, no list:
                        // `mark` moves to the walk's cluster at every power of
                        // two steps, and the walk is back at it once it has
                        // been round the loop, every cluster of it kept.
                        let mut left = entry.file_size.div_ceil(fat32.cluster_bytes());
                        let (mut mark, mut power, mut lap) = (c, 1u32, 0u32);
                        while left > 0 && fat32.is_data_cluster(c) {
                            keep(chain, n, c);
                            left -= 1;
                            if fat.reads.saturating_add(folder_reads) >= KEEP_FAT_READS {
                                *n = 0;
                                return Ok(());
                            }
                            c = fat.link(dev, fat32, c)?;
                            if c == mark {
                                break;
                            }
                            lap += 1;
                            if lap == power {
                                (mark, power, lap) = (c, power.saturating_mul(2), 0);
                            }
                        }
                    }
                    if *n == 0 {
                        return Ok(());
                    }
                }
            }
        }
        match next_dir_cluster(dev, fat32, cluster, &mut sectors_walked)? {
            Some(next) => cluster = next,
            None => return Ok(()),
        }
    }
}

/// Free `entry`'s chain, as a delete frees a file's: as many clusters as its
/// size takes, no more, and none that anything else on the card still names.
///
/// By size, as `read_file` takes a file: a chain running on past its file
/// (one damaged link, or a card written so) reaches another file's
/// clusters, and freeing them would lose that file, perhaps a seed backup,
/// to the next write.
///
/// Before any is freed, a cluster the root or another live entry names is
/// taken out ([`keep_named`]), so one damaged entry cannot free the root
/// and every backup. The walk stops at a cluster whose FAT word is not in
/// use (a free one is not freed twice, a bad mark stays), at a link back
/// into the chain, and at [`FREE_MOST`] clusters.
///
/// What is freed is zeroed first ([`zero_clusters`]): a deleted file, or the
/// old contents of one written over, are not left in clusters the table
/// calls free, for a recovery tool to read. Only what this driver frees; a
/// format writes a new file system and leaves the data area as it was. A
/// card keeps spare copies of its own that no write reaches, so this is no
/// proof the bytes are gone from the chip.
///
/// A round takes, checks and frees up to [`FREE_MAX`] clusters, and the
/// next starts from the link it read before freeing, so the list stays on
/// the stack. A round that keeps all it took ends the free. An empty
/// file frees nothing. A size short of its chain leaves the rest used and
/// named by nothing, as a cut delete does, for a disk check or a format to
/// take back.
pub(super) fn free_chain<D: BlockDevice>(
    dev: &mut D,
    fat32: &Fat32Info,
    entry: &DirEntry,
) -> Result<(), Fat32Error> {
    // The file's clusters: what its size takes, as `read_file` reads them,
    // up to `FREE_MOST`.
    let mut left = entry
        .file_size
        .div_ceil(fat32.cluster_bytes())
        .min(FREE_MOST);
    let mut cluster = entry.first_cluster();
    while left > 0 {
        let full;
        (cluster, full) = free_round(dev, fat32, cluster, &mut left)?;
        if !full {
            return Ok(());
        }
    }
    Ok(())
}

/// Zeros over every sector of `clusters`, each a data cluster of this
/// volume ([`free_round`] takes no other).
fn zero_clusters<D: BlockDevice>(
    dev: &mut D,
    fat32: &Fat32Info,
    clusters: &[u32],
) -> Result<(), Fat32Error> {
    let zeros = [0u8; 512];
    for &cluster in clusters {
        let first = fat32.cluster_to_sector(cluster);
        for i in 0..u32::from(fat32.sectors_per_cluster) {
            let sector = first
                .checked_add(i)
                .ok_or(Fat32Error::Format("Cluster out of range"))?;
            dev.write(sector, &zeros)?;
        }
    }
    Ok(())
}

/// One round of [`free_chain`]: up to [`FREE_MAX`] of the `left` clusters
/// from `cluster`, while each is in use and none repeats; those the card
/// still names are kept, the rest freed. Returns the next round's start,
/// read before anything was freed, and whether there is a next round (this
/// one took a full list and freed some of it).
fn free_round<D: BlockDevice>(
    dev: &mut D,
    fat32: &Fat32Info,
    mut cluster: u32,
    left: &mut u32,
) -> Result<(u32, bool), Fat32Error> {
    let mut chain = [0u32; FREE_MAX];
    let mut n = 0usize;
    // A cursor of the round's own: the last round's sector may hold words
    // it has since freed.
    let mut fat = FatCursor::new();
    while *left > 0 && n < FREE_MAX && fat32.is_data_cluster(cluster) {
        let next = fat.link(dev, fat32, cluster)?;
        if !in_use(next) || chain[..n].contains(&cluster) {
            break;
        }
        chain[n] = cluster;
        n += 1;
        *left -= 1;
        cluster = next;
    }
    let full = n == FREE_MAX;
    if n == 0 {
        return Ok((cluster, false));
    }

    // None that the root directory or another file names.
    keep_named(dev, fat32, &mut chain, &mut n)?;
    if n == 0 {
        return Ok((cluster, false));
    }

    // Their bytes first, while the table still calls them used: a cut here
    // leaves used clusters nothing names, zeroed or not, as a cut delete
    // does, and never a free cluster holding the file.
    zero_clusters(dev, fat32, &chain[..n])?;

    // The rest freed a FAT sector at a time, one read and one write each,
    // and the same in FAT2.
    let mut buf = [0u8; 512];
    let mut done = [false; FREE_MAX];
    let mut lowest = u32::MAX;
    for i in 0..n {
        if done[i] {
            continue;
        }
        let (fsector, _) = fat32.fat_sector_for_cluster(chain[i]);
        dev.read(fsector, &mut buf)?;
        let mut offs = [0usize; FREE_MAX];
        let mut n_offs = 0usize;
        for j in i..n {
            let (s, offset) = fat32.fat_sector_for_cluster(chain[j]);
            if done[j] || s != fsector {
                continue;
            }
            if offset + 3 >= 512 {
                return Err(Fat32Error::Format("FAT offset out of range"));
            }
            let word = u32::from_le_bytes([
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            ]);
            // The reserved high nibble kept, the value 0.
            buf[offset..offset + 4].copy_from_slice(&(word & 0xF000_0000).to_le_bytes());
            offs[n_offs] = offset;
            n_offs += 1;
            done[j] = true;
            lowest = lowest.min(chain[j]);
        }
        dev.write(fsector, &buf)?;
        if fat32.num_fats > 1 {
            let fat2_sector = fsector + fat32.fat_size_32;
            dev.read(fat2_sector, &mut buf)?;
            for &o in &offs[..n_offs] {
                let word = u32::from_le_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]);
                buf[o..o + 4].copy_from_slice(&(word & 0xF000_0000).to_le_bytes());
            }
            dev.write(fat2_sector, &buf)?;
        }
    }

    // The freed clusters go back to the count, and the lowest of them
    // becomes the search hint.
    update_fsinfo(dev, fat32, n as i32, lowest);
    Ok((cluster, full))
}
