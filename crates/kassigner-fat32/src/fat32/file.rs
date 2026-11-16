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

// Files in the root directory: found by 8.3 name, read whole or with
// progress, written (the volume marked dirty while the write runs),
// deleted and overwritten.

use super::*;

/// Find a file in the root directory by 8.3 name.
/// Returns (DirEntry, sector_of_entry, offset_in_sector) so we can update it.
///
/// A folder of that name gives `Format("Name is a folder")`: a save or delete
/// taking it for a file would leave its clusters used and named by nothing.
pub fn find_file_in_root<D: BlockDevice>(
    dev: &mut D,
    fat32: &Fat32Info,
    name_83: &[u8; 11],
) -> Result<(DirEntry, u32, usize), Fat32Error> {
    let mut cluster = fat32.root_cluster;
    let mut buf = [0u8; 512];
    let mut sectors_walked = 0u32;

    loop {
        let base_sector = fat32.cluster_to_sector(cluster);
        for s in 0..fat32.sectors_per_cluster as u32 {
            dev.read(base_sector + s, &mut buf)?;
            for i in 0..16 {
                // 16 entries per 512-byte sector
                let off = i * 32;
                if buf[off] == 0x00 {
                    return Err(Fat32Error::Format("File not found"));
                } // end of dir
                if let Some(entry) = DirEntry::from_bytes(&buf[off..off + 32]) {
                    // A volume label is the card's name, not a file, whatever
                    // its eleven bytes spell.
                    if entry.attr & ATTR_VOLUME_ID == 0 && entry.matches(name_83) {
                        if entry.is_dir() {
                            return Err(Fat32Error::Format("Name is a folder"));
                        }
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
    Err(Fat32Error::Format("File not found"))
}

/// Read a file's contents into the provided buffer. Returns bytes read.
/// Buffer must be large enough for the file (file_size bytes).
pub fn read_file<D: BlockDevice>(
    dev: &mut D,
    fat32: &Fat32Info,
    entry: &DirEntry,
    out: &mut [u8],
) -> Result<usize, Fat32Error> {
    read_file_progress(dev, fat32, entry, out, &mut |_, _| {})
}

/// Read a file with a progress callback, given (bytes_read, total_bytes).
pub fn read_file_progress<D: BlockDevice>(
    dev: &mut D,
    fat32: &Fat32Info,
    entry: &DirEntry,
    out: &mut [u8],
    progress: &mut dyn FnMut(usize, usize),
) -> Result<usize, Fat32Error> {
    let file_size = entry.file_size as usize;
    if out.len() < file_size {
        return Err(Fat32Error::Format("Buffer too small"));
    }
    walk_file(
        dev,
        fat32,
        entry,
        &mut |dev, run| {
            let to = &mut out[run.at..run.at + run.bytes];
            if run.sectors > 1 {
                dev.read_many(run.sector, to)?;
            } else {
                let mut sector_buf = [0u8; 512];
                dev.read(run.sector, &mut sector_buf)?;
                to.copy_from_slice(&sector_buf[..run.bytes]);
            }
            Ok(())
        },
        progress,
    )
}

/// Whether `entry` holds exactly `data`: its size, then every byte read back
/// through [`read_file`]'s walk and checks. For checking a write against its
/// data without a second file-sized buffer.
///
/// # Errors
///
/// A chain [`read_file`] would refuse, or a device error.
pub fn file_holds<D: BlockDevice>(
    dev: &mut D,
    fat32: &Fat32Info,
    entry: &DirEntry,
    data: &[u8],
) -> Result<bool, Fat32Error> {
    if entry.file_size as usize != data.len() {
        return Ok(false);
    }
    let mut same = true;
    walk_file(
        dev,
        fat32,
        entry,
        &mut |dev, run| {
            let mut back = [0u8; 512];
            for k in 0..run.sectors as usize {
                dev.read(run.sector + k as u32, &mut back)?;
                let from = run.at + k * 512;
                let n = (run.bytes - k * 512).min(512);
                same &= back[..n] == data[from..from + n];
            }
            Ok(())
        },
        &mut |_, _| {},
    )?;
    Ok(same)
}

/// A run of a file's sectors, as [`walk_file`] hands it on: the file's
/// `bytes` bytes from `at` on are in `sectors` sectors from `sector` on,
/// whole sectors but for the file's last.
#[derive(Clone, Copy)]
struct Run {
    sector: u32,
    sectors: u32,
    at: usize,
    bytes: usize,
}

/// A file's sectors in order, cluster by cluster for as many bytes as its
/// size, each [`Run`] handed to `piece`, with the checks every read makes.
/// Returns the bytes walked. Shared by [`read_file`] and [`file_holds`], so
/// a read-back takes the file as a read does.
fn walk_file<D: BlockDevice>(
    dev: &mut D,
    fat32: &Fat32Info,
    entry: &DirEntry,
    piece: &mut dyn FnMut(&mut D, Run) -> Result<(), Fat32Error>,
    progress: &mut dyn FnMut(usize, usize),
) -> Result<usize, Fat32Error> {
    let file_size = entry.file_size as usize;
    let mut cluster = entry.first_cluster();
    let first_cluster = cluster; // the loop check's anchor, below
    let mut remaining = file_size;
    let mut pos = 0usize;
    let spc = fat32.sectors_per_cluster as u32;

    // Bounded without a counter: each pass takes up to a cluster's bytes
    // (the mount refused zero sectors per cluster), whatever the chain does.
    while remaining > 0 && fat32.is_data_cluster(cluster) {
        let base_sector = fat32.cluster_to_sector(cluster);
        // Two or more whole sectors go as one piece, read straight into the
        // buffer; any other sector, the file's last part one included, alone,
        // read through a buffer of its own, so no bytes past the file's end
        // reach a buffer a caller may reuse for secrets.
        let whole = (remaining / 512).min(spc as usize) as u32;
        let mut s = 0u32;
        if whole > 1 {
            let bytes = whole as usize * 512;
            piece(
                dev,
                Run {
                    sector: base_sector,
                    sectors: whole,
                    at: pos,
                    bytes,
                },
            )?;
            pos += bytes;
            remaining -= bytes;
            s = whole;
        }
        while s < spc && remaining > 0 {
            let chunk = remaining.min(512);
            piece(
                dev,
                Run {
                    sector: base_sector + s,
                    sectors: 1,
                    at: pos,
                    bytes: chunk,
                },
            )?;
            pos += chunk;
            remaining -= chunk;
            s += 1;
        }
        progress(pos, file_size);
        if remaining > 0 {
            let next = read_fat_entry(dev, fat32, cluster)?;
            // The walk ends by bytes, not at an end-of-chain mark, so a loop
            // would give a file of repeated clusters. The two loops damage
            // makes most, a cluster linking to itself or back to the first,
            // are refused here; any other after the loop, at one FAT read a
            // file, where a tortoise-and-hare check here would cost one per
            // two clusters.
            if next == cluster || next == first_cluster {
                return Err(Fat32Error::Format("Circular FAT chain"));
            }
            cluster = next;
        }
    }

    // Everything was read, or the chain stopped being a data cluster: a short
    // chain, or a non-empty file with no first cluster, is an error, not a
    // short read.
    if pos != file_size {
        return Err(Fat32Error::Format("Short FAT chain"));
    }

    // And the chain must end here: a link on means a loop or a size that
    // disagrees with the chain, and this catches every loop. Such a file
    // would fail AES-256-GCM or the firmware hash, and a person told the
    // passphrase is wrong when the card is failing might re-enter a seed.
    if fat32.is_data_cluster(cluster) {
        let next = read_fat_entry(dev, fat32, cluster)?;
        if (2..0x0FFF_FFF8).contains(&next) {
            return Err(Fat32Error::Format("FAT chain outlives the file"));
        }
    }

    Ok(pos)
}
/// Create a new file in the root directory. Allocates clusters and writes data.
/// Returns the created DirEntry.
pub fn create_file<D: BlockDevice>(
    dev: &mut D,
    fat32: &Fat32Info,
    name_83: &[u8; 11],
    data: &[u8],
) -> Result<DirEntry, Fat32Error> {
    create_file_progress(dev, fat32, name_83, data, &mut |_, _| {})
}

/// Create a file with a progress callback, given (bytes_written, total_bytes).
///
/// Refused before anything is written if the name starts with a marker
/// byte, the root has an entry of that name (file or folder), or the root
/// cannot be walked to its end. The entry's place is found first, the data
/// written second, the entry last: a root found unwalkable after the
/// clusters were claimed would leave them used and named by nothing.
pub fn create_file_progress<D: BlockDevice>(
    dev: &mut D,
    fat32: &Fat32Info,
    name_83: &[u8; 11],
    data: &[u8],
    progress: &mut dyn FnMut(usize, usize),
) -> Result<DirEntry, Fat32Error> {
    writable(name_83)?;
    let slot = root_slot(dev, fat32, name_83)?;
    while_dirty(dev, fat32, |dev| {
        // Where the end goes once its slot is taken, found before anything
        // is written, so a root that cannot say refuses the save whole.
        let (sector, offset, after) = match slot {
            Slot::At(sector, offset) => (sector, offset, None),
            Slot::End(cluster, sector, offset) => (
                sector,
                offset,
                slot_after(dev, fat32, cluster, sector, offset)?,
            ),
            Slot::Past { last, walked } => {
                let (sector, offset) = grow_root(dev, fat32, last, walked)?;
                (sector, offset, None)
            }
        };
        let first_cluster = write_chain(dev, fat32, data, progress)?;
        let entry = DirEntry {
            name: *name_83,
            attr: 0x20,
            cluster_hi: (first_cluster >> 16) as u16,
            cluster_lo: first_cluster as u16,
            file_size: data.len() as u32,
        };

        // The slot is still free: only `grow_root` wrote the directory since
        // the walk, and it zeroed the slot.
        //
        // Taking the end marker's slot puts a new marker in the next slot, as
        // entries past the end need not be zeros. In another sector it is
        // written first: a cut between the two writes leaves the directory
        // as it was.
        let mut buf = [0u8; 512];
        if let Some((there, at)) = after.filter(|&(there, _)| there != sector) {
            end_at(dev, there, at)?;
        }
        dev.read(sector, &mut buf)?;
        put_short_entry(&mut buf, offset, &entry);
        if let Some((_, at)) = after.filter(|&(there, _)| there == sector) {
            buf[at] = 0x00;
        }
        dev.write(sector, &buf)?;

        Ok(entry)
    })
}

/// FAT32's clean-shutdown bit, in the FAT's entry for cluster 1: set, the
/// volume was left whole; clear, a write was under way and did not finish.
const CLEAN_SHUTDOWN: u32 = 0x0800_0000;

/// Set or clear the volume's clean-shutdown bit, in every FAT kept.
fn set_clean<D: BlockDevice>(
    dev: &mut D,
    fat32: &Fat32Info,
    clean: bool,
) -> Result<(), Fat32Error> {
    let mut buf = [0u8; 512];
    for copy in 0..u32::from(fat32.num_fats) {
        // Cluster 1's entry: bytes 4 to 7 of the FAT's first sector. Inside
        // the FATs, whose end the mount checked against the data's start.
        let sector = fat32.fat_start_sector + copy * fat32.fat_size_32;
        dev.read(sector, &mut buf)?;
        let was = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let now = if clean {
            was | CLEAN_SHUTDOWN
        } else {
            was & !CLEAN_SHUTDOWN
        };
        if now != was {
            buf[4..8].copy_from_slice(&now.to_le_bytes());
            dev.write(sector, &buf)?;
        }
    }
    Ok(())
}

/// Run a write with the volume's clean-shutdown bit cleared, and set it
/// again once `op` succeeds. A card cut mid-write, or a failed write, stays
/// marked, and a computer checks it. The order of each step keeps the card
/// readable at any cut; the mark tells a computer to look.
fn while_dirty<D: BlockDevice, T>(
    dev: &mut D,
    fat32: &Fat32Info,
    op: impl FnOnce(&mut D) -> Result<T, Fat32Error>,
) -> Result<T, Fat32Error> {
    set_clean(dev, fat32, false)?;
    let done = op(dev)?;
    set_clean(dev, fat32, true)?;
    Ok(done)
}

/// Claim a chain for `data` and write it, named by no entry yet. Returns the
/// first cluster, 0 for no data. [`create_file`] and [`overwrite_file`]
/// write the data before the entry: cut between, the chain is used clusters
/// nothing names, a leak a format clears.
fn write_chain<D: BlockDevice>(
    dev: &mut D,
    fat32: &Fat32Info,
    data: &[u8],
    progress: &mut dyn FnMut(usize, usize),
) -> Result<u32, Fat32Error> {
    let file_size = data.len() as u32;
    let cluster_bytes = fat32.cluster_bytes();
    let clusters_needed = if file_size == 0 {
        0
    } else {
        file_size.div_ceil(cluster_bytes)
    };

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

        while remaining > 0 && fat32.is_data_cluster(cluster) {
            let base_sector = fat32.cluster_to_sector(cluster);
            // How many full sectors can we write from the data?
            let full_sectors = (remaining / 512).min(spc as usize) as u32;

            if full_sectors >= 1 {
                // Multi-block write for full sectors
                let write_bytes = full_sectors as usize * 512;
                dev.write_many(base_sector, &data[pos..pos + write_bytes])?;
                pos += write_bytes;
                remaining -= write_bytes;
            }

            // The cluster's other sectors: a part last sector, then zeros.
            let sectors_done = full_sectors;
            for s in sectors_done..spc {
                let mut sector_buf = [0u8; 512];
                if remaining == 0 {
                    dev.write(base_sector + s, &sector_buf)?;
                    continue;
                }
                let chunk = if remaining >= 512 { 512 } else { remaining };
                sector_buf[..chunk].copy_from_slice(&data[pos..pos + chunk]);
                dev.write(base_sector + s, &sector_buf)?;
                pos += chunk;
                remaining -= chunk;
            }

            progress(pos, total);
            if remaining > 0 {
                let next = read_fat_entry(dev, fat32, cluster)?;
                // The chain is `allocate_chain`'s, so a loop is our bug and
                // would write a cluster twice. Only the read's two quick
                // checks here: a save is read back after it is written
                // (`kassigner_fw::card::write`), and that read refuses every
                // loop.
                if next == cluster || next == first_cluster {
                    return Err(Fat32Error::Format("Circular FAT chain"));
                }
                cluster = next;
            }
        }
    }

    Ok(first_cluster)
}

/// Delete a file from the root directory: mark its entry deleted, zero its
/// clusters and free them.
pub fn delete_file<D: BlockDevice>(
    dev: &mut D,
    fat32: &Fat32Info,
    name_83: &[u8; 11],
) -> Result<(), Fat32Error> {
    let (entry, sector, offset) = find_file_in_root(dev, fat32, name_83)?;
    while_dirty(dev, fat32, |dev| {
        delete_found(dev, fat32, &entry, sector, offset)
    })
}

/// [`delete_file`]'s writes, once the entry is found.
fn delete_found<D: BlockDevice>(
    dev: &mut D,
    fat32: &Fat32Info,
    entry: &DirEntry,
    sector: u32,
    offset: usize,
) -> Result<(), Fat32Error> {
    // Entry first, chain second: a power loss between leaves used clusters
    // nothing names, a leak a format recovers. The other order would leave a
    // live entry on free clusters, which the next create can give another
    // file, whose data the stale entry would then read.
    let mut buf = [0u8; 512];
    dev.read(sector, &mut buf)?;
    buf[offset] = 0xE5;
    // The long-name entries in front of it with its checksum go too, back to
    // the one with `LFN_LAST`; left, a computer's disk check reports them. In
    // this sector only, where `write_dir_entry_with_long_name` puts a set; a
    // computer's set across a sector boundary keeps its earlier part, which
    // its checksum keeps from naming any file.
    let sum = lfn_checksum(&entry.name);
    let mut at = offset;
    while at >= 32 {
        at -= 32;
        if buf[at + 11] != ATTR_LFN || buf[at] == 0xE5 || buf[at + 13] != sum {
            break;
        }
        let first = buf[at] & LFN_LAST != 0;
        buf[at] = 0xE5;
        if first {
            break;
        }
    }
    dev.write(sector, &buf)?;

    free_chain(dev, fat32, entry)
}

/// Replace a file's contents, or create it when there is none of that name.
///
/// The new contents go into a chain of their own, the old entry is pointed
/// at it in one sector write, and only then is the old chain zeroed and
/// freed. Cut
/// anywhere, the card holds the old file or the new one whole, at worst with
/// used clusters nothing names. Delete-then-create would let the allocator
/// hand the freed clusters straight back, and a cut between would leave
/// neither: a seed backup lost while the seed is only in RAM.
///
/// The card needs room for both. The entry keeps its name, attributes and
/// any long name.
pub fn overwrite_file<D: BlockDevice>(
    dev: &mut D,
    fat32: &Fat32Info,
    name_83: &[u8; 11],
    data: &[u8],
) -> Result<(), Fat32Error> {
    // "Not found" makes this a create; any other failure writes nothing.
    let (old, sector, offset) = match find_file_in_root(dev, fat32, name_83) {
        Ok(found) => found,
        Err(Fat32Error::Format("File not found")) => {
            create_file(dev, fat32, name_83, data)?;
            return Ok(());
        }
        Err(e) => return Err(e),
    };

    while_dirty(dev, fat32, |dev| {
        let first = write_chain(dev, fat32, data, &mut |_, _| {})?;

        let mut buf = [0u8; 512];
        dev.read(sector, &mut buf)?;
        buf[offset + 20..offset + 22].copy_from_slice(&((first >> 16) as u16).to_le_bytes());
        buf[offset + 26..offset + 28].copy_from_slice(&(first as u16).to_le_bytes());
        buf[offset + 28..offset + 32].copy_from_slice(&(data.len() as u32).to_le_bytes());
        dev.write(sector, &buf)?;

        free_chain(dev, fat32, &old)
    })
}
