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

// The root directory: the slot an entry goes in, growing the root, the
// listings, and long names.
//
// Long names written, so a computer shows a file by the name it was given
// (`kaspa-transfer.kspt`, not `KASPA-~1.KSP`); `list_root_dir_lfn` reads
// them. The firmware itself writes only 8.3 names (`SD0001.KAS`,
// `TX0001.KSP`); the writer is kept, and tested, for a caller that names
// files as a person does. A delete takes the long-name entries in front of
// its file, in its sector, whoever wrote them.

use super::*;

/// Characters a long-name entry carries.
const LFN_CHARS_PER_ENTRY: usize = 13;
/// Attribute byte marking a long-name entry: a combination no real file has,
/// so a driver that knows nothing of long names skips them.
pub(super) const ATTR_LFN: u8 = 0x0F;
/// A directory entry's volume-label bit: the card's name, not a file.
pub(super) const ATTR_VOLUME_ID: u8 = 0x08;
/// Bit set on the last long-name entry of a set, which is written first.
pub(super) const LFN_LAST: u8 = 0x40;
/// The longest long name this writes or shows: six entries of thirteen
/// characters, a set that fits in one sector with its short entry.
pub const MAX_LONG_NAME: usize = 78;

/// What [`list_root_dir_lfn`] puts in a name for each character outside
/// printable ASCII: DEL, a byte a name never shows as itself and a font
/// here has no glyph for.
pub const NOT_SHOWN: u8 = 0x7F;

/// A byte of an 8.3 name as [`list_root_dir_lfn`] shows it: printable
/// ASCII as it is, any other as [`NOT_SHOWN`].
const fn shown(b: u8) -> u8 {
    if b >= 0x20 && b < 0x7F {
        b
    } else {
        NOT_SHOWN
    }
}

/// The checksum every long-name entry carries to bind it to its short name:
/// if a driver that knows nothing of long names renames or moves the short
/// entry, the long name stops matching and is ignored. Rotate-then-add, as
/// the specification has it, not a plain sum.
pub fn lfn_checksum(name_83: &[u8; 11]) -> u8 {
    let mut sum: u8 = 0;
    for &c in name_83.iter() {
        sum = sum.rotate_right(1).wrapping_add(c);
    }
    sum
}

/// Fill one 32-byte long-name entry.
///
/// `seq` is 1-based from the name's start; the entries go on the card
/// highest first, that one marked [`LFN_LAST`]. Characters past the name are
/// 0x0000 for the terminator and 0xFFFF after it: zeros throughout show as
/// trailing spaces on a computer.
fn fill_lfn_entry(out: &mut [u8; 32], name: &[u16], seq: usize, last: bool, checksum: u8) {
    out.fill(0);
    out[0] = seq as u8 | if last { LFN_LAST } else { 0 };
    out[11] = ATTR_LFN;
    out[12] = 0;
    out[13] = checksum;
    // The short entry's cluster field, zero in a long-name entry.
    out[26] = 0;
    out[27] = 0;

    // Where the thirteen characters sit: five, then six, then two.
    const SLOTS: [usize; LFN_CHARS_PER_ENTRY] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];

    let base = (seq - 1) * LFN_CHARS_PER_ENTRY;
    for (k, &at) in SLOTS.iter().enumerate() {
        let ch = match base + k {
            i if i < name.len() => name[i],
            i if i == name.len() => 0x0000,
            _ => 0xFFFF,
        };
        let b = ch.to_le_bytes();
        out[at] = b[0];
        out[at + 1] = b[1];
    }
}

/// How many long-name entries a name needs.
fn lfn_entry_count(len: usize) -> usize {
    len.div_ceil(LFN_CHARS_PER_ENTRY)
}

/// 1980-01-01, the first day FAT can say, as the dates of every entry this
/// writes: the device has no clock, and zero (month 0, day 0) is no date.
const FAT_FIRST_DAY: u16 = (1 << 5) | 1;

/// `entry` as a short directory entry, the 32 bytes at `off` in `buf`: its
/// name, attributes, first cluster and size, times of midnight and dates of
/// [`FAT_FIRST_DAY`], the rest zero.
pub(super) fn put_short_entry(buf: &mut [u8; 512], off: usize, entry: &DirEntry) {
    let e = &mut buf[off..off + 32];
    e.fill(0);
    e[..11].copy_from_slice(&entry.name);
    e[11] = entry.attr;
    let day = FAT_FIRST_DAY.to_le_bytes();
    e[16..18].copy_from_slice(&day); // created
    e[18..20].copy_from_slice(&day); // last opened
    e[20..22].copy_from_slice(&entry.cluster_hi.to_le_bytes());
    e[24..26].copy_from_slice(&day); // written
    e[26..28].copy_from_slice(&entry.cluster_lo.to_le_bytes());
    e[28..32].copy_from_slice(&entry.file_size.to_le_bytes());
}

/// Where a new root entry goes.
#[derive(Clone, Copy)]
pub(super) enum Slot {
    /// A deleted entry's slot, before the end: its sector and its offset in
    /// it.
    At(u32, usize),
    /// The end-of-directory marker's slot: its cluster, its sector and its
    /// offset in it. Taken, the end moves to the slot after it.
    End(u32, u32, usize),
    /// None free: the root's last cluster and the sectors walked to it, for
    /// [`grow_root`].
    Past { last: u32, walked: u32 },
}

/// The first free slot in the root for an entry named `name_83`, found by
/// walking the root to its end, so a name already there, a file's or a
/// folder's, is found too. Writes nothing.
///
/// # Errors
///
/// `Format("Name already in use")` for a name the root has, a volume label
/// aside; a root that cannot be walked; a device error.
pub(super) fn root_slot<D: BlockDevice>(
    dev: &mut D,
    fat32: &Fat32Info,
    name_83: &[u8; 11],
) -> Result<Slot, Fat32Error> {
    let mut cluster = fat32.root_cluster;
    let mut buf = [0u8; 512];
    let mut walked = 0u32;
    let mut free: Option<(u32, usize)> = None;
    loop {
        let base = fat32.cluster_to_sector(cluster);
        for s in 0..fat32.sectors_per_cluster as u32 {
            dev.read(base + s, &mut buf)?;
            for i in 0..16 {
                let off = i * 32;
                match buf[off] {
                    // The end: every live entry has been seen.
                    0x00 => {
                        return Ok(match free {
                            Some((sector, offset)) => Slot::At(sector, offset),
                            None => Slot::End(cluster, base + s, off),
                        });
                    }
                    0xE5 => {
                        free.get_or_insert((base + s, off));
                    }
                    _ => {
                        let taken = DirEntry::from_bytes(&buf[off..off + 32])
                            .is_some_and(|e| e.attr & ATTR_VOLUME_ID == 0 && e.matches(name_83));
                        if taken {
                            return Err(Fat32Error::Format("Name already in use"));
                        }
                    }
                }
            }
        }
        match next_dir_cluster(dev, fat32, cluster, &mut walked)? {
            Some(next) => cluster = next,
            None => {
                return Ok(match free {
                    Some((sector, offset)) => Slot::At(sector, offset),
                    None => Slot::Past {
                        last: cluster,
                        walked,
                    },
                })
            }
        }
    }
}

/// The slot after the one at `offset` in `sector` of root cluster
/// `cluster`: in the same sector, the next sector, or the root's next
/// cluster; `None` when the root ends there. Where the new end-of-directory
/// marker goes when the old one's slot is taken.
///
/// # Errors
///
/// `Format("Circular FAT chain")` if the next cluster is one the root has
/// already passed (a marker there would hide live entries); a device error.
pub(super) fn slot_after<D: BlockDevice>(
    dev: &mut D,
    fat32: &Fat32Info,
    cluster: u32,
    sector: u32,
    offset: usize,
) -> Result<Option<(u32, usize)>, Fat32Error> {
    if offset + 32 < 512 {
        return Ok(Some((sector, offset + 32)));
    }
    let base = fat32.cluster_to_sector(cluster);
    if sector + 1 < base + fat32.sectors_per_cluster as u32 {
        return Ok(Some((sector + 1, 0)));
    }
    let mut walked = 0u32;
    let Some(next) = next_dir_cluster(dev, fat32, cluster, &mut walked)? else {
        return Ok(None);
    };
    // The root from its start to `cluster`, under the walk's own bound: a
    // loop back to any of those clusters is refused, not written into.
    let mut at = fat32.root_cluster;
    let mut walked = 0u32;
    loop {
        if at == next {
            return Err(Fat32Error::Format("Circular FAT chain"));
        }
        if at == cluster {
            break;
        }
        match next_dir_cluster(dev, fat32, at, &mut walked)? {
            Some(n) => at = n,
            None => break,
        }
    }
    Ok(Some((fat32.cluster_to_sector(next), 0)))
}

/// Make the slot at `offset` in `sector` the end of the directory: its
/// first byte zero. Written only if it is not that already, as on a card
/// whose slots past the end are zeros.
pub(super) fn end_at<D: BlockDevice>(
    dev: &mut D,
    sector: u32,
    offset: usize,
) -> Result<(), Fat32Error> {
    let mut buf = [0u8; 512];
    dev.read(sector, &mut buf)?;
    if buf[offset] != 0x00 {
        buf[offset] = 0x00;
        dev.write(sector, &buf)?;
    }
    Ok(())
}

/// Extend the root by a cluster after `last`, its last, and give the new
/// cluster's first slot. `walked` is the sectors walked to `last`.
///
/// The cluster is claimed, zeroed, then linked: until linked it is past the
/// chain's end, where no reader looks, so a cut or failed write leaves the
/// directory as it was, at worst with a claimed cluster nothing names.
/// Linked first, a cut before the zeros would end the directory in an old
/// file's bytes, read as entries. It counts against [`MAX_DIR_SECTORS`]
/// before it is claimed.
pub(super) fn grow_root<D: BlockDevice>(
    dev: &mut D,
    fat32: &Fat32Info,
    last: u32,
    walked: u32,
) -> Result<(u32, usize), Fat32Error> {
    let spc = fat32.sectors_per_cluster as u32;
    if walked.saturating_add(spc) > MAX_DIR_SECTORS {
        return Err(Fat32Error::Format("Directory too large"));
    }
    let new_cl = allocate_cluster(dev, fat32, last + 1)?;
    let zeros = [0u8; 512];
    let new_base = fat32.cluster_to_sector(new_cl);
    for s in 0..spc {
        dev.write(new_base + s, &zeros)?;
    }
    write_fat_entry(dev, fat32, last, new_cl)?;
    Ok((new_base, 0))
}

/// List files in root directory. Calls callback for each entry.
/// Callback returns true to continue, false to stop.
///
/// Folders are listed with the files, volume labels are not. A walk by
/// [`RootCursor`], as a caller that reads files between entries walks it.
pub fn list_root_dir<D: BlockDevice, F>(
    dev: &mut D,
    fat32: &Fat32Info,
    mut callback: F,
) -> Result<(), Fat32Error>
where
    F: FnMut(&DirEntry) -> bool,
{
    let mut root = RootCursor::new(fat32);
    while let Some(entry) = root.next(dev, fat32)? {
        if !callback(&entry) {
            break;
        }
    }
    Ok(())
}

/// A walk of the root an entry at a time that keeps its place between
/// calls, so a caller can read files as it goes and still walk the root
/// once: the entries [`list_root_dir`] gives, in order. The cursor holds its
/// sector, so the root must not be written while a walk is under way.
pub struct RootCursor {
    cluster: u32,
    /// The sector in `cluster`, and the slot in it, that come next.
    sector: u32,
    slot: usize,
    /// Sectors walked, for `next_dir_cluster`'s bound.
    walked: u32,
    /// Which sector `buf` holds.
    held: Option<u32>,
    buf: [u8; 512],
    done: bool,
}

impl RootCursor {
    /// At the root's first entry.
    pub fn new(fat32: &Fat32Info) -> Self {
        Self {
            cluster: fat32.root_cluster,
            sector: 0,
            slot: 0,
            walked: 0,
            held: None,
            buf: [0; 512],
            done: false,
        }
    }

    /// The root's next entry, a file's or a folder's, with deleted entries,
    /// long-name parts and volume labels stepped over; `None` once the root
    /// has ended.
    ///
    /// # Errors
    ///
    /// A root whose chain cannot be walked, as every root walk here refuses
    /// one, or a device error. The cursor stays where it was.
    pub fn next<D: BlockDevice>(
        &mut self,
        dev: &mut D,
        fat32: &Fat32Info,
    ) -> Result<Option<DirEntry>, Fat32Error> {
        while !self.done {
            if self.slot == 16 {
                self.slot = 0;
                self.sector += 1;
            }
            if self.sector == fat32.sectors_per_cluster as u32 {
                match next_dir_cluster(dev, fat32, self.cluster, &mut self.walked)? {
                    Some(next) => {
                        self.cluster = next;
                        self.sector = 0;
                    }
                    None => self.done = true,
                }
                continue;
            }
            let at = fat32.cluster_to_sector(self.cluster) + self.sector;
            if self.held != Some(at) {
                self.held = None;
                dev.read(at, &mut self.buf)?;
                self.held = Some(at);
            }
            let off = self.slot * 32;
            if self.buf[off] == 0x00 {
                self.done = true;
                continue;
            }
            self.slot += 1;
            if let Some(entry) = DirEntry::from_bytes(&self.buf[off..off + 32]) {
                if entry.attr & ATTR_VOLUME_ID == 0 {
                    return Ok(Some(entry));
                }
            }
        }
        Ok(None)
    }
}

/// List root directory with LFN (Long File Name) support.
/// Callback receives (&DirEntry, &display_name, display_name_len).
/// display_name holds the long name if there is one, else the 8.3 name.
///
/// Printable ASCII is shown as it is, any other character as one
/// [`NOT_SHOWN`] (a block on screen), so a name is never shown as one it is
/// not. A long name with such a character carries the 8.3 name after it,
/// `caf■.jpg (CAFE~1.JPG)`, so names apart only there are shown apart.
///
/// A long name is shown only when its set is whole, parts 1 to the last,
/// each carrying [`lfn_checksum`] of the short entry after it, so a deleted
/// file's set never names what follows. Otherwise, or past
/// [`MAX_LONG_NAME`], the 8.3 name, not a cut name that could read as
/// another file's.
pub fn list_root_dir_lfn<D: BlockDevice, F>(
    dev: &mut D,
    fat32: &Fat32Info,
    mut callback: F,
) -> Result<(), Fat32Error>
where
    F: FnMut(&DirEntry, &[u8; MAX_LONG_NAME], usize) -> bool,
{
    /// Parts a name this crate writes can have.
    const PARTS: usize = MAX_LONG_NAME / LFN_CHARS_PER_ENTRY;

    let mut cluster = fat32.root_cluster;
    let mut buf = [0u8; 512];
    let mut lfn_buf = [0u8; MAX_LONG_NAME];
    // The set being gathered: each part's UTF-16LE characters and checksum,
    // which parts have arrived, how many the set has, and whether it has more
    // than fit.
    let mut lfn_parts: [([u8; 26], u8); PARTS] = [([0; 26], 0); PARTS];
    let mut arrived = 0u8;
    let mut count = 0usize;
    let mut too_long = false;
    let mut sectors_walked = 0u32;

    loop {
        let base_sector = fat32.cluster_to_sector(cluster);
        for s in 0..fat32.sectors_per_cluster as u32 {
            dev.read(base_sector + s, &mut buf)?;
            for i in 0..16 {
                let off = i * 32;
                if buf[off] == 0x00 {
                    return Ok(());
                }
                if buf[off] == 0xE5 {
                    count = 0;
                    continue;
                }

                let attr = buf[off + 11];
                if attr == ATTR_LFN {
                    let seq = (buf[off] & 0x3F) as usize;
                    // The part written first, with the highest number, starts
                    // a set: whatever was gathered before it is not this one's.
                    if buf[off] & LFN_LAST != 0 {
                        arrived = 0;
                        count = seq;
                        too_long = seq > PARTS;
                    }
                    if (1..=PARTS).contains(&seq) {
                        // Thirteen UTF-16LE characters, five, six and two.
                        let mut utf16 = [0u8; 26];
                        utf16[0..10].copy_from_slice(&buf[off + 1..off + 11]);
                        utf16[10..22].copy_from_slice(&buf[off + 14..off + 26]);
                        utf16[22..26].copy_from_slice(&buf[off + 28..off + 32]);
                        lfn_parts[seq - 1] = (utf16, buf[off + 13]);
                        arrived |= 1 << (seq - 1);
                    }
                    continue;
                }

                // Regular entry — check if we have LFN parts
                if let Some(entry) = DirEntry::from_bytes(&buf[off..off + 32]) {
                    if entry.attr & 0x08 != 0 {
                        count = 0;
                        continue;
                    }

                    // Build display name, from a whole set that names this
                    // entry.
                    let sum = lfn_checksum(&entry.name);
                    let whole = count > 0
                        && !too_long
                        && u32::from(arrived) == (1u32 << count) - 1
                        && lfn_parts[..count].iter().all(|&(_, c)| c == sum);
                    let mut lfn_len = 0usize;
                    // Whether a character went as [`NOT_SHOWN`].
                    let mut lossy = false;
                    if whole {
                        // Whether the unit before was the first half of a
                        // character UTF-16 writes in two, which is one
                        // character, so one mark, not two.
                        let mut high = false;
                        for (utf16, _) in lfn_parts.iter().take(count) {
                            for c in 0..13 {
                                let unit = u16::from_le_bytes([utf16[c * 2], utf16[c * 2 + 1]]);
                                // The padding after a name, and its end.
                                if unit == 0xFFFF || unit == 0x0000 {
                                    break;
                                }
                                if lfn_len >= MAX_LONG_NAME {
                                    break;
                                }
                                let second = core::mem::replace(
                                    &mut high,
                                    (0xD800..=0xDBFF).contains(&unit),
                                ) && (0xDC00..=0xDFFF).contains(&unit);
                                if second {
                                    continue;
                                }
                                lfn_buf[lfn_len] = match u8::try_from(unit) {
                                    Ok(b) if (0x20..0x7F).contains(&b) => b,
                                    _ => {
                                        lossy = true;
                                        NOT_SHOWN
                                    }
                                };
                                lfn_len += 1;
                            }
                        }
                    }

                    let mut disp = [0u8; 13];
                    let dlen = format_83_display(&entry.name, &mut disp);
                    for b in &mut disp[..dlen] {
                        *b = shown(*b);
                    }
                    if lfn_len == 0 {
                        // No long name: the 8.3 one.
                        lfn_buf[..dlen].copy_from_slice(&disp[..dlen]);
                        lfn_len = dlen;
                    } else if lossy {
                        // A character not shown: the 8.3 name, unique in the
                        // directory, after as much of the long name as fits.
                        let tail = dlen + 3;
                        lfn_len = lfn_len.min(MAX_LONG_NAME - tail);
                        lfn_buf[lfn_len..lfn_len + 2].copy_from_slice(b" (");
                        lfn_buf[lfn_len + 2..lfn_len + 2 + dlen].copy_from_slice(&disp[..dlen]);
                        lfn_buf[lfn_len + 2 + dlen] = b')';
                        lfn_len += tail;
                    }

                    count = 0;
                    if !callback(&entry, &lfn_buf, lfn_len) {
                        return Ok(());
                    }
                } else {
                    count = 0;
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

/// Write a directory entry with a long name.
///
/// Writes the long-name entries and the short entry as one contiguous set, in
/// the specification's order: highest sequence first, the short entry last.
///
/// A reader takes the entries just before a short entry as its long name,
/// so the set needs `n + 1` free slots in a row. They are found in one
/// sector: one write puts the set down whole, and a delete, which looks only
/// in its file's sector, takes it whole.
///
/// A reader stops at the first entry whose first byte is zero. A set that
/// takes that slot makes the slot after it the new end, as [`create_file`]
/// does. One that does not fit in the rest of the marker's sector goes at
/// the start of the next, and the marker's slots to its sector's end are
/// then marked deleted: until then the set is past the end and unseen, so a
/// power loss leaves the directory as it was. Past the marker every slot is
/// free, whatever it holds.
///
/// # Errors
///
/// `Format` if the name is empty or longer than [`MAX_LONG_NAME`], if the
/// short name starts with a byte the directory reads as a marker, or if the
/// root has no run of free slots that long or cannot be walked; `Device` on
/// a device error.
pub fn write_dir_entry_with_long_name<D: BlockDevice>(
    dev: &mut D,
    fat32: &Fat32Info,
    entry: &DirEntry,
    long_name: &[u16],
) -> Result<(), Fat32Error> {
    if long_name.is_empty() || long_name.len() > MAX_LONG_NAME {
        return Err(Fat32Error::Format("Long name length"));
    }
    writable(&entry.name)?;

    let n = lfn_entry_count(long_name.len());
    let needed = n + 1;
    // Sixteen entries to a sector, and a set must not straddle two.
    if needed > 16 {
        return Err(Fat32Error::Format("Long name needs too many entries"));
    }

    let checksum = lfn_checksum(&entry.name);
    let mut cluster = fat32.root_cluster;
    let mut buf = [0u8; 512];
    let mut sectors_walked = 0u32;
    // Where the end-of-directory marker is: its sector and slot.
    let mut end: Option<(u32, usize)> = None;

    loop {
        let base_sector = fat32.cluster_to_sector(cluster);
        for s in 0..fat32.sectors_per_cluster as u32 {
            let sector = base_sector + s;
            dev.read(sector, &mut buf)?;
            if end.is_none() {
                end = (0..16).find(|&i| buf[i * 32] == 0x00).map(|i| (sector, i));
            }

            // The first slot past the end in this sector: the marker's in its
            // sector, the first in a later one. Slots past the end are free
            // whatever they hold: old entries skipped over would come back as
            // files once the marker is lifted.
            let past_from = match end {
                Some((marked, slot)) if marked == sector => slot,
                Some(_) => 0,
                None => 16,
            };

            // The first slot of a free run long enough to hold the set, and
            // whether the run reaches past the end.
            let mut run_start: Option<usize> = None;
            let mut run = 0usize;
            let mut ends = false;
            for i in 0..16 {
                let past = i >= past_from;
                let free = past || buf[i * 32] == 0xE5;
                if free {
                    if run == 0 {
                        run_start = Some(i);
                        ends = false;
                    }
                    run += 1;
                    ends |= past;
                    if run == needed {
                        break;
                    }
                } else {
                    run = 0;
                    run_start = None;
                }
            }

            let Some(start) = run_start.filter(|_| run >= needed) else {
                continue;
            };

            // Long-name entries, highest sequence first. The one written first
            // carries LFN_LAST and holds the *end* of the name.
            for k in 0..n {
                let seq = n - k;
                let off = (start + k) * 32;
                let mut lfn = [0u8; 32];
                fill_lfn_entry(&mut lfn, long_name, seq, k == 0, checksum);
                buf[off..off + 32].copy_from_slice(&lfn);
            }

            // Then the short entry the set names.
            let off = (start + n) * 32;
            put_short_entry(&mut buf, off, entry);

            // A new end marker only where the set took the old one's place:
            // after a set in deleted slots may be a live entry, which a marker
            // would hide with every entry after it. In the next sector, when
            // the set ends one, it is written first: a cut between the two
            // writes leaves the directory as it was.
            let next_end = if ends {
                slot_after(dev, fat32, cluster, sector, off)?
            } else {
                None
            };
            if let Some((there, at)) = next_end.filter(|&(there, _)| there != sector) {
                end_at(dev, there, at)?;
            }
            if let Some((_, at)) = next_end.filter(|&(there, _)| there == sector) {
                buf[at] = 0x00;
            }

            dev.write(sector, &buf)?;

            // The set is past a marker in an earlier sector: lift it.
            if let Some((marked, slot)) = end.filter(|&(marked, _)| marked != sector) {
                dev.read(marked, &mut buf)?;
                for i in slot..16 {
                    buf[i * 32] = 0xE5;
                }
                dev.write(marked, &buf)?;
            }
            return Ok(());
        }

        // Counted by `next_dir_cluster` alone: counting here too would halve
        // the walk's budget.
        match next_dir_cluster(dev, fat32, cluster, &mut sectors_walked)? {
            Some(next) => cluster = next,
            None => return Err(Fat32Error::Format("No room for a long name")),
        }
    }
}
