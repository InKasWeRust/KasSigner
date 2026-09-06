use signer_firmware_core::storage::fat32_lfn::{
    DirectoryEntryKind, LfnAccumulator, classify_directory_entry,
};
use super::super::{DirEntry, Fat32Info, SdCardType, sd_read_block};

const DIRECTORY_ENTRY_BYTES: usize = 32;
const ENTRIES_PER_SECTOR: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ScanControl {
    Continue,
    Stop,
}

pub(super) fn scan_cluster<F>(
    card_type: SdCardType,
    fat32: &Fat32Info,
    cluster: u32,
    names: &mut LfnAccumulator,
    callback: &mut F,
) -> Result<ScanControl, &'static str>
where
    F: FnMut(&DirEntry, &[u8; 64], usize) -> bool,
{
    let base_sector = fat32.cluster_to_sector(cluster);
    let mut sector = [0u8; 512];
    for offset in 0..fat32.sectors_per_cluster as u32 {
        sd_read_block(card_type, base_sector + offset, &mut sector)?;
        if scan_sector(&sector, names, callback) == ScanControl::Stop {
            return Ok(ScanControl::Stop);
        }
    }
    Ok(ScanControl::Continue)
}

fn scan_sector<F>(sector: &[u8; 512], names: &mut LfnAccumulator, callback: &mut F) -> ScanControl
where
    F: FnMut(&DirEntry, &[u8; 64], usize) -> bool,
{
    for index in 0..ENTRIES_PER_SECTOR {
        let offset = index * DIRECTORY_ENTRY_BYTES;
        let raw = &sector[offset..offset + DIRECTORY_ENTRY_BYTES];
        if process_entry(raw, names, callback) == ScanControl::Stop {
            return ScanControl::Stop;
        }
    }
    ScanControl::Continue
}

fn process_entry<F>(raw: &[u8], names: &mut LfnAccumulator, callback: &mut F) -> ScanControl
where
    F: FnMut(&DirEntry, &[u8; 64], usize) -> bool,
{
    match classify_directory_entry(raw) {
        DirectoryEntryKind::End => ScanControl::Stop,
        DirectoryEntryKind::Deleted | DirectoryEntryKind::Volume => {
            names.reset();
            ScanControl::Continue
        }
        DirectoryEntryKind::LongName => {
            names.record(raw);
            ScanControl::Continue
        }
        DirectoryEntryKind::Regular => process_regular_entry(raw, names, callback),
    }
}

fn process_regular_entry<F>(
    raw: &[u8],
    names: &mut LfnAccumulator,
    callback: &mut F,
) -> ScanControl
where
    F: FnMut(&DirEntry, &[u8; 64], usize) -> bool,
{
    let Some(entry) = DirEntry::from_bytes(raw) else {
        names.reset();
        return ScanControl::Continue;
    };
    let (display, length) = names.display_name(&entry.name);
    let keep_scanning = callback(&entry, display, length);
    names.reset();
    if keep_scanning {
        ScanControl::Continue
    } else {
        ScanControl::Stop
    }
}
