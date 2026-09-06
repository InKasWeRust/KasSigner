use super::super::{Fat32Info, SdCardType, sd_read_block, sd_write_block};
use super::cache::normalized_hint;

pub(super) fn update_fsinfo_hint(card_type: SdCardType, fat32: &Fat32Info, next_free: u32) {
    let Some(primary) = fat32.fs_info_sector else { return; };
    let mut sector = [0u8; 512];
    if sd_read_block(card_type, primary, &mut sector).is_err() || !valid_fsinfo(&sector) { return; }
    sector[488..492].copy_from_slice(&u32::MAX.to_le_bytes());
    sector[492..496].copy_from_slice(&normalized_hint(fat32, next_free).to_le_bytes());
    if sd_write_block(card_type, primary, &sector).is_err() { return; }
    if let Some(backup) = fat32.backup_fs_info_sector {
        let _ = sd_write_block(card_type, backup, &sector);
    }
}

fn valid_fsinfo(sector: &[u8; 512]) -> bool {
    &sector[0..4] == b"RRaA"
        && &sector[484..488] == b"rrAa"
        && sector[510] == 0x55
        && sector[511] == 0xAA
}
