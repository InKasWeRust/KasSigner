// Shared SD controller helpers and stable crate-visible utility functions.

use crate::services::storage_device;

/// Shared state for SD backup/restore touch handlers.
/// Parse v1.0.6 `multi_hd45(...)` descriptors and legacy `multi_hd(...)`
/// descriptors. The function prefix is authoritative for the derivation scheme.
///
/// where each participant hex = compressed pubkey (33 bytes = 66 hex)
/// immediately followed by chain code (32 bytes = 64 hex), for a total
/// of 130 hex chars. Trailing whitespace is tolerated.
///
/// Returns `(m, n, cosigner_pubkeys, cosigner_chain_codes)` on success.
///
/// The `multi_hd` function name distinguishes this format from the v1.0.x
/// `multi(...)` single-point format which was incompatible with per-address
/// HD derivation. Old `multi(...)` descriptors will fail to parse here —
/// that's intentional: v1.0.x multisigs cannot be rebuilt as HD wallets
/// because the account-level xpub (needed for child derivation) was never
/// recorded.
const _: [(); offline_signer::transaction::model::MAX_MULTISIG_KEYS] =
    [(); kassigner_protocol::wire::multisig_descriptor::MAX_DESCRIPTOR_PARTICIPANTS];

pub(in crate::runtime::interactions::sd) type ParsedMultisigDescriptor =
    kassigner_protocol::wire::multisig_descriptor::ParsedMultisigDescriptor;

pub(in crate::runtime::interactions::sd) fn parse_descriptor(
    data: &[u8],
) -> Option<ParsedMultisigDescriptor> {
    kassigner_protocol::wire::multisig_descriptor::parse_multisig_descriptor(data)
        .ok()
        .filter(|parsed| parsed.is_hd())
}

/// Check if a file with the given 8.3 name exists on the SD card.
/// Returns true if the file exists, false if not found or on SD error.
pub(crate) fn sd_file_exists(
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    delay: &mut esp_hal::delay::Delay,
    name_83: &[u8; 11],
) -> bool {
    let _ = &mut *i2c;
    storage_device::with_sd_card!(i2c, delay, |ct| {
        let fat32 = storage_device::mount_fat32(ct)?;
        storage_device::find_file_in_root(ct, &fat32, name_83)?;
        Ok(())
    }).is_ok()
}

/// Build an 8.3 filename from pp_input buffer with given 3-byte extension.
/// Uppercases the name portion as required by the FAT32 directory format.
pub(crate) fn build_filename_83(pp_buf: &[u8], pp_len: usize, ext: &[u8; 3]) -> [u8; 11] {
    let mut name = [b' '; 11];
    let len = pp_len.min(8);
    for j in 0..len {
        let c = pp_buf[j];
        name[j] = if c >= b'a' && c <= b'z' { c - 32 } else { c };
    }
    name[8] = ext[0];
    name[9] = ext[1];
    name[10] = ext[2];
    name
}

/// Write data to SD card, replacing any existing file with the same name.
pub(crate) fn write_file_to_sd(
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    delay: &mut esp_hal::delay::Delay,
    fname: &[u8; 11],
    data: &[u8],
) -> Result<(), &'static str> {
    let _ = &mut *i2c;
    storage_device::with_sd_card!(i2c, delay, |ct| {
        let fat32 = storage_device::mount_fat32(ct)?;
        storage_device::overwrite_file(ct, &fat32, fname, data)?;
        Ok(())
    })
}

/// Generate a nonce for non-backup AES-GCM workflows.
pub(crate) fn generate_trng_nonce() -> Result<[u8; 12], &'static str> {
    let mut nonce = [0u8; 12];
    crate::crypto::entropy::fill(&mut nonce)
        .map_err(crate::services::entropy::EntropyError::message)?;
    Ok(nonce)
}

/// Scan SD card for the highest auto-increment number matching a prefix+extension pattern.
/// Returns the next number (max_found + 1). Prefix is 2 bytes (e.g. "SD", "TX", "XP", "KP", "MS").
pub(crate) fn scan_auto_increment(
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    delay: &mut esp_hal::delay::Delay,
    prefix: &[u8; 2],
    ext: &[u8; 3],
) -> u32 {
    let _ = &mut *i2c;
    let mut max_num: u32 = 0;
    let p0 = prefix[0];
    let p1 = prefix[1];
    let e0 = ext[0];
    let e1 = ext[1];
    let e2 = ext[2];
    let scan_ok = storage_device::with_sd_card!(i2c, delay, |ct| {
        let fat32 = storage_device::mount_fat32(ct)?;
        storage_device::list_root_dir(ct, &fat32, |entry| {
            if entry.name[0] == p0 && entry.name[1] == p1
                && entry.name[8] == e0 && entry.name[9] == e1 && entry.name[10] == e2
            {
                let mut n: u32 = 0;
                let mut valid = true;
                for k in 2..8usize {
                    let c = entry.name[k];
                    if c >= b'0' && c <= b'9' {
                        n = n * 10 + (c - b'0') as u32;
                    } else if c == b' ' {
                        break;
                    } else {
                        valid = false;
                        break;
                    }
                }
                if valid && n > max_num { max_num = n; }
            }
            true
        })?;
        Ok(())
    });
    if scan_ok.is_err() { max_num = 0; }
    max_num + 1
}

/// Format an auto-increment number into an 8.3 name: prefix(2) + zero-padded digits(6) + ext(3).
pub(crate) fn format_auto_name(prefix: &[u8; 2], num: u32, ext: &[u8; 3]) -> [u8; 11] {
    let mut name = [b'0'; 11];
    name[0] = prefix[0];
    name[1] = prefix[1];
    let mut val = num;
    for k in (2..8usize).rev() {
        name[k] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    name[8] = ext[0];
    name[9] = ext[1];
    name[10] = ext[2];
    name
}
