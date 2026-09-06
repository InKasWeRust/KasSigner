//! Current device-bound encrypted account-XPrv backup.

use shared_signer::bytes::zeroize_bytes;
use super::{BackupDevice, BackupError, container::{self, BackupKind, CURRENT_HEADER_SIZE}};

pub const MAX_XPRV_DATA: usize = 120;
pub const MAX_XPRV_BACKUP_SIZE: usize = CURRENT_HEADER_SIZE + MAX_XPRV_DATA
    + offline_signer::crypto::device_bound_storage::TAG_SIZE;

pub fn encrypt_xprv_backup(
    xprv: &[u8],
    password: &[u8],
    device: &mut dyn BackupDevice,
    out: &mut [u8; MAX_XPRV_BACKUP_SIZE],
) -> Result<usize, BackupError> {
    out.fill(0);
    if xprv.is_empty() || xprv.len() > MAX_XPRV_DATA {
        return Err(BackupError::InvalidLength);
    }
    // Validate before persisting secret material so corrupt/untyped strings do
    // not become authenticated wallet backups.
    offline_signer::derivation::xpub::import_xprv_with_metadata(xprv)
        .map_err(|_| BackupError::InvalidFormat)?;
    container::seal(BackupKind::Xprv, xprv, password, device, out)
}

pub fn decrypt_xprv_backup_progress(
    input: &[u8],
    password: &[u8],
    device: &mut dyn BackupDevice,
    out: &mut [u8; MAX_XPRV_DATA],
) -> Result<usize, BackupError> {
    out.fill(0);
    let mut plaintext = [0u8; container::MAX_PLAINTEXT];
    let result = (|| {
        let length = container::open(BackupKind::Xprv, input, password, device, &mut plaintext)?;
        if length > out.len() { return Err(BackupError::BufferTooSmall); }
        offline_signer::derivation::xpub::import_xprv_with_metadata(&plaintext[..length])
            .map_err(|_| BackupError::InvalidFormat)?;
        out[..length].copy_from_slice(&plaintext[..length]);
        Ok(length)
    })();
    zeroize_bytes(&mut plaintext);
    if result.is_err() { out.fill(0); }
    result
}
