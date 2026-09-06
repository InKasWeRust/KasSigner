//! Current device-bound encrypted BIP39 mnemonic backup.

use shared_signer::bytes::zeroize_bytes;

use super::{BackupDevice, BackupError, container::{self, BackupKind, CURRENT_HEADER_SIZE}};

const MAX_SEED_PAYLOAD: usize = 1 + 24 * 2;
pub const MAX_BACKUP_SIZE: usize = CURRENT_HEADER_SIZE + MAX_SEED_PAYLOAD
    + offline_signer::crypto::device_bound_storage::TAG_SIZE;

pub fn encrypt_backup_progress(
    indices: &[u16; 24],
    word_count: u8,
    password: &[u8],
    device: &mut dyn BackupDevice,
    out: &mut [u8; MAX_BACKUP_SIZE],
) -> Result<usize, BackupError> {
    out.fill(0);
    if !crate::wallet::mnemonic::validate(indices, word_count) {
        return Err(BackupError::InvalidMnemonic);
    }
    let words = match word_count { 12 => 12usize, 24 => 24usize, _ => return Err(BackupError::InvalidMnemonic) };
    let mut plaintext = [0u8; MAX_SEED_PAYLOAD];
    plaintext[0] = word_count;
    for (index, word) in indices[..words].iter().enumerate() {
        plaintext[1 + index * 2..3 + index * 2].copy_from_slice(&word.to_le_bytes());
    }
    let length = container::seal(BackupKind::Seed, &plaintext[..1 + words * 2], password, device, out);
    zeroize_bytes(&mut plaintext);
    length
}

pub fn decrypt_backup_progress(
    input: &[u8],
    password: &[u8],
    device: &mut dyn BackupDevice,
    out_indices: &mut [u16; 24],
) -> Result<u8, BackupError> {
    out_indices.fill(0);
    let mut plaintext = [0u8; container::MAX_PLAINTEXT];
    let result = (|| {
        let length = container::open(BackupKind::Seed, input, password, device, &mut plaintext)?;
        let word_count = plaintext[0];
        let words = match word_count { 12 => 12usize, 24 => 24usize, _ => return Err(BackupError::InvalidMnemonic) };
        if length != 1 + words * 2 { return Err(BackupError::InvalidLength); }
        for index in 0..words {
            let offset = 1 + index * 2;
            let word = u16::from_le_bytes([plaintext[offset], plaintext[offset + 1]]);
            if word >= 2048 { return Err(BackupError::InvalidMnemonic); }
            out_indices[index] = word;
        }
        if !crate::wallet::mnemonic::validate(out_indices, word_count) {
            return Err(BackupError::InvalidMnemonic);
        }
        Ok(word_count)
    })();
    zeroize_bytes(&mut plaintext);
    if result.is_err() { out_indices.fill(0); }
    result
}
