// KasSigner — Air-gapped hardware wallet for Kaspa
// Copyright (C) 2025 KasSigner Project (kassigner@proton.me)
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

// hw/sd_backup.rs — AES-GCM encrypted seed backup to SD card
// 100% Rust, no-std, no-alloc
//
// Export: seed → serialize → AES-256-GCM encrypt → write to SD as .KAS file
// Import: read .KAS from SD → decrypt → deserialize → load into seed slot
//
// File format (v1):
//   [magic: 4B "KAS\x01"]
//   [word_count: 1B (12 or 24)]
//   [nonce: 12B]
//   [ciphertext: N bytes (word_count * 2 = 24 or 48 bytes)]
//   [tag: 16B]
//
// Total: 4 + 1 + 12 + 48 + 16 = 81 bytes (24 words)
//        4 + 1 + 12 + 24 + 16 = 57 bytes (12 words)
//
// Encryption:
//   passphrase → PBKDF2-SHA256(100k iter, salt="KasSigner-SD-v1") → AES-256 key
//   AES-256-GCM(key, nonce, aad=magic+word_count) → ciphertext + tag
//
// The passphrase is entered by the user on the device before export/import.
// Different salt from NVS storage ensures SD backup key ≠ flash storage key.


#![allow(dead_code)]
use aes_gcm::{
    Aes256Gcm,
    aead::{AeadInPlace, KeyInit, generic_array::GenericArray},
};
use crate::wallet::hmac::zeroize_buf;

// ─── Constants ───────────────────────────────────────────────────────

/// Magic bytes identifying a KasSigner seed backup file
const MAGIC: [u8; 4] = [b'K', b'A', b'S', 0x01];

/// PBKDF2 salt for SD backup key derivation (different from NVS salt)
const SD_SALT: &[u8] = b"KasSigner-SD-v1";

/// PBKDF2 iterations for SD backup key derivation.
/// 10k is sufficient for an air-gapped backup file requiring physical SD access.
/// Strong passphrase (8+ chars) is enforced at the UI level.
const PBKDF2_ITERATIONS: u32 = 10_000;

/// AES-GCM nonce size (96 bits)
const NONCE_SIZE: usize = 12;

/// AES-GCM tag size (128 bits)
const TAG_SIZE: usize = 16;

/// Header size: magic(4) + word_count(1)
const HEADER_SIZE: usize = 5;

/// Maximum backup file size (24 words: 5 + 12 + 48 + 16 = 81)
pub const MAX_BACKUP_SIZE: usize = HEADER_SIZE + NONCE_SIZE + 48 + TAG_SIZE;

/// File identifier: first 2 bytes of file content (magic) used to recognize our files
/// No file extension — files appear as "SDXXXX" on the SD card for OpSec.
pub const FILE_MAGIC: [u8; 4] = [b'K', b'A', b'S', 0x01];

/// Generate backup filename from seed fingerprint.
/// Format: "SDXXXX" where XXXX = first 4 hex chars of fingerprint.
/// Returns 8.3 name (11 bytes, extension all spaces = no extension).
pub fn backup_filename(fingerprint: &[u8; 4]) -> [u8; 11] {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut name = [b' '; 11];
    name[0] = b'S';
    name[1] = b'D';
    name[2] = HEX[(fingerprint[0] >> 4) as usize];
    name[3] = HEX[(fingerprint[0] & 0x0F) as usize];
    name[4] = HEX[(fingerprint[1] >> 4) as usize];
    name[5] = HEX[(fingerprint[1] & 0x0F) as usize];
    // Extension stays all spaces = no extension
    name
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

// ─── Errors ──────────────────────────────────────────────────────────

#[derive(Debug)]
/// Errors during SD card backup/restore operations.
pub enum BackupError {
    InvalidMagic,
    InvalidWordCount,
    FileTooSmall,
    EncryptionFailed,
    DecryptionFailed,
    BufferTooSmall,
}

// ─── PBKDF2 — delegate to wallet::storage ───────────────────────────

fn pbkdf2_derive_key(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    crate::wallet::storage::pbkdf2_sha256(password, salt, iterations)
}

/// PBKDF2 key derivation with progress callback
pub fn pbkdf2_derive_key_progress(password: &[u8], salt: &[u8], iterations: u32, progress: &mut dyn FnMut(u32, u32)) -> [u8; 32] {
    crate::wallet::storage::pbkdf2_sha256_progress(password, salt, iterations, progress)
}

// ─── Serialize / Deserialize ─────────────────────────────────────────

/// Serialize seed indices into bytes: [idx0_lo, idx0_hi, idx1_lo, idx1_hi, ...]
fn serialize_indices(indices: &[u16; 24], word_count: u8, out: &mut [u8]) -> usize {
    let wc = word_count as usize;
    for i in 0..wc {
        let le = indices[i].to_le_bytes();
        out[i * 2] = le[0];
        out[i * 2 + 1] = le[1];
    }
    wc * 2
}

/// Deserialize indices from bytes
fn deserialize_indices(data: &[u8], word_count: u8, out: &mut [u16; 24]) {
    let wc = word_count as usize;
    for i in 0..wc {
        out[i] = u16::from_le_bytes([data[i * 2], data[i * 2 + 1]]);
    }
}

// ─── Export (encrypt seed → file bytes) ──────────────────────────────
/// Encrypt seed backup with progress callback for PBKDF2.
pub fn encrypt_backup_progress(
    indices: &[u16; 24],
    word_count: u8,
    passphrase: &[u8],
    nonce_bytes: &[u8; NONCE_SIZE],
    out: &mut [u8; MAX_BACKUP_SIZE],
    progress: &mut dyn FnMut(u32, u32),
) -> Result<usize, BackupError> {
    if word_count != 12 && word_count != 24 {
        return Err(BackupError::InvalidWordCount);
    }

    let plaintext_len = word_count as usize * 2;
    let total_size = HEADER_SIZE + NONCE_SIZE + plaintext_len + TAG_SIZE;

    out[0..4].copy_from_slice(&MAGIC);
    out[4] = word_count;
    out[HEADER_SIZE..HEADER_SIZE + NONCE_SIZE].copy_from_slice(nonce_bytes);

    let ct_start = HEADER_SIZE + NONCE_SIZE;
    serialize_indices(indices, word_count, &mut out[ct_start..ct_start + plaintext_len]);

    let mut aes_key = pbkdf2_derive_key_progress(passphrase, SD_SALT, PBKDF2_ITERATIONS, progress);
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&aes_key));
    let nonce = GenericArray::from_slice(nonce_bytes);
    let aad = [MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3], word_count];

    let tag = cipher
        .encrypt_in_place_detached(nonce, &aad, &mut out[ct_start..ct_start + plaintext_len])
        .map_err(|_| BackupError::EncryptionFailed)?;

    zeroize_buf(&mut aes_key);

    let tag_start = ct_start + plaintext_len;
    out[tag_start..tag_start + TAG_SIZE].copy_from_slice(&tag);

    Ok(total_size)
}

// ─── Import (file bytes → decrypt seed) ──────────────────────────────

/// Decrypt a backup file and recover the seed.
/// Returns word_count on success.
pub fn decrypt_backup(
    file_data: &[u8],
    passphrase: &[u8],
    out_indices: &mut [u16; 24],
) -> Result<u8, BackupError> {
    decrypt_backup_progress(file_data, passphrase, out_indices, &mut |_, _| {})
}

/// Decrypt seed backup with progress callback for PBKDF2.
pub fn decrypt_backup_progress(
    file_data: &[u8],
    passphrase: &[u8],
    out_indices: &mut [u16; 24],
    progress: &mut dyn FnMut(u32, u32),
) -> Result<u8, BackupError> {
    // Minimum size: header(5) + nonce(12) + min_ct(24) + tag(16) = 57
    if file_data.len() < HEADER_SIZE + NONCE_SIZE + 24 + TAG_SIZE {
        return Err(BackupError::FileTooSmall);
    }

    // Verify magic
    if file_data[0..4] != MAGIC {
        return Err(BackupError::InvalidMagic);
    }

    let word_count = file_data[4];
    if word_count != 12 && word_count != 24 {
        return Err(BackupError::InvalidWordCount);
    }

    let plaintext_len = word_count as usize * 2;
    let expected_size = HEADER_SIZE + NONCE_SIZE + plaintext_len + TAG_SIZE;
    if file_data.len() < expected_size {
        return Err(BackupError::FileTooSmall);
    }

    // Extract parts
    let nonce_bytes = &file_data[HEADER_SIZE..HEADER_SIZE + NONCE_SIZE];
    let ct_start = HEADER_SIZE + NONCE_SIZE;
    let ciphertext = &file_data[ct_start..ct_start + plaintext_len];
    let tag_bytes = &file_data[ct_start + plaintext_len..ct_start + plaintext_len + TAG_SIZE];

    // Derive key
    let mut aes_key = pbkdf2_derive_key_progress(passphrase, SD_SALT, PBKDF2_ITERATIONS, progress);
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&aes_key));
    let nonce = GenericArray::from_slice(nonce_bytes);
    let tag = GenericArray::from_slice(tag_bytes);
    let aad = [MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3], word_count];

    // Decrypt into temp buffer
    let mut plaintext = [0u8; 48];
    plaintext[..plaintext_len].copy_from_slice(ciphertext);

    let result = cipher.decrypt_in_place_detached(
        nonce, &aad, &mut plaintext[..plaintext_len], tag,
    );

    zeroize_buf(&mut aes_key);

    match result {
        Ok(()) => {
            deserialize_indices(&plaintext[..plaintext_len], word_count, out_indices);
            zeroize_buf(&mut plaintext);
            Ok(word_count)
        }
        Err(_) => {
            zeroize_buf(&mut plaintext);
            Err(BackupError::DecryptionFailed)
        }
    }
}

// ─── XPrv Encrypted Backup ──────────────────────────────────────────
//
// File format (v2 — xprv):
//   [magic: 4B "KAS\x02"]
//   [data_len: 1B]
//   [nonce: 12B]
//   [ciphertext: data_len bytes (encrypted xprv base58 string)]
//   [tag: 16B]
//
// Filename: XP + 4 hex fingerprint chars, no extension.

/// Magic bytes for xprv backup (version 2)
const XPRV_MAGIC: [u8; 4] = [b'K', b'A', b'S', 0x02];

/// Max xprv string length (base58check of 78 bytes ≈ 111 chars)
const MAX_XPRV_DATA: usize = 120;

/// Max encrypted xprv file size: 4 + 1 + 12 + 120 + 16 = 153
pub const MAX_XPRV_BACKUP_SIZE: usize = 4 + 1 + NONCE_SIZE + MAX_XPRV_DATA + TAG_SIZE;

/// Generate xprv backup filename from seed fingerprint.
/// Format: "XPxxxx" (no extension).
pub fn xprv_backup_filename(fingerprint: &[u8; 4]) -> [u8; 11] {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut name = [b' '; 11];
    name[0] = b'X';
    name[1] = b'P';
    name[2] = HEX[(fingerprint[0] >> 4) as usize];
    name[3] = HEX[(fingerprint[0] & 0x0F) as usize];
    name[4] = HEX[(fingerprint[1] >> 4) as usize];
    name[5] = HEX[(fingerprint[1] & 0x0F) as usize];
    name
}
/// Encrypt an xprv string for SD card storage.
pub fn encrypt_xprv_backup(
    xprv_str: &[u8],
    xprv_len: usize,
    passphrase: &[u8],
    nonce_bytes: &[u8; NONCE_SIZE],
    out: &mut [u8; MAX_XPRV_BACKUP_SIZE],
) -> Result<usize, BackupError> {
    if xprv_len > MAX_XPRV_DATA || xprv_len == 0 {
        return Err(BackupError::BufferTooSmall);
    }

    let total_size = 4 + 1 + NONCE_SIZE + xprv_len + TAG_SIZE;

    // Header
    out[0..4].copy_from_slice(&XPRV_MAGIC);
    out[4] = xprv_len as u8;

    // Nonce
    out[5..5 + NONCE_SIZE].copy_from_slice(nonce_bytes);

    // Copy plaintext into ciphertext area
    let ct_start = 5 + NONCE_SIZE;
    out[ct_start..ct_start + xprv_len].copy_from_slice(&xprv_str[..xprv_len]);

    // Derive key
    let mut aes_key = pbkdf2_derive_key(passphrase, SD_SALT, PBKDF2_ITERATIONS);
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&aes_key));
    let nonce = GenericArray::from_slice(nonce_bytes);
    let aad = [XPRV_MAGIC[0], XPRV_MAGIC[1], XPRV_MAGIC[2], XPRV_MAGIC[3], xprv_len as u8];

    let tag = cipher
        .encrypt_in_place_detached(nonce, &aad, &mut out[ct_start..ct_start + xprv_len])
        .map_err(|_| BackupError::EncryptionFailed)?;

    zeroize_buf(&mut aes_key);

    let tag_start = ct_start + xprv_len;
    out[tag_start..tag_start + TAG_SIZE].copy_from_slice(&tag);

    Ok(total_size)
}

/// Decrypt an xprv backup file. Returns number of xprv bytes.
pub fn decrypt_xprv_backup(
    file_data: &[u8],
    passphrase: &[u8],
    out_xprv: &mut [u8; MAX_XPRV_DATA],
) -> Result<usize, BackupError> {
    if file_data.len() < 4 + 1 + NONCE_SIZE + 1 + TAG_SIZE {
        return Err(BackupError::FileTooSmall);
    }

    if file_data[0..4] != XPRV_MAGIC {
        return Err(BackupError::InvalidMagic);
    }

    let data_len = file_data[4] as usize;
    if data_len == 0 || data_len > MAX_XPRV_DATA {
        return Err(BackupError::InvalidWordCount);
    }

    let expected_size = 4 + 1 + NONCE_SIZE + data_len + TAG_SIZE;
    if file_data.len() < expected_size {
        return Err(BackupError::FileTooSmall);
    }

    let nonce_bytes = &file_data[5..5 + NONCE_SIZE];
    let ct_start = 5 + NONCE_SIZE;
    let ciphertext = &file_data[ct_start..ct_start + data_len];
    let tag_bytes = &file_data[ct_start + data_len..ct_start + data_len + TAG_SIZE];

    let mut aes_key = pbkdf2_derive_key(passphrase, SD_SALT, PBKDF2_ITERATIONS);
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&aes_key));
    let nonce = GenericArray::from_slice(nonce_bytes);
    let tag = GenericArray::from_slice(tag_bytes);
    let aad = [XPRV_MAGIC[0], XPRV_MAGIC[1], XPRV_MAGIC[2], XPRV_MAGIC[3], data_len as u8];

    out_xprv[..data_len].copy_from_slice(ciphertext);

    let result = cipher.decrypt_in_place_detached(
        nonce, &aad, &mut out_xprv[..data_len], tag,
    );

    zeroize_buf(&mut aes_key);

    match result {
        Ok(()) => Ok(data_len),
        Err(_) => {
            zeroize_buf(&mut out_xprv[..data_len]);
            Err(BackupError::DecryptionFailed)
        }
    }
}

// ─── Generic raw-bytes encrypt / decrypt (for passphrase stego) ─────

/// Magic for raw encrypted blobs (distinguishes from seed backups)
const RAW_MAGIC: [u8; 4] = [b'K', b'A', b'S', 0x02];

/// Max raw payload: 64 bytes passphrase text
pub const MAX_RAW_PAYLOAD: usize = 64;

/// Max raw encrypted size: magic(4) + len(1) + nonce(12) + data(64) + tag(16) = 97
pub const MAX_RAW_ENCRYPTED: usize = 4 + 1 + NONCE_SIZE + MAX_RAW_PAYLOAD + TAG_SIZE;
/// Encrypt arbitrary bytes with progress callback for PBKDF2.
pub fn encrypt_raw_progress(
    data: &[u8],
    data_len: usize,
    password: &[u8],
    nonce_bytes: &[u8; NONCE_SIZE],
    out: &mut [u8; MAX_RAW_ENCRYPTED],
    progress: &mut dyn FnMut(u32, u32),
) -> Result<usize, BackupError> {
    if data_len == 0 || data_len > MAX_RAW_PAYLOAD {
        return Err(BackupError::InvalidWordCount);
    }
    let total = 4 + 1 + NONCE_SIZE + data_len + TAG_SIZE;

    out[0..4].copy_from_slice(&RAW_MAGIC);
    out[4] = data_len as u8;
    out[5..5 + NONCE_SIZE].copy_from_slice(nonce_bytes);

    let ct_start = 5 + NONCE_SIZE;
    out[ct_start..ct_start + data_len].copy_from_slice(&data[..data_len]);

    let mut aes_key = pbkdf2_derive_key_progress(password, SD_SALT, PBKDF2_ITERATIONS, progress);
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&aes_key));
    let nonce = GenericArray::from_slice(nonce_bytes);
    let aad = [RAW_MAGIC[0], RAW_MAGIC[1], RAW_MAGIC[2], RAW_MAGIC[3], data_len as u8];

    let tag = cipher
        .encrypt_in_place_detached(nonce, &aad, &mut out[ct_start..ct_start + data_len])
        .map_err(|_| BackupError::EncryptionFailed)?;

    zeroize_buf(&mut aes_key);

    let tag_start = ct_start + data_len;
    out[tag_start..tag_start + TAG_SIZE].copy_from_slice(&tag);

    Ok(total)
}
/// Decrypt raw bytes with progress callback for PBKDF2.
pub fn decrypt_raw_progress(
    blob: &[u8],
    password: &[u8],
    out: &mut [u8; MAX_RAW_PAYLOAD],
    progress: &mut dyn FnMut(u32, u32),
) -> Result<usize, BackupError> {
    if blob.len() < 4 + 1 + NONCE_SIZE + 1 + TAG_SIZE {
        return Err(BackupError::FileTooSmall);
    }
    if blob[0..4] != RAW_MAGIC {
        return Err(BackupError::InvalidMagic);
    }
    let data_len = blob[4] as usize;
    if data_len == 0 || data_len > MAX_RAW_PAYLOAD {
        return Err(BackupError::InvalidWordCount);
    }
    let expected = 4 + 1 + NONCE_SIZE + data_len + TAG_SIZE;
    if blob.len() < expected {
        return Err(BackupError::FileTooSmall);
    }

    let nonce_bytes = &blob[5..5 + NONCE_SIZE];
    let ct_start = 5 + NONCE_SIZE;
    let ciphertext = &blob[ct_start..ct_start + data_len];
    let tag_bytes = &blob[ct_start + data_len..ct_start + data_len + TAG_SIZE];

    let mut aes_key = pbkdf2_derive_key_progress(password, SD_SALT, PBKDF2_ITERATIONS, progress);
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&aes_key));
    let nonce = GenericArray::from_slice(nonce_bytes);
    let tag = GenericArray::from_slice(tag_bytes);
    let aad = [RAW_MAGIC[0], RAW_MAGIC[1], RAW_MAGIC[2], RAW_MAGIC[3], data_len as u8];

    out[..data_len].copy_from_slice(ciphertext);
    let result = cipher.decrypt_in_place_detached(
        nonce, &aad, &mut out[..data_len], tag,
    );

    zeroize_buf(&mut aes_key);

    match result {
        Ok(()) => Ok(data_len),
        Err(_) => {
            zeroize_buf(&mut out[..data_len]);
            Err(BackupError::DecryptionFailed)
        }
    }
}
