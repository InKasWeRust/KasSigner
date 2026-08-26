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
/// Legacy PBKDF2 salt. Fixed for every device and every file, which is why it
/// is legacy-read only: one precomputed table over a password dictionary broke
/// every artifact any KasSigner ever produced, and the 100k cost was paid once
/// by the attacker for the whole population rather than once per target (M-01).
/// v3 containers carry 16 random bytes per file instead.
const SD_SALT: &[u8] = b"KasSigner-SD-v1";

// ─── Container format v3 ─────────────────────────────────────────────
//
// One container for every encrypted artifact this device writes. Replaces
// four near-identical formats that shared a salt and, in two cases, a magic.
//
//   off  size  field
//   0    4     magic   "KAS\x04"
//   4    1     version 3
//   5    1     purpose 1 seed, 2 xprv, 3 raw, 4 kspt
//   6    1     kdf_id  1 = PBKDF2-HMAC-SHA256, 100_000 iterations
//   7    1     len     plaintext length, 1..=MAX_V3_PAYLOAD
//   8    16    salt    per-file, from the TRNG
//   24   12    nonce   per-file, from the TRNG
//   36   len   ciphertext
//   +len 16    GCM tag
//
// AAD is bytes 0..24, the whole header through the salt. It is one contiguous
// slice by construction, so no caller can assemble it in the wrong order. The
// nonce is the GCM IV and is authenticated by the construction itself.
//
// The key is PBKDF2(password, salt ‖ purpose), so a container of one purpose
// cannot even produce the key of another. Rewriting the purpose byte changes
// both the AAD and the derived key, and fails twice over. That closes M-03,
// where XPRV_MAGIC and RAW_MAGIC were both KAS\x02 with the same salt and the
// same AAD shape, so a short xprv file authenticated cleanly in the hint path
// and handed extended private key bytes to code that prints text on screen.
//
// kdf_id is authenticated and explicit, so there is no trial ladder: a wrong
// password costs one derivation, not two, and a legacy file is identifiable
// rather than inferred (M-04). It is also the migration path for M-02: moving
// to a memory-hard KDF is a new kdf_id, not a second format bump.
//
// Magic bytes 0x01 (seed), 0x02 (xprv and raw) and 0x03 (KSPT) are taken by
// the legacy formats, which stay readable forever. 0x04 is the v3 container.

/// v3 container magic.
pub const V3_MAGIC: [u8; 4] = [b'K', b'A', b'S', 0x04];

/// v3 format version byte.
pub const V3_VERSION: u8 = 3;

/// Purpose byte: what a container holds. Authenticated, and mixed into the
/// key derivation.
pub const PURPOSE_SEED: u8 = 1;
pub const PURPOSE_XPRV: u8 = 2;
pub const PURPOSE_RAW: u8 = 3;
pub const PURPOSE_KSPT: u8 = 4;

/// KDF identifier: PBKDF2-HMAC-SHA256 at `PBKDF2_ITERATIONS`.
pub const KDF_PBKDF2_SHA256_100K: u8 = 1;

/// Per-file salt length.
pub const V3_SALT_SIZE: usize = 16;

/// Offset of the nonce, and therefore the length of the AAD.
pub const V3_HEADER_SIZE: usize = 8 + V3_SALT_SIZE;

/// Bytes a v3 container adds to its plaintext.
pub const V3_OVERHEAD: usize = V3_HEADER_SIZE + NONCE_SIZE + TAG_SIZE;

/// Largest plaintext a v3 container carries. Bounded by the xprv string, the
/// longest of the four payloads, and by `len` being a single byte.
pub const MAX_V3_PAYLOAD: usize = 120;

/// Largest v3 container.
pub const MAX_V3_CONTAINER: usize = V3_OVERHEAD + MAX_V3_PAYLOAD;


/// PBKDF2 iterations for SD backup key derivation.
/// 100k iterations: ~3-4s on ESP32-S3 at 240MHz (software SHA-256).
/// Progress callback keeps the UI responsive during derivation.
const PBKDF2_ITERATIONS: u32 = 100_000;

/// Legacy iteration count (v1.0.1). Used as fallback when 100K decrypt fails.
const PBKDF2_ITERATIONS_LEGACY: u32 = 10_000;

/// AES-GCM nonce size (96 bits)
const NONCE_SIZE: usize = 12;

/// AES-GCM tag size (128 bits)
const TAG_SIZE: usize = 16;

/// Header size: magic(4) + word_count(1)
const HEADER_SIZE: usize = 5;

/// Maximum seed backup size. v3 container around a 48-byte payload:
/// 24 + 12 + 48 + 16 = 100. Legacy v1 files are smaller (81) and read fine
/// into the same buffer.
pub const MAX_BACKUP_SIZE: usize = V3_OVERHEAD + 48;

/// File identifier: first 2 bytes of file content (magic) used to recognize our files
/// No file extension — files appear as "SDXXXX" on the SD card for OpSec.
/// Legacy seed-backup magic. Kept so old files stay recognisable; new files
/// are written as v3 containers (`V3_MAGIC`). Any code that classifies files
/// on the card must check `V3_MAGIC` too, or it silently hides everything the
/// current firmware writes.
pub const FILE_MAGIC: [u8; 4] = [b'K', b'A', b'S', 0x01];

/// Format an 8.3 name for display. Lives in kassigner-core::fat32 since
/// 1.0.7 (the LFN directory listing there uses it); re-exported so the
/// nine `sd_backup::format_83_display` callers are unchanged.
pub use kassigner_core::fat32::format_83_display;

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
    /// Container is v3 but names a KDF this firmware does not implement.
    /// Written by a newer firmware; the user needs to update, not retype.
    UnsupportedKdf,
    /// Container is well-formed but holds a different kind of secret than the
    /// caller asked for. Never a password problem.
    WrongPurpose,
    /// The salt or nonce came back all zeros, which is what
    /// `crypto::entropy::fill` leaves behind when the hardware RNG fails its
    /// continuous health tests. Refusing to encrypt is the whole point: a
    /// reused AES-GCM nonce is a total break, and a constant PBKDF2 salt is
    /// M-01 all over again.
    EntropyUnavailable,
}

// ─── PBKDF2 — delegate to wallet::storage ───────────────────────────

fn pbkdf2_derive_key(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    crate::wallet::storage::pbkdf2_sha256(password, salt, iterations)
}

/// PBKDF2 key derivation with progress callback.
///
/// The single funnel every SD encrypt and decrypt goes through: seed
/// backup, xprv backup, KSPT and raw all land here.
///
/// Measured cost, for anyone tempted to change the iteration count or
/// reach for the hardware SHA accelerator: 100k iterations run in ~9.2s
/// on the ESP32-S3 at 240MHz, ~22,100 cycles per iteration, which is
/// essentially all SHA-256. The esp-hal SHA peripheral was benchmarked
/// against this shape at 3.99x (see `app/sha_bench.rs`, feature-gated),
/// judged not worth a second implementation of key derivation.
pub fn pbkdf2_derive_key_progress(password: &[u8], salt: &[u8], iterations: u32, progress: &mut dyn FnMut(u32, u32)) -> [u8; 32] {
    crate::wallet::storage::pbkdf2_sha256_progress(password, salt, iterations, progress)
}

/// PBKDF2 key derivation for KSPT encryption (domain-separated salt)
const KSPT_SALT: &[u8] = b"KasSigner-KSPT-v1";

/// Derive AES-256 key for KSPT file encryption with progress callback
pub fn pbkdf2_key_for_kspt(password: &[u8], progress: &mut dyn FnMut(u32, u32)) -> [u8; 32] {
    pbkdf2_derive_key_progress(password, KSPT_SALT, PBKDF2_ITERATIONS, progress)
}

// ─── v3 container ────────────────────────────────────────────────────

/// Derive the container key: PBKDF2(password, per-file salt ‖ purpose).
///
/// The purpose byte is in the salt, not just the AAD, so a container of one
/// kind cannot even produce the key of another. An attacker who rewrites the
/// purpose byte to steer an xprv file into the hint-display path changes both
/// the derived key and the AAD, and the tag check fails on both counts.
fn v3_derive_key(
    password: &[u8],
    salt: &[u8; V3_SALT_SIZE],
    purpose: u8,
    kdf_id: u8,
    progress: &mut dyn FnMut(u32, u32),
) -> Result<[u8; 32], BackupError> {
    if kdf_id != KDF_PBKDF2_SHA256_100K {
        return Err(BackupError::UnsupportedKdf);
    }
    let mut kdf_salt = [0u8; V3_SALT_SIZE + 1];
    kdf_salt[..V3_SALT_SIZE].copy_from_slice(salt);
    kdf_salt[V3_SALT_SIZE] = purpose;
    Ok(pbkdf2_derive_key_progress(password, &kdf_salt, PBKDF2_ITERATIONS, progress))
}

/// Encrypt any secret into a v3 container. The one write path.
///
/// `salt` and `nonce` must both come from the TRNG and must never be reused
/// together with the same password. Callers pass them in rather than having
/// this function reach for entropy, so that entropy policy stays in one place
/// and this stays testable with fixed vectors.
///
/// Returns the container length written to `out`.
pub fn encrypt_v3(
    purpose: u8,
    plaintext: &[u8],
    password: &[u8],
    salt: &[u8; V3_SALT_SIZE],
    nonce_bytes: &[u8; NONCE_SIZE],
    out: &mut [u8],
    progress: &mut dyn FnMut(u32, u32),
) -> Result<usize, BackupError> {
    // Fail closed on dead randomness, checked HERE rather than at each of the
    // eleven call sites that generate a salt and nonce.
    //
    // `crypto::entropy::fill` zeroes its output and returns an error when the
    // hardware RNG fails its continuous health tests. Every caller of
    // `generate_trng_salt` / `generate_trng_nonce` therefore receives all
    // zeros, and this is the one place all of them converge, so one check
    // covers all of them and cannot be forgotten by a twelfth caller.
    //
    // An all-zero salt or nonce is never legitimate: both come from the TRNG on
    // every path. A reused GCM nonce is a total break of confidentiality and
    // authenticity, and a constant PBKDF2 salt reintroduces M-01.
    if salt.iter().all(|&b| b == 0) || nonce_bytes.iter().all(|&b| b == 0) {
        return Err(BackupError::EntropyUnavailable);
    }

    let len = plaintext.len();
    if len == 0 || len > MAX_V3_PAYLOAD {
        return Err(BackupError::InvalidWordCount);
    }
    let total = V3_OVERHEAD + len;
    if out.len() < total {
        return Err(BackupError::BufferTooSmall);
    }

    out[0..4].copy_from_slice(&V3_MAGIC);
    out[4] = V3_VERSION;
    out[5] = purpose;
    out[6] = KDF_PBKDF2_SHA256_100K;
    out[7] = len as u8;
    out[8..V3_HEADER_SIZE].copy_from_slice(salt);
    out[V3_HEADER_SIZE..V3_HEADER_SIZE + NONCE_SIZE].copy_from_slice(nonce_bytes);

    let ct_start = V3_HEADER_SIZE + NONCE_SIZE;
    out[ct_start..ct_start + len].copy_from_slice(plaintext);

    // AAD is the header through the salt, taken as one slice so it cannot be
    // assembled in the wrong order at some future call site.
    let mut aad = [0u8; V3_HEADER_SIZE];
    aad.copy_from_slice(&out[..V3_HEADER_SIZE]);

    let mut aes_key = v3_derive_key(password, salt, purpose, KDF_PBKDF2_SHA256_100K, progress)?;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&aes_key));
    let nonce = GenericArray::from_slice(nonce_bytes);

    let tag = cipher
        .encrypt_in_place_detached(nonce, &aad, &mut out[ct_start..ct_start + len])
        .map_err(|_| BackupError::EncryptionFailed);

    zeroize_buf(&mut aes_key);
    let tag = tag?;

    out[ct_start + len..ct_start + len + TAG_SIZE].copy_from_slice(&tag);
    Ok(total)
}

/// True if `data` looks like a v3 container. Used to route between the v3
/// reader and the legacy readers before any key derivation happens.
// `>= V3_OVERHEAD + 1` rather than clippy's `> V3_OVERHEAD`. Arithmetically
// identical, but the written form states the rule: the container's fixed
// overhead PLUS at least one byte of payload. A container with a zero-length
// payload is malformed, and that is what this line is checking for.
#[allow(clippy::int_plus_one)]
pub fn is_v3(data: &[u8]) -> bool {
    data.len() >= V3_OVERHEAD + 1 && data[0..4] == V3_MAGIC && data[4] == V3_VERSION
}

/// Read the purpose byte of a v3 container without decrypting it.
pub fn v3_purpose(data: &[u8]) -> Option<u8> {
    if is_v3(data) { Some(data[5]) } else { None }
}

/// Decrypt a v3 container. The one read path.
///
/// `expected_purpose` is checked before any work is done, and is mixed into
/// the key, so a container of the wrong kind is rejected as `WrongPurpose`
/// rather than being handed to a caller that would misinterpret it.
///
/// Returns the plaintext length written to `out`.
pub fn decrypt_v3(
    expected_purpose: u8,
    container: &[u8],
    password: &[u8],
    out: &mut [u8],
    progress: &mut dyn FnMut(u32, u32),
) -> Result<usize, BackupError> {
    if container.len() < V3_OVERHEAD + 1 {
        return Err(BackupError::FileTooSmall);
    }
    if container[0..4] != V3_MAGIC || container[4] != V3_VERSION {
        return Err(BackupError::InvalidMagic);
    }
    let purpose = container[5];
    if purpose != expected_purpose {
        return Err(BackupError::WrongPurpose);
    }
    let kdf_id = container[6];
    let len = container[7] as usize;
    if len == 0 || len > MAX_V3_PAYLOAD || len > out.len() {
        return Err(BackupError::InvalidWordCount);
    }
    if container.len() < V3_OVERHEAD + len {
        return Err(BackupError::FileTooSmall);
    }

    let mut salt = [0u8; V3_SALT_SIZE];
    salt.copy_from_slice(&container[8..V3_HEADER_SIZE]);
    let mut aad = [0u8; V3_HEADER_SIZE];
    aad.copy_from_slice(&container[..V3_HEADER_SIZE]);

    let nonce_bytes = &container[V3_HEADER_SIZE..V3_HEADER_SIZE + NONCE_SIZE];
    let ct_start = V3_HEADER_SIZE + NONCE_SIZE;
    let tag_bytes = &container[ct_start + len..ct_start + len + TAG_SIZE];

    // Reject an unknown KDF before spending nine seconds on a derivation that
    // could not have produced this file.
    let mut aes_key = v3_derive_key(password, &salt, purpose, kdf_id, progress)?;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&aes_key));

    out[..len].copy_from_slice(&container[ct_start..ct_start + len]);
    let result = cipher.decrypt_in_place_detached(
        GenericArray::from_slice(nonce_bytes),
        &aad,
        &mut out[..len],
        GenericArray::from_slice(tag_bytes),
    );

    zeroize_buf(&mut aes_key);

    match result {
        Ok(()) => Ok(len),
        Err(_) => {
            zeroize_buf(&mut out[..len]);
            Err(BackupError::DecryptionFailed)
        }
    }
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
/// Returns false, leaving `out` zeroed, if any index is outside the BIP39
/// wordlist.
///
/// The bytes reaching here have already passed AES-256-GCM authentication, so
/// they came from something holding the passphrase-derived key, and every
/// KasSigner writes indices below 2048. The check is for what happens if that
/// ever stops being true: an out-of-range index reaches `WORDLIST[idx]` on the
/// word-display path and again inside `seed_from_mnemonic_*`, and indexing a
/// 2048-entry table past its end is a panic, not a wrong word.
fn deserialize_indices(data: &[u8], word_count: u8, out: &mut [u16; 24]) -> bool {
    let wc = word_count as usize;
    for i in 0..wc {
        let idx = u16::from_le_bytes([data[i * 2], data[i * 2 + 1]]);
        if idx >= 2048 {
            for w in out.iter_mut() {
                unsafe { core::ptr::write_volatile(w, 0); }
            }
            return false;
        }
        out[i] = idx;
    }
    true
}

// ─── Export (encrypt seed → file bytes) ──────────────────────────────

/// Encrypt a seed backup. Writes a v3 container.
///
/// `salt` is new in v3 and must come from the TRNG, like the nonce. There is
/// no path that writes v1 any more; v1 and v2 are read-only formats now.
pub fn encrypt_backup_progress(
    indices: &[u16; 24],
    word_count: u8,
    passphrase: &[u8],
    salt: &[u8; V3_SALT_SIZE],
    nonce_bytes: &[u8; NONCE_SIZE],
    out: &mut [u8],
    progress: &mut dyn FnMut(u32, u32),
) -> Result<usize, BackupError> {
    if word_count != 12 && word_count != 24 {
        return Err(BackupError::InvalidWordCount);
    }
    let plaintext_len = word_count as usize * 2;
    let mut plaintext = [0u8; 48];
    serialize_indices(indices, word_count, &mut plaintext[..plaintext_len]);

    let r = encrypt_v3(
        PURPOSE_SEED,
        &plaintext[..plaintext_len],
        passphrase,
        salt,
        nonce_bytes,
        out,
        progress,
    );
    zeroize_buf(&mut plaintext);
    r
}

// ─── Import (file bytes → decrypt seed) ──────────────────────────────

/// Decrypt a seed backup, v3 or legacy v1.
///
/// Returns the word count. `Ok((wc, true))` means the file was v1 and the user
/// should be told to re-export it: v1 has the shared salt, so a dictionary
/// table built once attacks every v1 artifact in existence.
pub fn decrypt_backup_versioned(
    file_data: &[u8],
    passphrase: &[u8],
    out_indices: &mut [u16; 24],
    progress: &mut dyn FnMut(u32, u32),
) -> Result<(u8, bool), BackupError> {
    if is_v3(file_data) {
        let mut plaintext = [0u8; 48];
        let len = decrypt_v3(PURPOSE_SEED, file_data, passphrase, &mut plaintext, progress)?;
        if len != 24 && len != 48 {
            zeroize_buf(&mut plaintext);
            return Err(BackupError::InvalidWordCount);
        }
        let word_count = (len / 2) as u8;
        if !deserialize_indices(&plaintext[..len], word_count, out_indices) {
            zeroize_buf(&mut plaintext);
            return Err(BackupError::InvalidWordCount);
        }
        zeroize_buf(&mut plaintext);
        return Ok((word_count, false));
    }
    decrypt_backup_legacy_v1(file_data, passphrase, out_indices, progress).map(|wc| (wc, true))
}

/// Decrypt a seed backup. Kept for callers that do not surface the legacy
/// prompt.
pub fn decrypt_backup_progress(
    file_data: &[u8],
    passphrase: &[u8],
    out_indices: &mut [u16; 24],
    progress: &mut dyn FnMut(u32, u32),
) -> Result<u8, BackupError> {
    decrypt_backup_versioned(file_data, passphrase, out_indices, progress).map(|(wc, _)| wc)
}

/// Read a v1 seed backup: shared `SD_SALT`, magic KAS\x01, and the 100k-then-10k
/// trial ladder. Read-only, never written again. The ladder stays because v1
/// files carry no KDF identifier, which is M-04 and is exactly what v3 fixes.
fn decrypt_backup_legacy_v1(
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

    // Derive key (100K iterations — v1.0.2+)
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
            if !deserialize_indices(&plaintext[..plaintext_len], word_count, out_indices) {
                zeroize_buf(&mut plaintext);
                return Err(BackupError::InvalidWordCount);
            }
            zeroize_buf(&mut plaintext);
            Ok(word_count)
        }
        Err(_) => {
            // GCM auth failed — try legacy 10K iterations (v1.0.1 backup)
            zeroize_buf(&mut plaintext);
            let mut aes_key2 = pbkdf2_derive_key_progress(passphrase, SD_SALT, PBKDF2_ITERATIONS_LEGACY, progress);
            let cipher2 = Aes256Gcm::new(GenericArray::from_slice(&aes_key2));
            let mut pt2 = [0u8; 48];
            pt2[..plaintext_len].copy_from_slice(ciphertext);
            let result2 = cipher2.decrypt_in_place_detached(
                nonce, &aad, &mut pt2[..plaintext_len], tag,
            );
            zeroize_buf(&mut aes_key2);
            match result2 {
                Ok(()) => {
                    crate::log!("   SD backup: decrypted with legacy 10K iterations");
                    if !deserialize_indices(&pt2[..plaintext_len], word_count, out_indices) {
                        zeroize_buf(&mut pt2);
                        return Err(BackupError::InvalidWordCount);
                    }
                    zeroize_buf(&mut pt2);
                    Ok(word_count)
                }
                Err(_) => {
                    zeroize_buf(&mut pt2);
                    Err(BackupError::DecryptionFailed)
                }
            }
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

/// Max encrypted xprv file size. v3 container around a 120-byte payload:
/// 24 + 12 + 120 + 16 = 172. Legacy v2 files are smaller (153).
pub const MAX_XPRV_BACKUP_SIZE: usize = V3_OVERHEAD + MAX_XPRV_DATA;

/// Encrypt an xprv string into a v3 container.
pub fn encrypt_xprv_backup_v3(
    xprv_str: &[u8],
    xprv_len: usize,
    passphrase: &[u8],
    salt: &[u8; V3_SALT_SIZE],
    nonce_bytes: &[u8; NONCE_SIZE],
    out: &mut [u8],
    progress: &mut dyn FnMut(u32, u32),
) -> Result<usize, BackupError> {
    if xprv_len > MAX_XPRV_DATA || xprv_len == 0 {
        return Err(BackupError::BufferTooSmall);
    }
    encrypt_v3(
        PURPOSE_XPRV,
        &xprv_str[..xprv_len],
        passphrase,
        salt,
        nonce_bytes,
        out,
        progress,
    )
}

/// Decrypt an xprv backup, v3 or legacy v2.
///
/// `Ok((len, true))` means the file was legacy and should be re-exported.
pub fn decrypt_xprv_versioned(
    file_data: &[u8],
    passphrase: &[u8],
    out_xprv: &mut [u8; MAX_XPRV_DATA],
    progress: &mut dyn FnMut(u32, u32),
) -> Result<(usize, bool), BackupError> {
    if is_v3(file_data) {
        return decrypt_v3(PURPOSE_XPRV, file_data, passphrase, out_xprv, progress)
            .map(|n| (n, false));
    }
    decrypt_xprv_backup_progress(file_data, passphrase, out_xprv, progress).map(|n| (n, true))
}

/// Read a legacy v2 xprv backup: shared `SD_SALT`, magic KAS\x02 (which the raw
/// hint blob also used, M-03), and the trial ladder. Read-only.
pub fn decrypt_xprv_backup_progress(
    file_data: &[u8],
    passphrase: &[u8],
    out_xprv: &mut [u8; MAX_XPRV_DATA],
    progress: &mut dyn FnMut(u32, u32),
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

    let mut aes_key = pbkdf2_derive_key_progress(passphrase, SD_SALT, PBKDF2_ITERATIONS, progress);
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
            // Try legacy 10K iterations (v1.0.1 backup)
            zeroize_buf(&mut out_xprv[..data_len]);
            let mut aes_key2 = pbkdf2_derive_key_progress(passphrase, SD_SALT, PBKDF2_ITERATIONS_LEGACY, progress);
            let cipher2 = Aes256Gcm::new(GenericArray::from_slice(&aes_key2));
            out_xprv[..data_len].copy_from_slice(ciphertext);
            let result2 = cipher2.decrypt_in_place_detached(
                nonce, &aad, &mut out_xprv[..data_len], tag,
            );
            zeroize_buf(&mut aes_key2);
            match result2 {
                Ok(()) => {
                    crate::log!("   xprv backup: decrypted with legacy 10K iterations");
                    Ok(data_len)
                }
                Err(_) => {
                    zeroize_buf(&mut out_xprv[..data_len]);
                    Err(BackupError::DecryptionFailed)
                }
            }
        }
    }
}

// ─── Generic raw-bytes encrypt / decrypt (for passphrase stego) ─────

/// Magic for raw encrypted blobs (distinguishes from seed backups)
const RAW_MAGIC: [u8; 4] = [b'K', b'A', b'S', 0x02];

/// Max raw payload: 64 bytes passphrase text
pub const MAX_RAW_PAYLOAD: usize = 64;

/// Max raw encrypted size. v3 container around a 64-byte payload:
/// 24 + 12 + 64 + 16 = 116. Legacy blobs are smaller (97).
pub const MAX_RAW_ENCRYPTED: usize = V3_OVERHEAD + MAX_RAW_PAYLOAD;
/// Encrypt arbitrary bytes (the stego recovery hint) into a v3 container.
pub fn encrypt_raw_v3(
    data: &[u8],
    data_len: usize,
    password: &[u8],
    salt: &[u8; V3_SALT_SIZE],
    nonce_bytes: &[u8; NONCE_SIZE],
    out: &mut [u8],
    progress: &mut dyn FnMut(u32, u32),
) -> Result<usize, BackupError> {
    if data_len == 0 || data_len > MAX_RAW_PAYLOAD {
        return Err(BackupError::InvalidWordCount);
    }
    encrypt_v3(
        PURPOSE_RAW,
        &data[..data_len],
        password,
        salt,
        nonce_bytes,
        out,
        progress,
    )
}

/// Decrypt a raw blob, v3 or legacy.
///
/// The legacy branch is the M-03 hazard: a legacy raw blob and a legacy xprv
/// backup share magic KAS\x02, the salt and the AAD shape, so a short xprv file
/// authenticates here and hands extended private key bytes to a caller that
/// prints them as a hint. Unfixable for files that already exist. v3 containers
/// carry an authenticated purpose byte that is also mixed into the key, so the
/// confusion cannot happen again.
pub fn decrypt_raw_versioned(
    blob: &[u8],
    password: &[u8],
    out: &mut [u8; MAX_RAW_PAYLOAD],
    progress: &mut dyn FnMut(u32, u32),
) -> Result<(usize, bool), BackupError> {
    if is_v3(blob) {
        return decrypt_v3(PURPOSE_RAW, blob, password, out, progress).map(|n| (n, false));
    }
    decrypt_raw_progress(blob, password, out, progress).map(|n| (n, true))
}

/// Read a legacy raw blob. Read-only.
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
            // Try legacy 10K iterations (v1.0.1 stego)
            zeroize_buf(&mut out[..data_len]);
            let mut aes_key2 = pbkdf2_derive_key_progress(password, SD_SALT, PBKDF2_ITERATIONS_LEGACY, progress);
            let cipher2 = Aes256Gcm::new(GenericArray::from_slice(&aes_key2));
            out[..data_len].copy_from_slice(ciphertext);
            let result2 = cipher2.decrypt_in_place_detached(
                nonce, &aad, &mut out[..data_len], tag,
            );
            zeroize_buf(&mut aes_key2);
            match result2 {
                Ok(()) => {
                    crate::log!("   raw decrypt: legacy 10K iterations");
                    Ok(data_len)
                }
                Err(_) => {
                    zeroize_buf(&mut out[..data_len]);
                    Err(BackupError::DecryptionFailed)
                }
            }
        }
    }
}

// ─── Known-answer tests ──────────────────────────────────────────────

/// v3 container KAT, checked against an independent PBKDF2 and AES-GCM
/// implementation. Fixed password, salt and nonce, so the whole container is
/// byte-reproducible.
///
/// Every buffer here is on the PSRAM heap. These run inside the boot self-test,
/// which is already deep in the call stack, and stack-allocating a few hundred
/// bytes of container plus the copies the negative tests need was enough to
/// trip the stack guard on M5Stack. The negative tests mutate one buffer in
/// place and restore it rather than taking copies, for the same reason.
///
/// Costs one 100k PBKDF2 derivation, about nine seconds, so it lives behind
/// `verbose-boot` with the other slow KATs rather than running on every boot.
#[cfg(any(test, feature = "verbose-boot"))]
pub fn test_v3_container_kat() -> bool {
    const PASSWORD: &[u8] = b"correct horse";
    const SALT: [u8; V3_SALT_SIZE] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ];
    const NONCE: [u8; NONCE_SIZE] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b,
    ];
    // 12 words, "abandon" x11 + "about", little-endian u16 indices.
    const PLAINTEXT: [u8; 24] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0,
    ];
    const EXPECTED: [u8; 76] = [
        0x4b, 0x41, 0x53, 0x04, 0x03, 0x01, 0x01, 0x18,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x42, 0x22, 0x84, 0x40,
        0xfa, 0x2f, 0xfc, 0xd6, 0x01, 0x5a, 0xad, 0xc5,
        0xe2, 0x78, 0x12, 0xe2, 0x65, 0x04, 0x39, 0xdb,
        0x6b, 0xef, 0xe3, 0x62, 0xae, 0x11, 0x57, 0x5c,
        0x0c, 0x7f, 0x61, 0xf4, 0xf0, 0x96, 0xa5, 0x33,
        0x0a, 0xa5, 0x5c, 0x97,
    ];

    let mut noop = |_: u32, _: u32| {};
    let mut out = alloc::vec![0u8; V3_OVERHEAD + PLAINTEXT.len()];
    let mut back = alloc::vec![0u8; PLAINTEXT.len()];

    let n = match encrypt_v3(
        PURPOSE_SEED, &PLAINTEXT, PASSWORD, &SALT, &NONCE, &mut out, &mut noop,
    ) {
        Ok(n) => n,
        Err(_) => return false,
    };
    if n != EXPECTED.len() || out[..n] != EXPECTED {
        return false;
    }

    // Round trip.
    match decrypt_v3(PURPOSE_SEED, &out[..n], PASSWORD, &mut back, &mut noop) {
        Ok(len) => {
            if len != PLAINTEXT.len() || back[..len] != PLAINTEXT {
                return false;
            }
        }
        Err(_) => return false,
    }

    // Wrong password must fail the tag, not return garbage.
    if decrypt_v3(PURPOSE_SEED, &out[..n], b"wrong horse", &mut back, &mut noop).is_ok() {
        return false;
    }

    // Asking for the wrong purpose must be refused outright (M-03).
    if decrypt_v3(PURPOSE_RAW, &out[..n], PASSWORD, &mut back, &mut noop).is_ok() {
        return false;
    }

    // Rewriting the purpose byte must fail: it changes both the AAD and the
    // derived key, so an xprv container can never be opened as a hint blob.
    let saved = out[5];
    out[5] = PURPOSE_RAW;
    let forged_ok = decrypt_v3(PURPOSE_RAW, &out[..n], PASSWORD, &mut back, &mut noop).is_ok();
    out[5] = saved;
    if forged_ok {
        return false;
    }

    // Flipping a salt bit must fail: the salt is authenticated.
    out[8] ^= 0x01;
    let tampered_ok = decrypt_v3(PURPOSE_SEED, &out[..n], PASSWORD, &mut back, &mut noop).is_ok();
    out[8] ^= 0x01;
    if tampered_ok {
        return false;
    }

    // An unknown KDF must be reported as such, never as a bad password.
    let saved_kdf = out[6];
    out[6] = 0x7f;
    let unsupported = matches!(
        decrypt_v3(PURPOSE_SEED, &out[..n], PASSWORD, &mut back, &mut noop),
        Err(BackupError::UnsupportedKdf)
    );
    out[6] = saved_kdf;
    unsupported
}

/// Seed backup round trip through the public wrappers, v3 write and v3 read.
///
/// Heap-allocated for the same reason as the KAT above.
#[cfg(any(test, feature = "verbose-boot"))]
pub fn test_seed_backup_roundtrip() -> bool {
    const PASSWORD: &[u8] = b"pw";
    const SALT: [u8; V3_SALT_SIZE] = [0xA5; V3_SALT_SIZE];
    const NONCE: [u8; NONCE_SIZE] = [0x5A; NONCE_SIZE];
    let mut noop = |_: u32, _: u32| {};

    let mut file = alloc::vec![0u8; MAX_BACKUP_SIZE];

    for &wc in &[12u8, 24u8] {
        let mut indices = [0u16; 24];
        for i in 0..wc as usize {
            indices[i] = ((i * 83) % 2048) as u16;
        }
        let n = match encrypt_backup_progress(
            &indices, wc, PASSWORD, &SALT, &NONCE, &mut file, &mut noop,
        ) {
            Ok(n) => n,
            Err(_) => return false,
        };
        if n != V3_OVERHEAD + wc as usize * 2 {
            return false;
        }
        let mut out = [0u16; 24];
        match decrypt_backup_versioned(&file[..n], PASSWORD, &mut out, &mut noop) {
            Ok((got_wc, legacy)) => {
                if got_wc != wc || legacy {
                    return false;
                }
                for i in 0..wc as usize {
                    if out[i] != indices[i] {
                        return false;
                    }
                }
            }
            Err(_) => return false,
        }
    }
    true
}

/// Run the SD backup KATs. Returns (passed, total).
#[cfg(any(test, feature = "verbose-boot"))]
pub fn run_sd_backup_tests() -> (u32, u32) {
    let mut passed = 0u32;
    if test_v3_container_kat() { passed += 1; }
    if test_seed_backup_roundtrip() { passed += 1; }
    (passed, 2)
}
