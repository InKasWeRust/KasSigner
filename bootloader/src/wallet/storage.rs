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

// KasSigner — Encrypted Mnemonic Storage
// 100% Rust, no-std, no-alloc
//
// Encryption and decryption of the mnemonic for secure flash storage.
//
// Flujo de cifrado:
//   PIN + device_salt → PBKDF2-HMAC-SHA256 (100k iterations) → AES-256 key
//   mnemonic → AES-256-GCM(key, random_nonce, aad=version) → encrypted blob
//
// Formato del blob en flash:
//   [version: 1B][nonce: 12B][ciphertext: variable][tag: 16B]
//
// Seguridad:
//   - AES key is never stored — re-derived from PIN at each boot
//   - El nonce es random (12 bytes del TRNG)
//   - AAD includes version byte to prevent downgrade attacks
//   - Zeroization of all intermediate buffers
//   - 3 intentos fallidos → wipe (gestionado por el caller)
//
// NOTE: uses AeadInPlace to avoid alloc — all encrypt/decrypt in fixed buffers.


use sha2::{Sha256, Digest};
use aes_gcm::{
    Aes256Gcm,
    aead::{AeadInPlace, KeyInit, generic_array::GenericArray},
};
use super::hmac::zeroize_buf;

// ─── Constants ───────────────────────────────────────────────────────

/// Storage format version
pub const STORAGE_VERSION: u8 = 0x01;

/// PBKDF2 iterations for deriving AES key from PIN
pub const PBKDF2_ITERATIONS: u32 = 100_000;

/// AES-GCM nonce size (96 bits)
const NONCE_SIZE: usize = 12;

/// AES-GCM tag size (128 bits)
const TAG_SIZE: usize = 16;

/// Maximum encrypted blob size
pub const MAX_ENCRYPTED_SIZE: usize = 300;

/// Maximum serialized mnemonic size
const MAX_MNEMONIC_SIZE: usize = 256;

// ─── Errores ──────────────────────────────────────────────────────────

#[derive(Debug, PartialEq)]
/// Errors during encrypted seed storage operations.
pub enum StorageError {
    WeakPin,
    EncryptionFailed,
    DecryptionFailed,
    UnsupportedVersion,
    BufferTooSmall,
    MnemonicTooLong,
}

// ─── PIN Validation ────────────────────────────────────────────────

#[derive(Debug, PartialEq)]
/// PIN/passphrase strength classification.
pub enum PinStrength {
    Weak,
    Medium,
    Strong,
}

/// Valida la fortaleza de un PIN/password.
///
/// Minimum 6 digits or 8 alphanumeric characters.
/// Rechaza: todo igual, secuencias +1/-1.
pub fn validate_pin(pin: &[u8]) -> Result<PinStrength, StorageError> {
    if pin.len() < 6 {
        return Err(StorageError::WeakPin);
    }

    // All the same character
    if pin.len() > 1 && pin.iter().all(|&b| b == pin[0]) {
        return Err(StorageError::WeakPin);
    }

    // Secuencia incremental
    if pin.windows(2).all(|w| w[1] == w[0].wrapping_add(1)) {
        return Err(StorageError::WeakPin);
    }

    // Secuencia decremental
    if pin.windows(2).all(|w| w[0] == w[1].wrapping_add(1)) {
        return Err(StorageError::WeakPin);
    }

    let has_alpha = pin.iter().any(|&b| b.is_ascii_alphabetic());
    let has_digit = pin.iter().any(|&b| b.is_ascii_digit());
    let has_special = pin.iter().any(|&b| !b.is_ascii_alphanumeric());

    // Alphanumeric needs minimum 8 chars
    if has_alpha && pin.len() < 8 {
        return Err(StorageError::WeakPin);
    }

    let strength = if pin.len() >= 12 && has_alpha && has_digit && has_special {
        PinStrength::Strong
    } else if pin.len() >= 8 && (has_alpha || has_special) {
        PinStrength::Medium
    } else {
        PinStrength::Medium
    };

    Ok(strength)
}

// ─── PBKDF2-HMAC-SHA256 ──────────────────────────────────────────────

/// HMAC-SHA256 (RFC 2104)
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5C;

    let mut k_prime = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hash = Sha256::digest(key);
        k_prime[..32].copy_from_slice(&hash);
    } else {
        k_prime[..key.len()].copy_from_slice(key);
    }

    let mut ipad_key = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad_key[i] = k_prime[i] ^ IPAD;
    }
    let mut inner = Sha256::new();
    inner.update(&ipad_key);
    inner.update(message);
    let inner_hash = inner.finalize();

    let mut opad_key = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        opad_key[i] = k_prime[i] ^ OPAD;
    }
    let mut outer = Sha256::new();
    outer.update(&opad_key);
    outer.update(&inner_hash);
    let outer_hash = outer.finalize();

    zeroize_buf(&mut k_prime);
    zeroize_buf(&mut ipad_key);
    zeroize_buf(&mut opad_key);

    let mut result = [0u8; 32];
    result.copy_from_slice(&outer_hash);
    result
}

/// PBKDF2-HMAC-SHA256 — derive 32 bytes (AES-256 key) from password + salt.
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    pbkdf2_sha256_progress(password, salt, iterations, &mut |_, _| {})
}

/// PBKDF2-SHA256 with progress callback. Callback receives (current_iter, total_iters).
pub fn pbkdf2_sha256_progress(password: &[u8], salt: &[u8], iterations: u32, progress: &mut dyn FnMut(u32, u32)) -> [u8; 32] {
    let mut salt_buf = [0u8; 128];
    let slen = salt.len().min(124);
    salt_buf[..slen].copy_from_slice(&salt[..slen]);
    salt_buf[slen..slen + 4].copy_from_slice(&1u32.to_be_bytes());

    let mut u_prev = hmac_sha256(password, &salt_buf[..slen + 4]);
    let mut result = [0u8; 32];
    result.copy_from_slice(&u_prev);

    let step = iterations / 20; // update ~20 times
    for i in 1..iterations {
        let u_next = hmac_sha256(password, &u_prev);
        for j in 0..32 {
            result[j] ^= u_next[j];
        }
        u_prev = u_next;
        if step > 0 && i % step == 0 {
            progress(i, iterations);
        }
    }

    zeroize_buf(&mut u_prev);
    zeroize_buf(&mut salt_buf);
    result
}

// ─── Cifrado / Descifrado (in-place, sin alloc) ──────────────────────

/// Encrypt a mnemonic for flash storage.
///
/// Output format: [version:1][nonce:12][ciphertext][tag:16]
pub fn encrypt_mnemonic(
    mnemonic_bytes: &[u8],
    pin: &[u8],
    device_salt: &[u8],
    nonce_bytes: &[u8; NONCE_SIZE],
    output: &mut [u8],
) -> Result<usize, StorageError> {
    let mlen = mnemonic_bytes.len();
    if mlen > MAX_MNEMONIC_SIZE {
        return Err(StorageError::MnemonicTooLong);
    }
    let total_size = 1 + NONCE_SIZE + mlen + TAG_SIZE;
    if output.len() < total_size {
        return Err(StorageError::BufferTooSmall);
    }

    let mut aes_key = pbkdf2_sha256(pin, device_salt, PBKDF2_ITERATIONS);
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&aes_key));
    let nonce = GenericArray::from_slice(nonce_bytes);
    let aad = [STORAGE_VERSION];

    // Copy plaintext to buffer (after version + nonce)
    let ct_start = 1 + NONCE_SIZE;
    output[ct_start..ct_start + mlen].copy_from_slice(mnemonic_bytes);

    // Cifrar in-place
    let tag = cipher
        .encrypt_in_place_detached(nonce, &aad, &mut output[ct_start..ct_start + mlen])
        .map_err(|_| StorageError::EncryptionFailed)?;

    zeroize_buf(&mut aes_key);

    // Header
    output[0] = STORAGE_VERSION;
    output[1..1 + NONCE_SIZE].copy_from_slice(nonce_bytes);
    // Tag al final
    output[ct_start + mlen..ct_start + mlen + TAG_SIZE].copy_from_slice(&tag);

    Ok(total_size)
}

/// Decrypt a flash blob and recover the mnemonic.
///
/// Retorna `DecryptionFailed` si PIN incorrecto o datos corruptos.
pub fn decrypt_mnemonic(
    encrypted: &[u8],
    pin: &[u8],
    device_salt: &[u8],
    output: &mut [u8],
) -> Result<usize, StorageError> {
    let min_size = 1 + NONCE_SIZE + TAG_SIZE;
    if encrypted.len() < min_size {
        return Err(StorageError::DecryptionFailed);
    }

    if encrypted[0] != STORAGE_VERSION {
        return Err(StorageError::UnsupportedVersion);
    }

    let nonce_bytes = &encrypted[1..1 + NONCE_SIZE];
    let ct_and_tag = &encrypted[1 + NONCE_SIZE..];

    if ct_and_tag.len() < TAG_SIZE {
        return Err(StorageError::DecryptionFailed);
    }

    let ct_len = ct_and_tag.len() - TAG_SIZE;
    if output.len() < ct_len {
        return Err(StorageError::BufferTooSmall);
    }

    let ciphertext = &ct_and_tag[..ct_len];
    let tag_bytes = &ct_and_tag[ct_len..];

    let mut aes_key = pbkdf2_sha256(pin, device_salt, PBKDF2_ITERATIONS);
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&aes_key));
    let nonce = GenericArray::from_slice(nonce_bytes);
    let aad = [STORAGE_VERSION];
    let tag = GenericArray::from_slice(tag_bytes);

    output[..ct_len].copy_from_slice(ciphertext);

    let result = cipher.decrypt_in_place_detached(
        nonce, &aad, &mut output[..ct_len], tag,
    );

    zeroize_buf(&mut aes_key);

    match result {
        Ok(()) => Ok(ct_len),
        Err(_) => {
            zeroize_buf(&mut output[..ct_len]);
            Err(StorageError::DecryptionFailed)
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests (all use few PBKDF2 iterations for speed on ESP32)
// ═══════════════════════════════════════════════════════════════════════

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: PIN strength validation rules.
pub fn test_pin_validation() -> bool {
    if validate_pin(b"123") != Err(StorageError::WeakPin) { return false; }
    if validate_pin(b"111111") != Err(StorageError::WeakPin) { return false; }
    if validate_pin(b"123456") != Err(StorageError::WeakPin) { return false; }
    if validate_pin(b"654321") != Err(StorageError::WeakPin) { return false; }
    if validate_pin(b"abc123") != Err(StorageError::WeakPin) { return false; }
    if validate_pin(b"192837").is_err() { return false; }
    match validate_pin(b"MyStr0ng!Pass99") {
        Ok(PinStrength::Strong) => {},
        _ => return false,
    }
    true
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: PBKDF2 key derivation is deterministic.
pub fn test_pbkdf2_deterministic() -> bool {
    let key1 = pbkdf2_sha256(b"password", b"salt", 100);
    let key2 = pbkdf2_sha256(b"password", b"salt", 100);
    if key1 != key2 { return false; }
    let key3 = pbkdf2_sha256(b"different", b"salt", 100);
    if key1 == key3 { return false; }
    let key4 = pbkdf2_sha256(b"password", b"other", 100);
    key1 != key4
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: AES-GCM encrypt/decrypt round-trip.
pub fn test_encrypt_decrypt_fast() -> bool {
    let mnemonic = b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let pin = b"192837";
    let salt = b"test-device-salt";
    let nonce: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

    let aes_key = pbkdf2_sha256(pin, salt, 100);
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&aes_key));
    let nonce_ga = GenericArray::from_slice(&nonce);
    let aad = [STORAGE_VERSION];

    let mlen = mnemonic.len();
    let mut buf = [0u8; MAX_MNEMONIC_SIZE];
    buf[..mlen].copy_from_slice(mnemonic);

    let tag = match cipher.encrypt_in_place_detached(nonce_ga, &aad, &mut buf[..mlen]) {
        Ok(t) => t,
        Err(_) => return false,
    };

    match cipher.decrypt_in_place_detached(nonce_ga, &aad, &mut buf[..mlen], &tag) {
        Ok(()) => {},
        Err(_) => return false,
    }

    buf[..mlen] == mnemonic[..]
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: decryption with wrong key fails.
pub fn test_wrong_key_fails() -> bool {
    let mnemonic = b"test mnemonic data";
    let nonce: [u8; 12] = [0xAA; 12];
    let aad = [STORAGE_VERSION];

    let key1 = pbkdf2_sha256(b"correct_pin", b"salt", 100);
    let cipher1 = Aes256Gcm::new(GenericArray::from_slice(&key1));
    let nonce_ga = GenericArray::from_slice(&nonce);

    let mlen = mnemonic.len();
    let mut buf = [0u8; 64];
    buf[..mlen].copy_from_slice(mnemonic);

    let tag = match cipher1.encrypt_in_place_detached(nonce_ga, &aad, &mut buf[..mlen]) {
        Ok(t) => t,
        Err(_) => return false,
    };

    let key2 = pbkdf2_sha256(b"wrong_pin!", b"salt", 100);
    let cipher2 = Aes256Gcm::new(GenericArray::from_slice(&key2));

    cipher2.decrypt_in_place_detached(nonce_ga, &aad, &mut buf[..mlen], &tag).is_err()
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Run all storage encryption tests.
pub fn run_storage_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 4u32;

    if test_pin_validation() { passed += 1; }
    if test_pbkdf2_deterministic() { passed += 1; }
    if test_encrypt_decrypt_fast() { passed += 1; }
    if test_wrong_key_fails() { passed += 1; }

    (passed, total)
}
