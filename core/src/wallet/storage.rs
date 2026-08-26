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

// KasSigner — Encrypted Mnemonic Storage
// 100% Rust, no-std, no-alloc
//
// Encryption and decryption of the mnemonic for secure flash storage.
//
// Encryption flow:
//   PIN + device_salt → PBKDF2-HMAC-SHA256 (100k iterations) → AES-256 key
//   mnemonic → AES-256-GCM(key, random_nonce, aad=version) → encrypted blob
//
// Blob format in flash:
//   [version: 1B][nonce: 12B][ciphertext: variable][tag: 16B]
//
// Security:
//   - AES key is never stored — re-derived from PIN at each boot
//   - Nonce is random (12 bytes from TRNG)
//   - AAD includes version byte to prevent downgrade attacks
//   - Zeroization of all intermediate buffers
//   - 3 failed attempts → wipe (managed by the caller)
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
/// Rejects: all identical, +1/-1 sequences.
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
/// Reference (naive) HMAC-SHA256: rebuilds both pad blocks on every call.
///
/// No longer used by `pbkdf2_sha256_progress`, which caches the pad
/// midstates instead. Kept as the reference implementation that
/// `test_pbkdf2_midstate_equivalence` checks the fast path against.
#[allow(dead_code)]
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
    inner.update(ipad_key);
    inner.update(message);
    let inner_hash = inner.finalize();

    let mut opad_key = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        opad_key[i] = k_prime[i] ^ OPAD;
    }
    let mut outer = Sha256::new();
    outer.update(opad_key);
    outer.update(inner_hash);
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
    const BLOCK_SIZE: usize = 64;

    // The HMAC key is the password and never changes across iterations, so
    // the two pad blocks are hashed ONCE here and every iteration resumes
    // from the resulting midstates via `clone()`.
    //
    // The previous code called `hmac_sha256(password, ..)` per iteration,
    // which rebuilt k_prime and both pad keys and then hashed 64 bytes of
    // pad plus 32 bytes of message on each side: two blocks in, two blocks
    // out, FOUR SHA-256 compressions per iteration. Resuming from the
    // midstates leaves 32 bytes plus padding on each side, one block each,
    // TWO compressions. Measured cost before this change was 35,401
    // cycles/iteration, 14.75s for the 100k-iteration SD key derivation.
    //
    // Output is bit-identical: this is the standard PBKDF2 structure, not
    // an approximation. `test_pbkdf2_midstate_equivalence` checks it
    // against the naive formulation at boot.
    let mut k_prime = [0u8; BLOCK_SIZE];
    if password.len() > BLOCK_SIZE {
        let hash = Sha256::digest(password);
        k_prime[..32].copy_from_slice(&hash);
    } else {
        k_prime[..password.len()].copy_from_slice(password);
    }
    let mut ipad_key = [0u8; BLOCK_SIZE];
    let mut opad_key = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad_key[i] = k_prime[i] ^ 0x36;
        opad_key[i] = k_prime[i] ^ 0x5C;
    }
    let mut inner_base = Sha256::new();
    inner_base.update(ipad_key);
    let mut outer_base = Sha256::new();
    outer_base.update(opad_key);
    zeroize_buf(&mut k_prime);
    zeroize_buf(&mut ipad_key);
    zeroize_buf(&mut opad_key);

    // One HMAC round from the cached midstates.
    let hmac_from_mid = |msg: &[u8]| -> [u8; 32] {
        let mut inner = inner_base.clone();
        inner.update(msg);
        let inner_hash = inner.finalize();
        let mut outer = outer_base.clone();
        outer.update(inner_hash);
        let outer_hash = outer.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&outer_hash);
        out
    };

    let mut salt_buf = [0u8; 128];
    let slen = salt.len().min(124);
    salt_buf[..slen].copy_from_slice(&salt[..slen]);
    salt_buf[slen..slen + 4].copy_from_slice(&1u32.to_be_bytes());

    let mut u_prev = hmac_from_mid(&salt_buf[..slen + 4]);
    let mut result = [0u8; 32];
    result.copy_from_slice(&u_prev);

    let step = iterations / 20; // update ~20 times
    for i in 1..iterations {
        let u_next = hmac_from_mid(&u_prev);
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

// ─── Encryption / Decryption (in-place, no alloc) ──────────────────────
// ═══════════════════════════════════════════════════════════════════════
// Tests (all use few PBKDF2 iterations for speed on ESP32)
// ═══════════════════════════════════════════════════════════════════════

#[cfg(any(test, not(feature = "skip-tests")))]
/// Test: the midstate-cached PBKDF2 matches the naive formulation exactly.
///
/// This is the check that matters most in this file. `pbkdf2_sha256` derives
/// the AES key for every SD backup; if the fast path diverged by one bit,
/// new backups would be written under a key that no old build can read and
/// existing backups would stop decrypting, with no error message to say why.
pub fn test_pbkdf2_midstate_equivalence() -> bool {
    // Naive PBKDF2 built from the reference HMAC, exactly as the code read
    // before the midstate change.
    fn naive(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
        let mut salt_buf = [0u8; 128];
        let slen = salt.len().min(124);
        salt_buf[..slen].copy_from_slice(&salt[..slen]);
        salt_buf[slen..slen + 4].copy_from_slice(&1u32.to_be_bytes());
        let mut u_prev = hmac_sha256(password, &salt_buf[..slen + 4]);
        let mut result = [0u8; 32];
        result.copy_from_slice(&u_prev);
        for _ in 1..iterations {
            let u_next = hmac_sha256(password, &u_prev);
            for j in 0..32 {
                result[j] ^= u_next[j];
            }
            u_prev = u_next;
        }
        result
    }

    // Short key, key exactly one block, and key longer than a block (which
    // takes the "hash the key first" branch). Iteration counts kept small.
    let cases: [(&[u8], &[u8], u32); 4] = [
        (b"pw", b"salt", 1),
        (b"pw", b"KasSigner-KSPT-v1", 7),
        (&[0x41u8; 64], b"salt", 5),
        (&[0x42u8; 100], b"salt", 5),
    ];
    for (pw, salt, iters) in cases {
        if pbkdf2_sha256(pw, salt, iters) != naive(pw, salt, iters) {
            return false;
        }
    }
    true
}

#[cfg(any(test, not(feature = "skip-tests")))]
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

#[cfg(any(test, not(feature = "skip-tests")))]
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

#[cfg(any(test, not(feature = "skip-tests")))]
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

// Reachable in shipped builds. Gated on `skip-tests` only: NOT on
// `verbose-boot` (which also enables the sighash debug dump and must
// never ship) and NOT on `silent` (a logging flag must not be able to
// switch off a correctness check). Called from boot_test::run_crypto_kats.
#[cfg(any(test, not(feature = "skip-tests")))]
/// Run all storage encryption tests.
pub fn run_storage_tests() -> (u32, u32) {
    let mut passed = 0u32;
    // 4, not 5: test_pin_validation is gone. KasSigner has no PIN at all.
    // It is a stateless signer with no persistent key storage, so booting
    // a device to check PIN-strength rules tested a feature that does not
    // exist. validate_pin and PinStrength are now unreferenced dead code;
    // removing them is L-09 and is tracked separately.
    let total = 4u32;

    if test_pbkdf2_midstate_equivalence() { passed += 1; }
    if test_pbkdf2_deterministic() { passed += 1; }
    if test_encrypt_decrypt_fast() { passed += 1; }
    if test_wrong_key_fails() { passed += 1; }

    (passed, total)
}
