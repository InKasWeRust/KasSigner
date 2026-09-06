//! Restore-only PBKDF2-HMAC-SHA256 compatibility primitive.
//!
//! New KasSigner-owned password formats MUST use `password_kdf` Argon2id.
//! This module exists solely for authenticated, explicitly versioned legacy readers.

use sha2::{Digest, Sha256};

use crate::derivation::hmac::zeroize_buf;

/// HMAC-SHA256 (RFC 2104).
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;

    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hash = Sha256::digest(key);
        key_block[..32].copy_from_slice(&hash);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner_key = [0u8; BLOCK_SIZE];
    let mut outer_key = [0u8; BLOCK_SIZE];
    for index in 0..BLOCK_SIZE {
        inner_key[index] = key_block[index] ^ IPAD;
        outer_key[index] = key_block[index] ^ OPAD;
    }

    let mut inner = Sha256::new();
    inner.update(inner_key);
    inner.update(message);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_key);
    outer.update(inner_hash);
    let outer_hash = outer.finalize();

    zeroize_buf(&mut key_block);
    zeroize_buf(&mut inner_key);
    zeroize_buf(&mut outer_key);

    let mut result = [0u8; 32];
    result.copy_from_slice(&outer_hash);
    result
}

/// Derive 32 bytes with PBKDF2-HMAC-SHA256.
pub fn derive_legacy_32(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    derive_legacy_32_progress(password, salt, iterations, &mut |_, _| {})
}

/// Derive 32 bytes and report periodic progress as `(current, total)`.
pub fn derive_legacy_32_progress(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    progress: &mut dyn FnMut(u32, u32),
) -> [u8; 32] {
    let mut salt_block = [0u8; 128];
    let salt_len = salt.len().min(124);
    salt_block[..salt_len].copy_from_slice(&salt[..salt_len]);
    salt_block[salt_len..salt_len + 4].copy_from_slice(&1u32.to_be_bytes());

    let mut previous = hmac_sha256(password, &salt_block[..salt_len + 4]);
    let mut result = previous;
    let progress_step = iterations / 20;

    for iteration in 1..iterations {
        let next = hmac_sha256(password, &previous);
        for index in 0..32 {
            result[index] ^= next[index];
        }
        previous = next;
        if progress_step > 0 && iteration.is_multiple_of(progress_step) {
            progress(iteration, iterations);
        }
    }

    zeroize_buf(&mut previous);
    zeroize_buf(&mut salt_block);
    result
}

#[cfg(any(test, feature = "verbose-boot"))]
#[path = "unit_tests/legacy_pbkdf2_tests.rs"]
pub mod unit_tests;
