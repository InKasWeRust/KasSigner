// KasSigner — HMAC-SHA512 (RFC 2104)
// 100% Rust, no-std, no-alloc
//
// Manual HMAC-SHA512 implementation shared between
// BIP39 (PBKDF2) y BIP32 (master key + child derivation).
//
// Uses only the `sha2` crate — no additional dependencies.


use sha2::{Sha256, Sha512, Digest};

const BLOCK_SIZE: usize = 128; // SHA-512 block size
const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5C;

/// SHA-256 hash of arbitrary data. Returns 32-byte digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// HMAC-SHA512 (RFC 2104)
///
/// HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
/// donde K' = K si len(K) ≤ block_size, o H(K) si len(K) > block_size
pub fn hmac_sha512(key: &[u8], message: &[u8]) -> [u8; 64] {
    // Step 1: Si key > block_size, key = SHA512(key)
    let mut k_prime = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let mut hasher = Sha512::new();
        hasher.update(key);
        let hash = hasher.finalize();
        k_prime[..64].copy_from_slice(&hash);
    } else {
        k_prime[..key.len()].copy_from_slice(key);
    }
    // Resto ya es cero (padding)

    // Step 2: inner = H((K' ⊕ ipad) || message)
    let mut inner_hasher = Sha512::new();
    let mut ipad_key = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad_key[i] = k_prime[i] ^ IPAD;
    }
    inner_hasher.update(&ipad_key);
    inner_hasher.update(message);
    let inner_hash = inner_hasher.finalize();

    // Step 3: outer = H((K' ⊕ opad) || inner_hash)
    let mut outer_hasher = Sha512::new();
    let mut opad_key = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        opad_key[i] = k_prime[i] ^ OPAD;
    }
    outer_hasher.update(&opad_key);
    outer_hasher.update(&inner_hash);
    let outer_hash = outer_hasher.finalize();

    // Zeroize sensitive material
    zeroize_buf(&mut k_prime);
    zeroize_buf(&mut ipad_key);
    zeroize_buf(&mut opad_key);

    let mut result = [0u8; 64];
    result.copy_from_slice(&outer_hash);
    result
}

/// Securely zeroize a buffer (volatile writes).
pub fn zeroize_buf(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe {
            core::ptr::write_volatile(b, 0);
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
