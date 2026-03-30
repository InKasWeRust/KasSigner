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

// KasSigner — BIP32 Hierarchical Deterministic Key Derivation
// 100% Rust, no-std, no-alloc
//
// BIP32 Hierarchical Deterministic key derivation:
//   1. Seed (512 bits) → HMAC-SHA512("Bitcoin seed", seed) → Master Key + Chain Code
//   2. Child key derivation (hardened and normal)
//   3. Path parsing: m/44'/111111'/0'/0/0 (Kaspa mainnet)
//
// secp256k1 arithmetic via `k256` crate (RustCrypto, pure Rust, no-std).
//
// Security:
//   - All private keys are zeroized on Drop
//   - No se usa heap/alloc
//   - Hardened derivation for sensitive path levels


use k256::{
    SecretKey,
    elliptic_curve::sec1::ToEncodedPoint,
};
use super::hmac::{hmac_sha512, zeroize_buf};

// ─── Constants ───────────────────────────────────────────────────────

/// BIP32 key for master key HMAC
const BITCOIN_SEED: &[u8] = b"Bitcoin seed";

/// secp256k1 curve order (n)
/// n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// Hardened derivation flag bit (0x80000000)
const HARDENED_BIT: u32 = 0x8000_0000;

// ─── Kaspa derivation paths ───────────────────────────────────────────

/// Kaspa mainnet path: m/44'/111111'/0'/0/0
pub const KASPA_MAINNET_PATH: &[u32] = &[
    44 | HARDENED_BIT,       // purpose (BIP44)
    111111 | HARDENED_BIT,   // coin_type (Kaspa, SLIP-44)
    0 | HARDENED_BIT,        // account 0
    0,                       // change (external)
    0,                       // address_index 0
];

/// Kaspa testnet path: m/44'/1'/0'/0/0
pub const KASPA_TESTNET_PATH: &[u32] = &[
    44 | HARDENED_BIT,
    1 | HARDENED_BIT,
    0 | HARDENED_BIT,
    0,
    0,
];

// ─── Errores ──────────────────────────────────────────────────────────

#[derive(Debug, PartialEq)]
/// Errors during HD key derivation (BIP32).
pub enum Bip32Error {
    /// Derived private key is zero or >= curve order
    InvalidKey,
    /// Invalid chain code
    InvalidChainCode,
    /// Error parsing key with k256
    CurveError,
    /// Empty derivation path
    EmptyPath,
}

// ─── Tipos ────────────────────────────────────────────────────────────

/// Extended private key: private key (32 bytes) + chain code (32 bytes)
pub struct ExtendedPrivKey {
    /// Private key (secp256k1 scalar, 32 bytes big-endian)
    key: [u8; 32],
    /// Chain code for child derivation
    chain_code: [u8; 32],
    /// Depth in the tree (0 = master)
    pub depth: u8,
}

impl ExtendedPrivKey {
    /// Zeroiza ambos campos de forma segura
    pub fn zeroize(&mut self) {
        zeroize_buf(&mut self.key);
        zeroize_buf(&mut self.chain_code);
    }

    /// Export raw bytes (key + chain_code + depth) for caching.
    /// Returns 65 bytes: [key:32][chain_code:32][depth:1]
    pub fn to_raw(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[..32].copy_from_slice(&self.key);
        out[32..64].copy_from_slice(&self.chain_code);
        out[64] = self.depth;
        out
    }

    /// Restore from raw bytes exported by to_raw().
    pub fn from_raw(raw: &[u8; 65]) -> Self {
        let mut key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        key.copy_from_slice(&raw[..32]);
        chain_code.copy_from_slice(&raw[32..64]);
        Self { key, chain_code, depth: raw[64] }
    }

    /// Construct from individual parts (used by xprv import).
    pub fn from_parts(key: [u8; 32], chain_code: [u8; 32], depth: u8) -> Self {
        Self { key, chain_code, depth }
    }

    /// Return reference to private key (32 bytes)
    pub fn private_key_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Returns reference to the chain code
    pub fn chain_code_bytes(&self) -> &[u8; 32] {
        &self.chain_code
    }

    /// Compute compressed public key (33 bytes: 02/03 + X)
    pub fn public_key_compressed(&self) -> Result<[u8; 33], Bip32Error> {
        let sk = SecretKey::from_slice(&self.key)
            .map_err(|_| Bip32Error::CurveError)?;
        let pk = sk.public_key();
        let point = pk.to_encoded_point(true); // compressed
        let bytes = point.as_bytes();
        let mut result = [0u8; 33];
        result.copy_from_slice(bytes);
        Ok(result)
    }


    /// Return only the X coordinate of the public key (32 bytes)
    /// This is what Kaspa uses for Schnorr addresses.
    pub fn public_key_x_only(&self) -> Result<[u8; 32], Bip32Error> {
        let compressed = self.public_key_compressed()?;
        let mut x = [0u8; 32];
        x.copy_from_slice(&compressed[1..33]); // skip prefix byte
        Ok(x)
    }
}

impl Drop for ExtendedPrivKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Derive x-only public key (32 bytes) from a raw 32-byte private key.
/// Used for imported raw keys (not BIP32-derived).
pub fn pubkey_from_raw_key(privkey: &[u8; 32]) -> Result<[u8; 32], Bip32Error> {
    let sk = SecretKey::from_slice(privkey)
        .map_err(|_| Bip32Error::CurveError)?;
    let pk = sk.public_key();
    let point = pk.to_encoded_point(true);
    let bytes = point.as_bytes();
    let mut x = [0u8; 32];
    x.copy_from_slice(&bytes[1..33]);
    Ok(x)
}

// ─── Master Key Generation ────────────────────────────────────────────

/// Generate the master extended private key from a BIP39 seed.
///
/// BIP32 spec:
///   I = HMAC-SHA512(key="Bitcoin seed", data=seed)
///   IL = first 32 bytes → master private key
///   IR = last 32 bytes → master chain code
///
/// The private key must be: 0 < IL < n (secp256k1 curve order)
/// If IL >= n or IL == 0, the seed is invalid (probability ~2^-128).
pub fn master_key_from_seed(seed: &[u8; 64]) -> Result<ExtendedPrivKey, Bip32Error> {
    let i = hmac_sha512(BITCOIN_SEED, seed);

    let mut key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    key.copy_from_slice(&i[..32]);
    chain_code.copy_from_slice(&i[32..]);

    // Validate that the key is a valid scalar (0 < key < n)
    if is_zero(&key) || !is_less_than_order(&key) {
        zeroize_buf(&mut key);
        zeroize_buf(&mut chain_code);
        return Err(Bip32Error::InvalidKey);
    }

    // Verify that k256 accepts this key
    if SecretKey::from_slice(&key).is_err() {
        zeroize_buf(&mut key);
        zeroize_buf(&mut chain_code);
        return Err(Bip32Error::CurveError);
    }

    Ok(ExtendedPrivKey {
        key,
        chain_code,
        depth: 0,
    })
}

// ─── Child Key Derivation ─────────────────────────────────────────────

/// Derive a child key from an extended private key.
///
/// BIP32 child key derivation:
///
/// **Hardened** (index >= 0x80000000):
///   data = 0x00 || parent_key || index_BE
///   I = HMAC-SHA512(key=parent_chain_code, data=data)
///
/// **Normal** (index < 0x80000000):
///   data = parent_pubkey_compressed || index_BE
///   I = HMAC-SHA512(key=parent_chain_code, data=data)
///
/// child_key = (IL + parent_key) mod n
/// child_chain_code = IR
pub fn derive_child(
    parent: &ExtendedPrivKey,
    index: u32,
) -> Result<ExtendedPrivKey, Bip32Error> {
    let is_hardened = index & HARDENED_BIT != 0;

    // Build data for HMAC
    // Hardened: 0x00 + key(32) + index(4) = 37 bytes
    // Normal: pubkey(33) + index(4) = 37 bytes
    let mut data = [0u8; 37];

    if is_hardened {
        // data = 0x00 || parent_key || ser32(index)
        data[0] = 0x00;
        data[1..33].copy_from_slice(&parent.key);
    } else {
        // data = ser_P(parent_pubkey) || ser32(index)
        let pubkey = parent.public_key_compressed()?;
        data[..33].copy_from_slice(&pubkey);
    }
    // Append index as big-endian u32
    data[33..37].copy_from_slice(&index.to_be_bytes());

    // I = HMAC-SHA512(key=chain_code, data=data)
    let i = hmac_sha512(&parent.chain_code, &data);

    let mut il = [0u8; 32];
    let mut child_chain_code = [0u8; 32];
    il.copy_from_slice(&i[..32]);
    child_chain_code.copy_from_slice(&i[32..]);

    // Validar IL
    if !is_less_than_order(&il) {
        zeroize_buf(&mut il);
        zeroize_buf(&mut child_chain_code);
        zeroize_buf(&mut data);
        return Err(Bip32Error::InvalidKey);
    }

    // child_key = (IL + parent_key) mod n
    let mut child_key = scalar_add_mod_n(&il, &parent.key);

    // Zeroize IL — no longer needed
    zeroize_buf(&mut il);
    zeroize_buf(&mut data);

    // child_key cannot be zero
    if is_zero(&child_key) {
        zeroize_buf(&mut child_key);
        zeroize_buf(&mut child_chain_code);
        return Err(Bip32Error::InvalidKey);
    }

    // Verify that k256 accepts the derived key
    if SecretKey::from_slice(&child_key).is_err() {
        zeroize_buf(&mut child_key);
        zeroize_buf(&mut child_chain_code);
        return Err(Bip32Error::CurveError);
    }

    Ok(ExtendedPrivKey {
        key: child_key,
        chain_code: child_chain_code,
        depth: parent.depth.saturating_add(1),
    })
}

/// Derive along a complete path (e.g. m/44'/111111'/0'/0/0).
///
/// Each path element is a u32. The HARDENED_BIT (0x80000000)
/// indicates hardened derivation (marked with ' in notation).
pub fn derive_path(
    seed: &[u8; 64],
    path: &[u32],
) -> Result<ExtendedPrivKey, Bip32Error> {
    if path.is_empty() {
        return Err(Bip32Error::EmptyPath);
    }

    let mut current = master_key_from_seed(seed)?;

    for &index in path.iter() {
        let child = derive_child(&current, index)?;
        current.zeroize(); // Zeroize parent before overwriting
        current = child;
    }

    Ok(current)
}

// ─── Multi-address support ───────────────────────────────────────────

/// Number of addresses pre-cached on seed load (0..=19)
pub const CACHED_ADDR_COUNT: usize = 20;

/// Kaspa account-level path: m/44'/111111'/0' (3 hardened levels)
/// From here we derive /0/index for each receive address.
const KASPA_ACCOUNT_PATH: [u32; 3] = [
    44 | HARDENED_BIT,       // purpose (BIP44)
    111111 | HARDENED_BIT,   // coin_type (Kaspa)
    0 | HARDENED_BIT,        // account 0
];

/// Derive the Kaspa account key at m/44'/111111'/0'.
/// This is expensive (3 hardened derivations with HMAC-SHA512 each),
/// but only needs to be done once per seed load.
pub fn derive_account_key(seed: &[u8; 64]) -> Result<ExtendedPrivKey, Bip32Error> {
    derive_path(seed, &KASPA_ACCOUNT_PATH)
}

/// From an account key (m/44'/111111'/0'), derive the key at /0/index.
/// This is cheap: just 2 normal (non-hardened) child derivations.
/// Any index up to 2^31-1 is valid (BIP32 normal child).
pub fn derive_address_key(
    account_key: &ExtendedPrivKey,
    index: u16,
) -> Result<ExtendedPrivKey, Bip32Error> {
    // m/44'/111111'/0' → /0 (external chain)
    let change_key = derive_child(account_key, 0)?;
    // /0 → /index (address index)
    let addr_key = derive_child(&change_key, index as u32)?;
    Ok(addr_key)
}

/// From an account key (m/44'/111111'/0'), derive the CHANGE key at /1/index.
/// Change addresses use the internal chain (index 1) per BIP44.
/// Used to verify that TX outputs returning funds to our wallet are legitimate.
pub fn derive_change_key(
    account_key: &ExtendedPrivKey,
    index: u16,
) -> Result<ExtendedPrivKey, Bip32Error> {
    // m/44'/111111'/0' → /1 (internal/change chain)
    let internal_key = derive_child(account_key, 1)?;
    // /1 → /index (change address index)
    let addr_key = derive_child(&internal_key, index as u32)?;
    Ok(addr_key)
}

/// Derive a full Kaspa address key at m/44'/111111'/0'/0/{index} from seed.
/// Convenience function when you don't have a cached account key.
pub fn derive_path_for_index(
    seed: &[u8; 64],
    index: u16,
) -> Result<ExtendedPrivKey, Bip32Error> {
    let path: [u32; 5] = [
        44 | HARDENED_BIT,
        111111 | HARDENED_BIT,
        0 | HARDENED_BIT,
        0,
        index as u32,
    ];
    derive_path(seed, &path)
}

/// Given an account key and a 32-byte x-only pubkey, find which address
/// index produced it. Scans 0..99 (covers typical wallet usage).
/// Returns None if no match. Used for multi-input signing.
/// Given an account key and a 32-byte x-only pubkey, find which address
/// index produced it. Scans both receive (chain 0) and change (chain 1)
/// paths, indices 0..99.
/// Returns Some((index, is_change)) or None if no match.
/// Used for multi-input signing.
pub fn find_address_index_for_pubkey(
    account_key: &ExtendedPrivKey,
    target_pubkey: &[u8; 32],
) -> Option<(u16, bool)> {
    // Search receive chain first (m/44'/111111'/0'/0/idx)
    for idx in 0..100u16 {
        if let Ok(key) = derive_address_key(account_key, idx) {
            if let Ok(pk) = key.public_key_x_only() {
                if pk == *target_pubkey {
                    return Some((idx, false));
                }
            }
        }
    }
    // Search change chain (m/44'/111111'/0'/1/idx)
    for idx in 0..100u16 {
        if let Ok(key) = derive_change_key(account_key, idx) {
            if let Ok(pk) = key.public_key_x_only() {
                if pk == *target_pubkey {
                    return Some((idx, true));
                }
            }
        }
    }
    None
}

// ─── secp256k1 modular arithmetic ─────────────────────────────────────

/// Checks if a 32-byte scalar is zero.
fn is_zero(a: &[u8; 32]) -> bool {
    let mut acc: u8 = 0;
    for &b in a.iter() {
        acc |= b;
    }
    acc == 0
}

/// Checks if a < n (secp256k1 order).
/// Big-endian byte-by-byte comparison.
fn is_less_than_order(a: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] < SECP256K1_ORDER[i] {
            return true;
        }
        if a[i] > SECP256K1_ORDER[i] {
            return false;
        }
    }
    false // a == n → no es menor
}

/// Modular addition: (a + b) mod n
/// where n is the order of secp256k1.
///
/// Algoritmo:
///   1. Add a + b as 256-bit integers (with carry)
///   2. If result >= n, subtract n
fn scalar_add_mod_n(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    // Step 1: Big-endian addition with carry
    let mut result = [0u8; 32];
    let mut carry: u16 = 0;

    for i in (0..32).rev() {
        let sum = (a[i] as u16) + (b[i] as u16) + carry;
        result[i] = (sum & 0xFF) as u8;
        carry = sum >> 8;
    }

    // Step 2: If carry=1 or result >= n, subtract n
    // (carry=1 means the result is >= 2^256, which is > n)
    let needs_reduce = carry > 0 || !less_than(&result, &SECP256K1_ORDER);

    if needs_reduce {
        subtract_order(&mut result);
    }

    result
}

/// Compares a < b (big-endian, 32 bytes).
fn less_than(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] < b[i] {
            return true;
        }
        if a[i] > b[i] {
            return false;
        }
    }
    false // a == b
}

/// Resta in-place: a -= n (orden de secp256k1).
/// Asume que a >= n.
fn subtract_order(a: &mut [u8; 32]) {
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let diff = (a[i] as i16) - (SECP256K1_ORDER[i] as i16) - borrow;
        if diff < 0 {
            a[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            a[i] = diff as u8;
            borrow = 0;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests con vectores BIP32 conocidos
// ═══════════════════════════════════════════════════════════════════════
//
// Vectores de: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
//
// Test Vector 1:
//   Seed: 000102030405060708090a0b0c0d0e0f
//   Master key: e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35
//   Master chain: 873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508
//   Master pubkey (compressed): 0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2

/// Test vector 1: Master key from seed
#[cfg(any(test, feature = "verbose-boot"))]
/// BIP32 test vector 1: master key derivation.
pub fn test_vector1_master() -> bool {
    // Known seed (abandon×11 + about, no passphrase):
    let known_seed: [u8; 64] = [
        0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08,
        0x48, 0x89, 0xa8, 0xab, 0x91, 0x55, 0x56, 0x81,
        0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8, 0x5e, 0x70,
        0x81, 0x1a, 0xae, 0xd6, 0xf6, 0xda, 0x5f, 0xc1,
        0x9a, 0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70,
        0xd0, 0x86, 0x20, 0x6d, 0xec, 0x8a, 0xa6, 0xc4,
        0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad, 0x3d,
        0x8d, 0x48, 0xb2, 0xd2, 0xce, 0x9e, 0x38, 0xe4,
    ];

    let master = match master_key_from_seed(&known_seed) {
        Ok(m) => m,
        Err(_) => return false,
    };

    // Verify master key is valid (non-zero, < n)
    if is_zero(&master.key) {
        return false;
    }
    if !is_less_than_order(&master.key) {
        return false;
    }
    if master.depth != 0 {
        return false;
    }

    // Verify public key can be computed
    master.public_key_compressed().is_ok()
}

/// Test: BIP32 test vector 1 con seed hex 000102030405060708090a0b0c0d0e0f
/// We use HMAC-SHA512 directly to verify against the official test vector.
#[cfg(any(test, feature = "verbose-boot"))]
/// BIP32 test vector 1: official test vectors.
pub fn test_vector1_official() -> bool {
    // BIP32 Test Vector 1 seed (16 bytes — la spec dice que se pasa tal cual a HMAC)
    let seed_short: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ];

    // I = HMAC-SHA512("Bitcoin seed", seed)
    let i = hmac_sha512(BITCOIN_SEED, &seed_short);

    // Expected master private key
    let expected_key: [u8; 32] = [
        0xe8, 0xf3, 0x2e, 0x72, 0x3d, 0xec, 0xf4, 0x05,
        0x1a, 0xef, 0xac, 0x8e, 0x2c, 0x93, 0xc9, 0xc5,
        0xb2, 0x14, 0x31, 0x38, 0x17, 0xcd, 0xb0, 0x1a,
        0x14, 0x94, 0xb9, 0x17, 0xc8, 0x43, 0x6b, 0x35,
    ];

    // Expected master chain code
    let expected_chain: [u8; 32] = [
        0x87, 0x3d, 0xff, 0x81, 0xc0, 0x2f, 0x52, 0x56,
        0x23, 0xfd, 0x1f, 0xe5, 0x16, 0x7e, 0xac, 0x3a,
        0x55, 0xa0, 0x49, 0xde, 0x3d, 0x31, 0x4b, 0xb4,
        0x2e, 0xe2, 0x27, 0xff, 0xed, 0x37, 0xd5, 0x08,
    ];

    if i[..32] != expected_key {
        return false;
    }
    if i[32..] != expected_chain {
        return false;
    }

    // Verify public key derivation
    let sk: SecretKey = match SecretKey::from_slice(&expected_key) {
        Ok(sk) => sk,
        Err(_) => return false,
    };
    let pk = sk.public_key();
    let point = pk.to_encoded_point(true);
    let pk_bytes = point.as_bytes();

    // Expected compressed public key
    let expected_pub: [u8; 33] = [
        0x03, 0x39, 0xa3, 0x60, 0x13, 0x30, 0x15, 0x97,
        0xda, 0xef, 0x41, 0xfb, 0xe5, 0x93, 0xa0, 0x2c,
        0xc5, 0x13, 0xd0, 0xb5, 0x55, 0x27, 0xec, 0x2d,
        0xf1, 0x05, 0x0e, 0x2e, 0x8f, 0xf4, 0x9c, 0x85,
        0xc2,
    ];

    pk_bytes == expected_pub
}

/// Test: child derivation hardened (m/0')
/// BIP32 Test Vector 1, Chain m/0':
///   key:   edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea
///   chain: 47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141
#[cfg(any(test, feature = "verbose-boot"))]
/// BIP32 test vector 1: hardened child derivation.
pub fn test_vector1_child_hardened() -> bool {
    let seed_short: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ];

    // Generate master key manually (16-byte seed, not 64)
    let i = hmac_sha512(BITCOIN_SEED, &seed_short);
    let mut master_key = [0u8; 32];
    let mut master_chain = [0u8; 32];
    master_key.copy_from_slice(&i[..32]);
    master_chain.copy_from_slice(&i[32..]);

    let master = ExtendedPrivKey {
        key: master_key,
        chain_code: master_chain,
        depth: 0,
    };

    // Derive m/0' (hardened)
    let child = match derive_child(&master, 0 | HARDENED_BIT) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let expected_child_key: [u8; 32] = [
        0xed, 0xb2, 0xe1, 0x4f, 0x9e, 0xe7, 0x7d, 0x26,
        0xdd, 0x93, 0xb4, 0xec, 0xed, 0xe8, 0xd1, 0x6e,
        0xd4, 0x08, 0xce, 0x14, 0x9b, 0x6c, 0xd8, 0x0b,
        0x07, 0x15, 0xa2, 0xd9, 0x11, 0xa0, 0xaf, 0xea,
    ];

    let expected_child_chain: [u8; 32] = [
        0x47, 0xfd, 0xac, 0xbd, 0x0f, 0x10, 0x97, 0x04,
        0x3b, 0x78, 0xc6, 0x3c, 0x20, 0xc3, 0x4e, 0xf4,
        0xed, 0x9a, 0x11, 0x1d, 0x98, 0x00, 0x47, 0xad,
        0x16, 0x28, 0x2c, 0x7a, 0xe6, 0x23, 0x61, 0x41,
    ];

    if child.key != expected_child_key {
        return false;
    }
    if child.chain_code != expected_child_chain {
        return false;
    }
    if child.depth != 1 {
        return false;
    }

    true
}

/// Test: Kaspa path derivation (m/44'/111111'/0'/0/0)
/// Verify that full Kaspa path derivation does not fail
/// and produces a valid key.
#[cfg(any(test, feature = "verbose-boot"))]
/// Kaspa-specific path derivation (m/44'/111111'/0').
pub fn test_kaspa_path_derivation() -> bool {
    // Use known seed (abandon×11 + about, no passphrase)
    let seed: [u8; 64] = [
        0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08,
        0x48, 0x89, 0xa8, 0xab, 0x91, 0x55, 0x56, 0x81,
        0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8, 0x5e, 0x70,
        0x81, 0x1a, 0xae, 0xd6, 0xf6, 0xda, 0x5f, 0xc1,
        0x9a, 0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70,
        0xd0, 0x86, 0x20, 0x6d, 0xec, 0x8a, 0xa6, 0xc4,
        0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad, 0x3d,
        0x8d, 0x48, 0xb2, 0xd2, 0xce, 0x9e, 0x38, 0xe4,
    ];

    // Derivar path completo de Kaspa mainnet
    let result = derive_path(&seed, KASPA_MAINNET_PATH);
    let key = match result {
        Ok(k) => k,
        Err(_) => return false,
    };

    // The key must be valid
    if is_zero(&key.key) {
        return false;
    }
    if !is_less_than_order(&key.key) {
        return false;
    }
    if key.depth != 5 {
        return false;
    }

    // Must be able to generate public key
    let pubkey = match key.public_key_compressed() {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    // Compressed pubkey: 33 bytes, prefix 02 o 03
    if pubkey[0] != 0x02 && pubkey[0] != 0x03 {
        return false;
    }

    // x-only pubkey (for Kaspa Schnorr): 32 bytes
    key.public_key_x_only().is_ok()
}

/// Test: modular arithmetic
#[cfg(any(test, feature = "verbose-boot"))]
pub fn test_scalar_arithmetic() -> bool {
    // Test 1: 1 + 1 = 2
    let one = {
        let mut a = [0u8; 32];
        a[31] = 1;
        a
    };
    let two = scalar_add_mod_n(&one, &one);
    if two[31] != 2 {
        return false;
    }

    // Test 2: (n-1) + 1 = 0 mod n
    let n_minus_1 = {
        let mut a = SECP256K1_ORDER;
        // Restar 1
        let mut borrow: i16 = 1;
        for i in (0..32).rev() {
            let diff = (a[i] as i16) - borrow;
            if diff < 0 {
                a[i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                a[i] = diff as u8;
                borrow = 0;
            }
        }
        a
    };
    let should_be_zero = scalar_add_mod_n(&n_minus_1, &one);
    if !is_zero(&should_be_zero) {
        return false;
    }

    // Test 3: (n-1) + 2 = 1 mod n
    let two_val = {
        let mut a = [0u8; 32];
        a[31] = 2;
        a
    };
    let should_be_one = scalar_add_mod_n(&n_minus_1, &two_val);
    if should_be_one[31] != 1 {
        return false;
    }
    // Check rest is zero
    for i in 0..31 {
        if should_be_one[i] != 0 {
            return false;
        }
    }

    true
}

/// Test: Multi-address derivation — derive_path_for_index matches derive_path
/// Verifies that derive_path_for_index(seed, 0) == derive_path(seed, KASPA_MAINNET_PATH)
/// and that different indices produce different keys.
#[cfg(any(test, feature = "verbose-boot"))]
pub fn test_multi_address_derivation() -> bool {
    let seed: [u8; 64] = [
        0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08,
        0x48, 0x89, 0xa8, 0xab, 0x91, 0x55, 0x56, 0x81,
        0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8, 0x5e, 0x70,
        0x81, 0x1a, 0xae, 0xd6, 0xf6, 0xda, 0x5f, 0xc1,
        0x9a, 0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70,
        0xd0, 0x86, 0x20, 0x6d, 0xec, 0x8a, 0xa6, 0xc4,
        0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad, 0x3d,
        0x8d, 0x48, 0xb2, 0xd2, 0xce, 0x9e, 0x38, 0xe4,
    ];

    // 1. derive_path_for_index(seed, 0) must match KASPA_MAINNET_PATH
    let key_idx0 = match derive_path_for_index(&seed, 0) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let key_mainnet = match derive_path(&seed, KASPA_MAINNET_PATH) {
        Ok(k) => k,
        Err(_) => return false,
    };
    if key_idx0.private_key_bytes() != key_mainnet.private_key_bytes() {
        return false;
    }

    // 2. derive_account_key + derive_address_key must match derive_path_for_index
    let acct = match derive_account_key(&seed) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let key_idx0_via_acct = match derive_address_key(&acct, 0) {
        Ok(k) => k,
        Err(_) => return false,
    };
    if key_idx0_via_acct.private_key_bytes() != key_idx0.private_key_bytes() {
        return false;
    }

    // 3. Different indices produce different keys
    let key_idx1 = match derive_address_key(&acct, 1) {
        Ok(k) => k,
        Err(_) => return false,
    };
    if key_idx1.private_key_bytes() == key_idx0.private_key_bytes() {
        return false; // indices 0 and 1 must differ
    }

    // 4. find_address_index_for_pubkey works
    let pk0 = match key_idx0.public_key_x_only() {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let pk1 = match key_idx1.public_key_x_only() {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    if find_address_index_for_pubkey(&acct, &pk0) != Some((0, false)) {
        return false;
    }
    if find_address_index_for_pubkey(&acct, &pk1) != Some((1, false)) {
        return false;
    }

    // 5. Non-existent pubkey returns None
    let fake_pk = [0xFFu8; 32];
    if find_address_index_for_pubkey(&acct, &fake_pk).is_some() {
        return false;
    }

    true
}

/// Run all BIP32 tests.
/// Returns (passed, total).
#[cfg(any(test, feature = "verbose-boot"))]
pub fn run_bip32_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 6u32;

    if test_vector1_master() { passed += 1; }
    if test_vector1_official() { passed += 1; }
    if test_vector1_child_hardened() { passed += 1; }
    if test_kaspa_path_derivation() { passed += 1; }
    if test_scalar_arithmetic() { passed += 1; }
    if test_multi_address_derivation() { passed += 1; }

    (passed, total)
}
