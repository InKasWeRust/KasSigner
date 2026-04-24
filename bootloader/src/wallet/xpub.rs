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

// KasSigner — Extended Public Key (kpub) Export
// 100% Rust, no-std, no-alloc
//
// Implements:
//   - Base58 encoding (Bitcoin alphabet)
//   - Base58Check: payload + 4-byte SHA256d checksum
//   - BIP32 xpub serialization with Kaspa version bytes
//   - Account-level key derivation: m/44'/111111'/0'
//
// The resulting "kpub..." string is compatible with Kaspium and
// KasWare for watch-only wallet import.


use sha2::{Sha256, Digest};
use super::bip32::{ExtendedPrivKey, derive_path, Bip32Error};
use super::hmac::zeroize_buf;

// ─── Constants ────────────────────────────────────────────────────────

/// Kaspa mainnet extended public key version bytes.
/// Encodes to "kpub" prefix in base58.
const KASPA_XPUB_VERSION: [u8; 4] = [0x03, 0x8f, 0x33, 0x2e];

/// BIP32 serialized extended key is always 78 bytes.
pub const XPUB_PAYLOAD_LEN: usize = 78;

/// Maximum base58check output length for 78-byte payload.
/// 78 bytes + 4 checksum = 82 bytes → max ~112 base58 chars.
/// Standard xpub is 111 chars. We allocate 120 for safety.
pub const KPUB_MAX_LEN: usize = 120;

/// Kaspa account-level path: m/44'/111111'/0'
/// (3 levels, all hardened — this is the xpub derivation point)
const KASPA_ACCOUNT_PATH: [u32; 3] = [
    0x8000_002C, // 44'
    0x8001_B207, // 111111'
    0x8000_0000, // 0'
];

/// Bitcoin base58 alphabet
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// ─── Base58 Encoding ──────────────────────────────────────────────────

/// Encode bytes as base58 string. Returns the number of chars written to `out`.
///
/// Algorithm: repeatedly divmod by 58 on the big-endian integer,
/// then reverse. Leading zero bytes become '1' characters.
fn base58_encode(data: &[u8], out: &mut [u8]) -> usize {
    // Count leading zeros
    let mut leading_zeros = 0usize;
    for &b in data {
        if b == 0 { leading_zeros += 1; } else { break; }
    }

    // Work buffer: copy input as big-endian integer
    // Max input is 82 bytes (78 + 4 checksum)
    let mut buf = [0u8; 128];
    let len = data.len().min(128);
    buf[..len].copy_from_slice(&data[..len]);

    // Encode: divmod 58 repeatedly
    let mut encoded = [0u8; 128];
    let mut encoded_len = 0usize;

    let mut start = 0usize;
    while start < len {
        // Skip leading zeros in work buffer
        while start < len && buf[start] == 0 {
            start += 1;
        }
        if start >= len { break; }

        // Divide the entire number by 58
        let mut remainder: u32 = 0;
        for i in start..len {
            let val = (remainder << 8) | (buf[i] as u32);
            buf[i] = (val / 58) as u8;
            remainder = val % 58;
        }

        encoded[encoded_len] = BASE58_ALPHABET[remainder as usize];
        encoded_len += 1;
    }

    // Write leading '1's for leading zero bytes
    let mut pos = 0usize;
    for _ in 0..leading_zeros {
        if pos < out.len() {
            out[pos] = b'1';
            pos += 1;
        }
    }

    // Write encoded digits in reverse order
    for i in (0..encoded_len).rev() {
        if pos < out.len() {
            out[pos] = encoded[i];
            pos += 1;
        }
    }

    pos
}

/// SHA256 double hash (SHA256d): SHA256(SHA256(data))
fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize()
    };
    let mut h = Sha256::new();
    h.update(first);
    let result: [u8; 32] = h.finalize().into();
    result
}

/// Base58Check encode: data + 4-byte SHA256d checksum → base58 string.
/// Returns the number of chars written to `out`.
fn base58check_encode(data: &[u8], out: &mut [u8]) -> usize {
    // Compute checksum
    let checksum = sha256d(data);

    // Build payload + checksum
    let total_len = data.len() + 4;
    let mut buf = [0u8; 128];
    buf[..data.len()].copy_from_slice(data);
    buf[data.len()..total_len].copy_from_slice(&checksum[..4]);

    base58_encode(&buf[..total_len], out)
}

// ─── BIP32 xpub Serialization ─────────────────────────────────────────

/// Serialize an account-level extended public key in BIP32 format.
///
/// Format (78 bytes):
///   [4] version bytes (0x038f332e for Kaspa "kpub")
///   [1] depth (3 for account level)
///   [4] parent fingerprint (hash160 of parent pubkey, first 4 bytes)
///   [4] child index (big-endian, last path component)
///   [32] chain code
///   [33] compressed public key (02/03 prefix + X coordinate)
///
/// Returns the number of base58check chars written to `out`.
pub fn serialize_kpub(
    account_key: &ExtendedPrivKey,
    parent_pubkey_compressed: &[u8; 33],
    child_index: u32,
    out: &mut [u8; KPUB_MAX_LEN],
) -> Result<usize, Bip32Error> {
    let mut payload = [0u8; XPUB_PAYLOAD_LEN];

    // Version bytes
    payload[0..4].copy_from_slice(&KASPA_XPUB_VERSION);

    // Depth = 3 (m / 44' / 111111' / 0')
    payload[4] = 3;

    // Parent fingerprint: HASH160(parent_compressed_pubkey)[0..4]
    // HASH160 = RIPEMD160(SHA256(pubkey))
    // Since we don't have RIPEMD160, we use SHA256 and take first 4 bytes.
    // This matches kaspad's behavior for Schnorr keys.
    let parent_sha = {
        let mut h = Sha256::new();
        h.update(parent_pubkey_compressed);
        let result: [u8; 32] = h.finalize().into();
        result
    };
    payload[5..9].copy_from_slice(&parent_sha[..4]);

    // Child index (big-endian)
    payload[9] = (child_index >> 24) as u8;
    payload[10] = (child_index >> 16) as u8;
    payload[11] = (child_index >> 8) as u8;
    payload[12] = child_index as u8;

    // Chain code (32 bytes)
    payload[13..45].copy_from_slice(account_key.chain_code_bytes());

    // Compressed public key (33 bytes)
    let pubkey = account_key.public_key_compressed()?;
    payload[45..78].copy_from_slice(&pubkey);

    // Base58Check encode
    let len = base58check_encode(&payload, out);

    // Zeroize payload (contains chain code which is sensitive)
    zeroize_buf(&mut payload);

    Ok(len)
}

/// Derive the account-level extended key at m/44'/111111'/0'
/// and serialize as a Kaspa kpub string.
///
/// Returns the number of chars written to `out`, or an error.
pub fn derive_and_serialize_kpub(
    seed: &[u8; 64],
    out: &mut [u8; KPUB_MAX_LEN],
) -> Result<usize, Bip32Error> {
    // Derive parent key at m/44'/111111' (depth 2) for fingerprint
    let parent_path: [u32; 2] = [
        0x8000_002C, // 44'
        0x8001_B207, // 111111'
    ];
    let parent_key = derive_path(seed, &parent_path)?;
    let parent_pubkey = parent_key.public_key_compressed()?;

    // Derive account key at m/44'/111111'/0' (depth 3)
    let account_key = derive_path(seed, &KASPA_ACCOUNT_PATH)?;

    // Serialize
    let len = serialize_kpub(
        &account_key,
        &parent_pubkey,
        KASPA_ACCOUNT_PATH[2], // 0x80000000 (0' hardened)
        out,
    )?;

    Ok(len)
}

/// Derive the account-level extended key at m/44'/111111'/0' and
/// produce the **raw 78-byte serialized payload** (same layout as the
/// base58-decoded body of a legacy kpub string, without the base58
/// check encoding).
///
/// Used by the V1-raw QR export path: the 78-byte payload gets a
/// 1-byte version header prepended (`qr::payload::PAYLOAD_V1_RAW`),
/// giving a 79-byte compact QR blob that fits a V4 byte-mode QR —
/// much smaller than the ~111-char base58 ASCII form (V6-V7).
///
/// Writes to the first 78 bytes of `out` and returns the length
/// written (always 78), or an error if key derivation fails.
pub fn derive_account_raw_kpub_payload(
    seed: &[u8; 64],
    out: &mut [u8; XPUB_PAYLOAD_LEN],
) -> Result<usize, Bip32Error> {
    // Derive parent key at m/44'/111111' (depth 2) for fingerprint
    let parent_path: [u32; 2] = [
        0x8000_002C, // 44'
        0x8001_B207, // 111111'
    ];
    let parent_key = derive_path(seed, &parent_path)?;
    let parent_pubkey = parent_key.public_key_compressed()?;

    // Derive account key at m/44'/111111'/0' (depth 3)
    let account_key = derive_path(seed, &KASPA_ACCOUNT_PATH)?;

    // Version bytes
    out[0..4].copy_from_slice(&KASPA_XPUB_VERSION);

    // Depth = 3
    out[4] = 3;

    // Parent fingerprint: SHA256 of compressed parent pubkey, first 4 bytes
    // (matches kaspad convention — see serialize_kpub for rationale).
    let parent_sha = {
        let mut h = Sha256::new();
        h.update(parent_pubkey);
        let result: [u8; 32] = h.finalize().into();
        result
    };
    out[5..9].copy_from_slice(&parent_sha[..4]);

    // Child index (0x80000000 = 0' hardened), big-endian
    let child_index = KASPA_ACCOUNT_PATH[2];
    out[9] = (child_index >> 24) as u8;
    out[10] = (child_index >> 16) as u8;
    out[11] = (child_index >> 8) as u8;
    out[12] = child_index as u8;

    // Chain code (32 bytes) — sensitive
    out[13..45].copy_from_slice(account_key.chain_code_bytes());

    // Compressed public key (33 bytes)
    let pubkey = account_key.public_key_compressed()?;
    out[45..78].copy_from_slice(&pubkey);

    Ok(XPUB_PAYLOAD_LEN)
}

/// Convert a legacy ASCII base58check-encoded kpub string into its
/// 78-byte raw payload form. Used by the multi-frame V1-raw export
/// path so the export handler does not need to re-derive from the
/// seed (no extra PBKDF2 cost, no additional key-material exposure).
///
/// Returns the number of bytes written (always `XPUB_PAYLOAD_LEN`
/// on success), or an error if the input isn't a valid kpub.
pub fn kpub_ascii_to_raw(
    ascii: &[u8],
    out: &mut [u8; XPUB_PAYLOAD_LEN],
) -> Result<usize, Bip32Error> {
    let mut buf = [0u8; 128];
    let plen = base58check_decode(ascii, &mut buf);
    if plen != XPUB_PAYLOAD_LEN {
        zeroize_buf(&mut buf);
        return Err(Bip32Error::InvalidKey);
    }
    // Sanity-check the version bytes match Kaspa kpub.
    if buf[0..4] != KASPA_XPUB_VERSION {
        zeroize_buf(&mut buf);
        return Err(Bip32Error::InvalidKey);
    }
    out[..XPUB_PAYLOAD_LEN].copy_from_slice(&buf[..XPUB_PAYLOAD_LEN]);
    zeroize_buf(&mut buf);
    Ok(XPUB_PAYLOAD_LEN)
}

// ─── XPrv (Extended Private Key) ─────────────────────────────────────

/// Kaspa mainnet extended private key version bytes.
/// Encodes to "xprv" prefix in base58.
const KASPA_XPRV_VERSION: [u8; 4] = [0x03, 0x8f, 0x2e, 0xf4];

/// Maximum base58check output length for xprv.
pub const XPRV_MAX_LEN: usize = 120;

/// Derive the account-level extended private key at m/44'/111111'/0'
/// and serialize as a Kaspa xprv string.
pub fn derive_and_serialize_xprv(
    seed: &[u8; 64],
    out: &mut [u8; XPRV_MAX_LEN],
) -> Result<usize, Bip32Error> {
    // Derive parent key at m/44'/111111' for fingerprint
    let parent_path: [u32; 2] = [0x8000_002C, 0x8001_B207];
    let parent_key = derive_path(seed, &parent_path)?;
    let parent_pubkey = parent_key.public_key_compressed()?;

    // Derive account key at m/44'/111111'/0'
    let account_key = derive_path(seed, &KASPA_ACCOUNT_PATH)?;

    // Serialize as BIP32 xprv (78 bytes)
    let mut payload = [0u8; XPUB_PAYLOAD_LEN];

    // Version bytes (xprv)
    payload[0..4].copy_from_slice(&KASPA_XPRV_VERSION);

    // Depth = 3
    payload[4] = 3;

    // Parent fingerprint
    let parent_sha = {
        let mut h = Sha256::new();
        h.update(parent_pubkey);
        let result: [u8; 32] = h.finalize().into();
        result
    };
    payload[5..9].copy_from_slice(&parent_sha[..4]);

    // Child index (0x80000000 = 0' hardened)
    payload[9..13].copy_from_slice(&KASPA_ACCOUNT_PATH[2].to_be_bytes());

    // Chain code (32 bytes)
    payload[13..45].copy_from_slice(account_key.chain_code_bytes());

    // Private key: 0x00 prefix + 32-byte key
    payload[45] = 0x00;
    payload[46..78].copy_from_slice(account_key.private_key_bytes());

    let len = base58check_encode(&payload, out);
    zeroize_buf(&mut payload);

    Ok(len)
}

// ─── Base58 Decode ───────────────────────────────────────────────────

/// Reverse lookup: base58 char → value (0-57), or 0xFF for invalid.
fn base58_char_value(ch: u8) -> u8 {
    for (i, &c) in BASE58_ALPHABET.iter().enumerate() {
        if c == ch { return i as u8; }
    }
    0xFF
}

/// Base58 decode. Returns number of bytes written to `out`, or 0 on error.
fn base58_decode(input: &[u8], out: &mut [u8; 128]) -> usize {
    if input.is_empty() { return 0; }

    // Count leading '1's (map to leading zero bytes)
    let mut leading_ones = 0usize;
    for &ch in input {
        if ch == b'1' { leading_ones += 1; } else { break; }
    }

    // Convert base58 to big-endian bytes via repeated multiply+add
    let mut buf = [0u8; 128];
    let mut buf_len = 0usize;

    for &ch in input {
        let val = base58_char_value(ch);
        if val == 0xFF { return 0; }

        // Multiply buf by 58 and add val
        let mut carry = val as u32;
        for j in (0..buf_len).rev() {
            carry += (buf[j] as u32) * 58;
            buf[j] = (carry & 0xFF) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            if buf_len >= 128 { return 0; }
            // Shift right to make room
            let mut j = buf_len;
            while j > 0 {
                buf[j] = buf[j - 1];
                j -= 1;
            }
            buf[0] = (carry & 0xFF) as u8;
            carry >>= 8;
            buf_len += 1;
        }
        if buf_len == 0 && val > 0 {
            buf[0] = val;
            buf_len = 1;
        }
    }

    let mut pos = 0;
    for _ in 0..leading_ones {
        if pos < 128 { out[pos] = 0; pos += 1; }
    }
    for i in 0..buf_len {
        if pos < 128 { out[pos] = buf[i]; pos += 1; }
    }
    pos
}

/// Base58Check decode: verify checksum, return payload bytes.
/// Returns payload length, or 0 on error.
fn base58check_decode(input: &[u8], out: &mut [u8; 128]) -> usize {
    let mut raw = [0u8; 128];
    let raw_len = base58_decode(input, &mut raw);
    if raw_len < 5 { return 0; }

    let payload_len = raw_len - 4;
    let checksum = sha256d(&raw[..payload_len]);

    if raw[payload_len] != checksum[0]
        || raw[payload_len + 1] != checksum[1]
        || raw[payload_len + 2] != checksum[2]
        || raw[payload_len + 3] != checksum[3]
    {
        return 0;
    }

    out[..payload_len].copy_from_slice(&raw[..payload_len]);
    payload_len
}

/// Import a Kaspa xprv string → ExtendedPrivKey.
/// Accepts base58check-encoded xprv at account level.
pub fn import_xprv(xprv_str: &[u8]) -> Result<ExtendedPrivKey, Bip32Error> {
    let mut payload = [0u8; 128];
    let plen = base58check_decode(xprv_str, &mut payload);

    if plen != XPUB_PAYLOAD_LEN {
        return Err(Bip32Error::InvalidKey);
    }

    if payload[0..4] != KASPA_XPRV_VERSION {
        return Err(Bip32Error::InvalidKey);
    }

    let depth = payload[4];

    if payload[45] != 0x00 {
        return Err(Bip32Error::InvalidKey);
    }

    let mut key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    key.copy_from_slice(&payload[46..78]);
    chain_code.copy_from_slice(&payload[13..45]);

    zeroize_buf(&mut payload);

    Ok(ExtendedPrivKey::from_parts(key, chain_code, depth))
}

/// Import a Kaspa kpub string → 32-byte x-only public key.
/// Accepts base58check-encoded kpub at account level.
/// Returns the 32-byte x-coordinate of the compressed public key.
/// Decode a Kaspa account-level xpub (kpub) and return the full
/// extended public key (compressed 33-byte pubkey + 32-byte chain code).
///
/// HD-multisig callers need BOTH the parent pubkey and chain code to
/// derive per-address child pubkeys via `derive_child_pub()`. Callers
/// that only need the x-only account pubkey can use `.x_only()` on
/// the returned `ExtendedPubKey`.
pub fn import_kpub(kpub_str: &[u8]) -> Result<super::bip32::ExtendedPubKey, Bip32Error> {
    let mut payload = [0u8; 128];
    let plen = base58check_decode(kpub_str, &mut payload);

    if plen != XPUB_PAYLOAD_LEN {
        return Err(Bip32Error::InvalidKey);
    }

    // Check kpub version bytes
    if payload[0..4] != KASPA_XPUB_VERSION {
        return Err(Bip32Error::InvalidKey);
    }

    // Payload layout:
    //   [0..4]    version
    //   [4]       depth
    //   [5..9]    parent fingerprint
    //   [9..13]   child number
    //   [13..45]  chain code (32 bytes)
    //   [45..78]  compressed pubkey (33 bytes, 02/03 prefix + X)
    let depth = payload[4];
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&payload[13..45]);
    let mut pubkey = [0u8; 33];
    pubkey.copy_from_slice(&payload[45..78]);

    zeroize_buf(&mut payload);

    Ok(super::bip32::ExtendedPubKey {
        pubkey,
        chain_code,
        depth,
    })
}

/// Import a Kaspa kpub from its raw 78-byte payload (no base58 wrapping).
///
/// This is the V1 binary format: the bytes match the base58-decoded
/// payload of a legacy kpub string. Used by QR decoders that received
/// a V1_RAW-wrapped payload (after stripping the 1-byte version
/// header). Pure byte parsing — no encoding conversion.
pub fn import_kpub_raw(payload: &[u8]) -> Result<super::bip32::ExtendedPubKey, Bip32Error> {
    if payload.len() != XPUB_PAYLOAD_LEN {
        return Err(Bip32Error::InvalidKey);
    }
    if payload[0..4] != KASPA_XPUB_VERSION {
        return Err(Bip32Error::InvalidKey);
    }

    let depth = payload[4];
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&payload[13..45]);
    let mut pubkey = [0u8; 33];
    pubkey.copy_from_slice(&payload[45..78]);

    Ok(super::bip32::ExtendedPubKey {
        pubkey,
        chain_code,
        depth,
    })
}

/// Version-aware kpub import that accepts either a legacy base58
/// string or a V1_RAW-wrapped payload. Dispatches based on the
/// 1-byte format header defined in `qr::payload`.
///
/// This is the entry point QR-scan handlers should use when they
/// don't already know which format they received.
pub fn import_kpub_any(blob: &[u8]) -> Result<super::bip32::ExtendedPubKey, Bip32Error> {
    use crate::qr::payload::{classify, PayloadKind};
    match classify(blob) {
        PayloadKind::V1Raw(raw) => import_kpub_raw(raw),
        PayloadKind::Legacy(ascii) => import_kpub(ascii),
    }
}

// ─── Self-Tests ───────────────────────────────────────────────────────

/// Test base58 encoding with known vectors
fn test_base58_encoding() -> bool {
    // Test vector: empty → ""
    let mut out = [0u8; 64];
    let len = base58_encode(&[], &mut out);
    if len != 0 { return false; }

    // Test vector: [0] → "1"
    let len = base58_encode(&[0], &mut out);
    if len != 1 || out[0] != b'1' { return false; }

    // Test vector: [0, 0, 1] → "112"
    let len = base58_encode(&[0, 0, 1], &mut out);
    if len != 3 || &out[..3] != b"112" { return false; }

    // Test vector: "Hello World" → "JxF12TrwUP45BMd"
    let len = base58_encode(b"Hello World", &mut out);
    if len != 15 || &out[..15] != b"JxF12TrwUP45BMd" { return false; }

    true
}

/// Test base58check encoding
fn test_base58check() -> bool {
    // Base58Check of a single zero byte should produce specific output
    // (this is used as Bitcoin version 0x00 → address starting with "1")
    let mut out = [0u8; 64];
    let len = base58check_encode(&[0u8; 1], &mut out);
    // SHA256d([0x00]) checksum is known, result should start with '1'
    if len == 0 || out[0] != b'1' { return false; }

    true
}

/// Test SHA256d
fn test_sha256d() -> bool {
    // SHA256d("") = SHA256(SHA256(""))
    // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    // SHA256(above) = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
    let h = sha256d(b"");
    h[0] == 0x5d && h[1] == 0xf6 && h[2] == 0xe0 && h[3] == 0xe2
}

/// Test kpub derivation produces a string starting with "kpub"
fn test_kpub_prefix() -> bool {
    // Use a known test seed (BIP39 test vector 1)
    // Mnemonic: "abandon abandon ... about"
    // Seed (hex): 5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1...
    // We'll use a simpler approach: derive from a fixed 64-byte seed
    let mut seed = [0u8; 64];
    // Fill with deterministic data for testing
    for i in 0..64 {
        seed[i] = (i as u8).wrapping_mul(7).wrapping_add(13);
    }

    let mut out = [0u8; KPUB_MAX_LEN];
    match derive_and_serialize_kpub(&seed, &mut out) {
        Ok(len) => {
            // Must start with "kpub"
            if len < 4 { return false; }
            &out[..4] == b"kpub"
        }
        Err(_) => false,
    }
}

/// Run extended public key test suite.
pub fn run_xpub_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 4u32;

    if test_base58_encoding() { passed += 1; }
    if test_base58check() { passed += 1; }
    if test_sha256d() { passed += 1; }
    if test_kpub_prefix() { passed += 1; }

    (passed, total)
}
