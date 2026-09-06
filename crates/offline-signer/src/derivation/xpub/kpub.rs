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

// Kaspa extended-public-key derivation, canonical text encoding, and import.

use crate::derivation::bip32::{
    derive_multisig_account_key, derive_path, Bip32Error, ExtendedPrivKey, ExtendedPubKey,
};
use crate::derivation::hmac::zeroize_buf;
use shared_signer::account_key::{
    decode_account_key_text, encode_account_key_text, validate_account_key_payload,
    ACCOUNT_KEY_CHILD_INDEX, ACCOUNT_KEY_DEPTH, ACCOUNT_KEY_VERSION,
};

use super::{
    base58::base58check_encode,
    constants::{KASPA_ACCOUNT_PATH, KPUB_MAX_LEN, XPUB_PAYLOAD_LEN},
    fingerprint::parent_fingerprint,
};

/// Exact Base58Check length of a historical Kaspa `kpub` account key.
/// v1.0.6 `multi_hd45` descriptors sort and store this textual form.
pub const LEGACY_KPUB_LEN: usize = 111;

/// Complete metadata of a serialized account-level kpub. 45' descriptors
/// must retain every field because parent ordering is over the serialized key,
/// not merely over the compressed public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KpubParts {
    pub depth: u8,
    pub parent_fp: [u8; 4],
    pub child_num: [u8; 4],
    pub chain_code: [u8; 32],
    pub pubkey: [u8; 33],
}

pub(super) fn parts_from_payload(payload: &[u8; XPUB_PAYLOAD_LEN]) -> Option<KpubParts> {
    if payload[..4] != ACCOUNT_KEY_VERSION || !matches!(payload[45], 0x02 | 0x03) {
        return None;
    }
    let mut parts = KpubParts {
        depth: payload[4],
        parent_fp: [0; 4],
        child_num: [0; 4],
        chain_code: [0; 32],
        pubkey: [0; 33],
    };
    parts.parent_fp.copy_from_slice(&payload[5..9]);
    parts.child_num.copy_from_slice(&payload[9..13]);
    parts.chain_code.copy_from_slice(&payload[13..45]);
    parts.pubkey.copy_from_slice(&payload[45..78]);
    Some(parts)
}

/// Decode any supported account-key representation while retaining all BIP32
/// serialization metadata. This is the parser used by `multi_hd45` import.
pub fn parse_kpub_parts(text: &[u8]) -> Option<KpubParts> {
    let mut payload = [0u8; XPUB_PAYLOAD_LEN];
    decode_kpub_compatible(text, &mut payload).ok()?;
    let parts = parts_from_payload(&payload);
    zeroize_buf(&mut payload);
    parts
}

/// Serialize all account-key fields in the historical Base58Check form used by
/// v1.0.6 `multi_hd45` descriptors and the dedicated Multisig kpub QR.
pub fn serialize_legacy_kpub_parts(parts: &KpubParts, out: &mut [u8]) -> usize {
    let mut payload = [0u8; XPUB_PAYLOAD_LEN];
    payload[..4].copy_from_slice(&ACCOUNT_KEY_VERSION);
    payload[4] = parts.depth;
    payload[5..9].copy_from_slice(&parts.parent_fp);
    payload[9..13].copy_from_slice(&parts.child_num);
    payload[13..45].copy_from_slice(&parts.chain_code);
    payload[45..78].copy_from_slice(&parts.pubkey);
    let len = base58check_encode(&payload, out);
    zeroize_buf(&mut payload);
    len
}

/// Derive the account-level 45' cosigner key at `m/45'/111111'/account'`
/// together with the metadata required for deterministic descriptor ordering.
pub fn derive_multisig_account_parts(
    seed: &[u8; 64],
    account: u32,
) -> Result<KpubParts, Bip32Error> {
    if account >= 0x8000_0000 {
        return Err(Bip32Error::InvalidKey);
    }
    let parent_path = [0x8000_002D, 0x8001_B207];
    let parent = derive_path(seed, &parent_path)?;
    let parent_pubkey = parent.public_key_compressed()?;
    let account_key = derive_multisig_account_key(seed, account)?;
    let child = 0x8000_0000u32 + account;
    Ok(KpubParts {
        depth: 3,
        parent_fp: parent_fingerprint(&parent_pubkey),
        child_num: child.to_be_bytes(),
        chain_code: *account_key.chain_code_bytes(),
        pubkey: account_key.public_key_compressed()?,
    })
}

/// Dedicated v1.0.6-compatible 45' multisig kpub export.
pub fn derive_and_serialize_multisig_kpub(
    seed: &[u8; 64],
    out: &mut [u8],
) -> Result<usize, Bip32Error> {
    let parts = derive_multisig_account_parts(seed, 0)?;
    let len = serialize_legacy_kpub_parts(&parts, out);
    if len != LEGACY_KPUB_LEN {
        return Err(Bip32Error::InvalidKey);
    }
    Ok(len)
}

fn write_account_payload(
    account_key: &ExtendedPrivKey,
    parent_fingerprint: [u8; 4],
    child_index: u32,
    out: &mut [u8; XPUB_PAYLOAD_LEN],
) -> Result<(), Bip32Error> {
    out[0..4].copy_from_slice(&ACCOUNT_KEY_VERSION);
    out[4] = ACCOUNT_KEY_DEPTH;

    out[5..9].copy_from_slice(&parent_fingerprint);
    if child_index != ACCOUNT_KEY_CHILD_INDEX {
        return Err(Bip32Error::InvalidKey);
    }
    out[9..13].copy_from_slice(&child_index.to_be_bytes());
    out[13..45].copy_from_slice(account_key.chain_code_bytes());
    out[45..78].copy_from_slice(&account_key.public_key_compressed()?);
    Ok(())
}

/// Encode a raw account-key payload as canonical lowercase text.
///
/// Format: `kpub1:` followed by exactly 156 lowercase hexadecimal characters.
pub fn encode_kpub_text(
    payload: &[u8; XPUB_PAYLOAD_LEN],
    out: &mut [u8; KPUB_MAX_LEN],
) -> Result<usize, Bip32Error> {
    encode_account_key_text(payload, out).ok_or(Bip32Error::InvalidKey)
}

/// Decode the canonical `kpub1:` text form into its 78-byte payload.
pub fn decode_kpub_text(
    text: &[u8],
    out: &mut [u8; XPUB_PAYLOAD_LEN],
) -> Result<usize, Bip32Error> {
    decode_account_key_text(text, out).ok_or(Bip32Error::InvalidKey)
}

/// Decode canonical `kpub1:` text, a historical Base58Check kpub, or an
/// account-level BIP32 xpub.
pub fn decode_kpub_compatible(
    text: &[u8],
    out: &mut [u8; XPUB_PAYLOAD_LEN],
) -> Result<usize, Bip32Error> {
    if let Some(length) = decode_account_key_text(text, out) {
        return Ok(length);
    }
    if shared_signer::legacy_account_key::decode_legacy_kpub(text, out).is_ok()
        || shared_signer::legacy_account_key::decode_bip32_xpub(text, out).is_ok()
    {
        return Ok(XPUB_PAYLOAD_LEN);
    }
    Err(Bip32Error::InvalidKey)
}

/// Normalize any supported account-key text to canonical `kpub1:` form.
pub fn normalize_kpub_text(text: &[u8], out: &mut [u8; KPUB_MAX_LEN]) -> Result<usize, Bip32Error> {
    let mut payload = [0u8; XPUB_PAYLOAD_LEN];
    decode_kpub_compatible(text, &mut payload)?;
    let result = encode_kpub_text(&payload, out);
    zeroize_buf(&mut payload);
    result
}

/// Serialize an account-level extended public key in canonical `kpub1:` form.
pub fn serialize_kpub(
    account_key: &ExtendedPrivKey,
    parent_pubkey_compressed: &[u8; 33],
    child_index: u32,
    out: &mut [u8; KPUB_MAX_LEN],
) -> Result<usize, Bip32Error> {
    let mut payload = [0u8; XPUB_PAYLOAD_LEN];
    write_account_payload(
        account_key,
        parent_fingerprint(parent_pubkey_compressed),
        child_index,
        &mut payload,
    )?;
    let result = encode_kpub_text(&payload, out);
    zeroize_buf(&mut payload);
    result
}

/// Serialize an imported account key using its original parent fingerprint.
pub fn serialize_account_kpub(
    account_key: &ExtendedPrivKey,
    parent_fingerprint: [u8; 4],
    out: &mut [u8; KPUB_MAX_LEN],
) -> Result<usize, Bip32Error> {
    let mut payload = [0u8; XPUB_PAYLOAD_LEN];
    write_account_payload(
        account_key,
        parent_fingerprint,
        KASPA_ACCOUNT_PATH[2],
        &mut payload,
    )?;
    let result = encode_kpub_text(&payload, out);
    zeroize_buf(&mut payload);
    result
}

/// Derive the account key at `m/44'/111111'/0'` and encode it as `kpub1:` text.
pub fn derive_and_serialize_kpub(
    seed: &[u8; 64],
    out: &mut [u8; KPUB_MAX_LEN],
) -> Result<usize, Bip32Error> {
    let parent_path = [0x8000_002C, 0x8001_B207];
    let parent_key = derive_path(seed, &parent_path)?;
    let parent_pubkey = parent_key.public_key_compressed()?;
    let account_key = derive_path(seed, &KASPA_ACCOUNT_PATH)?;
    serialize_kpub(&account_key, &parent_pubkey, KASPA_ACCOUNT_PATH[2], out)
}

/// Derive the account key and write its raw 78-byte payload.
pub fn derive_account_raw_kpub_payload(
    seed: &[u8; 64],
    out: &mut [u8; XPUB_PAYLOAD_LEN],
) -> Result<usize, Bip32Error> {
    let parent_path = [0x8000_002C, 0x8001_B207];
    let parent_key = derive_path(seed, &parent_path)?;
    let parent_pubkey = parent_key.public_key_compressed()?;
    let account_key = derive_path(seed, &KASPA_ACCOUNT_PATH)?;
    write_account_payload(
        &account_key,
        parent_fingerprint(&parent_pubkey),
        KASPA_ACCOUNT_PATH[2],
        out,
    )?;
    Ok(XPUB_PAYLOAD_LEN)
}

/// Convert canonical `kpub1:` text to its raw payload.
pub fn kpub_text_to_raw(
    text: &[u8],
    out: &mut [u8; XPUB_PAYLOAD_LEN],
) -> Result<usize, Bip32Error> {
    decode_kpub_text(text, out)
}

/// Import canonical `kpub1:` text as an extended public key.
pub fn import_kpub(kpub_text: &[u8]) -> Result<ExtendedPubKey, Bip32Error> {
    let mut payload = [0u8; XPUB_PAYLOAD_LEN];
    decode_kpub_compatible(kpub_text, &mut payload)?;
    let result = import_kpub_raw(&payload);
    zeroize_buf(&mut payload);
    result
}

/// Import the raw 78-byte account-key payload.
pub fn import_kpub_raw(payload: &[u8]) -> Result<ExtendedPubKey, Bip32Error> {
    if !validate_account_key_payload(payload) {
        return Err(Bip32Error::InvalidKey);
    }

    let depth = payload[4];
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&payload[13..45]);
    let mut pubkey = [0u8; 33];
    pubkey.copy_from_slice(&payload[45..78]);

    Ok(ExtendedPubKey {
        pubkey,
        chain_code,
        depth,
    })
}

/// Import the binary QR envelope used by KasSigner devices.
pub fn import_kpub_qr(blob: &[u8]) -> Result<ExtendedPubKey, Bip32Error> {
    let raw =
        kassigner_protocol::wire::qr_payload::unwrap_v1_raw(blob).ok_or(Bip32Error::InvalidKey)?;
    import_kpub_raw(raw)
}
