// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Kaspa account extended-private-key derivation, serialization, and import.

use crate::derivation::bip32::{derive_path, Bip32Error, ExtendedPrivKey};
use crate::derivation::hmac::zeroize_buf;

use super::{
    base58::{base58check_decode, base58check_encode},
    constants::{KASPA_ACCOUNT_PATH, KASPA_XPRV_VERSION, XPRV_MAX_LEN, XPUB_PAYLOAD_LEN},
    fingerprint::parent_fingerprint,
};

/// Imported account XPrv plus the BIP32 metadata needed for exact re-export.
pub struct ImportedAccountXprv {
    pub key: ExtendedPrivKey,
    pub parent_fingerprint: [u8; 4],
}

fn serialize_account_xprv(
    account_key: &ExtendedPrivKey,
    parent_fingerprint: [u8; 4],
    out: &mut [u8; XPRV_MAX_LEN],
) -> Result<usize, Bip32Error> {
    if account_key.depth != 3 {
        return Err(Bip32Error::InvalidKey);
    }

    let mut payload = [0u8; XPUB_PAYLOAD_LEN];
    payload[0..4].copy_from_slice(&KASPA_XPRV_VERSION);
    payload[4] = 3;
    payload[5..9].copy_from_slice(&parent_fingerprint);
    payload[9..13].copy_from_slice(&KASPA_ACCOUNT_PATH[2].to_be_bytes());
    payload[13..45].copy_from_slice(account_key.chain_code_bytes());
    payload[45] = 0;
    payload[46..78].copy_from_slice(account_key.private_key_bytes());

    let length = base58check_encode(&payload, out);
    zeroize_buf(&mut payload);
    Ok(length)
}

/// Serialize an already-imported account XPrv without discarding its metadata.
pub fn serialize_imported_xprv(
    imported: &ImportedAccountXprv,
    out: &mut [u8; XPRV_MAX_LEN],
) -> Result<usize, Bip32Error> {
    serialize_account_xprv(&imported.key, imported.parent_fingerprint, out)
}

/// Serialize an account key and its original parent fingerprint.
pub fn serialize_account_key_xprv(
    account_key: &ExtendedPrivKey,
    parent_fingerprint: [u8; 4],
    out: &mut [u8; XPRV_MAX_LEN],
) -> Result<usize, Bip32Error> {
    serialize_account_xprv(account_key, parent_fingerprint, out)
}

/// Derive the account-level extended private key at m/44'/111111'/0'
/// and serialize as a Kaspa xprv string.
pub fn derive_and_serialize_xprv(
    seed: &[u8; 64],
    out: &mut [u8; XPRV_MAX_LEN],
) -> Result<usize, Bip32Error> {
    let parent_path: [u32; 2] = [0x8000_002C, 0x8001_B207];
    let parent_key = derive_path(seed, &parent_path)?;
    let parent_pubkey = parent_key.public_key_compressed()?;
    let account_key = derive_path(seed, &KASPA_ACCOUNT_PATH)?;
    serialize_account_xprv(&account_key, parent_fingerprint(&parent_pubkey), out)
}

/// Import an account-level Kaspa xprv and preserve its BIP32 metadata.
pub fn import_xprv_with_metadata(xprv_text: &[u8]) -> Result<ImportedAccountXprv, Bip32Error> {
    let mut payload = [0u8; 128];
    let payload_length = base58check_decode(xprv_text, &mut payload);

    let result = (|| {
        if payload_length != XPUB_PAYLOAD_LEN
            || payload[0..4] != KASPA_XPRV_VERSION
            || payload[4] != 3
            || payload[9..13] != KASPA_ACCOUNT_PATH[2].to_be_bytes()
            || payload[45] != 0
        {
            return Err(Bip32Error::InvalidKey);
        }

        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&payload[5..9]);
        let mut key = [0u8; 32];
        key.copy_from_slice(&payload[46..78]);
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&payload[13..45]);
        let account = ExtendedPrivKey::from_parts(key, chain_code, payload[4]);
        account
            .public_key_compressed()
            .map_err(|_| Bip32Error::InvalidKey)?;
        Ok(ImportedAccountXprv {
            key: account,
            parent_fingerprint,
        })
    })();

    zeroize_buf(&mut payload);
    result
}

/// Import a Kaspa account xprv. Metadata-free callers receive only the key.
pub fn import_xprv(xprv_text: &[u8]) -> Result<ExtendedPrivKey, Bip32Error> {
    import_xprv_with_metadata(xprv_text).map(|imported| imported.key)
}
