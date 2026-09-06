// KasSee Web — BIP32 key derivation
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: MIT OR Apache-2.0
//
// bip32.rs — Parse kpub, derive receive/change addresses.
// Pure Rust using k256 crate (no C, no ring).
// Derived from project-owned KasSigner offline-signer and historical KasSee implementations.
// The KasSigner Project copyright holder intentionally dual-licensed this public watch-only
// protocol implementation under MIT OR Apache-2.0; the GPL application copies remain GPL.

//! BIP-32 hierarchical key derivation and the watch-only wallet descriptor model.

use hmac::{Hmac, Mac};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::PublicKey;
use serde::{Deserialize, Serialize};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

// ─── Data types ───

#[derive(Serialize, Deserialize, Clone)]
pub struct WalletData {
    pub kpub: String,
    pub receive_addresses: Vec<String>,
    pub change_addresses: Vec<String>,
    #[serde(default)]
    pub next_receive_index: usize,
    #[serde(default)]
    pub next_change_index: usize,
}

// ─── Extended public key ───

use shared_signer::account_key::{
    decode_account_key_text, encode_account_key_text, validate_account_key_payload,
    ACCOUNT_KEY_PAYLOAD_LEN, ACCOUNT_KEY_TEXT_LEN,
};
use shared_signer::legacy_account_key::{decode_bip32_xpub, decode_legacy_kpub};

pub fn decode_kpub_text(kpub_text: &str) -> Result<[u8; ACCOUNT_KEY_PAYLOAD_LEN], String> {
    let mut payload = [0u8; ACCOUNT_KEY_PAYLOAD_LEN];
    if decode_account_key_text(kpub_text.as_bytes(), &mut payload).is_some()
        || decode_legacy_kpub(kpub_text.as_bytes(), &mut payload).is_ok()
        || decode_bip32_xpub(kpub_text.as_bytes(), &mut payload).is_ok()
    {
        return Ok(payload);
    }
    Err(
        "Account key must be canonical kpub1 text, an original Base58Check kpub, or an account-level BIP32 xpub"
            .to_string(),
    )
}

fn canonical_kpub_text(payload: &[u8; ACCOUNT_KEY_PAYLOAD_LEN]) -> Result<String, String> {
    let mut encoded = [0u8; ACCOUNT_KEY_TEXT_LEN];
    let length = encode_account_key_text(payload, &mut encoded)
        .ok_or_else(|| "Account-key payload is not canonical".to_string())?;
    core::str::from_utf8(&encoded[..length])
        .map(str::to_string)
        .map_err(|_| "Canonical account-key text is not UTF-8".to_string())
}

pub struct ExtPubKey {
    pub key: PublicKey,
    pub chain_code: [u8; 32],
    pub depth: u8,
}

impl ExtPubKey {
    /// Parse the canonical `kpub1:` account-key text format.
    pub fn from_kpub(kpub_text: &str) -> Result<Self, String> {
        let payload = decode_kpub_text(kpub_text)?;
        Self::from_raw_payload(&payload)
    }

    /// Parse the 78-byte account-key payload used by the binary QR envelope.
    pub fn from_raw_payload(payload: &[u8]) -> Result<Self, String> {
        if !validate_account_key_payload(payload) {
            return Err(format!(
                "Raw account-key payload is not canonical ({} bytes)",
                payload.len()
            ));
        }

        let depth = payload[4];
        let chain_code: [u8; 32] = payload[13..45].try_into().map_err(|_| "Bad chain code")?;
        let key_bytes = &payload[45..78];

        let key =
            PublicKey::from_sec1_bytes(key_bytes).map_err(|e| format!("Invalid pubkey: {}", e))?;

        Ok(Self {
            key,
            chain_code,
            depth,
        })
    }

    /// Derive a non-hardened child key from the compressed parent key and child index.
    pub fn derive_child(&self, index: u32) -> Result<Self, String> {
        if index >= 0x80000000 {
            return Err("Cannot derive hardened child from public key".into());
        }

        let parent_point = self.key.to_encoded_point(true);
        let parent_bytes = parent_point.as_bytes(); // 33 bytes compressed

        let mut mac =
            HmacSha512::new_from_slice(&self.chain_code).map_err(|_| "HMAC init failed")?;
        mac.update(parent_bytes);
        mac.update(&index.to_be_bytes());
        let result = mac.finalize().into_bytes();

        let il = &result[..32]; // tweak scalar
        let ir = &result[32..]; // child chain code

        // Child key = parent_key + il*G (point addition via scalar tweak)
        use k256::elliptic_curve::ops::Add;
        use k256::elliptic_curve::ScalarPrimitive;
        use k256::Secp256k1;

        let tweak = ScalarPrimitive::<Secp256k1>::from_slice(il)
            .map_err(|e| format!("Invalid tweak: {}", e))?;
        let tweak_scalar = k256::Scalar::from(tweak);

        let parent_point = self.key.to_projective();
        let tweak_point = k256::ProjectivePoint::GENERATOR * tweak_scalar;
        let child_point = parent_point.add(&tweak_point);

        let child_affine = child_point.to_affine();
        let child_key = PublicKey::from_affine(child_affine)
            .map_err(|e| format!("Invalid child key: {}", e))?;

        let mut child_chain = [0u8; 32];
        child_chain.copy_from_slice(ir);

        Ok(Self {
            key: child_key,
            chain_code: child_chain,
            depth: self.depth + 1,
        })
    }

    /// Get the x-only (Schnorr) public key bytes (32 bytes)
    pub fn x_only_bytes(&self) -> [u8; 32] {
        let point = self.key.to_encoded_point(true);
        let compressed = point.as_bytes(); // 33 bytes: [prefix][x]
        let mut x = [0u8; 32];
        x.copy_from_slice(&compressed[1..33]);
        x
    }
}

// ─── Import kpub ───

/// Import kpub and derive addresses using the given prefix ("kaspa" or "kaspatest")
pub fn import_kpub(kpub_str: &str, prefix: &str) -> Result<WalletData, String> {
    let payload = decode_kpub_text(kpub_str)?;
    let canonical_kpub = canonical_kpub_text(&payload)?;
    let xpub = ExtPubKey::from_raw_payload(&payload)?;

    // Derive receive chain /0, then /0/0 .. /0/19
    let receive_chain = xpub.derive_child(0)?;
    let mut receive_addresses = Vec::with_capacity(20);
    for i in 0..20u32 {
        let child = receive_chain.derive_child(i)?;
        let addr = super::address::encode_p2pk_address(&child.x_only_bytes(), prefix);
        receive_addresses.push(addr);
    }

    // Derive change chain /1, then /1/0 .. /1/19. Matches receive depth
    // so wallets that have accumulated change UTXOs (multiple TXs over
    // time) show full balance on first load, not after a gap-expansion
    // pass triggers a second fetch.
    let change_chain = xpub.derive_child(1)?;
    let mut change_addresses = Vec::with_capacity(20);
    for i in 0..20u32 {
        let child = change_chain.derive_child(i)?;
        let addr = super::address::encode_p2pk_address(&child.x_only_bytes(), prefix);
        change_addresses.push(addr);
    }

    Ok(WalletData {
        kpub: canonical_kpub,
        receive_addresses,
        change_addresses,
        next_receive_index: 0,
        next_change_index: 0,
    })
}

/// Import the 78-byte payload from the binary QR envelope and store its
/// canonical `kpub1:` text representation.
pub fn import_kpub_raw(raw_payload: &[u8], prefix: &str) -> Result<WalletData, String> {
    if raw_payload.len() != ACCOUNT_KEY_PAYLOAD_LEN {
        return Err(format!(
            "Raw account-key payload must be {} bytes, got {}",
            ACCOUNT_KEY_PAYLOAD_LEN,
            raw_payload.len()
        ));
    }
    // Validate the payload before storing its canonical text form.
    let _ = ExtPubKey::from_raw_payload(raw_payload)?;

    let payload: &[u8; ACCOUNT_KEY_PAYLOAD_LEN] = raw_payload
        .try_into()
        .map_err(|_| "Raw account-key payload has the wrong length")?;
    let mut encoded = [0u8; ACCOUNT_KEY_TEXT_LEN];
    let encoded_len = encode_account_key_text(payload, &mut encoded)
        .ok_or_else(|| "Raw account-key payload is not canonical".to_string())?;
    let kpub_text = core::str::from_utf8(&encoded[..encoded_len])
        .map_err(|_| "Canonical account-key text is not UTF-8")?;
    import_kpub(kpub_text, prefix)
}

/// Derive additional receive and/or change addresses beyond what the
/// wallet currently holds. Called when all existing addresses are used
/// and the gap limit needs expanding.
///
/// `extra_receive`: number of new receive addresses to append.
/// `extra_change`: number of new change addresses to append.
///
/// Returns an updated WalletData with the new addresses appended.
/// The account key is re-parsed each time (one hex decode + one
/// EC point parse). The derive_child calls skip to the correct index
/// using the existing address count as the starting offset.
pub fn extend_addresses(
    wallet: &WalletData,
    extra_receive: u32,
    extra_change: u32,
    prefix: &str,
) -> Result<WalletData, String> {
    let xpub = ExtPubKey::from_kpub(&wallet.kpub)?;

    let mut receive_addresses = wallet.receive_addresses.clone();
    if extra_receive > 0 {
        let receive_chain = xpub.derive_child(0)?;
        let start = receive_addresses.len() as u32;
        for i in start..start + extra_receive {
            let child = receive_chain.derive_child(i)?;
            let addr = super::address::encode_p2pk_address(&child.x_only_bytes(), prefix);
            receive_addresses.push(addr);
        }
    }

    let mut change_addresses = wallet.change_addresses.clone();
    if extra_change > 0 {
        let change_chain = xpub.derive_child(1)?;
        let start = change_addresses.len() as u32;
        for i in start..start + extra_change {
            let child = change_chain.derive_child(i)?;
            let addr = super::address::encode_p2pk_address(&child.x_only_bytes(), prefix);
            change_addresses.push(addr);
        }
    }

    Ok(WalletData {
        kpub: wallet.kpub.clone(),
        receive_addresses,
        change_addresses,
        next_receive_index: wallet.next_receive_index,
        next_change_index: wallet.next_change_index,
    })
}
