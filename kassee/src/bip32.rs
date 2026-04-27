// KasSee Web — BIP32 key derivation
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0
//
// bip32.rs — Parse kpub, derive receive/change addresses.
// Pure Rust using k256 crate (no C, no ring).
// Ported from KasSigner bootloader/wallet/bip32.rs + KasSee CLI wallet.rs

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

pub(crate) struct ExtPubKey {
    pub(crate) key: PublicKey,
    pub(crate) chain_code: [u8; 32],
    pub(crate) depth: u8,
}

impl ExtPubKey {
    /// Parse a kpub (Kaspa extended public key, base58check encoded)
    pub(crate) fn from_kpub(kpub_str: &str) -> Result<Self, String> {
        if !kpub_str.starts_with("kpub") {
            return Err("Must start with 'kpub'".into());
        }

        let decoded = bs58::decode(kpub_str)
            .with_check(None)
            .into_vec()
            .map_err(|e| format!("Base58 decode failed: {}", e))?;

        // kpub format: [4 version][1 depth][4 fingerprint][4 child_num][32 chain_code][33 pubkey]
        if decoded.len() < 78 {
            return Err(format!("Too short: {} bytes (need 78)", decoded.len()))?;
        }

        Self::from_raw_payload(&decoded[..78])
    }

    /// Parse a 78-byte raw kpub payload (the decoded body of a base58
    /// kpub string, without the base58check checksum). Used for the
    /// V1-raw compact QR format — device exports `[0x01][78 raw bytes]`
    /// across 2 small QRs, KasSee strips the 0x01 header and parses
    /// the remaining 78 bytes here.
    pub(crate) fn from_raw_payload(payload: &[u8]) -> Result<Self, String> {
        if payload.len() != 78 {
            return Err(format!(
                "Raw kpub payload must be 78 bytes, got {}",
                payload.len()
            ));
        }

        let depth = payload[4];
        let chain_code: [u8; 32] = payload[13..45]
            .try_into()
            .map_err(|_| "Bad chain code")?;
        let key_bytes = &payload[45..78];

        let key = PublicKey::from_sec1_bytes(key_bytes)
            .map_err(|e| format!("Invalid pubkey: {}", e))?;

        Ok(Self {
            key,
            chain_code,
            depth,
        })
    }

    /// Derive a non-hardened child key: parent_key + HMAC-SHA512(chain_code, 0x00||key||index)
    pub(crate) fn derive_child(&self, index: u32) -> Result<Self, String> {
        if index >= 0x80000000 {
            return Err("Cannot derive hardened child from public key".into());
        }

        let parent_point = self.key.to_encoded_point(true);
        let parent_bytes = parent_point.as_bytes(); // 33 bytes compressed

        let mut mac = HmacSha512::new_from_slice(&self.chain_code)
            .map_err(|_| "HMAC init failed")?;
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
    fn x_only_bytes(&self) -> [u8; 32] {
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
    let xpub = ExtPubKey::from_kpub(kpub_str)?;

    web_sys::console::log_1(
        &format!("[KasSee] Parsed kpub at depth {}, prefix={}", xpub.depth, prefix).into(),
    );

    // Derive receive chain /0, then /0/0 .. /0/19
    let receive_chain = xpub.derive_child(0)?;
    let mut receive_addresses = Vec::with_capacity(20);
    for i in 0..20u32 {
        let child = receive_chain.derive_child(i)?;
        let addr = crate::address::encode_p2pk_address(&child.x_only_bytes(), prefix);
        receive_addresses.push(addr);
    }

    // Derive change chain /1, then /1/0 .. /1/4
    let change_chain = xpub.derive_child(1)?;
    let mut change_addresses = Vec::with_capacity(5);
    for i in 0..5u32 {
        let child = change_chain.derive_child(i)?;
        let addr = crate::address::encode_p2pk_address(&child.x_only_bytes(), prefix);
        change_addresses.push(addr);
    }

    web_sys::console::log_1(
        &format!(
            "[KasSee] Derived {} receive + {} change addresses ({})",
            receive_addresses.len(),
            change_addresses.len(),
            prefix,
        )
        .into(),
    );

    Ok(WalletData {
        kpub: kpub_str.to_string(),
        receive_addresses,
        change_addresses,
        next_receive_index: 0,
        next_change_index: 0,
    })
}

/// Import a V1-raw compact kpub from the 78-byte raw payload (as
/// decoded from the QR multi-frame reassembly — device exports
/// `[0x01 header][78 payload]` and KasSee strips the header before
/// calling this).
///
/// Re-encodes the raw payload as a standard base58check kpub string
/// so the rest of KasSee (storage, UI display, RPC) sees the same
/// shape regardless of which transport the user chose.
pub fn import_kpub_raw(raw_payload: &[u8], prefix: &str) -> Result<WalletData, String> {
    if raw_payload.len() != 78 {
        return Err(format!(
            "Raw kpub payload must be 78 bytes, got {}",
            raw_payload.len()
        ));
    }
    // Validate first (cheap structural check before base58 encoding).
    let _ = ExtPubKey::from_raw_payload(raw_payload)?;

    // Re-encode to base58check kpub string so downstream code
    // (WalletData.kpub field, UI, persistence) stays uniform.
    let kpub_str = bs58::encode(raw_payload)
        .with_check()
        .into_string();

    web_sys::console::log_1(
        &format!("[KasSee] V1-raw kpub re-encoded to ASCII ({} chars)",
            kpub_str.len()).into(),
    );

    import_kpub(&kpub_str, prefix)
}

/// Derive additional receive and/or change addresses beyond what the
/// wallet currently holds. Called when all existing addresses are used
/// and the gap limit needs expanding.
///
/// `extra_receive`: number of new receive addresses to append.
/// `extra_change`: number of new change addresses to append.
///
/// Returns an updated WalletData with the new addresses appended.
/// The kpub is re-parsed each time (cheap — one base58 decode + one
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
            let addr = crate::address::encode_p2pk_address(&child.x_only_bytes(), prefix);
            receive_addresses.push(addr);
        }
    }

    let mut change_addresses = wallet.change_addresses.clone();
    if extra_change > 0 {
        let change_chain = xpub.derive_child(1)?;
        let start = change_addresses.len() as u32;
        for i in start..start + extra_change {
            let child = change_chain.derive_child(i)?;
            let addr = crate::address::encode_p2pk_address(&child.x_only_bytes(), prefix);
            change_addresses.push(addr);
        }
    }

    web_sys::console::log_1(
        &format!(
            "[KasSee] Extended: {} receive (+{}), {} change (+{})",
            receive_addresses.len(), extra_receive,
            change_addresses.len(), extra_change,
        )
        .into(),
    );

    Ok(WalletData {
        kpub: wallet.kpub.clone(),
        receive_addresses,
        change_addresses,
        next_receive_index: wallet.next_receive_index,
        next_change_index: wallet.next_change_index,
    })
}
