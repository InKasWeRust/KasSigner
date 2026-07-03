// KasSee Web — Stealth Addresses
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0
//
// stealth.rs — DKSAP (Dual-Key Stealth Address Protocol) for Kaspa.
//
// Protocol overview:
//   Receiver publishes a stealth meta-address: (scan_pubkey V, spend_pubkey B)
//   Sender picks ephemeral scalar r, computes:
//     - Shared secret S = r * V  (ECDH)
//     - Tweak t = SHA256("KasStealth" || S.x || counter)
//     - One-time pubkey P = B + t*G
//     - Ephemeral pubkey R = r*G
//   Sender pays to address(P), announces R to a well-known on-chain address.
//   Receiver scans announcements, for each R:
//     - S = v * R  (scan privkey × ephemeral)
//     - t = SHA256("KasStealth" || S.x || counter)
//     - P = B + t*G
//     - Checks if P matches any UTXO
//   Device signs with privkey (b + t) — KasSee passes the tweak index,
//   device derives account key and KasSee applies the tweak in the PSKT.
//
// Zero firmware changes: the device signs with its BIP32-derived key at
// a high index in the /0/ (receive) chain. The "stealth index" is derived
// deterministically from the ECDH shared secret so both sender and
// receiver agree on the same address without communication.
//
// Announcement: a tiny TX to a well-known per-network announcement address.
// The TX carries R (32 bytes) as the first output's pubkey in a P2PK output.
// The receiver scans this announcement address for all TXs and extracts R.

//! Stealth-address cryptography (dual-key ECDH with view tags): meta-address
//! derivation, payment scanning, and spend-key recovery.

use k256::elliptic_curve::ops::Add;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::ScalarPrimitive;
use k256::{ProjectivePoint, PublicKey, Scalar, Secp256k1};
use sha2::{Digest, Sha256};

/// Domain separator for stealth tweak derivation.
/// Ensures stealth tweaks don't collide with BIP32 or other derivation schemes.
const STEALTH_TAG: &[u8] = b"KasStealth";

/// Well-known announcement address seed.
/// The announcement address is derived by hashing this seed → 32-byte "pubkey"
/// → P2PK address. This is a burn address (no one has the private key).
/// Different per network prefix.
const ANNOUNCEMENT_SEED: &[u8] = b"KasSigner-Stealth-Announce-v1";

/// Domain separator for the one-byte view tag.
/// Distinct from STEALTH_TAG so the published tag leaks no bits of the
/// spend tweak: tag = SHA256(VIEW_TAG_TAG || S.x)[0], tweak uses STEALTH_TAG.
const VIEW_TAG_TAG: &[u8] = b"KasStealthViewTag";

// ─── Stealth meta-address ───

/// A stealth meta-address: scan pubkey + spend pubkey.
/// The receiver publishes this. The sender uses it to derive one-time addresses.
pub struct StealthMeta {
    /// Scan public key V (used for ECDH — only the receiver has v)
    pub scan_pubkey: PublicKey,
    /// Spend public key B (the base for one-time keys)
    pub spend_pubkey: PublicKey,
}

/// Derive a stealth meta-address from a kpub.
///
/// scan_pubkey = kpub/2/0  (branch 2 = stealth scan chain)
/// spend_pubkey = kpub      (the account-level pubkey itself)
///
/// The scan private key lives only in the device seed — KasSee
/// derives the scan PUBLIC key from the kpub for publishing.
/// Actual scanning requires the scan PRIVATE key, which is derived
/// on-device or via the mnemonic in a trusted environment.
pub fn derive_stealth_meta(account_key: &crate::bip32::ExtPubKey) -> Result<StealthMeta, String> {
    // Scan chain: /2/0
    let scan_chain = account_key.derive_child(2)?;
    let scan_key = scan_chain.derive_child(0)?;

    Ok(StealthMeta {
        scan_pubkey: scan_key.key,
        spend_pubkey: account_key.key,
    })
}

/// Encode a stealth meta-address as 64 hex chars (scan_xonly || spend_xonly).
pub fn encode_stealth_meta(meta: &StealthMeta) -> String {
    let scan_x = x_only_bytes(&meta.scan_pubkey);
    let spend_x = x_only_bytes(&meta.spend_pubkey);
    format!("{}{}", hex::encode(scan_x), hex::encode(spend_x))
}

/// Decode a 128-char hex stealth meta-address → (scan_pubkey, spend_pubkey).
pub fn decode_stealth_meta(hex_str: &str) -> Result<StealthMeta, String> {
    if hex_str.len() != 128 {
        return Err(format!(
            "Stealth meta-address must be 128 hex chars, got {}",
            hex_str.len()
        ));
    }
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;

    let scan_pubkey = pubkey_from_xonly(&bytes[..32])?;
    let spend_pubkey = pubkey_from_xonly(&bytes[32..64])?;

    Ok(StealthMeta {
        scan_pubkey,
        spend_pubkey,
    })
}

// ─── Sender side: generate stealth payment ───

/// Result of generating a stealth payment.
pub struct StealthPayment {
    /// The one-time pubkey P — encode this as a Kaspa P2PK address for the payment
    pub one_time_pubkey: [u8; 32],
    /// The ephemeral pubkey R — announce this on-chain so the receiver can find it
    pub ephemeral_pubkey: [u8; 32],
    /// The BIP32-compatible stealth index (derived from ECDH shared secret)
    pub stealth_index: u32,
    /// One-byte view tag = SHA256("KasStealthViewTag" || S.x)[0]. Publish it
    /// alongside R so a scanner can cheaply skip non-matching announcements.
    pub view_tag: u8,
}

/// Generate a stealth payment: derive one-time address + ephemeral R.
///
/// The sender calls this with the receiver's stealth meta-address.
/// Returns the one-time pubkey (for payment) and ephemeral R (for announcement).
///
/// `entropy` must be 32 bytes of cryptographic randomness (from window.crypto).
pub fn generate_stealth_payment(
    meta: &StealthMeta,
    entropy: &[u8; 32],
) -> Result<StealthPayment, String> {
    // Ephemeral scalar r from entropy
    let r_scalar = scalar_from_bytes(entropy)?;

    // R = r * G (ephemeral pubkey to announce)
    let r_point = ProjectivePoint::GENERATOR * r_scalar;
    let r_affine = r_point.to_affine();
    let r_pubkey =
        PublicKey::from_affine(r_affine).map_err(|e| format!("Bad ephemeral point: {}", e))?;

    // Shared secret S = r * V (ECDH with scan pubkey)
    let v_point = meta.scan_pubkey.to_projective();
    let s_point = v_point * r_scalar;
    let s_affine = s_point.to_affine();
    let s_x = x_only_bytes_from_affine(&s_affine);

    // Tweak t = SHA256("KasStealth" || S.x || 0u32)
    let (tweak_scalar, stealth_index) = derive_tweak(&s_x, 0);

    // One-time pubkey P = B + t*G
    let b_point = meta.spend_pubkey.to_projective();
    let tweak_point = ProjectivePoint::GENERATOR * tweak_scalar;
    let p_point = b_point.add(&tweak_point);
    let p_affine = p_point.to_affine();
    let p_xonly = x_only_bytes_from_affine(&p_affine);

    // View tag from the same shared secret (sender side).
    let view_tag = view_tag_from_secret(&s_x);

    Ok(StealthPayment {
        one_time_pubkey: p_xonly,
        ephemeral_pubkey: x_only_bytes(&r_pubkey),
        stealth_index,
        view_tag,
    })
}

// ─── Receiver side: scan announcements ───

/// Result of scanning a single announcement.
pub struct StealthMatch {
    /// The one-time pubkey P that should appear as a UTXO
    pub one_time_pubkey: [u8; 32],
    /// The stealth index for BIP32 derivation on the device
    pub stealth_index: u32,
    /// One-byte view tag derived from the shared secret (matches the sender's).
    // Kept: retained for future use; not currently wired.
    #[allow(dead_code)]
    pub view_tag: u8,
    /// The tweak scalar bytes (32 bytes) — needed for spending
    pub tweak: [u8; 32],
}

/// Scan a single ephemeral R against our stealth keys.
///
/// `scan_privkey` is the 32-byte private key for the scan chain (/2/0).
/// `spend_pubkey` is the account-level public key (B).
/// `r_pubkey_bytes` is the 32-byte x-only ephemeral pubkey from the announcement.
///
/// Returns Some(StealthMatch) if the derived one-time pubkey matches
/// a known UTXO, or always returns the derived pubkey for external checking.
pub fn scan_announcement(
    scan_privkey: &[u8; 32],
    spend_pubkey: &PublicKey,
    r_pubkey_bytes: &[u8; 32],
) -> Result<StealthMatch, String> {
    // Parse R
    let r_pubkey = pubkey_from_xonly(r_pubkey_bytes)?;

    // Shared secret S = v * R (scan privkey × ephemeral)
    let v_scalar = scalar_from_bytes(scan_privkey)?;
    let r_point = r_pubkey.to_projective();
    let s_point = r_point * v_scalar;
    let s_affine = s_point.to_affine();
    let s_x = x_only_bytes_from_affine(&s_affine);

    // Tweak t = SHA256("KasStealth" || S.x || 0u32)
    let (tweak_scalar, stealth_index) = derive_tweak(&s_x, 0);

    // One-time pubkey P = B + t*G
    let b_point = spend_pubkey.to_projective();
    let tweak_point = ProjectivePoint::GENERATOR * tweak_scalar;
    let p_point = b_point.add(&tweak_point);
    let p_affine = p_point.to_affine();
    let p_xonly = x_only_bytes_from_affine(&p_affine);

    // Tweak bytes for spending
    let tweak_bytes = tweak_scalar.to_bytes();
    let mut tweak = [0u8; 32];
    tweak.copy_from_slice(&tweak_bytes);

    // View tag from the same shared secret (receiver side).
    let view_tag = view_tag_from_secret(&s_x);

    Ok(StealthMatch {
        one_time_pubkey: p_xonly,
        stealth_index,
        view_tag,
        tweak,
    })
}

// ─── Receiver side: view-tag fast-path scan ───

/// Scan a single announcement using the published view tag as a fast filter.
///
/// Computes the ECDH shared secret once, checks the 1-byte view tag, and
/// returns `Ok(None)` immediately on a mismatch (skipping the `B + t*G`
/// one-time-key derivation). On a view-tag hit it returns the full match. The
/// view tag has a 1/256 false-positive rate, so a hit still requires the
/// caller to confirm the derived one-time pubkey against an actual output.
///
/// This is the per-announcement primitive for the lane scanner: pull each
/// entry's `(R, view_tag)` from the payload, call this, and only do output
/// matching on the survivors.
// Kept: retained for future use; not currently wired.
#[allow(dead_code)]
pub fn scan_announcement_vt(
    scan_privkey: &[u8; 32],
    spend_pubkey: &PublicKey,
    r_pubkey_bytes: &[u8; 32],
    announced_view_tag: u8,
) -> Result<Option<StealthMatch>, String> {
    // Shared secret S = v * R (scan privkey × ephemeral)
    let r_pubkey = pubkey_from_xonly(r_pubkey_bytes)?;
    let v_scalar = scalar_from_bytes(scan_privkey)?;
    let s_point = r_pubkey.to_projective() * v_scalar;
    let s_affine = s_point.to_affine();
    let s_x = x_only_bytes_from_affine(&s_affine);

    // Cheap reject: view tags disagree, so this announcement is not ours.
    if view_tag_from_secret(&s_x) != announced_view_tag {
        return Ok(None);
    }

    // View tag matched: derive the one-time key and spend tweak.
    let (tweak_scalar, stealth_index) = derive_tweak(&s_x, 0);
    let tweak_point = ProjectivePoint::GENERATOR * tweak_scalar;
    let p_point = spend_pubkey.to_projective().add(&tweak_point);
    let p_affine = p_point.to_affine();
    let p_xonly = x_only_bytes_from_affine(&p_affine);

    let tweak_bytes = tweak_scalar.to_bytes();
    let mut tweak = [0u8; 32];
    tweak.copy_from_slice(&tweak_bytes);

    Ok(Some(StealthMatch {
        one_time_pubkey: p_xonly,
        stealth_index,
        view_tag: announced_view_tag,
        tweak,
    }))
}

// ─── Announcement address ───

/// Derive the well-known stealth announcement address for a given network prefix.
/// This is a burn address — no one has the private key.
/// All stealth senders announce their ephemeral R to this address.
pub fn announcement_address(prefix: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ANNOUNCEMENT_SEED);
    hasher.update(prefix.as_bytes());
    let hash = hasher.finalize();
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&hash);
    crate::address::encode_p2pk_address(&pubkey, prefix)
}

// ─── Spending support ───
//
// The one-time spending key is the scalar (b + t), where b is the account
// spend key and t is the ECDH-derived tweak. KasSee puts t in the PSKB
// (proprietaries.stealthTweak); the firmware derives b on-device and adds t
// (with even-Y canonicalization of b). There is deliberately NO BIP32-index
// path: t comes from the ECDH shared secret, not from BIP32 child derivation,
// so mapping the stealth index to a receive index would derive the wrong key.

// ─── Internal helpers ───

/// Derive the one-byte view tag from the ECDH shared secret x-coordinate.
/// Sender and scanner both compute S.x, so both arrive at the same byte.
/// Domain-separated from derive_tweak (VIEW_TAG_TAG vs STEALTH_TAG) so the
/// published tag reveals no information about the spend tweak.
fn view_tag_from_secret(shared_secret_x: &[u8; 32]) -> u8 {
    let mut hasher = Sha256::new();
    hasher.update(VIEW_TAG_TAG);
    hasher.update(shared_secret_x);
    let hash = hasher.finalize();
    hash[0]
}

/// Derive the stealth tweak from ECDH shared secret.
/// Returns (tweak_scalar, stealth_index).
fn derive_tweak(shared_secret_x: &[u8; 32], counter: u32) -> (Scalar, u32) {
    let mut hasher = Sha256::new();
    hasher.update(STEALTH_TAG);
    hasher.update(shared_secret_x);
    hasher.update(counter.to_be_bytes());
    let hash = hasher.finalize();

    // Tweak scalar from hash (reduce mod n)
    let tweak_primitive = ScalarPrimitive::<Secp256k1>::from_slice(&hash).unwrap_or_else(|_| {
        // If hash >= n (astronomically unlikely), just use it mod n
        // by taking the lower 31 bytes + 1 zero byte
        let mut adjusted = [0u8; 32];
        adjusted[1..].copy_from_slice(&hash[..31]);
        ScalarPrimitive::<Secp256k1>::from_slice(&adjusted).unwrap()
    });
    let tweak_scalar = Scalar::from(tweak_primitive);

    // Stealth index: first 4 bytes of the hash, mod 2^31 (non-hardened BIP32)
    let idx_bytes: [u8; 4] = hash[..4].try_into().unwrap();
    let stealth_index = u32::from_be_bytes(idx_bytes) & 0x7FFFFFFF;

    (tweak_scalar, stealth_index)
}

/// Extract x-only bytes from a PublicKey (public for WASM layer).
pub fn x_only_pub(pk: &PublicKey) -> [u8; 32] {
    x_only_bytes(pk)
}

/// Extract x-only bytes from a PublicKey.
fn x_only_bytes(pk: &PublicKey) -> [u8; 32] {
    let point = pk.to_encoded_point(true);
    let compressed = point.as_bytes(); // 33 bytes: [prefix][x]
    let mut x = [0u8; 32];
    x.copy_from_slice(&compressed[1..33]);
    x
}

/// Extract x-only bytes from an AffinePoint.
fn x_only_bytes_from_affine(affine: &k256::AffinePoint) -> [u8; 32] {
    use k256::elliptic_curve::sec1::ToEncodedPoint as _;
    let point = affine.to_encoded_point(true);
    let compressed = point.as_bytes();
    let mut x = [0u8; 32];
    x.copy_from_slice(&compressed[1..33]);
    x
}

/// Parse an x-only pubkey (32 bytes) → PublicKey (assumes even Y).
pub fn pubkey_from_xonly(bytes: &[u8]) -> Result<PublicKey, String> {
    if bytes.len() != 32 {
        return Err(format!(
            "xonly pubkey must be 32 bytes, got {}",
            bytes.len()
        ));
    }
    // Prepend 0x02 for even Y (BIP340 convention)
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(bytes);
    PublicKey::from_sec1_bytes(&compressed).map_err(|e| format!("Invalid pubkey: {}", e))
}

/// Parse 32 bytes as a secp256k1 scalar.
fn scalar_from_bytes(bytes: &[u8; 32]) -> Result<Scalar, String> {
    let primitive = ScalarPrimitive::<Secp256k1>::from_slice(bytes)
        .map_err(|e| format!("Invalid scalar: {}", e))?;
    Ok(Scalar::from(primitive))
}
