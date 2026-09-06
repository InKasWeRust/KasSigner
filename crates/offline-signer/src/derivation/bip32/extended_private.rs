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

use k256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::error::Bip32Error;

// ─── Tipos ────────────────────────────────────────────────────────────

/// Extended private key: private key (32 bytes) + chain code (32 bytes)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ExtendedPrivKey {
    /// Private key (secp256k1 scalar, 32 bytes big-endian)
    pub(super) key: [u8; 32],
    /// Chain code for child derivation
    pub(super) chain_code: [u8; 32],
    /// Depth in the tree (0 = master)
    pub depth: u8,
}

impl ExtendedPrivKey {
    /// Zeroiza ambos campos de forma segura
    pub fn zeroize(&mut self) {
        <Self as Zeroize>::zeroize(self);
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
        Self {
            key,
            chain_code,
            depth: raw[64],
        }
    }

    /// Construct from individual parts (used by xprv import).
    pub fn from_parts(key: [u8; 32], chain_code: [u8; 32], depth: u8) -> Self {
        Self {
            key,
            chain_code,
            depth,
        }
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
        let sk = SecretKey::from_slice(&self.key).map_err(|_| Bip32Error::CurveError)?;
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

/// Derive the compressed public key (33 bytes) from a raw private key.
pub fn compressed_pubkey_from_raw_key(privkey: &[u8; 32]) -> Result<[u8; 33], Bip32Error> {
    let secret_key = SecretKey::from_slice(privkey).map_err(|_| Bip32Error::CurveError)?;
    let encoded = secret_key.public_key().to_encoded_point(true);
    let mut compressed = [0u8; 33];
    compressed.copy_from_slice(encoded.as_bytes());
    Ok(compressed)
}

/// Derive the x-only public key (32 bytes) from a raw private key.
/// Used for imported raw keys (not BIP32-derived).
pub fn pubkey_from_raw_key(privkey: &[u8; 32]) -> Result<[u8; 32], Bip32Error> {
    let compressed = compressed_pubkey_from_raw_key(privkey)?;
    let mut x = [0u8; 32];
    x.copy_from_slice(&compressed[1..]);
    Ok(x)
}
