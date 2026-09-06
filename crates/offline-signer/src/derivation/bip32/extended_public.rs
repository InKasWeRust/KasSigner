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

use super::{error::Bip32Error, extended_private::ExtendedPrivKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Extended public key: compressed pubkey (33B) + chain code (32B).
///
/// Used as input to `derive_child_pub` for HD multisig address derivation.
/// Constructed either from a decoded kpub payload (see `import_kpub_xpub`
/// in `offline_signer::derivation::xpub`) or from an `ExtendedPrivKey` via
/// `ExtendedPrivKey::to_xpub()`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ExtendedPubKey {
    /// Compressed pubkey: 0x02 or 0x03 prefix + 32-byte X coordinate.
    pub pubkey: [u8; 33],
    /// BIP32 chain code — entropy used in child derivation HMAC.
    pub chain_code: [u8; 32],
    /// Depth in the derivation tree (0 = master).
    pub depth: u8,
}

impl ExtendedPubKey {
    /// Wipe the public material and BIP32 chain code in place.
    pub fn zeroize(&mut self) {
        <Self as Zeroize>::zeroize(self);
    }

    /// Return the x-only 32-byte pubkey (Kaspa / BIP340 form).
    pub fn x_only(&self) -> [u8; 32] {
        let mut x = [0u8; 32];
        x.copy_from_slice(&self.pubkey[1..33]);
        x
    }
}

impl ExtendedPrivKey {
    /// Derive the extended public key (pubkey + chain_code + depth).
    pub fn to_xpub(&self) -> Result<ExtendedPubKey, Bip32Error> {
        let pubkey = self.public_key_compressed()?;
        Ok(ExtendedPubKey {
            pubkey,
            chain_code: self.chain_code,
            depth: self.depth,
        })
    }
}
