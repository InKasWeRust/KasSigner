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

//! BIP32 private derivation (`CKDpriv`), as BIP32 writes it; Kaspa changes
//! only the serialization prefixes.
//!
//! `CKDpub` is in `kassigner_kaspa::bip32_public`, which an integrator links
//! without reaching this crate. Hardened derivation feeds the private key
//! into the HMAC, so only this half can do it, and every level of a Kaspa
//! path down to the account is hardened.
//!
//! Everything zeroizes: a key with its chain code is the wallet, and the
//! HMAC's left half plus the parent key is the child key. Every buffer and
//! every [`Scalar`](k256::Scalar) holding a key or a tweak is wiped.
//! `Scalar` is `Copy`, so compiler copies in spills or registers are out of
//! reach: wiping shortens the window, it does not close it.

use hmac::{Hmac, KeyInit, Mac};
use k256::ProjectivePoint;
use sha2::Sha512;
use zeroize::Zeroize;

use kassigner_kaspa::base58;
use kassigner_kaspa::bip32_public::{
    fingerprint, Bip32Error as PublicError, ChildNumber, ExtendedPublicKey, CHAIN_CODE_SIZE,
    EXTENDED_KEY_SIZE, FINGERPRINT_SIZE, HARDENED_OFFSET, PUBLIC_KEY_SIZE,
};

use crate::curve::{scalar_of, tweak_of};

/// Length of a private key.
pub const PRIVATE_KEY_SIZE: usize = 32;

/// The HMAC key for the master node, from the specification.
const MASTER_KEY: &[u8] = b"Bitcoin seed";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bip32Error {
    /// The seed is outside 16 to 64 bytes.
    BadSeedLength(usize),
    /// A derived key was zero or past the curve order. BIP32 says to skip
    /// to the next index; that is the caller's call, as a wallet that moved
    /// silently would derive addresses no other implementation finds.
    InvalidChild,
    /// The parent key is not a valid scalar.
    InvalidParent,
    /// The caller's buffer is too small.
    BufferTooSmall,
    /// A key at depth 0 that names a parent or a child number: a master key
    /// has neither, and BIP32's invalid test vectors refuse both.
    NotAMaster,
    /// The child would be the 256th level. Depth is one byte; saturating
    /// would give a child and its parent the same depth, 255.
    DepthOverflow,
    /// A fault from the public half.
    Public(PublicError),
}

impl From<PublicError> for Bip32Error {
    fn from(e: PublicError) -> Self {
        Bip32Error::Public(e)
    }
}

/// The network prefix of an extended private key's text form.
///
/// Upstream: `wallet/bip32/src/prefix.rs`, `KPRV` and `KTRV`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivatePrefix {
    /// Mainnet: `kprv`.
    Kprv,
    /// Testnet: `ktrv`.
    Ktrv,
}

impl PrivatePrefix {
    pub const fn version(self) -> u32 {
        match self {
            PrivatePrefix::Kprv => 0x038f_2ef4,
            PrivatePrefix::Ktrv => 0x0390_9e07,
        }
    }

    pub const fn from_version(v: u32) -> Option<Self> {
        match v {
            0x038f_2ef4 => Some(PrivatePrefix::Kprv),
            0x0390_9e07 => Some(PrivatePrefix::Ktrv),
            _ => None,
        }
    }
}

/// Characters an extended private key's text form can take.
pub const XPRV_TEXT_MAX: usize = base58::encoded_max(EXTENDED_KEY_SIZE);

/// An extended private key. Zeroizes key and chain code on drop.
///
/// The child number is held as four big-endian bytes, so the struct is 73
/// bytes, unpadded: a `Wallet` holds three, and a `u32` would push that
/// variant past clippy's large-enum-variant limit.
#[derive(Clone)]
pub struct ExtendedPrivateKey {
    private_key: [u8; PRIVATE_KEY_SIZE],
    chain_code: [u8; CHAIN_CODE_SIZE],
    depth: u8,
    parent_fingerprint: [u8; FINGERPRINT_SIZE],
    child_number: [u8; 4],
}

impl core::fmt::Debug for ExtendedPrivateKey {
    /// Redacted: depth and child number only. Never the chain code either:
    /// with any non-hardened child's private key it yields this key.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ExtendedPrivateKey(depth {}, child {}, redacted)",
            self.depth,
            self.child_number().0
        )
    }
}

impl Drop for ExtendedPrivateKey {
    fn drop(&mut self) {
        self.private_key.zeroize();
        self.chain_code.zeroize();
    }
}

impl ExtendedPrivateKey {
    /// The master key for a seed: HMAC-SHA512 under `"Bitcoin seed"`, the
    /// left half the key, the right half the chain code.
    ///
    /// # Errors
    ///
    /// `BadSeedLength` outside 16 to 64 bytes; `InvalidChild` if the left
    /// half is zero or past the curve order (negligible odds).
    pub fn from_seed(seed: &[u8]) -> Result<Self, Bip32Error> {
        if seed.len() < 16 || seed.len() > 64 {
            return Err(Bip32Error::BadSeedLength(seed.len()));
        }
        let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(MASTER_KEY)
            .expect("HMAC accepts a key of any length");
        mac.update(seed);
        let mut i = mac.finalize().into_bytes();

        let mut key = [0u8; PRIVATE_KEY_SIZE];
        let mut cc = [0u8; CHAIN_CODE_SIZE];
        key.copy_from_slice(&i[..32]);
        cc.copy_from_slice(&i[32..]);
        i.zeroize();

        // Checked, not assumed: an invalid left half is a key nobody can
        // spend from.
        let valid = match scalar_of(&key) {
            Some(mut d) => {
                d.zeroize();
                true
            }
            None => false,
        };
        if !valid {
            key.zeroize();
            cc.zeroize();
            return Err(Bip32Error::InvalidChild);
        }

        // The arrays are `Copy`: the key is built from copies, and the locals
        // are wiped here.
        let master = Self {
            private_key: key,
            chain_code: cc,
            depth: 0,
            parent_fingerprint: [0u8; FINGERPRINT_SIZE],
            child_number: [0u8; 4],
        };
        key.zeroize();
        cc.zeroize();
        Ok(master)
    }

    /// Rebuild a key from its parts, as restored from storage. The key is
    /// validated, so a corrupted restore fails here.
    ///
    /// # Errors
    ///
    /// `InvalidParent` if the key is zero or past the curve order;
    /// `NotAMaster` for depth 0 with a parent fingerprint or a child number.
    pub fn from_parts(
        private_key: &[u8; PRIVATE_KEY_SIZE],
        chain_code: &[u8; CHAIN_CODE_SIZE],
        depth: u8,
        parent_fingerprint: [u8; FINGERPRINT_SIZE],
        child_number: ChildNumber,
    ) -> Result<Self, Bip32Error> {
        match scalar_of(private_key) {
            Some(mut d) => d.zeroize(),
            None => return Err(Bip32Error::InvalidParent),
        }
        if depth == 0 && (parent_fingerprint != [0; FINGERPRINT_SIZE] || child_number.0 != 0) {
            return Err(Bip32Error::NotAMaster);
        }
        Ok(Self {
            private_key: *private_key,
            chain_code: *chain_code,
            depth,
            parent_fingerprint,
            child_number: child_number.to_be_bytes(),
        })
    }

    /// The private key bytes, borrowed, never copied out.
    pub const fn private_key(&self) -> &[u8; PRIVATE_KEY_SIZE] {
        &self.private_key
    }

    pub const fn chain_code(&self) -> &[u8; CHAIN_CODE_SIZE] {
        &self.chain_code
    }

    pub const fn depth(&self) -> u8 {
        self.depth
    }

    pub const fn child_number(&self) -> ChildNumber {
        ChildNumber(u32::from_be_bytes(self.child_number))
    }

    pub const fn parent_fingerprint(&self) -> [u8; FINGERPRINT_SIZE] {
        self.parent_fingerprint
    }

    /// Write the text form: the 78-byte body (version, depth, parent
    /// fingerprint, child number, chain code, a zero byte and the key) in
    /// Base58Check, as upstream's `ExtendedKey` (`wallet/bip32/src/xkey.rs`).
    /// Returns characters written; `out` needs [`XPRV_TEXT_MAX`]. The text is
    /// the key: the caller wipes `out`.
    ///
    /// # Errors
    ///
    /// `BufferTooSmall`.
    pub fn to_text(&self, prefix: PrivatePrefix, out: &mut [u8]) -> Result<usize, Bip32Error> {
        let mut body = [0u8; EXTENDED_KEY_SIZE];
        body[0..4].copy_from_slice(&prefix.version().to_be_bytes());
        body[4] = self.depth;
        body[5..9].copy_from_slice(&self.parent_fingerprint);
        body[9..13].copy_from_slice(&self.child_number);
        body[13..45].copy_from_slice(&self.chain_code);
        body[45] = 0;
        body[46..78].copy_from_slice(&self.private_key);
        let mut scratch = [0u8; EXTENDED_KEY_SIZE + 4];
        let r =
            base58::encode_check(&body, &mut scratch, out).map_err(|_| Bip32Error::BufferTooSmall);
        body.zeroize();
        scratch.zeroize();
        r
    }

    /// Read the text form.
    ///
    /// # Errors
    ///
    /// `InvalidParent` for text that is not Base58Check of a 78-byte body
    /// with a known private prefix and a zero byte before the key, or whose
    /// key is invalid.
    pub fn from_text(text: &[u8]) -> Result<(PrivatePrefix, Self), Bip32Error> {
        let mut body = [0u8; base58::decoded_max(XPRV_TEXT_MAX)];
        let r = base58::decode_check(text, &mut body);
        let parsed = match r {
            Ok(EXTENDED_KEY_SIZE) => Self::from_body(&body[..EXTENDED_KEY_SIZE]),
            _ => Err(Bip32Error::InvalidParent),
        };
        body.zeroize();
        parsed
    }

    fn from_body(b: &[u8]) -> Result<(PrivatePrefix, Self), Bip32Error> {
        let mut v = [0u8; 4];
        v.copy_from_slice(&b[0..4]);
        let prefix =
            PrivatePrefix::from_version(u32::from_be_bytes(v)).ok_or(Bip32Error::InvalidParent)?;
        if b[45] != 0 {
            return Err(Bip32Error::InvalidParent);
        }
        let mut parent_fingerprint = [0u8; FINGERPRINT_SIZE];
        parent_fingerprint.copy_from_slice(&b[5..9]);
        let mut cn = [0u8; 4];
        cn.copy_from_slice(&b[9..13]);
        let mut chain_code = [0u8; CHAIN_CODE_SIZE];
        chain_code.copy_from_slice(&b[13..45]);
        let mut private_key = [0u8; PRIVATE_KEY_SIZE];
        private_key.copy_from_slice(&b[46..78]);
        let k = Self::from_parts(
            &private_key,
            &chain_code,
            b[4],
            parent_fingerprint,
            ChildNumber(u32::from_be_bytes(cn)),
        );
        private_key.zeroize();
        chain_code.zeroize();
        Ok((prefix, k?))
    }

    /// The compressed public key.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_SIZE] {
        compressed_public_key(&self.private_key).expect("checked on construction")
    }

    /// The matching extended public key, for a watch-only wallet.
    pub fn to_extended_public_key(&self) -> ExtendedPublicKey {
        ExtendedPublicKey {
            public_key: self.public_key(),
            chain_code: self.chain_code,
            depth: self.depth,
            parent_fingerprint: self.parent_fingerprint,
            child_number: self.child_number(),
        }
    }

    /// This key's fingerprint, which its children carry as their parent's.
    pub fn fingerprint(&self) -> [u8; FINGERPRINT_SIZE] {
        fingerprint(&self.public_key())
    }

    /// Derive a child, hardened or normal.
    ///
    /// # Errors
    ///
    /// `InvalidChild` when the HMAC's left half is past the curve order or
    /// the sum is zero (skipping to the next index is the caller's call);
    /// `DepthOverflow` for a child of a key at depth 255.
    pub fn derive_child(&self, child: ChildNumber) -> Result<Self, Bip32Error> {
        let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(&self.chain_code)
            .expect("HMAC accepts a key of any length");

        if child.0 >= HARDENED_OFFSET {
            // Hardened: a zero byte, then the private key, which the public
            // half does not have.
            mac.update(&[0u8]);
            mac.update(&self.private_key);
        } else {
            mac.update(&self.public_key());
        }
        mac.update(&child.0.to_be_bytes());
        let mut i = mac.finalize().into_bytes();

        let mut il = [0u8; 32];
        il.copy_from_slice(&i[..32]);
        let mut cc = [0u8; CHAIN_CODE_SIZE];
        cc.copy_from_slice(&i[32..]);
        i.zeroize();

        // `il` plus the parent is the child key: wiped on every path out.
        // Zero is a valid tweak, as BIP32 and upstream take it; past the
        // order is not.
        let mut tweak = match tweak_of(&il) {
            Some(t) => t,
            None => {
                il.zeroize();
                cc.zeroize();
                return Err(Bip32Error::InvalidChild);
            }
        };
        il.zeroize();

        let mut parent = match scalar_of(&self.private_key) {
            Some(p) => p,
            None => {
                tweak.zeroize();
                cc.zeroize();
                return Err(Bip32Error::InvalidParent);
            }
        };

        // The child key. `tweak`, `parent` and `sum` are wiped on every path
        // out.
        let mut sum = tweak + parent;
        tweak.zeroize();
        parent.zeroize();
        if bool::from(sum.is_zero()) {
            sum.zeroize();
            cc.zeroize();
            return Err(Bip32Error::InvalidChild);
        }

        let depth = match self.depth.checked_add(1) {
            Some(d) => d,
            None => {
                sum.zeroize();
                cc.zeroize();
                return Err(Bip32Error::DepthOverflow);
            }
        };

        // The scalar's bytes are bound so they can be wiped, and the locals
        // are wiped once the key is built from copies, as in `from_seed`.
        let mut key = [0u8; PRIVATE_KEY_SIZE];
        let mut bytes = sum.to_bytes();
        key.copy_from_slice(&bytes);
        bytes.zeroize();
        sum.zeroize();

        let derived = Self {
            private_key: key,
            chain_code: cc,
            depth,
            parent_fingerprint: self.fingerprint(),
            child_number: child.to_be_bytes(),
        };
        key.zeroize();
        cc.zeroize();
        Ok(derived)
    }

    /// Derive along a path of child numbers. Each step drops, and so wipes,
    /// the one before it.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::derive_child`] returns, at the first step that fails.
    pub fn derive_path(&self, path: &[ChildNumber]) -> Result<Self, Bip32Error> {
        let mut node = self.clone();
        for &c in path {
            node = node.derive_child(c)?;
        }
        Ok(node)
    }
}

/// The compressed public key of a private key.
///
/// # Errors
///
/// `InvalidParent` if the key is zero or past the curve order.
pub fn compressed_public_key(
    private_key: &[u8; PRIVATE_KEY_SIZE],
) -> Result<[u8; PUBLIC_KEY_SIZE], Bip32Error> {
    let mut d = scalar_of(private_key).ok_or(Bip32Error::InvalidParent)?;
    let point = ProjectivePoint::GENERATOR * d;
    d.zeroize();
    Ok(compress(&point))
}

/// SEC1 compressed form of a point.
fn compress(point: &ProjectivePoint) -> [u8; PUBLIC_KEY_SIZE] {
    use k256::elliptic_curve::sec1::ToSec1Point;
    let affine = point.to_affine();
    let encoded = affine.to_sec1_point(true);
    let mut out = [0u8; PUBLIC_KEY_SIZE];
    out.copy_from_slice(encoded.as_bytes());
    out
}
