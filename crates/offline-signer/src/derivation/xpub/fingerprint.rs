//! Standard BIP32 parent-fingerprint derivation.

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// Return `RIPEMD160(SHA256(compressed_parent_pubkey))[0..4]`.
#[must_use]
pub(super) fn parent_fingerprint(compressed_parent_pubkey: &[u8]) -> [u8; 4] {
    let sha256 = Sha256::digest(compressed_parent_pubkey);
    let hash160 = Ripemd160::digest(sha256);
    [hash160[0], hash160[1], hash160[2], hash160[3]]
}
