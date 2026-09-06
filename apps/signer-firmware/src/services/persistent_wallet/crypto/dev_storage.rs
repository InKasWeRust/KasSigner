//! CoreS3 development-only software HMAC identity for persistence workflow testing.
//!
//! This key is intentionally derivable from the public development signing identity.
//! It provides deterministic encrypted-storage functionality for development/HIL, not
//! production device binding. Production firmware does not compile this module and
//! rejects its reserved record key-slot marker.

use offline_signer::derivation::hmac::zeroize_buf;
use sha2::{Digest, Sha256};

pub(super) const KEY_SLOT: u8 = 0xFE;
const KEY_DOMAIN: &[u8] = b"KasSigner/CoreS3/dev-storage-test-key/v1";
const BLOCK_SIZE: usize = 64;

pub(super) fn hmac(parts: &[&[u8]]) -> [u8; 32] {
    let mut key_hasher = Sha256::new();
    key_hasher.update(KEY_DOMAIN);
    key_hasher.update(signer_firmware_core::update::release::DEV_TEST_PUBKEY);
    let mut key: [u8; 32] = key_hasher.finalize().into();

    let mut inner_pad = [0x36u8; BLOCK_SIZE];
    let mut outer_pad = [0x5cu8; BLOCK_SIZE];
    for index in 0..key.len() {
        inner_pad[index] ^= key[index];
        outer_pad[index] ^= key[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    for part in parts { inner.update(*part); }
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_hash);
    let result = outer.finalize().into();

    zeroize_buf(&mut key);
    zeroize_buf(&mut inner_pad);
    zeroize_buf(&mut outer_pad);
    result
}
