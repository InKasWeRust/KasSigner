use sha2::{Digest, Sha256};

const ANNOUNCEMENT_SEED: &[u8] = b"KasSigner-Stealth-Announce-v1";

pub fn announcement_address(prefix: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ANNOUNCEMENT_SEED);
    hasher.update(prefix.as_bytes());
    let public_key: [u8; 32] = hasher.finalize().into();
    crate::account::address::encode_p2pk_address(&public_key, prefix)
}
