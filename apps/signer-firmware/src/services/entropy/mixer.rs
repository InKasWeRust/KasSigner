// Small, explicit entropy-pool operations.

use sha2::{Digest, Sha256};

pub fn xor_digest(pool: &mut [u8; 32], digest: &[u8]) {
    for (destination, source) in pool.iter_mut().zip(digest.iter().copied()) {
        *destination ^= source;
    }
}

/// Mix optional user-entered d6 rolls into an already validated hardware/camera pool.
/// The hardware/camera pool remains mandatory; dice can only add a domain-separated
/// contribution and can never replace the checked device entropy path.
pub fn mix_additive_dice(pool: &mut [u8; 32], rolls: &[u8]) -> bool {
    if rolls.is_empty() || rolls.len() > 200 || rolls.iter().any(|roll| !(1..=6).contains(roll)) {
        return false;
    }
    let mut hasher = Sha256::new();
    hasher.update(b"KasSigner/additive-dice/v1");
    hasher.update((rolls.len() as u16).to_le_bytes());
    hasher.update(&*pool);
    hasher.update(rolls);
    let digest = hasher.finalize();
    pool.copy_from_slice(&digest);
    true
}

/// Mix a completed user touch transcript into an already validated entropy pool.
/// Touch is additive only: it can never replace the mandatory checked device pool.
pub fn mix_additive_touch(pool: &mut [u8; 32], touch_digest: &mut [u8; 32]) {
    let mut hasher = Sha256::new();
    hasher.update(b"KasSigner/additive-touch/v1");
    hasher.update(&*pool);
    hasher.update(&*touch_digest);
    let digest = hasher.finalize();
    pool.copy_from_slice(&digest);
    zeroize(touch_digest);
}

pub fn zeroize(bytes: &mut [u8]) {
    shared_signer::bytes::zeroize_bytes(bytes);
}
