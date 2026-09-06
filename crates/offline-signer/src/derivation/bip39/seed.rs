// BIP39 mnemonic serialization and seed derivation.

use super::{Mnemonic12, Mnemonic24, Seed};
use crate::derivation::bip39_wordlist::WORDLIST;
use crate::derivation::hmac::{hmac_sha512, zeroize_buf};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ─── Seed derivation (PBKDF2-HMAC-SHA512) ─────────────────────────────

const BIP39_PBKDF2_ROUNDS: u16 = 2048;

/// Resumable BIP39 PBKDF2-HMAC-SHA512 derivation for cooperative embedded loops.
/// Sensitive phrase and PBKDF2 state is zeroized when the work object is dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SeedDerivation {
    phrase_buf: [u8; 256],
    phrase_len: usize,
    salt_buf: [u8; 256],
    salt_len: usize,
    u_prev: [u8; 64],
    result: [u8; 64],
    rounds_complete: u16,
    finished: bool,
}

impl SeedDerivation {
    pub fn from_mnemonic_12(mnemonic: &Mnemonic12, passphrase: &str) -> Self {
        Self::new(&mnemonic.indices, passphrase)
    }

    pub fn from_mnemonic_24(mnemonic: &Mnemonic24, passphrase: &str) -> Self {
        Self::new(&mnemonic.indices, passphrase)
    }

    fn new(indices: &[u16], passphrase: &str) -> Self {
        let mut phrase_buf = [0u8; 256];
        let phrase_len = serialize_mnemonic(indices, &mut phrase_buf);
        let mut salt_buf = [0u8; 256];
        let salt_len = build_salt(passphrase, &mut salt_buf);
        Self {
            phrase_buf,
            phrase_len,
            salt_buf,
            salt_len,
            u_prev: [0u8; 64],
            result: [0u8; 64],
            rounds_complete: 0,
            finished: false,
        }
    }

    /// Advance by at most `round_budget` PBKDF2 rounds. Returns the final seed
    /// exactly once when all 2048 BIP39 rounds have completed.
    pub fn advance(&mut self, round_budget: u16) -> Option<Seed> {
        if self.finished {
            return None;
        }

        // Construct a fixed upper bound before doing any cryptographic work.
        // The loop range is therefore finite even if a mutation corrupts the
        // internal progress assignment, preventing mutation tests from hanging.
        let target_round = self
            .rounds_complete
            .saturating_add(round_budget)
            .min(BIP39_PBKDF2_ROUNDS);

        if self.rounds_complete == 0 && target_round > 0 {
            let mut salt_with_index = [0u8; 260];
            salt_with_index[..self.salt_len].copy_from_slice(&self.salt_buf[..self.salt_len]);
            salt_with_index[self.salt_len..self.salt_len + 4].copy_from_slice(&1u32.to_be_bytes());
            self.u_prev = hmac_sha512(
                &self.phrase_buf[..self.phrase_len],
                &salt_with_index[..self.salt_len + 4],
            );
            self.result = self.u_prev;
            self.rounds_complete = 1;
            zeroize_buf(&mut salt_with_index);
            zeroize_buf(&mut self.salt_buf);
            self.salt_len = 0;
        }

        // The range is captured from the precomputed target. A faulty progress
        // mutation can produce a wrong result, but cannot turn this call into an
        // unbounded loop.
        let first_round = self.rounds_complete;
        for completed_round in first_round..target_round {
            let u_next = hmac_sha512(&self.phrase_buf[..self.phrase_len], &self.u_prev);
            for (result, next) in self.result.iter_mut().zip(u_next.iter()) {
                *result ^= *next;
            }
            self.u_prev = u_next;
            self.rounds_complete = completed_round.saturating_add(1);
        }

        if self.rounds_complete != BIP39_PBKDF2_ROUNDS {
            return None;
        }
        let seed = Seed { bytes: self.result };
        self.wipe();
        self.finished = true;
        Some(seed)
    }

    pub fn progress_percent(&self) -> u8 {
        if self.finished {
            return 100;
        }
        if self.rounds_complete == 0 {
            return 0;
        }
        let percent =
            ((u32::from(self.rounds_complete) * 100) / u32::from(BIP39_PBKDF2_ROUNDS)) as u8;
        percent.max(1)
    }

    fn wipe(&mut self) {
        self.phrase_buf.zeroize();
        self.salt_buf.zeroize();
        self.u_prev.zeroize();
        self.result.zeroize();
        self.phrase_len.zeroize();
        self.salt_len.zeroize();
        self.rounds_complete.zeroize();
    }

    #[cfg(test)]
    pub(crate) fn sensitive_state_is_zeroized(&self) -> bool {
        self.phrase_buf.iter().all(|byte| *byte == 0)
            && self.salt_buf.iter().all(|byte| *byte == 0)
            && self.u_prev.iter().all(|byte| *byte == 0)
            && self.result.iter().all(|byte| *byte == 0)
            && self.phrase_len == 0
            && self.salt_len == 0
            && self.rounds_complete == 0
    }
}

/// Derive a 512-bit seed from a 12-word mnemonic + passphrase.
///
/// BIP39 spec: PBKDF2(password=mnemonic_sentence, salt="mnemonic"+passphrase,
/// iterations=2048, dklen=64).
pub fn seed_from_mnemonic_12(mnemonic: &Mnemonic12, passphrase: &str) -> Seed {
    let mut checkpoint = || {};
    seed_from_indices(&mnemonic.indices, passphrase, &mut checkpoint)
}

/// Derive a 512-bit seed from a 12-word mnemonic while periodically yielding
/// to a caller-owned liveness checkpoint. The callback does not influence any
/// cryptographic input or output.
pub fn seed_from_mnemonic_12_with_checkpoint(
    mnemonic: &Mnemonic12,
    passphrase: &str,
    checkpoint: &mut impl FnMut(),
) -> Seed {
    seed_from_indices(&mnemonic.indices, passphrase, checkpoint)
}

/// Derive a 512-bit seed from a 24-word mnemonic + passphrase.
pub fn seed_from_mnemonic_24(mnemonic: &Mnemonic24, passphrase: &str) -> Seed {
    let mut checkpoint = || {};
    seed_from_indices(&mnemonic.indices, passphrase, &mut checkpoint)
}

/// 24-word counterpart of [`seed_from_mnemonic_12_with_checkpoint`].
pub fn seed_from_mnemonic_24_with_checkpoint(
    mnemonic: &Mnemonic24,
    passphrase: &str,
    checkpoint: &mut impl FnMut(),
) -> Seed {
    seed_from_indices(&mnemonic.indices, passphrase, checkpoint)
}

fn seed_from_indices(indices: &[u16], passphrase: &str, checkpoint: &mut impl FnMut()) -> Seed {
    // 24 BIP39 words plus separators fit comfortably in this stack buffer.
    let mut phrase_buf = [0u8; 256];
    let phrase_len = serialize_mnemonic(indices, &mut phrase_buf);

    let mut salt_buf = [0u8; 256];
    let salt_len = build_salt(passphrase, &mut salt_buf);
    let seed = pbkdf2_hmac_sha512(
        &phrase_buf[..phrase_len],
        &salt_buf[..salt_len],
        2048,
        checkpoint,
    );

    zeroize_buf(&mut phrase_buf);
    zeroize_buf(&mut salt_buf);
    seed
}

/// Serialize a mnemonic as a space-separated UTF-8 string.
fn serialize_mnemonic(indices: &[u16], buf: &mut [u8]) -> usize {
    let mut pos = 0;
    for (word_index, &index) in indices.iter().enumerate() {
        if word_index > 0 {
            buf[pos] = b' ';
            pos += 1;
        }
        let word_bytes = WORDLIST[index as usize].as_bytes();
        buf[pos..pos + word_bytes.len()].copy_from_slice(word_bytes);
        pos += word_bytes.len();
    }
    pos
}

/// Builds the BIP39 salt: "mnemonic" + passphrase
fn build_salt(passphrase: &str, buf: &mut [u8]) -> usize {
    let prefix = b"mnemonic";
    buf[..8].copy_from_slice(prefix);
    let pp_bytes = passphrase.as_bytes();
    buf[8..8 + pp_bytes.len()].copy_from_slice(pp_bytes);
    8 + pp_bytes.len()
}

// ═══════════════════════════════════════════════════════════════════════
// PBKDF2-HMAC-SHA512 — manual no-std implementation
// ═══════════════════════════════════════════════════════════════════════
//
// HMAC-SHA512 from offline_signer::derivation::hmac (shared with BIP32).
// Only PBKDF2 here, which is BIP39-specific.

/// PBKDF2-HMAC-SHA512 (RFC 2898)
///
/// DK = T1 || T2 || ... (we only need T1 for 64 bytes = 512 bits)
/// Ti = U1 ⊕ U2 ⊕ ... ⊕ Uc
/// U1 = HMAC(password, salt || INT(i))
/// Uj = HMAC(password, U_{j-1})
fn pbkdf2_hmac_sha512(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    checkpoint: &mut impl FnMut(),
) -> Seed {
    // For BIP39 we only need 64 bytes = one SHA512 block
    // So we only compute T1 (block_index = 1)

    // U1 = HMAC(password, salt || BE32(1))
    let mut salt_with_index = [0u8; 260]; // 256 max salt + 4 bytes index
    salt_with_index[..salt.len()].copy_from_slice(salt);
    // Append block index as big-endian u32
    let idx_bytes = 1u32.to_be_bytes();
    salt_with_index[salt.len()..salt.len() + 4].copy_from_slice(&idx_bytes);

    let mut u_prev = hmac_sha512(password, &salt_with_index[..salt.len() + 4]);
    let mut result = [0u8; 64];
    result.copy_from_slice(&u_prev);
    checkpoint();

    // U2..Uc. Checkpoint once per 64 completed rounds: frequent enough to
    // prove runtime progress on embedded targets without coupling crypto to a
    // particular watchdog implementation.
    for round in 1..iterations {
        let u_next = hmac_sha512(password, &u_prev);
        for j in 0..64 {
            result[j] ^= u_next[j];
        }
        u_prev = u_next;
        if round & 63 == 0 {
            checkpoint();
        }
    }
    checkpoint();

    // Zeroize temporaries
    zeroize_buf(&mut u_prev);
    zeroize_buf(&mut salt_with_index);

    Seed { bytes: result }
}
