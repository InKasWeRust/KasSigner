//! Device-cycle SHA-256 calibration harness. Measurement only.
//!
//! Password-KDF calibration belongs to the dedicated Argon2 Bench so this
//! diagnostic never normalizes a retired KasSigner PBKDF2 password policy.

use sha2::{Digest, Sha256};
use shared_signer::bytes::zeroize_bytes;

const SHA_ROUNDS: u32 = 2_000;

pub(crate) fn run() {
    let mut block = [0xA5u8; 32];
    let sha_start = esp_hal::xtensa_lx::timer::get_cycle_count();
    for round in 0..SHA_ROUNDS {
        let mut hash = Sha256::new();
        hash.update(block);
        hash.update(round.to_le_bytes());
        block.copy_from_slice(&hash.finalize());
    }
    let sha_cycles = esp_hal::xtensa_lx::timer::get_cycle_count().wrapping_sub(sha_start);
    crate::log!(
        "[sha-bench] SHA-256 {} rounds: {} cycles/round",
        SHA_ROUNDS,
        sha_cycles / SHA_ROUNDS,
    );
    crate::log!("[sha-bench] password KDF calibration moved to Settings -> Developer -> Argon2 Bench");
    zeroize_bytes(&mut block);
}

pub(crate) fn run_and_halt(delay: &mut esp_hal::delay::Delay) -> ! {
    run();
    crate::log!("[sha-bench] diagnostic complete; wallet routing disabled");
    crate::halt_forever(delay)
}
