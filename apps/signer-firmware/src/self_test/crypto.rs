// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Cryptographic known-answer checks shared by physical boards and QEMU.

use core::sync::atomic::{compiler_fence, Ordering};
use sha2::{Digest, Sha256};

pub(crate) fn test_sha256() -> bool {
    const EXPECTED_ABC: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    ];
    const EXPECTED_EMPTY_PREFIX: [u8; 4] = [0xe3, 0xb0, 0xc4, 0x42];

    let computed_abc: [u8; 32] = Sha256::digest(b"abc").into();
    let mut difference = 0u8;
    for index in 0..EXPECTED_ABC.len() {
        difference |= computed_abc[index] ^ EXPECTED_ABC[index];
    }
    compiler_fence(Ordering::SeqCst);
    if difference != 0 {
        return false;
    }

    let computed_empty: [u8; 32] = Sha256::digest(b"").into();
    computed_empty[..EXPECTED_EMPTY_PREFIX.len()] == EXPECTED_EMPTY_PREFIX
}
