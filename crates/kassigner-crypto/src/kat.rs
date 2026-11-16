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

//! Known answers for this crate's primitives, for a device to run at boot.
//!
//! The host suite checks the source, not the binary about to derive a key:
//! a toolchain, a linker, a patched HAL and the silicon sit between them,
//! and a fault there can be silent and pass every test on a laptop. A broken
//! curve is caught when [`crate::sign::sign`] verifies its own output; a
//! wrong derivation is not, as it signs validly for an address nobody owns.
//!
//! The values are the specifications' (BIP39, BIP32, BIP340, GCM, RFC 7914,
//! RFC 9106), a seed backup a v1.0.7 unit wrote and rusty-kaspa's derivation
//! of a public seed, as the host tests hold them: a vector taken from the
//! code it checks proves only that the code still does what it did.
//!
//! Each function returns `(passed, total)`; a caller adds them up and halts
//! on any shortfall. The counts say which of a set failed, and `total` is a
//! constant, so a suite that silently ran nothing shows as a zero.

use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
use hmac::Hmac;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::bip32::ExtendedPrivateKey;
use crate::bip39::{from_entropy, scratch_for, to_seed};
use crate::container::{open_with_key, seal_with_key, Argon2Block, SealingKey};
use crate::sign::{public_key, sign};
use crate::slot::{from_seedqr, to_seedqr, Slots, SEEDQR_MAX};
use crate::wallet::Wallet;
use kassigner_kaspa::derivation::Path;
use kassigner_protocol::container::{file_size, parse, Kdf, Layout, Purpose};

/// The BIP39 vector's seed: the all-zero entropy's words under the
/// passphrase `TREZOR`, held to the specification's by `tests/bip39.rs`.
pub const BIP39_SEED: [u8; 64] = [
    0xc5, 0x52, 0x57, 0xc3, 0x60, 0xc0, 0x7c, 0x72, 0x02, 0x9a, 0xeb, 0xc1, 0xb5, 0x3c, 0x05, 0xed,
    0x03, 0x62, 0xad, 0xa3, 0x8e, 0xad, 0x3e, 0x3e, 0x9e, 0xfa, 0x37, 0x08, 0xe5, 0x34, 0x95, 0x53,
    0x1f, 0x09, 0xa6, 0x98, 0x75, 0x99, 0xd1, 0x82, 0x64, 0xc1, 0xe1, 0xc9, 0x2f, 0x2c, 0xf1, 0x41,
    0x63, 0x0c, 0x7a, 0x3c, 0x4a, 0xb7, 0xc8, 0x1b, 0x2f, 0x00, 0x16, 0x98, 0xe7, 0x46, 0x3b, 0x04,
];

/// BIP39: the all-zero entropy vector, entropy to words to seed, all 64
/// bytes of [`BIP39_SEED`]: the word list, the checksum and PBKDF2's 2,048
/// rounds of HMAC-SHA512. **The passphrase is `TREZOR`**, the reference
/// vectors'; an empty one gives another seed.
pub fn bip39() -> (u32, u32) {
    const TOTAL: u32 = 2;
    let mut passed = 0;

    let entropy = [0u8; 16];
    let Ok(m) = from_entropy(&entropy) else {
        return (0, TOTAL);
    };
    if m.len() == 12 && m.word(0) == Some("abandon") && m.word(11) == Some("about") {
        passed += 1;
    }

    // The scratch sized as a caller sizes it, from the passphrase's length;
    // the `Seed` wipes itself.
    const PASSPHRASE: &str = "TREZOR";
    let mut scratch = [0u8; scratch_for(PASSPHRASE.len())];
    if let Ok(seed) = to_seed(&m, PASSPHRASE, &mut scratch) {
        if *seed.as_bytes() == BIP39_SEED {
            passed += 1;
        }
    }
    scratch.fill(0);
    (passed, TOTAL)
}

/// BIP32's first test vector's master private key; its chain code and
/// compressed public key follow. Held to the specification's by
/// `tests/bip32.rs`.
pub const BIP32_MASTER_KEY: [u8; 32] = [
    0xe8, 0xf3, 0x2e, 0x72, 0x3d, 0xec, 0xf4, 0x05, 0x1a, 0xef, 0xac, 0x8e, 0x2c, 0x93, 0xc9, 0xc5,
    0xb2, 0x14, 0x31, 0x38, 0x17, 0xcd, 0xb0, 0x1a, 0x14, 0x94, 0xb9, 0x17, 0xc8, 0x43, 0x6b, 0x35,
];

/// See [`BIP32_MASTER_KEY`].
pub const BIP32_MASTER_CHAIN_CODE: [u8; 32] = [
    0x87, 0x3d, 0xff, 0x81, 0xc0, 0x2f, 0x52, 0x56, 0x23, 0xfd, 0x1f, 0xe5, 0x16, 0x7e, 0xac, 0x3a,
    0x55, 0xa0, 0x49, 0xde, 0x3d, 0x31, 0x4b, 0xb4, 0x2e, 0xe2, 0x27, 0xff, 0xed, 0x37, 0xd5, 0x08,
];

/// See [`BIP32_MASTER_KEY`].
pub const BIP32_MASTER_PUBLIC_KEY: [u8; 33] = [
    0x03, 0x39, 0xa3, 0x60, 0x13, 0x30, 0x15, 0x97, 0xda, 0xef, 0x41, 0xfb, 0xe5, 0x93, 0xa0, 0x2c,
    0xc5, 0x13, 0xd0, 0xb5, 0x55, 0x27, 0xec, 0x2d, 0xf1, 0x05, 0x0e, 0x2e, 0x8f, 0xf4, 0x9c, 0x85,
    0xc2,
];

/// BIP32: the first test vector's master key, whole ([`BIP32_MASTER_KEY`]
/// and the two after it), and its depth: HMAC-SHA512 over a seed and the
/// check against the curve order. No child is derived here; [`slot`]
/// derives a wallet's keys.
pub fn bip32() -> (u32, u32) {
    const TOTAL: u32 = 3;
    let mut passed = 0;

    let seed: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let Ok(m) = ExtendedPrivateKey::from_seed(&seed) else {
        return (0, TOTAL);
    };

    if *m.private_key() == BIP32_MASTER_KEY && *m.chain_code() == BIP32_MASTER_CHAIN_CODE {
        passed += 1;
    }
    if m.public_key() == BIP32_MASTER_PUBLIC_KEY {
        passed += 1;
    }
    if m.depth() == 0 {
        passed += 1;
    }
    (passed, TOTAL)
}

/// BIP340 vector 0's public key, whole: the x-coordinate of `3·G`.
pub const BIP340_PUBLIC_KEY: [u8; 32] = [
    0xf9, 0x30, 0x8a, 0x01, 0x92, 0x58, 0xc3, 0x10, 0x49, 0x34, 0x4f, 0x85, 0xf8, 0x9d, 0x52, 0x29,
    0xb5, 0x31, 0xc8, 0x45, 0x83, 0x6f, 0x99, 0xb0, 0x86, 0x01, 0xf1, 0x13, 0xbc, 0xe0, 0x36, 0xf9,
];

/// BIP340 vector 0's signature, whole: `R`'s x-coordinate, then `s`.
pub const BIP340_SIGNATURE: [u8; 64] = [
    0xe9, 0x07, 0x83, 0x1f, 0x80, 0x84, 0x8d, 0x10, 0x69, 0xa5, 0x37, 0x1b, 0x40, 0x24, 0x10, 0x36,
    0x4b, 0xdf, 0x1c, 0x5f, 0x83, 0x07, 0xb0, 0x08, 0x4c, 0x55, 0xf1, 0xce, 0x2d, 0xca, 0x82, 0x15,
    0x25, 0xf6, 0x6a, 0x4a, 0x85, 0xea, 0x8b, 0x71, 0xe4, 0x82, 0xa7, 0x4f, 0x38, 0x2d, 0x2c, 0xe5,
    0xeb, 0xee, 0xe8, 0xfd, 0xb2, 0x17, 0x2f, 0x47, 0x7d, 0xf4, 0x90, 0x0d, 0x31, 0x05, 0x36, 0xc0,
];

/// BIP340: the specification's vector 0, signed and checked byte for byte.
///
/// Deterministic given the key, message and auxiliary bytes, so a known
/// answer rather than a round trip, which would pass on a consistently wrong
/// curve. All 64 bytes, and all 32 of the key: the first half of a signature
/// is `R`, which the nonce alone decides, so a prefix check would pass a
/// wrong `s`, the half carrying the key and the challenge.
pub fn bip340() -> (u32, u32) {
    const TOTAL: u32 = 2;
    let mut passed = 0;

    let mut sk = [0u8; 32];
    sk[31] = 3;
    let aux = [0u8; 32];
    let msg = [0u8; 32];

    if let Ok(p) = public_key(&sk) {
        if p == BIP340_PUBLIC_KEY {
            passed += 1;
        }
    }
    if let Ok(s) = sign(&sk, &msg, &aux) {
        if *s.as_bytes() == BIP340_SIGNATURE {
            passed += 1;
        }
    }
    sk.fill(0);
    (passed, TOTAL)
}

/// The seed [`slot`] runs, as the standard SeedQR a scan hands over: the
/// all-zero entropy's words, "abandon" eleven times and "about" (index 3).
pub const SLOT_SEEDQR: &[u8; 48] = b"000000000000000000000000000000000000000000000003";

/// That seed's BIP32 master fingerprint with no passphrase, `73c5da0a`, as
/// every wallet shows it. Held to rusty-kaspa's derivation by
/// `tests/kat.rs`, and to a v1.0.7 unit's backup of it by `tests/v107.rs`.
pub const SLOT_FINGERPRINT: [u8; 4] = [0x73, 0xc5, 0xda, 0x0a];

/// That wallet's receive address 0's x-only key, `m/44'/111111'/0'/0/0`,
/// paid and spent in the v1.0.7 corpus (`spec/vectors/v107`). Held to
/// rusty-kaspa's derivation by `tests/kat.rs`.
pub const SLOT_RECEIVE0: [u8; 32] = [
    0x1b, 0xac, 0xea, 0x84, 0xca, 0x72, 0x1c, 0x95, 0xd6, 0x7e, 0xca, 0xce, 0x19, 0xbc, 0x49, 0x9a,
    0x77, 0xc0, 0x37, 0x26, 0xbc, 0x87, 0x39, 0xaf, 0x63, 0x7b, 0xcd, 0x89, 0xab, 0xaa, 0xf0, 0x58,
];

/// A seed through the path a real one takes, from a scanned SeedQR to a
/// wallet's key, which no answer above covers: a fault there gives
/// addresses no other wallet derives. Run whole, as loading a seed does:
///
/// 1. The SeedQR read into words, written back as the same digits.
/// 2. The words stored in a slot, the scan's copy left empty.
/// 3. The slot opened with [`Wallet::open`], as the flow opens one: its
///    fingerprint, [`SLOT_FINGERPRINT`].
/// 4. Its receive address 0's key, [`SLOT_RECEIVE0`]: the 44' account's
///    hardened levels and the two below.
///
/// No passphrase, as the published answers have none. Everything made is
/// wiped as it goes: the slot by [`Slots`]'s drop, the keys by theirs, the
/// stretch's scratch by [`Wallet::open`].
pub fn slot() -> (u32, u32) {
    const TOTAL: u32 = 4;
    let mut passed = 0;

    let Ok(mut m) = from_seedqr(SLOT_SEEDQR) else {
        return (0, TOTAL);
    };
    let mut digits = [0u8; SEEDQR_MAX];
    let n = to_seedqr(&m, &mut digits);
    if digits[..n] == SLOT_SEEDQR[..] {
        passed += 1;
    }
    digits.zeroize();

    let mut slots = Slots::<1>::new();
    let Ok(index) = slots.store_mnemonic(&mut m, b"") else {
        return (passed, TOTAL);
    };
    if m.is_empty() {
        passed += 1;
    }
    if slots.activate(index).is_err() {
        return (passed, TOTAL);
    }
    let Some((_, slot)) = slots.active() else {
        return (passed, TOTAL);
    };
    let mut scratch = [0u8; scratch_for(0)];
    let Ok(wallet) = Wallet::open(slot, &mut scratch) else {
        return (passed, TOTAL);
    };
    if wallet.fingerprint() == SLOT_FINGERPRINT {
        passed += 1;
    }
    if let Ok(key) = wallet.signing_key(Path::receive(0)) {
        if key.x_only() == SLOT_RECEIVE0 {
            passed += 1;
        }
    }
    (passed, TOTAL)
}

// ── Sealing and opening a backup ────────────────────────────────────────────

/// Test Case 16 of the GCM specification ("The Galois/Counter Mode of
/// Operation (GCM)", revised), with a 256-bit key and additional data: its
/// key, IV, additional data, plaintext, ciphertext and tag.
const GCM_KEY: [u8; 32] = [
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
];
const GCM_IV: [u8; 12] = [
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
];
const GCM_AAD: [u8; 20] = [
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xab, 0xad, 0xda, 0xd2,
];
const GCM_PLAINTEXT: [u8; 60] = [
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
    0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
    0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39,
];
const GCM_CIPHERTEXT: [u8; 60] = [
    0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
    0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
    0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
    0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a, 0xbc, 0xc9, 0xf6, 0x62,
];
const GCM_TAG: [u8; 16] = [
    0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68, 0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55, 0x1b,
];

/// RFC 7914's first PBKDF2-HMAC-SHA256 vector (section 11): `passwd` under
/// `salt`, one round, 64 bytes.
const PBKDF2_SHA256: [u8; 64] = [
    0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f, 0xec, 0x16, 0x91, 0xc2, 0x25, 0x44, 0xb6, 0x05,
    0xf9, 0x41, 0x85, 0x21, 0x6d, 0xde, 0x04, 0x65, 0xe6, 0x8b, 0x9d, 0x57, 0xc2, 0x0d, 0xac, 0xbc,
    0x49, 0xca, 0x9c, 0xcc, 0xf1, 0x79, 0xb6, 0x45, 0x99, 0x16, 0x64, 0xb3, 0x9d, 0x77, 0xef, 0x31,
    0x7c, 0x71, 0xb8, 0x45, 0xb1, 0xe3, 0x0b, 0xd5, 0x09, 0x11, 0x20, 0x41, 0xd3, 0xa1, 0x97, 0x83,
];

/// `SD000001.KAS` of the v1.0.7 corpus (`spec/vectors/v107/cards`): the
/// abandon 12 seed's backup, as a v1.0.7 unit wrote it under the password
/// `abc`. `KAS\x04`, a layout read and never written.
const V107_CARD: [u8; 76] = [
    0x4b, 0x41, 0x53, 0x04, 0x03, 0x01, 0x01, 0x18, 0x71, 0x77, 0x7f, 0x85, 0x8d, 0x93, 0x9b, 0xa1,
    0xa9, 0xaf, 0xb7, 0xbd, 0xc5, 0xcb, 0xd3, 0xd9, 0xd2, 0xdf, 0xea, 0xf7, 0x06, 0x13, 0x1e, 0x2b,
    0x3a, 0x47, 0x52, 0x5f, 0x54, 0xd5, 0xf2, 0xa8, 0x87, 0xac, 0xb7, 0x6a, 0xcb, 0x51, 0xcd, 0xbf,
    0xf1, 0x00, 0x91, 0x7a, 0x7b, 0x2e, 0xf7, 0x83, 0xcc, 0x0b, 0x49, 0xe1, 0x1a, 0x6a, 0x48, 0xaf,
    0x0b, 0x0a, 0xfc, 0x91, 0x32, 0x9e, 0xb1, 0xff, 0x56, 0x96, 0x50, 0x70,
];

/// The key `abc` gives `SD000001.KAS`, the card [`container`] opens: 100,000
/// PBKDF2 rounds, worked out off the device as a boot cannot spend them.
/// `tests/kat.rs` derives it again, and the card's tag refuses any other key.
pub const V107_CARD_KEY: [u8; 32] = [
    0xa4, 0xce, 0x17, 0xba, 0x44, 0x01, 0x6c, 0x72, 0x82, 0xa2, 0x5a, 0xfa, 0xcb, 0x93, 0x55, 0x8f,
    0xea, 0xd8, 0xd2, 0xe0, 0x6a, 0x86, 0x56, 0x6e, 0xa6, 0x24, 0x76, 0xea, 0x27, 0xda, 0xb6, 0x83,
];

/// What [`V107_CARD`] holds: the abandon 12 seed's word indices, two
/// little-endian bytes each, eleven `abandon` (0) and `about` (3).
const V107_CARD_WORDS: [u8; 24] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0,
];

/// Sealing and opening a backup: the cipher, the password's derivation and
/// the container. A wrong answer here is silent: cards a wrong cipher writes
/// open on no other unit.
///
/// 1. AES-256-GCM, the GCM specification's Test Case 16, sealed: its
///    ciphertext and tag.
/// 2. Opened again: its plaintext.
/// 3. Its tag with one bit changed: refused.
/// 4. PBKDF2-HMAC-SHA256, RFC 7914's first vector, one round: a card's
///    100,000 are longer than a boot can spend.
/// 5. The seed backup a v1.0.7 unit wrote, opened with its key: its words.
/// 6. Those words sealed in the current layout under the same key, salt and
///    nonce, and opened again: a round trip, holding the written layout to
///    the read one.
///
/// Argon2id is [`argon2id`], as it needs memory lent.
pub fn container() -> (u32, u32) {
    const TOTAL: u32 = 6;
    let mut passed = 0;

    let cipher = Aes256Gcm::new((&GCM_KEY).into());
    let nonce = Nonce::from(GCM_IV);
    let mut buf = GCM_PLAINTEXT;
    if let Ok(tag) = cipher.encrypt_inout_detached(&nonce, &GCM_AAD, (&mut buf[..]).into()) {
        if buf == GCM_CIPHERTEXT && tag.as_slice() == GCM_TAG {
            passed += 1;
        }
    }
    let mut buf = GCM_CIPHERTEXT;
    let opened =
        cipher.decrypt_inout_detached(&nonce, &GCM_AAD, (&mut buf[..]).into(), &Tag::from(GCM_TAG));
    if opened.is_ok() && buf == GCM_PLAINTEXT {
        passed += 1;
    }
    let mut tag = GCM_TAG;
    tag[15] ^= 1;
    let mut buf = GCM_CIPHERTEXT;
    let forged =
        cipher.decrypt_inout_detached(&nonce, &GCM_AAD, (&mut buf[..]).into(), &Tag::from(tag));
    if forged.is_err() {
        passed += 1;
    }

    let mut derived = [0u8; 64];
    let r = pbkdf2::pbkdf2::<Hmac<Sha256>>(b"passwd", b"salt", 1, &mut derived);
    if r.is_ok() && derived == PBKDF2_SHA256 {
        passed += 1;
    }

    let mut words = [0u8; V107_CARD_WORDS.len()];
    let mut file = [0u8; file_size(V107_CARD_WORDS.len())];
    if let Ok(card) = parse(&V107_CARD) {
        let opened = open_with_key(&card, &V107_CARD_KEY, &mut words);
        if matches!(opened, Ok(o) if o.purpose == Purpose::Seed && o.layout == Layout::Legacy)
            && words == V107_CARD_WORDS
        {
            passed += 1;
        }
        words.zeroize();
        if let Some(salt) = card.salt {
            let sealing = SealingKey::known_answer(V107_CARD_KEY);
            let sealed = seal_with_key(
                Purpose::Seed,
                &V107_CARD_WORDS,
                &sealing,
                Kdf::Pbkdf2Sha256,
                salt,
                card.nonce,
                &mut file,
            );
            if sealed == Ok(file.len()) {
                if let Ok(c) = parse(&file) {
                    let opened = open_with_key(&c, &V107_CARD_KEY, &mut words);
                    if matches!(opened, Ok(o) if o.purpose == Purpose::Seed && o.layout == Layout::V1)
                        && words == V107_CARD_WORDS
                    {
                        passed += 1;
                    }
                }
            }
        }
    }
    words.zeroize();
    file.zeroize();
    (passed, TOTAL)
}

/// The blocks of memory [`argon2id`] needs lent: RFC 9106's vector's 32 KiB.
pub const ARGON2ID_BLOCKS: usize = 32;

/// RFC 9106's Argon2id vector (section 5.3): 32 KiB, three passes, four
/// lanes, a 32-byte tag; password 32 bytes of `01`, salt 16 of `02`, secret
/// 8 of `03`, associated data 12 of `04`.
const ARGON2ID_TAG: [u8; 32] = [
    0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9,
    0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59,
];

/// Argon2id: RFC 9106's vector, in `memory`, [`ARGON2ID_BLOCKS`] of it lent
/// by the caller and handed back wiped.
///
/// For a unit that uses Argon2id, the P4: a card's derivation is larger but
/// runs the same code (BLAKE2b, the block compression, the indexing).
pub fn argon2id(memory: &mut [Argon2Block]) -> (u32, u32) {
    const TOTAL: u32 = 1;
    let mut passed = 0;
    let Some(blocks) = memory.get_mut(..ARGON2ID_BLOCKS) else {
        return (0, TOTAL);
    };
    let params = AssociatedData::new(&[0x04; 12]).and_then(|data| {
        ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(data)
            .output_len(32)
            .build()
    });
    if let Ok(params) = params {
        let argon2 =
            Argon2::new_with_secret(&[0x03; 8], Algorithm::Argon2id, Version::V0x13, params);
        let mut tag = [0u8; 32];
        if let Ok(argon2) = argon2 {
            let r = argon2.hash_password_into_with_memory(
                &[0x01; 32],
                &[0x02; 16],
                &mut tag,
                &mut *blocks,
            );
            if r.is_ok() && tag == ARGON2ID_TAG {
                passed += 1;
            }
        }
    }
    for b in blocks.iter_mut() {
        b.zeroize();
    }
    (passed, TOTAL)
}

/// Every known answer in this crate that needs no memory lent, as one
/// total: all but [`argon2id`].
pub fn all() -> (u32, u32) {
    let mut passed = 0;
    let mut total = 0;
    for (p, t) in [bip39(), bip32(), bip340(), slot(), container()] {
        passed += p;
        total += t;
    }
    (passed, total)
}
