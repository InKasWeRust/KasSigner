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

//! Sealing and opening a stego backup; the walk key; v1.0.7's containers
//! through the photo's payload shape and back.

use kassigner_crypto::bip39::{self, Mnemonic};
use kassigner_crypto::container::{OpenError, PBKDF2_ITERATIONS};
use kassigner_crypto::stego::{self, StegoError, CONTAINER_MAX, HINT_MAX};
use kassigner_protocol::container::{parse, Purpose, SALT_SIZE};
use kassigner_protocol::stego::blob::{self, Shape, V2_HEAD};
use kassigner_protocol::stego::walk::KEY_LABEL;
use sha2::{Digest, Sha256};

const DESC: &[u8] = b"Rocky at the beach, summer 2024";
const SALT: [u8; SALT_SIZE] = [0x11; SALT_SIZE];
const NONCE: [u8; 12] = [0x22; 12];
const HINT: &[u8] = b"Name of my loved one?";

fn abandon12() -> Mnemonic {
    bip39::from_words(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            .split(' '),
    )
    .unwrap()
}

fn abandon24() -> Mnemonic {
    bip39::from_words(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
            .split(' '),
    )
    .unwrap()
}

fn words(m: &Mnemonic) -> Vec<&'static str> {
    (0..m.len()).map(|i| m.word(i).unwrap()).collect()
}

#[test]
fn a_backup_seals_and_opens_with_its_hint() {
    for m in [abandon12(), abandon24()] {
        let mut file = [0u8; CONTAINER_MAX];
        let n = stego::seal_backup(&m, HINT, DESC, &SALT, &NONCE, &mut file).unwrap();
        let c = parse(&file[..n]).unwrap();
        assert_eq!(c.purpose, Purpose::Stego);
        assert_eq!(c.len, 1 + m.len() * 2 + HINT.len());
        let mut hint = [0u8; HINT_MAX];
        let (back, h) = stego::open_backup(&file[..n], DESC, &mut hint).unwrap();
        assert_eq!(words(&back), words(&m));
        assert_eq!(&hint[..h], HINT);
    }
}

#[test]
fn no_hint_is_nothing_at_all() {
    let m = abandon12();
    let mut file = [0u8; CONTAINER_MAX];
    let n = stego::seal_backup(&m, b"", DESC, &SALT, &NONCE, &mut file).unwrap();
    assert_eq!(parse(&file[..n]).unwrap().len, 1 + 24);
    let mut hint = [0u8; HINT_MAX];
    let (back, h) = stego::open_backup(&file[..n], DESC, &mut hint).unwrap();
    assert_eq!(words(&back), words(&m));
    assert_eq!(h, 0);
}

#[test]
fn a_wrong_descriptor_is_authentication_and_nothing_else() {
    let m = abandon12();
    let mut file = [0u8; CONTAINER_MAX];
    let n = stego::seal_backup(&m, HINT, DESC, &SALT, &NONCE, &mut file).unwrap();
    let mut hint = [0u8; HINT_MAX];
    assert_eq!(
        stego::open_backup(&file[..n], b"Rocky at the beach, summer 2023", &mut hint).err(),
        Some(StegoError::Container(OpenError::Authentication))
    );
    assert_eq!(
        hint, [0u8; HINT_MAX],
        "nothing of the hint leaks on a failure"
    );
}

#[test]
fn the_purpose_keeps_a_card_backup_and_a_stego_one_apart() {
    use kassigner_crypto::backup::{open_slot, seal_slot};
    use kassigner_crypto::container::SealKdf;
    use kassigner_crypto::slot::Slot;
    let m = abandon12();
    let mut photo = [0u8; CONTAINER_MAX];
    let n = stego::seal_backup(&m, b"", DESC, &SALT, &NONCE, &mut photo).unwrap();
    // The same bytes offered as a card backup: refused by purpose.
    assert!(matches!(
        open_slot(&photo[..n], DESC, b"", None),
        Err(kassigner_crypto::backup::BackupError::WrongPurpose(
            Purpose::Stego
        ))
    ));
    // A card backup offered as a stego one: refused by purpose, before any
    // derivation.
    let slot = Slot::mnemonic(m, b"").unwrap();
    let password = b"Correct Horse 42!";
    let mut card = [0u8; 256];
    let k = seal_slot(
        &slot,
        password,
        &SALT,
        &NONCE,
        SealKdf::Pbkdf2Sha256,
        &mut card,
    )
    .unwrap();
    let mut hint = [0u8; HINT_MAX];
    assert_eq!(
        stego::open_backup(&card[..k], password, &mut hint).err(),
        Some(StegoError::WrongPurpose(Purpose::Seed))
    );
}

#[test]
fn the_stepped_derivation_seals_and_opens_the_same_bytes() {
    let m = abandon24();
    let mut one = [0u8; CONTAINER_MAX];
    let n = stego::seal_backup(&m, HINT, DESC, &SALT, &NONCE, &mut one).unwrap();

    let mut steps = stego::steps(DESC, &SALT);
    let mut ticks = 0;
    loop {
        let (done, total) = steps.step(10_000);
        ticks += 1;
        if done == total {
            break;
        }
    }
    assert_eq!(ticks, PBKDF2_ITERATIONS / 10_000);
    let key = steps.sealing_key().unwrap();
    let mut two = [0u8; CONTAINER_MAX];
    let k = stego::seal_backup_with_key(&m, HINT, &key, &SALT, &NONCE, &mut two).unwrap();
    assert_eq!(&one[..n], &two[..k]);

    let (salt, purpose) = stego::kdf_of(&one[..n]).unwrap();
    assert_eq!((salt, purpose), (SALT, Purpose::Stego));
    let mut steps = stego::steps(DESC, &salt);
    while steps.key().is_none() {
        steps.step(25_000);
    }
    let mut hint = [0u8; HINT_MAX];
    let (back, h) =
        stego::open_backup_with_key(&one[..n], &steps.key().unwrap(), &mut hint).unwrap();
    assert_eq!(words(&back), words(&m));
    assert_eq!(&hint[..h], HINT);
}

/// A backup's descriptor is proved by its tag, nothing opened, as a unit
/// asks before hiding a backup over another. Its key checks, and the copy
/// checked is left wiped past its header; another descriptor's key is
/// `Authentication`; v1.0.7's seed container checks under its own; a hint's
/// container is refused by purpose.
#[test]
fn a_backups_descriptor_is_checked_by_its_tag() {
    use kassigner_crypto::container::{Pbkdf2Steps, KEY_SIZE};
    let key_for = |file: &[u8], descriptor: &[u8]| -> zeroize::Zeroizing<[u8; KEY_SIZE]> {
        let (salt, purpose) = stego::kdf_of(file).unwrap();
        let mut steps = Pbkdf2Steps::new(descriptor, &salt, purpose);
        while steps.key().is_none() {
            steps.step(50_000);
        }
        steps.key().unwrap()
    };
    let mut photo = [0u8; CONTAINER_MAX];
    let n = stego::seal_backup(&abandon24(), HINT, DESC, &SALT, &NONCE, &mut photo).unwrap();
    let key = key_for(&photo[..n], DESC);
    let mut copy = photo;
    assert_eq!(stego::check_backup_with_key(&mut copy[..n], &key), Ok(()));
    assert_ne!(&copy[..n], &photo[..n], "the copy checked is left wiped");
    let mut copy = photo;
    assert_eq!(
        stego::check_backup_with_key(&mut copy[..n], &key_for(&photo[..n], b"another")),
        Err(StegoError::Container(OpenError::Authentication))
    );

    let mut seed = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../spec/vectors/v107/cards/SD000001.KAS"
    ))
    .to_vec();
    let key = key_for(&seed, b"abc");
    assert_eq!(stego::check_backup_with_key(&mut seed, &key), Ok(()));
    let mut raw = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../spec/vectors/v107/cards/RAWHINT.KAS"
    ))
    .to_vec();
    let key = key_for(&raw, b"abc");
    assert_eq!(
        stego::check_backup_with_key(&mut raw, &key),
        Err(StegoError::WrongPurpose(Purpose::Raw))
    );
}

#[test]
fn a_hint_is_bounded_and_ascii() {
    let m = abandon12();
    let mut file = [0u8; CONTAINER_MAX];
    assert!(stego::seal_backup(&m, &[b'x'; HINT_MAX], DESC, &SALT, &NONCE, &mut file).is_ok());
    assert_eq!(
        stego::seal_backup(&m, &[b'x'; HINT_MAX + 1], DESC, &SALT, &NONCE, &mut file).err(),
        Some(StegoError::Hint)
    );
    assert_eq!(
        stego::seal_backup(&m, "caf\u{e9}".as_bytes(), DESC, &SALT, &NONCE, &mut file).err(),
        Some(StegoError::Hint)
    );
    assert!(stego::hint_ok(b"") && !stego::hint_ok(b"\t"));
}

#[test]
fn a_zero_salt_or_nonce_is_refused() {
    let m = abandon12();
    let mut file = [0u8; CONTAINER_MAX];
    assert_eq!(
        stego::seal_backup(&m, b"", DESC, &[0; SALT_SIZE], &NONCE, &mut file).err(),
        Some(StegoError::Container(OpenError::ZeroSaltOrNonce))
    );
}

#[test]
fn the_walk_key_is_v107s() {
    let k = stego::walk_key(DESC);
    let mut h = Sha256::new();
    h.update(KEY_LABEL);
    h.update(DESC);
    assert_eq!(k[..], h.finalize()[..]);
    assert_eq!(KEY_LABEL, b"KasSigner-stego-perm-v1");
    assert_ne!(stego::walk_key(b"a"), stego::walk_key(b"b"));
}

/// The round trip a photo makes: seal, strip to the payload, rebuild, open.
#[test]
fn the_payload_shape_round_trips_through_level_1() {
    let m = abandon24();
    let mut file = [0u8; CONTAINER_MAX];
    let n = stego::seal_backup(&m, HINT, DESC, &SALT, &NONCE, &mut file).unwrap();
    let mut payload = [0u8; 256];
    let p = blob::strip(&file[..n], &mut payload).unwrap();
    assert_eq!(blob::shape(&payload[..p]), Ok(Shape::V3));
    let mut rebuilt = [0u8; 256];
    let u = blob::unpack(&payload[..p], &mut rebuilt).unwrap();
    assert_eq!(&rebuilt[u.seed.clone()], &file[..n]);
    let mut hint = [0u8; HINT_MAX];
    let (back, h) = stego::open_backup(&rebuilt[u.seed], DESC, &mut hint).unwrap();
    assert_eq!(words(&back), words(&m));
    assert_eq!(&hint[..h], HINT);
}

/// v1.0.7's containers from the corpus, a seed card and a raw hint, both
/// under `abc`: what a v1.0.7 stego export under the descriptor `abc` puts
/// in a photo.
#[test]
fn v107s_seed_and_hint_open_through_the_v2_payload() {
    let seed: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../spec/vectors/v107/cards/SD000001.KAS"
    ));
    let raw: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../spec/vectors/v107/cards/RAWHINT.KAS"
    ));
    let descriptor = b"abc";
    // As v1.0.7 embedded them: each from its length byte on, no separator.
    let mut payload = seed[V2_HEAD..].to_vec();
    payload.extend_from_slice(&raw[V2_HEAD..]);
    assert_eq!(blob::shape(&payload), Ok(Shape::V2));
    let mut rebuilt = [0u8; 512];
    let u = blob::unpack(&payload, &mut rebuilt).unwrap();
    assert_eq!(&rebuilt[u.seed.clone()], seed);
    assert_eq!(&rebuilt[u.hint.clone().unwrap()], raw);

    let m = stego::open_legacy_seed(&rebuilt[u.seed.clone()], descriptor).unwrap();
    assert_eq!(words(&m), words(&abandon12()));
    let mut hint = [0u8; HINT_MAX];
    let h =
        stego::open_legacy_hint(&rebuilt[u.hint.clone().unwrap()], descriptor, &mut hint).unwrap();
    assert_eq!(&hint[..h], b"stego hint: abandon 12");

    // Each under its own key, derived in steps from its own salt.
    for (range, purpose) in [
        (u.seed.clone(), Purpose::Seed),
        (u.hint.clone().unwrap(), Purpose::Raw),
    ] {
        let (salt, p) = stego::kdf_of(&rebuilt[range.clone()]).unwrap();
        assert_eq!(p, purpose);
        let mut steps = kassigner_crypto::container::Pbkdf2Steps::new(descriptor, &salt, p);
        while steps.key().is_none() {
            steps.step(50_000);
        }
        let key = steps.key().unwrap();
        match purpose {
            Purpose::Seed => {
                assert!(stego::open_legacy_seed_with_key(&rebuilt[range], &key).is_ok());
            }
            _ => {
                let mut hint = [0u8; HINT_MAX];
                assert!(stego::open_legacy_hint_with_key(&rebuilt[range], &key, &mut hint).is_ok());
            }
        }
    }

    // Wrong descriptor, and the wrong function for each.
    assert!(matches!(
        stego::open_legacy_seed(&rebuilt[u.seed.clone()], b"abd"),
        Err(StegoError::Container(OpenError::Authentication))
    ));
    assert_eq!(
        stego::open_legacy_seed(&rebuilt[u.hint.clone().unwrap()], descriptor).err(),
        Some(StegoError::WrongPurpose(Purpose::Raw))
    );
    assert_eq!(
        stego::open_legacy_hint(&rebuilt[u.seed.clone()], descriptor, &mut hint).err(),
        Some(StegoError::WrongPurpose(Purpose::Seed))
    );
    assert_eq!(
        stego::open_backup(&rebuilt[u.seed], descriptor, &mut hint).err(),
        Some(StegoError::WrongPurpose(Purpose::Seed))
    );
}
