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

//! The seed pool, against SHA-256 computed here so what it hashes is
//! pinned, and the dice path, against digests from Python's `hashlib`, as
//! anyone can recompute them.

use kassigner_crypto::bip39;
use kassigner_crypto::seed::{
    from_dice, Degenerate, Pool, SeedError, Words, DICE_MAX_RUN, DICE_RARE_FACE_DIVISOR, DOMAIN,
};
use sha2::{Digest, Sha256};

#[path = "../../../testkit/hex.rs"]
pub mod hex;
use hex::unhex;

fn indices(m: &bip39::Mnemonic) -> Vec<u16> {
    (0..m.len()).map(|i| m.index(i).unwrap()).collect()
}

/// An empty pool is not a seed.
#[test]
fn an_empty_pool_refuses() {
    assert_eq!(
        Pool::new().finish(Words::Twelve).err(),
        Some(SeedError::Empty)
    );
    assert_eq!(
        Pool::new().finish(Words::TwentyFour).err(),
        Some(SeedError::Empty)
    );
}

/// What the pool hashes: the domain, then per sample the tag length, the
/// tag, the byte length as four little-endian bytes, and the bytes.
#[test]
fn the_pool_is_sha256_over_the_framed_inputs() {
    let mut p = Pool::new();
    p.absorb(b"camera", &[1, 2, 3]);
    p.absorb(b"touch", &[]);
    assert_eq!(p.samples(), 2);

    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update([6u8]);
    h.update(b"camera");
    h.update(3u32.to_le_bytes());
    h.update([1u8, 2, 3]);
    h.update([5u8]);
    h.update(b"touch");
    h.update(0u32.to_le_bytes());
    let digest = h.finalize();

    let twelve = p.finish(Words::Twelve).unwrap();
    assert_eq!(twelve.len(), 12);
    assert_eq!(
        indices(&twelve),
        indices(&bip39::from_entropy(&digest[..16]).unwrap())
    );

    let mut p = Pool::new();
    p.absorb(b"camera", &[1, 2, 3]);
    p.absorb(b"touch", &[]);
    let twenty_four = p.finish(Words::TwentyFour).unwrap();
    assert_eq!(twenty_four.len(), 24);
    assert_eq!(
        indices(&twenty_four),
        indices(&bip39::from_entropy(&digest[..32]).unwrap())
    );
}

/// The pool matches `sha2` for every sample length from empty to past two
/// blocks. With the framing (17 bytes of domain, 1 of tag length, 3 of tag,
/// 4 of length) the total walks through 55, 56, 63, 64, 65, 119, 120 and
/// 128 bytes, SHA-256's padding boundaries.
#[test]
fn the_pool_pads_like_sha256_at_every_boundary() {
    for len in 0..=150usize {
        let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
        let mut p = Pool::new();
        p.absorb(b"cam", &bytes);

        let mut h = Sha256::new();
        h.update(DOMAIN);
        h.update([3u8]);
        h.update(b"cam");
        h.update((len as u32).to_le_bytes());
        h.update(&bytes);
        let digest = h.finalize();

        let m = p.finish(Words::TwentyFour).unwrap();
        assert_eq!(
            indices(&m),
            indices(&bip39::from_entropy(&digest[..32]).unwrap()),
            "sample of {len} bytes"
        );
    }

    // Bytes split across many absorbs, so a partial block carried between
    // calls is exercised at every fill level.
    let bytes: Vec<u8> = (0..300u32).map(|i| (i * 7 + 3) as u8).collect();
    let mut p = Pool::new();
    let mut h = Sha256::new();
    h.update(DOMAIN);
    for (i, chunk) in bytes.chunks(13).enumerate() {
        p.absorb(b"x", chunk);
        h.update([1u8]);
        h.update(b"x");
        h.update((chunk.len() as u32).to_le_bytes());
        h.update(chunk);
        assert_eq!(p.samples(), i as u32 + 1);
    }
    let digest = h.finalize();
    let m = p.finish(Words::TwentyFour).unwrap();
    assert_eq!(
        indices(&m),
        indices(&bip39::from_entropy(&digest[..32]).unwrap())
    );
}

/// The framing keeps different inputs apart: the same bytes split
/// differently, or under a different tag, are a different seed.
#[test]
fn framing_separates_inputs() {
    fn seed(samples: &[(&[u8], &[u8])]) -> Vec<u16> {
        let mut p = Pool::new();
        for (tag, bytes) in samples {
            p.absorb(tag, bytes);
        }
        indices(&p.finish(Words::TwentyFour).unwrap())
    }
    let a = seed(&[(b"a", b"xy")]);
    assert_eq!(a, seed(&[(b"a", b"xy")]));
    assert_ne!(a, seed(&[(b"ax", b"y")]));
    assert_ne!(a, seed(&[(b"a", b"x"), (b"a", b"y")]));
    assert_ne!(a, seed(&[(b"b", b"xy")]));
    assert_ne!(a, seed(&[(b"a", b"xy"), (b"a", b"")]));
}

/// The dice path is SHA-256 over the digits, checked against `hashlib`.
#[test]
fn dice_is_sha256_over_the_digits() {
    let rolls: Vec<u8> = b"123456".iter().cycle().take(99).copied().collect();
    let digest = unhex("5588d3630bd19f6375b7bd922457af34ea9c74f00807566a1cf808e445dc8c20");
    let m = from_dice(&rolls, Words::TwentyFour).unwrap();
    assert_eq!(indices(&m), indices(&bip39::from_entropy(&digest).unwrap()));
    let m = from_dice(&rolls, Words::Twelve).unwrap();
    assert_eq!(
        indices(&m),
        indices(&bip39::from_entropy(&digest[..16]).unwrap())
    );

    // Fifty rolls, the twelve-word minimum.
    let fifty: Vec<u8> = b"123456".iter().cycle().take(50).copied().collect();
    let digest = unhex("ee72ae915a4e6ea7ccbeb8e5e5eecef29a1d0d90f053183726a424b6d3b07325");
    let m = from_dice(&fifty, Words::Twelve).unwrap();
    assert_eq!(
        indices(&m),
        indices(&bip39::from_entropy(&digest[..16]).unwrap())
    );
}

/// Ninety-nine rolls by hand, checked against a second implementation, the
/// offline BIP39 "Mnemonic Code Converter": its *base 10* entropy type
/// hashes the digits as typed and shows these twenty-four words. Its *dice*
/// type maps `6` to `0` first, so it differs from this path, and its *hex*
/// type hashes the hex characters as text.
#[test]
fn dice_matches_a_second_implementation() {
    let rolls = b"413422516115524352653665244324315243526651442524133121526534251432565342514263436254151424356151432";
    assert_eq!(rolls.len(), 99);
    let want = "mule unit remember office sell reunion theory sadness catch summer annual \
                prosper grief yard online marble roast harsh magnet evidence delay option \
                science shadow";
    let m = from_dice(rolls, Words::TwentyFour).unwrap();
    let got: Vec<&str> = (0..24).map(|i| m.word(i).unwrap()).collect();
    assert_eq!(got.join(" "), want);

    // The twelve-word form is the digest's first sixteen bytes: only the
    // last word differs (its checksum bits).
    let m = from_dice(rolls, Words::Twelve).unwrap();
    let got: Vec<&str> = (0..12).map(|i| m.word(i).unwrap()).collect();
    assert_eq!(
        got.join(" "),
        "mule unit remember office sell reunion theory sadness catch summer annual provide"
    );
}

/// What the dice path refuses: a face that is not one, and too few rolls.
#[test]
fn dice_refuses() {
    let mut rolls = [b'3'; 99];
    rolls[40] = b'7';
    assert_eq!(
        from_dice(&rolls, Words::TwentyFour).err(),
        Some(SeedError::BadRoll { position: 40 })
    );
    rolls[40] = b'0';
    assert_eq!(
        from_dice(&rolls, Words::Twelve).err(),
        Some(SeedError::BadRoll { position: 40 })
    );
    assert_eq!(
        from_dice(&[b'2'; 98], Words::TwentyFour).err(),
        Some(SeedError::TooFewRolls { have: 98, need: 99 })
    );
    assert_eq!(
        from_dice(&[b'2'; 49], Words::Twelve).err(),
        Some(SeedError::TooFewRolls { have: 49, need: 50 })
    );
    // Enough rolls that look like dice are accepted (all twos would fail the
    // degenerate check below).
    let fifty: Vec<u8> = b"123456".iter().cycle().take(50).copied().collect();
    let ninety_nine: Vec<u8> = b"123456".iter().cycle().take(99).copied().collect();
    assert!(from_dice(&fifty, Words::Twelve).is_ok());
    assert!(from_dice(&ninety_nine, Words::TwentyFour).is_ok());
}

/// The pool's hasher wipes its state and buffered block when dropped
/// (`sha2`'s `zeroize` feature), checked by type; a pool abandoned halfway
/// relies on it too.
#[test]
fn the_pools_hasher_wipes_itself() {
    fn wipes_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    wipes_on_drop::<sha2::Sha256>();
}

/// Sequences typed, not rolled, are refused: all ones, a short pattern, a
/// stuck key. The thresholds sit where honest dice essentially never land
/// (see the constants' docs).
#[test]
fn dice_refuses_degenerate_sequences() {
    assert_eq!(DICE_RARE_FACE_DIVISOR, 60);
    assert_eq!(DICE_MAX_RUN, 10);

    // Ninety-nine ones: every other face is absent, and `2` is named first.
    assert_eq!(
        from_dice(&[b'1'; 99], Words::TwentyFour).err(),
        Some(SeedError::Degenerate(Degenerate::RareFace {
            face: b'2',
            count: 0
        }))
    );
    // `12345` over and over: `6` never appears.
    let five: Vec<u8> = b"12345".iter().cycle().take(99).copied().collect();
    assert_eq!(
        from_dice(&five, Words::TwentyFour).err(),
        Some(SeedError::Degenerate(Degenerate::RareFace {
            face: b'6',
            count: 0
        }))
    );
    // A face seen once in 99 is under the floor; seen twice is not.
    let mut once: Vec<u8> = b"12345".iter().cycle().take(98).copied().collect();
    once.push(b'6');
    assert_eq!(
        from_dice(&once, Words::TwentyFour).err(),
        Some(SeedError::Degenerate(Degenerate::RareFace {
            face: b'6',
            count: 1
        }))
    );
    let mut twice = once.clone();
    twice[0] = b'6';
    assert!(from_dice(&twice, Words::TwentyFour).is_ok());
    // At fifty rolls the floor is zero: a face seen once is accepted.
    let mut fifty: Vec<u8> = b"12345".iter().cycle().take(49).copied().collect();
    fifty.push(b'6');
    assert!(from_dice(&fifty, Words::Twelve).is_ok());

    // A stuck key: ten in a row, inside an otherwise balanced sequence.
    let mut run: Vec<u8> = b"123456".iter().cycle().take(99).copied().collect();
    for r in &mut run[30..40] {
        *r = b'4';
    }
    assert_eq!(
        from_dice(&run, Words::TwentyFour).err(),
        Some(SeedError::Degenerate(Degenerate::LongRun {
            face: b'4',
            length: 10
        }))
    );
    // Nine in a row is not.
    run[39] = b'5';
    assert!(from_dice(&run, Words::TwentyFour).is_ok());

    // Faces are checked before runs: a sequence failing both names the face.
    let mut both = vec![b'1'; 99];
    both[50] = b'2';
    assert_eq!(
        from_dice(&both, Words::TwentyFour).err(),
        Some(SeedError::Degenerate(Degenerate::RareFace {
            face: b'2',
            count: 1
        }))
    );
    // And a bad face or too few rolls is still reported ahead of either.
    assert_eq!(
        from_dice(&[b'1'; 98], Words::TwentyFour).err(),
        Some(SeedError::TooFewRolls { have: 98, need: 99 })
    );
}

/// A tag past 255 bytes is its first 255: its length is framed as one byte,
/// so the tag is cut there.
#[test]
fn a_long_tag_is_its_first_255_bytes() {
    let long = [b't'; 300];
    let mut a = Pool::new();
    a.absorb(&long, &[1, 2, 3]);
    a.absorb(b"touch", &[4]);
    let mut b = Pool::new();
    b.absorb(&long[..255], &[1, 2, 3]);
    b.absorb(b"touch", &[4]);
    assert_eq!(
        indices(&a.finish(Words::TwentyFour).unwrap()),
        indices(&b.finish(Words::TwentyFour).unwrap())
    );
}
