// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A card's backup line: written as rusty-kaspa encodes addresses, read back
//! to the same card, and refused for every way a copy can go wrong.

use kaspa_addresses::{Address, Prefix, Version};
use kassigner_protocol::card::backup::{
    read, write, BackupError, ADDRESS_LEN, MAX_LEN, NONE, SAVINGS_V1,
};
use kassigner_protocol::card::savings::{Savings, UnlockAt, FIRST_MINUTE, MINUTES_PER_DAY};
use secp256k1::{Keypair, SECP256K1};

/// 1 January 2027, 00:00 UTC, in minutes since the Unix epoch.
const NEW_YEAR_2027: u32 = 20_819 * MINUTES_PER_DAY;

/// 14:30 UTC, in minutes after midnight.
const HALF_PAST_TWO: u32 = 14 * 60 + 30;

/// The backup of the first of [`cards`], in full, so any format change shows.
const VECTOR: &str = "savings_v1(\
kaspa:qqdcf32k0vfxgsyet5ldt246q4jaw8scx3sysx0lnstlt6w4m5rc72kqpk9q3,\
kaspa:qpx5kmx3xcgr9j5m62htnkgq4fx5tk02mq9vjs3nwnz9rfe9f5rkvz0673pmd,\
01/01/2027 00:00,\
kaspa:ppx4y2gfned75sa9w64fw7rjumtng5yyzs4s4vmrv6appfgut0jcv5q4pg9pg)";

fn x(seed: u8) -> [u8; 32] {
    let kp = Keypair::from_seckey_slice(SECP256K1, &[seed; 32]).expect("a secret key");
    kp.x_only_public_key().0.serialize()
}

fn at(minutes: u32) -> UnlockAt {
    UnlockAt::new(minutes).expect("a minute")
}

/// Cards covering a recovery wallet or none, midnight and a time of day,
/// the first minute and the last.
fn cards() -> Vec<Savings> {
    let (a, b, c) = (x(1), x(2), x(3));
    vec![
        Savings::new(a, Some(b), at(NEW_YEAR_2027)).unwrap(),
        Savings::new(a, None, at(NEW_YEAR_2027)).unwrap(),
        Savings::new(c, Some(a), at(FIRST_MINUTE)).unwrap(),
        Savings::new(b, Some(c), at(u32::MAX)).unwrap(),
        Savings::new(b, Some(a), at(NEW_YEAR_2027 + HALF_PAST_TWO)).unwrap(),
    ]
}

fn line(card: &Savings) -> String {
    let mut out = [0u8; MAX_LEN];
    let n = write(card, &mut out).expect("a line");
    String::from_utf8(out[..n].to_vec()).unwrap()
}

/// Upstream's mainnet address for a payload.
fn theirs(version: Version, payload: &[u8]) -> String {
    Address::new(Prefix::Mainnet, version, payload).to_string()
}

/// Upstream's address for a card's program, on `prefix`.
fn card_address(card: &Savings, prefix: Prefix) -> String {
    let program = card.program();
    kaspa_txscript::extract_script_pub_key_address(
        &kaspa_txscript::pay_to_script_hash_script(&program),
        prefix,
    )
    .unwrap()
    .to_string()
}

/// The vector's four fields.
fn vector_fields() -> [String; 4] {
    let inner = &VECTOR[SAVINGS_V1.len()..VECTOR.len() - 1];
    let fields: Vec<String> = inner.split(',').map(str::to_string).collect();
    fields.try_into().unwrap()
}

/// The vector with `field`, 0 to 3, replaced by `with`.
fn with_field(field: usize, with: &str) -> String {
    let mut fields = vector_fields();
    fields[field] = with.to_string();
    format!("{SAVINGS_V1}{})", fields.join(","))
}

/// `address` with the character at `i` changed to another of bech32's.
fn one_typo(address: &str, i: usize) -> String {
    let mut b = address.to_string().into_bytes();
    b[i] = if b[i] == b'q' { b'p' } else { b'q' };
    String::from_utf8(b).unwrap()
}

/// A card's line is its fields as upstream encodes them, and reads back as
/// the card.
#[test]
fn a_backup_is_the_cards_fields_and_reads_back() {
    for card in cards() {
        let owner = theirs(Version::PubKey, card.owner());
        let recovery = card
            .recovery()
            .map_or(NONE.to_string(), |r| theirs(Version::PubKey, r));
        let (y, m, d) = card.unlock().date();
        let (h, min) = card.unlock().time();
        let address = card_address(&card, Prefix::Mainnet);
        let want =
            format!("{SAVINGS_V1}{owner},{recovery},{d:02}/{m:02}/{y} {h:02}:{min:02},{address})");
        assert_eq!(line(&card), want);
        assert_eq!(read(want.as_bytes()), Ok(card), "{want}");
        assert!(want.len() <= MAX_LEN);
        assert_eq!(owner.len(), ADDRESS_LEN);
        assert_eq!(address.len(), ADDRESS_LEN);
    }
    assert_eq!(line(&cards()[0]), VECTOR);
    assert_eq!(read(VECTOR.as_bytes()), Ok(cards()[0]));
    assert_eq!(VECTOR.len(), 232, "a four-digit year");
    assert!(
        line(&cards()[4]).contains(",01/01/2027 14:30,"),
        "a time of day"
    );
    assert_eq!(line(&cards()[1]).len(), 169, "no recovery wallet");
}

/// The last minute's line is the longest, and [`MAX_LEN`] holds it.
#[test]
fn max_len_holds_the_longest_line() {
    let last = &cards()[3];
    assert_eq!(line(last).len(), MAX_LEN);
    let mut short = [0u8; MAX_LEN - 1];
    assert_eq!(write(last, &mut short), Err(BackupError::BufferTooSmall));
    let mut empty = [0u8; 0];
    assert_eq!(
        write(&cards()[0], &mut empty),
        Err(BackupError::BufferTooSmall)
    );
}

/// Whitespace at the ends, as a scanner or a file adds it, is ignored;
/// whitespace inside is not.
#[test]
fn only_whitespace_at_the_ends_is_ignored() {
    let card = cards()[0];
    for padded in [
        format!("{VECTOR}\n"),
        format!("{VECTOR}\r\n"),
        format!("  \t{VECTOR} "),
    ] {
        assert_eq!(read(padded.as_bytes()), Ok(card));
    }
    let inside = VECTOR.replacen(',', ", ", 1);
    assert_eq!(read(inside.as_bytes()), Err(BackupError::BadKey));
}

/// Not a backup this reader knows, or not four fields.
#[test]
fn a_line_that_is_no_backup_is_refused() {
    for s in [
        String::new(),
        "multi_hd45(2,kpub1,kpub2)".into(),
        VECTOR.replacen("savings_v1(", "savings_v2(", 1),
        VECTOR.replacen("savings_v1(", "Savings_v1(", 1),
        VECTOR.replacen("savings_v1(", "savings_v1 (", 1),
        format!("x{VECTOR}"),
    ] {
        assert_eq!(read(s.as_bytes()), Err(BackupError::NotABackup), "{s}");
    }
    for s in [
        VECTOR[..VECTOR.len() - 1].to_string(),
        format!("{VECTOR})"),
        format!("{VECTOR}x"),
        format!("{VECTOR},"),
        VECTOR.replacen(",01/01/2027", "", 1),
        VECTOR.replacen("01/01/2027 00:00,", "01/01/2027 00:00,01/01/2027 00:00,", 1),
        VECTOR.replacen(",01/01", ",(01/01", 1),
        format!("{SAVINGS_V1})"),
    ] {
        assert_eq!(read(s.as_bytes()), Err(BackupError::Malformed), "{s}");
    }
}

/// A key field that is not a mainnet Schnorr address of a key.
#[test]
fn a_key_that_is_none_is_refused() {
    let [owner, _, _, card] = vector_fields();
    let testnet = Address::new(Prefix::Testnet, Version::PubKey, &x(1)).to_string();
    let ecdsa = {
        let kp = Keypair::from_seckey_slice(SECP256K1, &[1; 32]).unwrap();
        let key = kp.public_key().serialize();
        Address::new(Prefix::Mainnet, Version::PubKeyECDSA, &key).to_string()
    };
    let off_curve = theirs(Version::PubKey, &[0xff; 32]);
    // A script-hash address whose payload is the owner's key.
    let script_hash_of_key = theirs(Version::ScriptHash, &x(1));
    let typo = one_typo(&owner, 20);
    let upper_none = NONE.to_uppercase();
    let upper_owner = owner.to_uppercase();
    for field in [0, 1] {
        for bad in [
            upper_none.as_str(),
            "",
            &testnet,
            &ecdsa,
            &off_curve,
            &script_hash_of_key,
            &typo,
            &card,
            &upper_owner,
        ] {
            let s = with_field(field, bad);
            assert_eq!(
                read(s.as_bytes()),
                Err(BackupError::BadKey),
                "{field} {bad}"
            );
        }
    }
    assert_eq!(
        read(with_field(0, NONE).as_bytes()),
        Err(BackupError::BadKey),
        "none for the owner"
    );
}

/// A time that is not `DD/MM/YYYY HH:MM`, on a 24-hour clock, or not a
/// minute a card can unlock at.
#[test]
fn a_date_that_is_none_is_refused() {
    for bad in [
        "1/01/2027 00:00",
        "01/1/2027 00:00",
        "01/01/27 00:00",
        "01/01/02027 00:00",
        "2027/01/01 00:00",
        "01-01-2027 00:00",
        "01/01/2027/ 00:00",
        "31/04/2027 00:00",
        "29/02/2027 00:00",
        "29/02/2100 00:00",
        "00/01/2027 00:00",
        "01/13/2027 00:00",
        "05/11/1985 00:53",
        "01/01/1970 00:00",
        "aa/01/2027 00:00",
        "01/01/+2027 00:00",
        "01/01/ 2027 00:00",
        "01/01/123456 00:00",
        "01/01/99999999999 00:00",
        "17/02/10136 00:00",
        "16/02/10136 04:16",
        // The time of day: missing, short, past the day, another form.
        "01/01/2027",
        "01/01/2027 ",
        "01/01/2027 0:00",
        "01/01/2027 00:0",
        "01/01/2027 0000",
        "01/01/2027 00.00",
        "01/01/2027 24:00",
        "01/01/2027 00:60",
        "01/01/2027 00:00:00",
        "01/01/2027  00:00",
        "01/01/2027T00:00",
        "01/01/2027 aa:00",
        "01/01/2027 +1:00",
        "01/01/2027 00:00 ",
        "",
    ] {
        let s = with_field(2, bad);
        assert_eq!(read(s.as_bytes()), Err(BackupError::BadDate), "{bad}");
    }
    // Real times, but not this card's: its address does not match.
    for other in [
        "29/02/2028 00:00",
        "05/11/1985 00:54",
        "02/01/2027 00:00",
        "01/01/2028 00:00",
        "01/01/2027 00:01",
        "31/12/2026 23:59",
        "16/02/10136 04:15",
    ] {
        let s = with_field(2, other);
        assert_eq!(read(s.as_bytes()), Err(BackupError::NotTheCard), "{other}");
    }
}

/// A card field that is not a mainnet script-hash address.
#[test]
fn a_card_address_that_is_none_is_refused() {
    let [owner, _, _, card] = vector_fields();
    let testnet = card_address(&cards()[0], Prefix::Testnet);
    let typo = one_typo(&card, 30);
    let upper = card.to_uppercase();
    for bad in [owner.as_str(), "", NONE, &testnet, &typo, &upper] {
        let s = with_field(3, bad);
        assert_eq!(read(s.as_bytes()), Err(BackupError::BadAddress), "{bad}");
    }
}

/// Valid fields that make a different card from the one the address names.
#[test]
fn another_cards_address_is_refused() {
    let [owner, recovery, date, card] = vector_fields();
    let other = card_address(&cards()[2], Prefix::Mainnet);
    let third = theirs(Version::PubKey, &x(3));
    let none = NONE.to_string();
    for (o, r, a) in [
        (&owner, &recovery, &other),
        (&owner, &none, &card),
        (&owner, &third, &card),
        (&third, &recovery, &card),
        (&recovery, &owner, &card),
    ] {
        let s = format!("{SAVINGS_V1}{o},{r},{date},{a})");
        assert_eq!(read(s.as_bytes()), Err(BackupError::NotTheCard), "{s}");
    }
}

/// The owner's key as the recovery wallet is the card with none, whose line
/// says `none`: not canonical.
#[test]
fn the_owners_key_as_recovery_is_not_the_line() {
    let none = line(&cards()[1]);
    let owner = none[SAVINGS_V1.len()..].split(',').next().unwrap();
    let s = none.replacen(",none,", &format!(",{owner},"), 1);
    assert_eq!(read(s.as_bytes()), Err(BackupError::NotCanonical));
    assert_eq!(read(none.as_bytes()), Ok(cards()[1]));
}

/// One character changed anywhere, to any other of its kind, is refused.
#[test]
fn every_one_character_change_is_refused() {
    const BECH32: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    for card in cards() {
        let good = line(&card);
        for i in 0..good.len() {
            let c = good.as_bytes()[i];
            let others: Vec<u8> = if c.is_ascii_digit() {
                (b'0'..=b'9').filter(|&d| d != c).collect()
            } else if BECH32.contains(&c) {
                BECH32.iter().copied().filter(|&d| d != c).collect()
            } else {
                b"x ,/".iter().copied().filter(|&d| d != c).collect()
            };
            for o in others {
                let mut s = good.clone().into_bytes();
                s[i] = o;
                assert!(read(&s).is_err(), "{} read", String::from_utf8_lossy(&s));
            }
        }
    }
}
