// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Multisig descriptors.

use kassigner_protocol::descriptor::{
    max_len, parse, strip_header, write, DescriptorError, KPUB_STR_LEN, PREFIX,
};

/// A key of the right length, distinguishable by its first character.
fn key(c: char) -> String {
    let mut s = String::with_capacity(KPUB_STR_LEN);
    s.push(c);
    for _ in 1..KPUB_STR_LEN {
        s.push('x');
    }
    s
}

fn line(m: usize, keys: &[String]) -> String {
    let refs: Vec<&str> = keys.iter().map(String::as_str).collect();
    let mut out = vec![0u8; max_len(keys.len())];
    let n = write(m, &refs, &mut out).expect("write");
    String::from_utf8(out[..n].to_vec()).unwrap()
}

/// A descriptor round-trips through write and parse.
#[test]
fn a_descriptor_round_trips() {
    let keys = vec![key('a'), key('b'), key('c')];
    let text = line(2, &keys);
    assert!(text.starts_with(PREFIX));

    let mut out = [""; 8];
    let d = parse(&text, &mut out).expect("parse");
    assert_eq!(d.m, 2);
    assert_eq!(d.n, 3);
    assert_eq!(
        &out[..3],
        &[keys[0].as_str(), keys[1].as_str(), keys[2].as_str()]
    );
}

/// Prefixes other than `multi_hd45(` are not Kaspa multisig: `multi_hd(` is
/// 44', with no cosigner level, and `multi(` names no scheme.
#[test]
fn the_non_kaspa_prefixes_are_refused() {
    let entries = format!("{},{}", key('a'), key('b'));

    for prefix in ["multi_hd(", "multi(", "multisig(", "wsh(multi("] {
        // `out` lives inside the loop: its entries borrow from `text`.
        let mut out = [""; 8];
        let text = format!("{prefix}2,{entries})");
        assert_eq!(
            parse(&text, &mut out),
            Err(DescriptorError::BadScheme),
            "{prefix} was accepted"
        );
    }
}

/// The entries come back sorted, whatever the written order, as rusty-kaspa
/// sorts them before building a redeem script.
#[test]
fn entries_are_sorted_and_the_written_order_is_discarded() {
    let a = key('a');
    let b = key('b');
    let c = key('c');

    // The same three keys in all six orders.
    let orders = [
        [&a, &b, &c],
        [&a, &c, &b],
        [&b, &a, &c],
        [&b, &c, &a],
        [&c, &a, &b],
        [&c, &b, &a],
    ];
    for order in orders {
        let keys: Vec<String> = order.iter().map(|k| (*k).clone()).collect();
        let text = line(2, &keys);
        let mut out = [""; 8];
        parse(&text, &mut out).expect("parse");
        assert_eq!(
            &out[..3],
            &[a.as_str(), b.as_str(), c.as_str()],
            "written order leaked into the result"
        );
    }
}

/// The sort is a byte comparison, so uppercase sorts before lowercase: `Z`
/// before `t`.
#[test]
fn the_sort_is_a_byte_comparison() {
    let upper = key('Z');
    let lower = key('t');
    let text = line(1, &[lower.clone(), upper.clone()]);

    let mut out = [""; 4];
    parse(&text, &mut out).expect("parse");
    assert_eq!(out[0], upper.as_str(), "Z must sort before t");
    assert_eq!(out[1], lower.as_str());
}

/// A `#` header is skipped and never read: as an entry it would change the
/// sort and so every address.
#[test]
fn a_header_line_is_decorative() {
    let keys = vec![key('a'), key('b')];
    let body = line(2, &keys);

    let with_header = format!("# KasSigner multisig, 45' coordinated, 2-of-2\n{body}");
    assert_eq!(strip_header(&with_header), body);

    let mut out = [""; 4];
    let d = parse(&with_header, &mut out).expect("parse");
    assert_eq!(d.n, 2, "the header did not become an entry");
    assert_eq!(&out[..2], &[keys[0].as_str(), keys[1].as_str()]);

    // A header contradicting the descriptor loses.
    let lying = format!("# this says 44'\n{body}");
    assert_eq!(parse(&lying, &mut out).unwrap().n, 2);
}

/// A byte-order mark at the start of the text, as some editors write one, is
/// skipped, with or without a header line; anywhere else it is refused.
#[test]
fn a_byte_order_mark_ahead_of_the_text_is_skipped() {
    let keys = vec![key('a'), key('b')];
    let body = line(2, &keys);
    let mut out = [""; 4];
    let plain = parse(&body, &mut out).expect("parse");

    let marked = [
        format!("\u{FEFF}{body}"),
        format!("\u{FEFF}{body}\r\n"),
        format!("\u{FEFF}# KasSigner multisig, 45' coordinated, 2-of-2\r\n{body}\r\n"),
    ];
    for text in &marked {
        assert_eq!(strip_header(text).trim_end(), body, "{text:?}");
        assert_eq!(parse(text, &mut out), Ok(plain), "{text:?}");
        assert_eq!(&out[..2], &[keys[0].as_str(), keys[1].as_str()]);
    }

    let inside = format!("# KasSigner multisig\n\u{FEFF}{body}");
    assert_eq!(parse(&inside, &mut out), Err(DescriptorError::BadScheme));
    let twice = format!("\u{FEFF}\u{FEFF}{body}");
    assert_eq!(parse(&twice, &mut out), Err(DescriptorError::BadScheme));
}

/// A duplicate key is refused: this format's rule, as upstream's sort
/// refuses nothing.
#[test]
fn a_duplicate_key_is_refused() {
    let a = key('a');
    let text = line(1, &[a.clone(), key('b'), a.clone()]);
    let mut out = [""; 8];
    assert!(matches!(
        parse(&text, &mut out),
        Err(DescriptorError::DuplicateKey { .. })
    ));
}

/// The key count is bounded by the caller's slice, below the engine's limit.
#[test]
fn the_key_limit_comes_from_the_caller() {
    let keys: Vec<String> = "abcde".chars().map(key).collect();
    let text = line(2, &keys);

    let mut roomy = [""; 8];
    assert_eq!(parse(&text, &mut roomy).unwrap().n, 5);

    let mut tight = [""; 3];
    assert_eq!(
        parse(&text, &mut tight),
        Err(DescriptorError::TooManyKeys { found: 4, limit: 3 })
    );
}

/// A group past the engine's twenty keys is refused, read or written: its
/// address would hold coins nobody can move.
#[test]
fn a_group_past_the_engines_limit_is_refused() {
    let keys: Vec<String> = "abcdefghijklmnopqrstu".chars().map(key).collect();
    let refs: Vec<&str> = keys.iter().map(String::as_str).collect();
    let mut out = vec![0u8; max_len(keys.len())];
    let mut roomy = [""; 32];

    assert_eq!(
        write(2, &refs, &mut out),
        Err(DescriptorError::TooManyKeys {
            found: 21,
            limit: 20
        })
    );

    let twenty = line(2, &keys[..20]);
    assert_eq!(parse(&twenty, &mut roomy).unwrap().n, 20);

    let k = &keys[20];
    let twenty_one = format!("{},{k})", twenty.strip_suffix(')').unwrap());
    assert_eq!(
        parse(&twenty_one, &mut roomy),
        Err(DescriptorError::TooManyKeys {
            found: 21,
            limit: 20
        })
    );
}

/// Malformed descriptors are refused, each with its own error.
#[test]
fn malformed_descriptors_are_refused() {
    let mut out = [""; 8];
    let k = key('a');

    assert_eq!(
        parse("nonsense(1,x)", &mut out),
        Err(DescriptorError::BadScheme)
    );
    assert_eq!(
        parse("multi_hd45(1,x", &mut out),
        Err(DescriptorError::Unterminated)
    );
    // Terminated but empty: the parenthesis is there, the threshold is not.
    assert_eq!(
        parse("multi_hd45()", &mut out),
        Err(DescriptorError::BadThreshold)
    );

    // Threshold absent, not a number, zero, with a leading zero, or past
    // the engine's twenty keys. Bound to locals: `out` borrows from the text,
    // so a `format!` temporary would not compile.
    let no_threshold = format!("multi_hd45({k})");
    let not_a_digit = format!("multi_hd45(x,{k})");
    let zero = format!("multi_hd45(0,{k})");
    let leading_zero = format!("multi_hd45(01,{k})");
    let past_twenty = format!("multi_hd45(21,{k})");
    let three_digits = format!("multi_hd45(100,{k})");
    assert_eq!(
        parse(&no_threshold, &mut out),
        Err(DescriptorError::BadThreshold)
    );
    assert_eq!(
        parse(&not_a_digit, &mut out),
        Err(DescriptorError::BadThreshold)
    );
    assert_eq!(parse(&zero, &mut out), Err(DescriptorError::BadThreshold));
    for bad in [&leading_zero, &past_twenty, &three_digits] {
        assert_eq!(
            parse(bad, &mut out),
            Err(DescriptorError::BadThreshold),
            "{bad}"
        );
    }
    // Two digits are a threshold, above one key here.
    let ten = format!("multi_hd45(10,{k})");
    assert_eq!(
        parse(&ten, &mut out),
        Err(DescriptorError::ThresholdAboveKeys { m: 10, n: 1 })
    );

    // Threshold above the key count.
    let b = key('b');
    let too_high = format!("multi_hd45(3,{k},{b})");
    assert_eq!(
        parse(&too_high, &mut out),
        Err(DescriptorError::ThresholdAboveKeys { m: 3, n: 2 })
    );

    // An entry of the wrong length.
    assert_eq!(
        parse("multi_hd45(1,tooshort)", &mut out),
        Err(DescriptorError::BadEntryLength { index: 0, len: 8 })
    );
}

/// Writing refuses what parsing would refuse.
#[test]
fn writing_refuses_what_parsing_would() {
    let k = key('a');
    let mut out = vec![0u8; 1024];

    assert_eq!(write(1, &[], &mut out), Err(DescriptorError::NoKeys));
    assert_eq!(
        write(0, &[&k], &mut out),
        Err(DescriptorError::BadThreshold)
    );
    assert_eq!(
        write(2, &[&k], &mut out),
        Err(DescriptorError::ThresholdAboveKeys { m: 2, n: 1 })
    );
    assert_eq!(
        write(1, &["short"], &mut out),
        Err(DescriptorError::BadEntryLength { index: 0, len: 5 })
    );

    let mut tiny = [0u8; 10];
    assert_eq!(
        write(1, &[&k], &mut tiny),
        Err(DescriptorError::BufferTooSmall)
    );
}

/// The size bound covers what write produces.
#[test]
fn max_len_bounds_what_is_written() {
    for n in 1..=5usize {
        let keys: Vec<String> = "abcde".chars().take(n).map(key).collect();
        let refs: Vec<&str> = keys.iter().map(String::as_str).collect();
        let bound = max_len(n);
        let mut out = vec![0u8; bound];
        let written = write(1, &refs, &mut out).expect("write");
        assert_eq!(written, bound, "{n} keys");
    }
}

/// A two-digit threshold round-trips, at the bound's length. A non-ASCII
/// entry is refused whatever its byte length, reported in characters.
#[test]
fn a_two_digit_threshold_round_trips() {
    let names: Vec<char> = "abcdefghijklmnopqrst".chars().collect();
    let keys: Vec<String> = names.iter().copied().map(key).collect();
    let refs: Vec<&str> = keys.iter().map(String::as_str).collect();
    assert_eq!(refs.len(), 20);
    let mut text = vec![0u8; max_len(20)];
    let n = write(12, &refs, &mut text).expect("write");
    assert_eq!(n, max_len(20));
    let text = std::str::from_utf8(&text[..n]).unwrap();
    assert!(text.starts_with("multi_hd45(12,"));
    let mut out = [""; 20];
    let d = parse(text, &mut out).expect("parse");
    assert_eq!((d.m, d.n), (12, 20));
    assert_eq!(
        write(21, &refs, &mut [0u8; 2048]),
        Err(DescriptorError::BadThreshold)
    );

    let wide = format!("{}x", "é".repeat(KPUB_STR_LEN / 2));
    assert_eq!(wide.len(), KPUB_STR_LEN, "as long as a kpub, in bytes");
    let one = format!("multi_hd45(1,{wide})");
    assert_eq!(
        parse(&one, &mut out),
        Err(DescriptorError::BadEntryLength {
            index: 0,
            len: KPUB_STR_LEN / 2 + 1
        })
    );
}
